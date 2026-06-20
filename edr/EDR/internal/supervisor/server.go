package supervisor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"edr/internal/eventlog"
)

type Server struct {
	mu             sync.Mutex
	secret         []byte
	logger         *eventlog.Logger
	hosts          map[string]HeartbeatRequest
	lastDecisionAt map[string]time.Time
	seenRequests   map[string]time.Time
	decisions      []DecisionRecord
	statePath      string
	evidenceDir    string
	decisionTTL    time.Duration
	hostStaleAfter time.Duration
	replayWindow   time.Duration
	maxHistory     int
}

type State struct {
	Hosts          map[string]HeartbeatRequest `json:"hosts"`
	LastDecisionAt map[string]time.Time        `json:"last_decision_at"`
	Decisions      []DecisionRecord            `json:"decisions,omitempty"`
}

type Options struct {
	Secret         []byte
	Logger         *eventlog.Logger
	StatePath      string
	EvidenceDir    string
	DecisionTTL    time.Duration
	HostStaleAfter time.Duration
	ReplayWindow   time.Duration
	MaxHistory     int
}

type DecisionRecord struct {
	DecisionID string    `json:"decision_id,omitempty"`
	Host       string    `json:"host,omitempty"`
	InstanceID string    `json:"instance_id"`
	PeerHost   string    `json:"peer_host,omitempty"`
	Peer       string    `json:"peer"`
	Action     string    `json:"action"`
	RuleID     string    `json:"rule_id"`
	RecordedAt time.Time `json:"recorded_at"`
	Reason     string    `json:"reason,omitempty"`
	PeerState  string    `json:"peer_state,omitempty"`
}

func NewServer(secret []byte, logger *eventlog.Logger) *Server {
	return NewServerWithOptions(Options{Secret: secret, Logger: logger})
}

func NewServerWithOptions(opts Options) *Server {
	if opts.DecisionTTL <= 0 {
		opts.DecisionTTL = 30 * time.Second
	}
	if opts.HostStaleAfter <= 0 {
		opts.HostStaleAfter = 10 * time.Second
	}
	if opts.ReplayWindow <= 0 {
		opts.ReplayWindow = 30 * time.Second
	}
	if opts.MaxHistory <= 0 {
		opts.MaxHistory = 128
	}
	s := &Server{
		secret:         append([]byte(nil), opts.Secret...),
		logger:         opts.Logger,
		hosts:          make(map[string]HeartbeatRequest),
		lastDecisionAt: make(map[string]time.Time),
		seenRequests:   make(map[string]time.Time),
		decisions:      make([]DecisionRecord, 0, opts.MaxHistory),
		statePath:      opts.StatePath,
		evidenceDir:    opts.EvidenceDir,
		decisionTTL:    opts.DecisionTTL,
		hostStaleAfter: opts.HostStaleAfter,
		replayWindow:   opts.ReplayWindow,
		maxHistory:     opts.MaxHistory,
	}
	_ = s.loadState()
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "component": "supervisor"})
	})
	mux.HandleFunc("/v0/supervisor/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/v0/supervisor/evidence", s.handleEvidence)
	mux.HandleFunc("/v0/supervisor/status", s.handleStatus)
	return mux
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.authorizeRequest(r, body, req.RequestID, req.SentAt); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	resp := s.recordAndDecide(req)
	writeJSON(w, resp)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if err := s.authorizeRequest(r, nil, r.Header.Get("X-EDR-Request-ID"), parseHeaderTime(r.Header.Get("X-EDR-Timestamp"))); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.hosts))
	for k := range s.hosts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hosts := make([]HeartbeatRequest, 0, len(keys))
	for _, k := range keys {
		hosts = append(hosts, s.hosts[k])
	}
	writeJSON(w, map[string]any{
		"ok":        true,
		"hosts":     hosts,
		"groups":    s.groupsLocked(),
		"decisions": s.decisions,
	})
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var rec EvidenceRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rec.RecordedAt.IsZero() {
		rec.RecordedAt = time.Now().UTC()
	}
	if err := s.authorizeRequest(r, body, rec.RequestID, rec.RecordedAt); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := WriteEvidenceFile(s.evidenceDir, rec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) recordAndDecide(req HeartbeatRequest) HeartbeatResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	scope := scopeKey(req.Hostname, req.BootID)
	localKey := scopedInstanceKey(scope, req.InstanceID)
	peerKey := scopedInstanceKey(scope, req.PeerInstanceID)
	s.hosts[localKey] = req
	_ = s.saveStateLocked()
	resp := HeartbeatResponse{OK: true}
	if req.PeerInstanceID == "" || req.PeerState != "down" {
		s.auditDecision(req, resp, "skip", "peer_not_down", nil)
		return resp
	}
	peer, ok := s.hosts[peerKey]
	if ok && recent(peer.SentAt, s.hostStaleAfter) {
		// Both sides are alive from supervisor's perspective; avoid split brain.
		s.auditDecision(req, resp, "skip", "peer_recently_alive", map[string]any{"peer_sent_at": peer.SentAt})
		return resp
	}
	if peer.Priority > req.Priority {
		s.auditDecision(req, resp, "skip", "lower_priority", map[string]any{"peer_priority": peer.Priority})
		return resp
	}
	decisionKey := localKey + "->" + peerKey
	if last := s.lastDecisionAt[decisionKey]; recent(last, s.decisionTTL) {
		s.auditDecision(req, resp, "skip", "decision_cooldown", map[string]any{"last_decision_at": last})
		return resp
	}
	s.lastDecisionAt[decisionKey] = time.Now().UTC()
	_ = s.saveStateLocked()
	resp.DecisionID = sanitize(scope) + "-" + req.InstanceID + "-" + req.PeerInstanceID + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	resp.RestartIntent = RestartIntent{
		RequestID:  "remote-" + resp.DecisionID,
		Target:     req.PeerInstanceID,
		Generation: req.Local.RestartGeneration + 1,
		Reason:     "peer_down_remote_quorum",
	}
	s.auditDecision(req, resp, "issue_restart_intent", "supervisor-quorum", map[string]any{
		"peer_state": req.PeerState,
		"priority":   req.Priority,
	})
	return resp
}

func verifySignature(body []byte, signature string, secret []byte) bool {
	if len(secret) == 0 {
		return true
	}
	signature = strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

func verifySignedRequest(method, path string, body []byte, requestID string, ts time.Time, signature string, secret []byte) bool {
	if len(secret) == 0 {
		return true
	}
	signature = strings.TrimPrefix(signature, "sha256=")
	expected := signRequest(method, path, body, requestID, ts, secret)
	return hmac.Equal([]byte(signature), []byte(expected))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func recent(ts time.Time, d time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	delta := time.Since(ts)
	if delta < 0 {
		delta = -delta
	}
	return delta <= d
}

func (s *Server) loadState() error {
	if s.statePath == "" {
		return nil
	}
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.Hosts != nil {
		s.hosts = migrateScopedHosts(st.Hosts)
	}
	if st.LastDecisionAt != nil {
		s.lastDecisionAt = st.LastDecisionAt
	}
	if st.Decisions != nil {
		s.decisions = st.Decisions
	}
	return nil
}

func migrateScopedHosts(in map[string]HeartbeatRequest) map[string]HeartbeatRequest {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]HeartbeatRequest, len(in))
	for key, hb := range in {
		scopedKey := key
		if !strings.Contains(key, "::") {
			scope := scopeKey(hb.Hostname, hb.BootID)
			if hb.InstanceID != "" {
				scopedKey = scopedInstanceKey(scope, hb.InstanceID)
			} else {
				scopedKey = scopedInstanceKey(scope, key)
			}
		}
		if prev, ok := out[scopedKey]; ok && prev.SentAt.After(hb.SentAt) {
			continue
		}
		out[scopedKey] = hb
	}
	return out
}

func (s *Server) saveStateLocked() error {
	if s.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o750); err != nil {
		return err
	}
	st := State{
		Hosts:          s.hosts,
		LastDecisionAt: s.lastDecisionAt,
		Decisions:      s.decisions,
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath)
}

func (s *Server) auditDecision(req HeartbeatRequest, resp HeartbeatResponse, action, ruleID string, extra map[string]any) {
	if s.logger == nil {
		s.appendDecisionLocked(req, resp, action, ruleID, extra)
		_ = s.saveStateLocked()
		return
	}
	evID := resp.DecisionID
	if evID == "" {
		evID = req.InstanceID + "-" + req.PeerInstanceID + "-" + action + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	evidence := map[string]any{
		"peer_state": req.PeerState,
		"priority":   req.Priority,
	}
	for k, v := range extra {
		evidence[k] = v
	}
	s.appendDecisionLocked(req, resp, action, ruleID, evidence)
	_ = s.saveStateLocked()
	_ = s.logger.Write(eventlog.Event{
		EventID:  evID,
		Category: "supervisor",
		Severity: "high",
		Action:   action,
		Decision: "alert",
		RuleID:   ruleID,
		Subject: map[string]any{
			"instance_id": req.InstanceID,
			"peer":        req.PeerInstanceID,
		},
		Evidence: evidence,
	})
}

func (s *Server) appendDecisionLocked(req HeartbeatRequest, resp HeartbeatResponse, action, ruleID string, evidence map[string]any) {
	scope := scopeKey(req.Hostname, req.BootID)
	rec := DecisionRecord{
		DecisionID: resp.DecisionID,
		Host:       scope,
		InstanceID: req.InstanceID,
		PeerHost:   scope,
		Peer:       req.PeerInstanceID,
		Action:     action,
		RuleID:     ruleID,
		RecordedAt: time.Now().UTC(),
		PeerState:  req.PeerState,
	}
	if v, ok := evidence["reason"].(string); ok {
		rec.Reason = v
	}
	s.decisions = append(s.decisions, rec)
	if len(s.decisions) > s.maxHistory {
		s.decisions = append([]DecisionRecord(nil), s.decisions[len(s.decisions)-s.maxHistory:]...)
	}
}

func (s *Server) groupsLocked() []map[string]any {
	groups := make(map[string][]string)
	for _, hb := range s.hosts {
		key := scopeKey(hb.Hostname, hb.BootID)
		groups[key] = append(groups[key], hb.InstanceID)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		members := groups[k]
		sort.Strings(members)
		out = append(out, map[string]any{"group": k, "members": members})
	}
	return out
}

func scopeKey(hostname, bootID string) string {
	if hostname != "" {
		return hostname
	}
	if bootID != "" {
		return bootID
	}
	return "unknown"
}

func scopedInstanceKey(scope, instanceID string) string {
	return scope + "::" + instanceID
}

func parseHeaderTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func (s *Server) authorizeRequest(r *http.Request, body []byte, requestID string, ts time.Time) error {
	if len(s.secret) == 0 {
		return nil
	}
	if requestID == "" {
		requestID = r.Header.Get("X-EDR-Request-ID")
	}
	if requestID == "" {
		return fmt.Errorf("missing request id")
	}
	if ts.IsZero() {
		return fmt.Errorf("missing or invalid timestamp")
	}
	if !recent(ts, s.replayWindow) {
		return fmt.Errorf("request timestamp outside replay window")
	}
	if !verifySignedRequest(r.Method, r.URL.Path, body, requestID, ts, r.Header.Get("X-EDR-Signature"), s.secret) {
		return fmt.Errorf("invalid signature")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSeenLocked(ts)
	if seenAt, ok := s.seenRequests[requestID]; ok && recent(seenAt, s.replayWindow) {
		return fmt.Errorf("replayed request id")
	}
	s.seenRequests[requestID] = ts
	return nil
}

func (s *Server) pruneSeenLocked(now time.Time) {
	for id, ts := range s.seenRequests {
		if now.Sub(ts) > s.replayWindow {
			delete(s.seenRequests, id)
		}
	}
}
