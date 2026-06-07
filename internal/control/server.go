package control

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"edr/internal/baseline"
	"edr/internal/eventlog"
	"edr/internal/integrity"
	"edr/internal/policy"
)

type ServerOptions struct {
	BaselinePath   string
	PolicyPath     string
	EventPath      string
	ArtifactDir    string
	AllowedUIDs    []int
	IntegrityKey   []byte
	SigningKeyPath string
	Anchor         *eventlog.Anchor
	Shutdown       func()
}

const (
	defaultEventLimit = 50
	maxEventLimit     = 1000
)

func NewServer(agent *Agent, baselinePath string) http.Handler {
	return NewServerWithOptions(agent, ServerOptions{BaselinePath: baselinePath})
}

func NewServerWithOptions(agent *Agent, opts ServerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		writeJSON(w, map[string]any{"ok": true, "schema_version": "v0.1", "suppressor_state": agent.Suppressor.Snapshot()})
	})
	mux.HandleFunc("/v0/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		writeJSON(w, agent.Metrics())
	})
	mux.HandleFunc("/v0/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		pol := agent.CurrentPolicy()
		ring0 := "disabled"
		if h := agent.BPFHealth(); h.Attached {
			ring0 = "active"
		}
		writeJSON(w, map[string]any{"policy_rules": len(pol.Rules), "process_access": pol.ProcessAccess.Mode != "", "collector": "procfs", "ring0": ring0, "response_history": len(agent.ResponseHistory(0))})
	})
	mux.HandleFunc("/v0/policy/reload", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := opts.PolicyPath
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(filepath.Dir(opts.PolicyPath), override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			path = safePath
		}
		if path == "" {
			http.Error(w, "policy path is required", http.StatusBadRequest)
			return
		}
		if opts.PolicyPath != "" {
			_ = backupPolicy(opts.PolicyPath)
		}
		pol, err := policy.Load(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := verifyPolicySig(path, opts.SigningKeyPath); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		agent.ReplacePolicy(pol)
		writeJSON(w, map[string]any{"ok": true, "policy_path": path, "policy_rules": len(pol.Rules), "process_access": pol.ProcessAccess.Mode})
	})
	mux.HandleFunc("/v0/policy/versions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		versions, err := listPolicyVersions(opts.PolicyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"versions": versions})
	})
	mux.HandleFunc("/v0/policy/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		version := r.URL.Query().Get("version")
		path, err := rollbackPolicy(opts.PolicyPath, version)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pol, err := policy.Load(opts.PolicyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := verifyPolicySig(opts.PolicyPath, opts.SigningKeyPath); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		agent.ReplacePolicy(pol)
		writeJSON(w, map[string]any{"ok": true, "restored_from": path, "policy_rules": len(pol.Rules)})
	})
	mux.HandleFunc("/v0/policy/verify-signature", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := opts.PolicyPath
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(filepath.Dir(opts.PolicyPath), override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			path = safePath
		}
		if path == "" {
			http.Error(w, "policy path is required", http.StatusBadRequest)
			return
		}
		if opts.SigningKeyPath == "" {
			writeJSON(w, map[string]any{"ok": false, "detail": "signing key is not configured"})
			return
		}
		if err := verifyPolicySig(path, opts.SigningKeyPath); err != nil {
			writeJSON(w, map[string]any{"ok": false, "detail": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "policy_path": path})
	})

	mux.HandleFunc("/v0/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		result, err := queryEvents(opts.EventPath, eventQueryFromRequest(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/v0/events/verify", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if seqStr := r.URL.Query().Get("seq"); seqStr != "" {
			seq, err := strconv.ParseUint(seqStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid seq parameter", http.StatusBadRequest)
				return
			}
			result, err := verifyEventSeq(opts.EventPath, opts.IntegrityKey, seq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, result)
			return
		}
		result, err := eventlog.Verify(opts.EventPath, opts.IntegrityKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"verify":       result,
			"chain_state":  agent.Logger.ChainSnapshot(),
			"agent_schema": "v0.15",
		}
		if opts.Anchor != nil {
			snap := agent.Logger.ChainSnapshot()
			issues := opts.Anchor.CrossVerify(snap.ChainID, snap.LastSeq, snap.LastHash)
			if len(issues) > 0 {
				resp["anchor_issues"] = issues
			}
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/responses", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		limit := intParam(r, "limit", defaultEventLimit)
		writeJSON(w, map[string]any{"responses": agent.ResponseHistory(limit)})
	})
	mux.HandleFunc("/v0/network/nft/list", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if nftLister, ok := agent.Responder.(interface{ NFTList() any }); ok {
			writeJSON(w, nftLister.NFTList())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider is not available"})
	})
	mux.HandleFunc("/v0/network/nft/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if nftRollback, ok := agent.Responder.(interface{ NFTRollback() any }); ok {
			writeJSON(w, nftRollback.NFTRollback())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider is not available"})
	})
	mux.HandleFunc("/v0/forensics/export", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		outPath := ""
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(opts.ArtifactDir, override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			outPath = safePath
		}
		eventLimit := intParam(r, "event_limit", 200)
		bundle, err := ExportForensics(agent, opts.EventPath, outPath, eventLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, bundle)
	})

	mux.HandleFunc("/v0/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cred, loginUID, credErr := shutdownCredential(r)
		if credErr != nil {
			auditShutdown(agent, cred, loginUID, "deny", credErr.Error())
			http.Error(w, credErr.Error(), http.StatusForbidden)
			return
		}
		pol := agent.CurrentPolicy()
		if pol == nil || !pol.SelfProtection.ShutdownEnabled {
			reason := "self_protection.shutdown_enabled is false"
			auditShutdown(agent, cred, loginUID, "deny", reason)
			http.Error(w, reason, http.StatusForbidden)
			return
		}
		cred, loginUID, err := authorizeRootLogin(r)
		if err != nil {
			auditShutdown(agent, cred, loginUID, "deny", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if opts.Shutdown == nil {
			reason := "shutdown handler is not configured"
			auditShutdown(agent, cred, loginUID, "deny", reason)
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}
		auditShutdown(agent, cred, loginUID, "allow", "root login shutdown accepted")
		writeJSON(w, map[string]any{"ok": true, "shutdown": "scheduled"})
		opts.Shutdown()
	})

	mux.HandleFunc("/v0/baseline/run", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		t, err := baseline.Load(opts.BaselinePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, baseline.Run(t))
	})
	return mux
}

type eventQuery struct {
	Limit          int
	Offset         int
	Category       string
	Severity       string
	RuleID         string
	FilePath       string
	FileOp         string
	SubjectName    string
	SubjectPath    string
	SubjectCmdline string
	Since          time.Time
	Until          time.Time
}

type eventQueryResult struct {
	Events []map[string]any `json:"events"`
	Count  int              `json:"count"`
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
}

func auditShutdown(agent *Agent, cred peerCred, loginUID uint32, decision, reason string) {
	if agent == nil || agent.Logger == nil {
		return
	}
	severity := "critical"
	action := "shutdown"
	if decision != "allow" {
		action = "shutdown_denied"
	}
	_ = agent.Logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("shutdown-%s-%d", decision, time.Now().UnixNano()),
		Category: "self_protection",
		Severity: severity,
		Subject: map[string]any{
			"peer_uid":      cred.uid,
			"peer_gid":      cred.gid,
			"peer_pid":      cred.pid,
			"peer_loginuid": loginUID,
		},
		Action:   action,
		Decision: decision,
		RuleID:   "self-protect-shutdown",
		Evidence: map[string]any{"reason": reason, "boundary": "uid=0 and loginuid in {0,4294967295}"},
	})
}

func eventQueryFromRequest(r *http.Request) eventQuery {
	return eventQuery{Limit: intParam(r, "limit", defaultEventLimit), Offset: intParam(r, "offset", 0), Category: r.URL.Query().Get("category"), Severity: r.URL.Query().Get("severity"), RuleID: r.URL.Query().Get("rule_id"), FilePath: r.URL.Query().Get("file_path"), FileOp: r.URL.Query().Get("file_op"), SubjectName: r.URL.Query().Get("subject_name"), SubjectPath: r.URL.Query().Get("subject_path"), SubjectCmdline: r.URL.Query().Get("subject_cmdline"), Since: timeParam(r, "since"), Until: timeParam(r, "until")}
}

func queryEvents(path string, q eventQuery) (eventQueryResult, error) {
	if path == "" {
		return eventQueryResult{}, errors.New("event path is not configured")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return eventQueryResult{Events: []map[string]any{}, Limit: clampEventLimit(q.Limit), Offset: q.Offset}, nil
		}
		return eventQueryResult{}, err
	}
	defer f.Close()
	limit := clampEventLimit(q.Limit)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	page := make([]map[string]any, 0, minInt(limit, 128))
	total := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	ghostEvents := 0
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if q.Category != "" && event["category"] != q.Category {
			continue
		}
		if q.Severity != "" && event["severity"] != q.Severity {
			continue
		}
		if q.RuleID != "" && event["rule_id"] != q.RuleID {
			continue
		}
		if !eventMatchesFile(event, q.FilePath, q.FileOp) {
			continue
		}
		if !eventMatchesSubject(event, q.SubjectName, q.SubjectPath, q.SubjectCmdline) {
			continue
		}
		if !eventInTimeRange(event, q.Since, q.Until) {
			continue
		}
		if total >= offset && len(page) < limit {
			page = append(page, event)
		}
		total++
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			ghostEvents++
			fmt.Fprintf(os.Stderr, "edr-agent: WARNING: event log contains lines exceeding 1 MiB buffer; "+
				"%d oversized event(s) skipped in this query\n", ghostEvents)
		} else {
			return eventQueryResult{}, err
		}
	}
	if offset > total {
		offset = total
	}
	return eventQueryResult{Events: append([]map[string]any(nil), page...), Count: len(page), Total: total, Offset: offset, Limit: limit}, nil
}

func eventMatchesSubject(event map[string]any, name, path, cmdline string) bool {
	if name == "" && path == "" && cmdline == "" {
		return true
	}
	subj, ok := event["subject"].(map[string]any)
	if !ok {
		return false
	}
	if name != "" {
		v, _ := subj["name"].(string)
		if v != name {
			return false
		}
	}
	if path != "" {
		v, _ := subj["path"].(string)
		if v != path {
			return false
		}
	}
	if cmdline != "" {
		v, _ := subj["cmdline"].(string)
		if !strings.Contains(v, cmdline) {
			return false
		}
	}
	return true
}

func eventMatchesFile(event map[string]any, filePath, fileOp string) bool {
	if filePath == "" && fileOp == "" {
		return true
	}
	obj, ok := event["object"].(map[string]any)
	if !ok {
		return false
	}
	if filePath != "" {
		v, _ := obj["path"].(string)
		if v != filePath {
			return false
		}
	}
	if fileOp != "" {
		v, _ := obj["op"].(string)
		if !strings.EqualFold(v, fileOp) {
			return false
		}
	}
	return true
}

func eventInTimeRange(event map[string]any, since, until time.Time) bool {
	if since.IsZero() && until.IsZero() {
		return true
	}
	raw, ok := event["timestamp"].(string)
	if !ok || raw == "" {
		return false
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return false
	}
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

func timeParam(r *http.Request, key string) time.Time {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func intParam(r *http.Request, key string, fallback int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func clampEventLimit(n int) int {
	if n <= 0 {
		return defaultEventLimit
	}
	if n > maxEventLimit {
		return maxEventLimit
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// verifyEventSeq checks a single event by its sequence number. It scans
// the event file to reconstruct the chain state up to that seq, then
// verifies hash continuity and HMAC (when a key is provided).
func verifyEventSeq(path string, key []byte, targetSeq uint64) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"ok": true, "seq": targetSeq, "detail": "file not found"}, nil
		}
		return nil, err
	}
	defer f.Close()

	var prevHash string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		var e eventlog.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.IntegrityVersion != eventlog.IntegrityVersion {
			continue
		}
		if e.Seq == targetSeq {
			stored := e
			ok := true
			issues := []map[string]any{}

			if e.PrevHash != prevHash && targetSeq > 1 {
				ok = false
				issues = append(issues, map[string]any{
					"kind":     "prev_hash_break",
					"expected": prevHash,
					"actual":   e.PrevHash,
				})
			}

			// Recompute hash by stripping integrity fields.
			e.Hash = ""
			e.HMAC = ""
			payload, err := json.Marshal(e)
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			h.Write([]byte(prevHash))
			h.Write(payload)
			want := hex.EncodeToString(h.Sum(nil))
			if stored.Hash != want {
				ok = false
				issues = append(issues, map[string]any{
					"kind":     "hash_mismatch",
					"expected": want,
					"actual":   stored.Hash,
				})
			}

			hasHMAC := len(key) > 0
			hmacOK := true
			if hasHMAC {
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(stored.Hash))
				wantHMAC := hex.EncodeToString(mac.Sum(nil))
				if wantHMAC != stored.HMAC {
					hmacOK = false
					ok = false
					issues = append(issues, map[string]any{
						"kind":     "hmac_mismatch",
						"expected": wantHMAC,
						"actual":   stored.HMAC,
					})
				}
			}

			return map[string]any{
				"ok":        ok,
				"seq":       targetSeq,
				"hash":      stored.Hash,
				"prev_hash": stored.PrevHash,
				"chain_id":  stored.ChainID,
				"has_hmac":  hasHMAC,
				"hmac_ok":   hmacOK,
				"issues":    issues,
			}, nil
		}
		prevHash = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": false, "seq": targetSeq, "detail": "sequence not found"}, nil
}

type policyVersion struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

func backupPolicy(path string) error {
	if path == "" {
		return nil
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	backupDir := filepath.Join(filepath.Dir(path), ".versions")
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s.%s.bak", filepath.Base(path), time.Now().UTC().Format("20060102T150405.000000000Z"))
	out, err := os.OpenFile(filepath.Join(backupDir, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func listPolicyVersions(policyPath string) ([]policyVersion, error) {
	backupDir := filepath.Join(filepath.Dir(policyPath), ".versions")
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []policyVersion{}, nil
		}
		return nil, err
	}
	versions := make([]policyVersion, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bak") || strings.Contains(entry.Name(), string(filepath.Separator)) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		versions = append(versions, policyVersion{Name: entry.Name(), Path: filepath.Join(backupDir, entry.Name()), Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].ModTime.After(versions[j].ModTime) })
	return versions, nil
}

func rollbackPolicy(policyPath, version string) (string, error) {
	versions, err := listPolicyVersions(policyPath)
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", errors.New("no policy versions available")
	}
	selected := versions[0]
	if version != "" {
		found := false
		for _, v := range versions {
			if v.Name == version {
				selected = v
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("policy version %q not found", version)
		}
	}
	if err := backupPolicy(policyPath); err != nil {
		return "", err
	}
	in, err := os.Open(selected.Path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(policyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return selected.Path, nil
}

// policySignatureFile returns the conventional .sig path for a policy file.
func policySignatureFile(policyPath string) string {
	return policyPath + ".sig"
}

// verifyPolicySig checks the Ed25519 signature for a policy file when a
// signing key is configured. Returns an error when no signing key is
// configured, effectively disabling the policy reload endpoint for
// security (M8 fix: empty path must not bypass verification).
func verifyPolicySig(policyPath, signingKeyPath string) error {
	if signingKeyPath == "" {
		return fmt.Errorf("policy signing key not configured; reload endpoint disabled for security")
	}
	sigPath := policySignatureFile(policyPath)
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy signature file %q not found", sigPath)
		}
		return fmt.Errorf("read signature: %w", err)
	}
	// Verify needs only the public key. The agent must NOT hold the
	// signing private key — possession of the private key would let
	// a compromised host forge合法 policies.
	pubKeyPath := signingKeyPath + ".pub"
	pub, err := integrity.LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("public key %q: %w (agent must not hold signing private key)", pubKeyPath, err)
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	ok, err := integrity.Verify(pub, raw, string(sigData))
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return fmt.Errorf("policy signature does not match")
	}
	return nil
}
