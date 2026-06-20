package supervisor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"edr/internal/liveness"
)

func signBody(body []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func signedRequest(t *testing.T, method, path string, body []byte, secret []byte, requestID string, ts time.Time) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if len(secret) > 0 {
		req.Header.Set("X-EDR-Request-ID", requestID)
		req.Header.Set("X-EDR-Timestamp", ts.UTC().Format(time.RFC3339Nano))
		req.Header.Set("X-EDR-Signature", "sha256="+signRequest(method, path, body, requestID, ts, secret))
	}
	return req
}

func TestSupervisorHeartbeatRejectsBadSignature(t *testing.T) {
	srv := NewServer([]byte("secret"), nil)
	req := httptest.NewRequest(http.MethodPost, "/v0/supervisor/heartbeat", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-EDR-Signature", "sha256=bad")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestSupervisorHeartbeatReturnsRestartIntentWhenPeerDown(t *testing.T) {
	srv := NewServer([]byte("secret"), nil)
	now := time.Now().UTC()

	req := HeartbeatRequest{
		RequestID:         "hb-1",
		InstanceID:        "edr-a",
		PeerInstanceID:    "edr-b",
		Hostname:          "host-1",
		Priority:          100,
		HeartbeatEverySec: 1,
		SentAt:            now,
		PeerState:         "down",
		Local:             liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 7},
	}
	body, _ := json.Marshal(req)
	httpReq := signedRequest(t, http.MethodPost, "/v0/supervisor/heartbeat", body, []byte("secret"), req.RequestID, now)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httpReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp HeartbeatResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RestartIntent.Target != "edr-b" {
		t.Fatalf("target = %q, want edr-b", resp.RestartIntent.Target)
	}
	if resp.RestartIntent.Generation != 8 {
		t.Fatalf("generation = %d, want 8", resp.RestartIntent.Generation)
	}
}

func TestSupervisorPersistsStateAndCooldown(t *testing.T) {
	statePath := t.TempDir() + "/supervisor-state.json"
	now := time.Now().UTC()
	srv := NewServerWithOptions(Options{
		Secret:      []byte("secret"),
		StatePath:   statePath,
		DecisionTTL: 30 * time.Second,
	})
	req := HeartbeatRequest{
		RequestID:         "hb-2",
		InstanceID:        "edr-a",
		PeerInstanceID:    "edr-b",
		Hostname:          "host-1",
		Priority:          100,
		HeartbeatEverySec: 1,
		SentAt:            now,
		PeerState:         "down",
		Local:             liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 4},
	}
	resp1 := srv.recordAndDecide(req)
	if resp1.RestartIntent.RequestID == "" {
		t.Fatal("expected first decision to issue restart intent")
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected persisted state")
	}
	srv2 := NewServerWithOptions(Options{
		Secret:      []byte("secret"),
		StatePath:   statePath,
		DecisionTTL: 30 * time.Second,
	})
	resp2 := srv2.recordAndDecide(req)
	if resp2.RestartIntent.RequestID != "" {
		t.Fatalf("expected cooldown to suppress duplicate decision, got %+v", resp2)
	}
}

func TestSupervisorSkipsWhenPeerRecentlyAlive(t *testing.T) {
	srv := NewServerWithOptions(Options{
		Secret:         []byte("secret"),
		HostStaleAfter: 10 * time.Second,
	})
	now := time.Now().UTC()
	srv.hosts["host-1::edr-b"] = HeartbeatRequest{
		InstanceID: "edr-b",
		Hostname:   "host-1",
		SentAt:     now,
		Priority:   90,
	}
	resp := srv.recordAndDecide(HeartbeatRequest{
		RequestID:         "hb-3",
		InstanceID:        "edr-a",
		PeerInstanceID:    "edr-b",
		Hostname:          "host-1",
		Priority:          100,
		HeartbeatEverySec: 1,
		SentAt:            now,
		PeerState:         "down",
		Local:             liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 1},
	})
	if resp.RestartIntent.RequestID != "" {
		t.Fatalf("expected no restart intent while peer is recently alive, got %+v", resp)
	}
}

func TestSupervisorStatusIncludesGroupsAndDecisions(t *testing.T) {
	srv := NewServerWithOptions(Options{Secret: []byte("secret")})
	now := time.Now().UTC()
	srv.recordAndDecide(HeartbeatRequest{
		RequestID:      "hb-4",
		InstanceID:     "edr-a",
		PeerInstanceID: "edr-b",
		Hostname:       "host-1",
		SentAt:         now,
		PeerState:      "down",
		Priority:       100,
		Local:          liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 1},
	})
	req := signedRequest(t, http.MethodGet, "/v0/supervisor/status", nil, []byte("secret"), "status-1", now)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !bytes.Contains([]byte(body), []byte(`"groups"`)) {
		t.Fatalf("expected groups in status, got %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"decisions"`)) {
		t.Fatalf("expected decisions in status, got %s", body)
	}
}

func TestSupervisorEvidenceEndpointWritesFile(t *testing.T) {
	dir := t.TempDir()
	srv := NewServerWithOptions(Options{
		Secret:      []byte("secret"),
		EvidenceDir: dir,
	})
	rec := EvidenceRecord{
		RequestID:  "ev-1",
		DecisionID: "d1",
		Host:       "host-1",
		InstanceID: "edr-a",
		Category:   "supervisor",
		Action:     "restart_peer",
		RuleID:     "supervisor-restart",
		RecordedAt: time.Now().UTC(),
	}
	body, _ := json.Marshal(rec)
	req := signedRequest(t, http.MethodPost, "/v0/supervisor/evidence", body, []byte("secret"), rec.RequestID, rec.RecordedAt)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 evidence file, got %d", len(matches))
	}
}

func TestSupervisorScopesHostsPerHostname(t *testing.T) {
	srv := NewServer([]byte("secret"), nil)
	now := time.Now().UTC()
	respA := srv.recordAndDecide(HeartbeatRequest{
		RequestID:      "ha",
		Hostname:       "host-a",
		InstanceID:     "edr-a",
		PeerInstanceID: "edr-b",
		Priority:       100,
		SentAt:         now,
		PeerState:      "down",
		Local:          liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 1},
	})
	if respA.RestartIntent.RequestID == "" {
		t.Fatal("expected host-a to get restart intent")
	}
	srv.recordAndDecide(HeartbeatRequest{
		RequestID:      "hb",
		Hostname:       "host-b",
		InstanceID:     "edr-b",
		PeerInstanceID: "edr-a",
		Priority:       90,
		SentAt:         now,
		PeerState:      "healthy",
		Local:          liveness.Heartbeat{InstanceID: "edr-b", RestartGeneration: 1},
	})
	respAgain := srv.recordAndDecide(HeartbeatRequest{
		RequestID:      "hc",
		Hostname:       "host-a",
		InstanceID:     "edr-a",
		PeerInstanceID: "edr-b",
		Priority:       100,
		SentAt:         now.Add(time.Second),
		PeerState:      "down",
		Local:          liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 2},
	})
	if respAgain.RestartIntent.RequestID != "" {
		t.Fatalf("expected cooldown, not peer state leakage from host-b: %+v", respAgain)
	}
}

func TestSupervisorRejectsReplayedRequestID(t *testing.T) {
	srv := NewServer([]byte("secret"), nil)
	now := time.Now().UTC()
	req := HeartbeatRequest{
		RequestID:      "replay-1",
		Hostname:       "host-1",
		InstanceID:     "edr-a",
		PeerInstanceID: "edr-b",
		Priority:       100,
		SentAt:         now,
		PeerState:      "down",
		Local:          liveness.Heartbeat{InstanceID: "edr-a", RestartGeneration: 1},
	}
	body, _ := json.Marshal(req)
	first := signedRequest(t, http.MethodPost, "/v0/supervisor/heartbeat", body, []byte("secret"), req.RequestID, req.SentAt)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, first)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d body=%s", rr.Code, rr.Body.String())
	}
	second := signedRequest(t, http.MethodPost, "/v0/supervisor/heartbeat", body, []byte("secret"), req.RequestID, req.SentAt)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, second)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected replay rejection, got %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestSupervisorLoadStateMigratesLegacyHostKeys(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "supervisor-state.json")
	now := time.Now().UTC()
	st := State{
		Hosts: map[string]HeartbeatRequest{
			"edr-a": {
				InstanceID: "edr-a",
				Hostname:   "host-1",
				BootID:     "boot-1",
				SentAt:     now.Add(-time.Second),
			},
			"host-1::edr-a": {
				InstanceID: "edr-a",
				Hostname:   "host-1",
				BootID:     "boot-1",
				SentAt:     now,
			},
			"edr-b": {
				InstanceID: "edr-b",
				Hostname:   "host-1",
				BootID:     "boot-1",
				SentAt:     now,
			},
		},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := NewServerWithOptions(Options{Secret: []byte("secret"), StatePath: statePath})
	if len(srv.hosts) != 2 {
		t.Fatalf("expected migrated deduped hosts, got %d: %#v", len(srv.hosts), srv.hosts)
	}
	if _, ok := srv.hosts["host-1::edr-a"]; !ok {
		t.Fatalf("expected migrated scoped key for edr-a, got %#v", srv.hosts)
	}
	if _, ok := srv.hosts["host-1::edr-b"]; !ok {
		t.Fatalf("expected migrated scoped key for edr-b, got %#v", srv.hosts)
	}
}
