package control

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/integrity"
	"edr/internal/policy"
	"edr/internal/response"
	"edr/internal/transport"
)

func TestServerPolicyReloadAndStatus(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeJSONFile(t, policyPath, policy.Policy{SchemaVersion: policy.SchemaVersion, ProcessAccess: policy.ProcessAccess{Mode: "monitor", Action: "kill"}})
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{PolicyPath: policyPath, AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodPost, "/v0/policy/reload"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (no signing key), got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestServerPolicyReloadWithSigningKey(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeJSONFile(t, policyPath, policy.Policy{SchemaVersion: policy.SchemaVersion, ProcessAccess: policy.ProcessAccess{Mode: "monitor", Action: "kill"}})

	// Generate and save signing key pair using the integrity package helpers.
	sk, err := integrity.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	if err := integrity.SaveSigningKey(sk, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := integrity.SavePublicKey(sk.Public, keyPath+".pub"); err != nil {
		t.Fatal(err)
	}

	// Sign the policy file.
	raw, _ := os.ReadFile(policyPath)
	sigHex, err := integrity.Sign(sk, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath+".sig", []byte(sigHex), 0o644); err != nil {
		t.Fatal(err)
	}

	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{PolicyPath: policyPath, AllowedUIDs: []int{0}, SigningKeyPath: keyPath})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodPost, "/v0/policy/reload"))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected reload ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	if agent.CurrentPolicy().ProcessAccess.Mode != "monitor" {
		t.Fatalf("policy was not reloaded: %#v", agent.CurrentPolicy())
	}
}

func TestQueryEventsFiltersAndLimits(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(events, []byte(`{"timestamp":"2026-01-01T00:00:00Z","category":"process","severity":"high","rule_id":"p1","subject":{"name":"bash","path":"/usr/bin/bash","cmdline":"bash -lc test"}}
{"timestamp":"2026-01-01T00:01:00Z","category":"network","severity":"high","rule_id":"n1"}
{"timestamp":"2026-01-01T00:02:00Z","category":"process","severity":"low","rule_id":"p2","subject":{"name":"python3","path":"/usr/bin/python3","cmdline":"python3 app.py"}}
{"timestamp":"2026-01-01T00:03:00Z","category":"file","severity":"medium","rule_id":"f1","object":{"path":"configs/policy.json","op":"write"}}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	since, _ := time.Parse(time.RFC3339, "2026-01-01T00:01:00Z")
	out, err := queryEvents(events, eventQuery{Category: "process", Since: since, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Total != 1 || out.Events[0]["rule_id"] != "p2" {
		t.Fatalf("unexpected events: %#v", out)
	}
	fileOut, err := queryEvents(events, eventQuery{Category: "file", FilePath: "configs/policy.json", FileOp: "write", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if fileOut.Count != 1 || fileOut.Events[0]["rule_id"] != "f1" {
		t.Fatalf("unexpected file events: %#v", fileOut)
	}
	subjOut, err := queryEvents(events, eventQuery{Category: "process", SubjectName: "python3", SubjectCmdline: "app.py", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if subjOut.Count != 1 || subjOut.Events[0]["rule_id"] != "p2" {
		t.Fatalf("unexpected subject-filtered events: %#v", subjOut)
	}
}

func TestPolicyBackupAndRollback(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeJSONFile(t, policyPath, policy.Policy{SchemaVersion: policy.SchemaVersion, ProcessAccess: policy.ProcessAccess{Mode: "monitor", Action: "kill"}})
	if err := BackupPolicy(policyPath); err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, policyPath, policy.Policy{SchemaVersion: policy.SchemaVersion, ProcessAccess: policy.ProcessAccess{Mode: "enforce", Action: "kill"}})
	if _, err := RollbackPolicyFile(policyPath, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProcessAccess.Mode != "monitor" {
		t.Fatalf("expected rollback to monitor, got %#v", loaded.ProcessAccess)
	}
}

func TestResponseHistoryLimit(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, MaxHistory: 2}
	agent.recordResponse(ResponseRecord{RuleID: "r1", Result: response.Result{Success: true}})
	time.Sleep(time.Nanosecond)
	agent.recordResponse(ResponseRecord{RuleID: "r2", Result: response.Result{Success: true}})
	agent.recordResponse(ResponseRecord{RuleID: "r3", Result: response.Result{Success: true}})
	history := agent.ResponseHistory(10)
	if len(history) != 2 || history[0].RuleID != "r2" || history[1].RuleID != "r3" {
		t.Fatalf("unexpected history: %#v", history)
	}
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServerForensicsExport(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	artifactDir := filepath.Join(dir, "artifacts")
	if err := os.WriteFile(eventPath, []byte(`{"timestamp":"2026-01-01T00:00:00Z","category":"process","severity":"high","rule_id":"p1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 1, Name: "init"}}}}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{EventPath: eventPath, ArtifactDir: artifactDir, AllowedUIDs: []int{0}})
	outPath := filepath.Join(artifactDir, "forensics.json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodPost, "/v0/forensics/export?path="+outPath))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected export ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected forensics export file, got %v", err)
	}
}

func TestServerEventsIngestRequiresAuthOrSignature(t *testing.T) {
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}, IngestKey: []byte("secret")})

	req := httptest.NewRequest(http.MethodPost, "/v0/events/ingest", strings.NewReader(`{"rule_id":"x","severity":"high","category":"process"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unsigned unauthenticated ingest, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestServerEventsIngestAcceptsValidSignature(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Logger:    logger,
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	key := []byte("secret")
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}, IngestKey: key})
	body := `{"rule_id":"x","severity":"high","category":"process","decision":"alert","host":"edge-01"}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))

	req := httptest.NewRequest(http.MethodPost, "/v0/events/ingest?source=edge-01", strings.NewReader(body))
	ts := time.Now().UTC()
	requestID := "ingest-1"
	req.Header.Set("X-EDR-Request-ID", requestID)
	req.Header.Set("X-EDR-Timestamp", ts.Format(time.RFC3339Nano))
	signed := hmac.New(sha256.New, key)
	signed.Write([]byte(http.MethodPost))
	signed.Write([]byte{'\n'})
	signed.Write([]byte("/v0/events/ingest"))
	signed.Write([]byte{'\n'})
	signed.Write([]byte(ts.Format(time.RFC3339Nano)))
	signed.Write([]byte{'\n'})
	signed.Write([]byte(requestID))
	signed.Write([]byte{'\n'})
	signed.Write([]byte(body))
	req.Header.Set("X-EDR-Ingest-Signature", "sha256="+hex.EncodeToString(signed.Sum(nil)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for signed ingest, got %d body=%s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"event_id":"peer-x-`) {
		t.Fatalf("expected peer event to be written, got %s", string(raw))
	}
}

func TestSafePathUnderRejectsEscape(t *testing.T) {
	base := t.TempDir()
	if _, err := safePathUnder(base, filepath.Join(base, "..", "escape")); err == nil {
		t.Fatal("expected path escape rejection")
	}
}

func TestSafePathUnderRejectsSymlinkBase(t *testing.T) {
	root := t.TempDir()
	realBase := filepath.Join(root, "real")
	linkBase := filepath.Join(root, "link")
	if err := os.MkdirAll(realBase, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBase, linkBase); err != nil {
		t.Fatal(err)
	}
	_, err := safePathUnder(linkBase, filepath.Join(linkBase, "bundle.json"))
	if err == nil {
		t.Fatal("symlink base should be rejected at request time")
	}
}

func TestValidateBaseNotSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	linkDir := filepath.Join(root, "link")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBaseNotSymlink(realDir); err != nil {
		t.Fatalf("real dir should pass: %v", err)
	}
	if err := ValidateBaseNotSymlink(linkDir); err == nil {
		t.Fatal("symlink dir should be rejected")
	}
}

func TestValidateBaseNotSymlinkParentSymlink(t *testing.T) {
	root := t.TempDir()
	// Create: root/real/ (real dir)
	// Create: root/link -> root/real (symlink)
	// Validate: root/link/subdir — parent is a symlink, should reject
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBaseNotSymlink(filepath.Join(root, "link", "subdir")); err == nil {
		t.Fatal("path with symlink parent should be rejected")
	}
}

func TestValidateBaseNotSymlinkCreatesMissing(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "a", "b", "c")
	if err := ValidateBaseNotSymlink(missing); err != nil {
		t.Fatalf("should create missing dirs: %v", err)
	}
	info, err := os.Stat(missing)
	if err != nil {
		t.Fatalf("dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("should be a directory")
	}
}

func TestQueryEventsCapsMemoryWindow(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(events)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		_, _ = f.WriteString(`{"timestamp":"2026-01-01T00:00:00Z","category":"process","severity":"low","rule_id":"p"}` + "\n")
	}
	_ = f.Close()
	out, err := queryEvents(events, eventQuery{Limit: 10, Offset: 5})
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 10 || out.Total != 200 {
		t.Fatalf("unexpected pagination result: %#v", out)
	}
}

func TestQueryEventsClampsLimit(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(events)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1100; i++ {
		_, _ = f.WriteString(`{"timestamp":"2026-01-01T00:00:00Z","category":"process","severity":"low","rule_id":"p"}` + "\n")
	}
	_ = f.Close()
	out, err := queryEvents(events, eventQuery{Limit: 50000})
	if err != nil {
		t.Fatal(err)
	}
	if out.Limit != maxEventLimit || out.Count != maxEventLimit || out.Total != 1100 {
		t.Fatalf("unexpected clamped result: %#v", out)
	}
}

func TestServerRejectsUnauthenticatedRequests(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v0/health", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected unauthorized request to be rejected, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestServerAcceptsAuthorizedUnixPeerCredentials(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "control.sock")
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{os.Geteuid()}})

	srv, ln, err := transport.ListenUnix(socketPath, h, ConnContext)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()

	client := transport.NewUnixHTTPClient(socketPath)
	resp, err := client.Get("http://unix/v0/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 via unix peer auth, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestServerRejectsUnixRequestWithoutConnContext(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "control.sock")
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{os.Geteuid()}})

	srv, ln, err := transport.ListenUnix(socketPath, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()

	client := transport.NewUnixHTTPClient(socketPath)
	resp, err := client.Get("http://unix/v0/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 without ConnContext, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestServerRejectsEmptyAllowlist(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/metrics"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected empty allowlist rejection, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestServerHAStatusEndpoint(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{
		AllowedUIDs: []int{0},
		HAStatus: func() (any, error) {
			return map[string]any{"ok": true, "instance_id": "edr-a", "peer_state": "healthy"}, nil
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/ha/status"))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["instance_id"] != "edr-a" || body["peer_state"] != "healthy" {
		t.Fatalf("unexpected ha status body: %#v", body)
	}
}

func TestServerRootSessionStatusEndpoint(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{
		AllowedUIDs: []int{0},
		RootSessionStatus: func() (any, error) {
			return map[string]any{"enabled": true, "mode": "audit"}, nil
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/root-sessions/status"))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"mode":"audit"`) {
		t.Fatalf("unexpected root session status body: %s", rr.Body.String())
	}
}

func TestServerRootSessionRespondEndpoint(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	var got map[string]any
	h := NewServerWithOptions(agent, ServerOptions{
		AllowedUIDs: []int{0},
		RootSessionRespond: func(v map[string]any) (any, error) {
			got = v
			return map[string]any{"ok": true}, nil
		},
	})
	body := `{"pid":123,"session_id":"s1","tty":"/dev/pts/0","nonce":"n1","deadline":"2026-06-18T10:00:00Z","response":"deadbeef"}`
	req := authedRequest(http.MethodPost, "/v0/root-sessions/respond")
	req.Body = io.NopCloser(strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got["session_id"] != "s1" || got["response"] != "deadbeef" {
		t.Fatalf("unexpected payload: %#v", got)
	}
	if got["deadline"] != "2026-06-18T10:00:00Z" {
		t.Fatalf("unexpected deadline payload: %#v", got["deadline"])
	}
}

func TestServerRootSessionBypassEndpoint(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	var ttl time.Duration
	h := NewServerWithOptions(agent, ServerOptions{
		AllowedUIDs: []int{0},
		RootSessionBypass: func(token string, d time.Duration) (any, error) {
			if token != "break-glass" {
				t.Fatalf("unexpected token %q", token)
			}
			ttl = d
			return map[string]any{"ok": true}, nil
		},
	})
	req := authedRequest(http.MethodPost, "/v0/root-sessions/bypass")
	req.Body = io.NopCloser(strings.NewReader(`{"token":"break-glass","ttl_sec":45}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if ttl != 45*time.Second {
		t.Fatalf("ttl = %v, want 45s", ttl)
	}
}

func TestServerRootSessionBypassClearEndpoint(t *testing.T) {
	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	called := false
	h := NewServerWithOptions(agent, ServerOptions{
		AllowedUIDs: []int{0},
		RootSessionClearBypass: func() (any, error) {
			called = true
			return map[string]any{"ok": true}, nil
		},
	})
	req := authedRequest(http.MethodPost, "/v0/root-sessions/bypass/clear")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("expected bypass clear handler to be called")
	}
}

func TestServerEventsVerifyReturnsChainState(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{
		Integrity: eventlog.IntegrityOptions{EnableChain: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.Write(eventlog.Event{EventID: "e" + itoaS(i), Category: "process", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Logger:    logger,
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	h := NewServerWithOptions(agent, ServerOptions{EventPath: eventPath, AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/events/verify"))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify endpoint returned %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Verify eventlog.VerifyResult `json:"verify"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Verify.OK {
		t.Fatalf("verify should be ok on a fresh chain, got %+v", body.Verify)
	}
	if body.Verify.LastSeq != 3 || body.Verify.ChainLines != 3 {
		t.Fatalf("verify counts: %+v", body.Verify)
	}
}

func TestServerEventsVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{
		Integrity: eventlog.IntegrityOptions{EnableChain: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := logger.Write(eventlog.Event{EventID: "e" + itoaS(i), Category: "process", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}
	// Tamper: change the second line's severity.
	raw, _ := os.ReadFile(eventPath)
	lines := splitLinesS(raw)
	var e eventlog.Event
	_ = json.Unmarshal(lines[1], &e)
	e.Severity = "critical"
	mutated, _ := json.Marshal(&e)
	lines[1] = mutated
	_ = os.WriteFile(eventPath, concatLinesS(lines), 0o600)

	agent := &Agent{Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion}, Logger: logger, Collector: &collector.ProcfsCollector{}, Responder: response.SoftResponder{DryRun: true}}
	h := NewServerWithOptions(agent, ServerOptions{EventPath: eventPath, AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/events/verify"))
	var body struct {
		Verify eventlog.VerifyResult `json:"verify"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Verify.OK {
		t.Fatalf("verify should fail on tampered file, got %+v", body.Verify)
	}
}

func itoaS(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func splitLinesS(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func concatLinesS(lines [][]byte) []byte {
	var out []byte
	for i, l := range lines {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, l...)
	}
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out
}

func authedRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(req.Context(), peerCredKey{}, peerCred{uid: 0, gid: 0, pid: int32(os.Getpid())})
	return req.WithContext(ctx)
}

func TestShutdownRequiresRootLoginBoundary(t *testing.T) {
	orig := readPeerLoginUID
	defer func() { readPeerLoginUID = orig }()

	tests := []struct {
		name          string
		cred          peerCred
		loginUID      uint32
		policy        policy.SelfProtection
		wantStatus    int
		wantShutdown  bool
		wantDecision  string
		wantReasonSub string
	}{
		{
			name:          "disabled by policy",
			cred:          peerCred{uid: 0, gid: 0, pid: 111},
			loginUID:      0,
			policy:        policy.SelfProtection{Enabled: true, ShutdownEnabled: false},
			wantStatus:    http.StatusForbidden,
			wantDecision:  "deny",
			wantReasonSub: "shutdown_enabled is false",
		},
		{
			name:          "plain user denied",
			cred:          peerCred{uid: 1000, gid: 1000, pid: 112},
			loginUID:      1000,
			policy:        policy.SelfProtection{Enabled: true, ShutdownEnabled: true},
			wantStatus:    http.StatusForbidden,
			wantDecision:  "deny",
			wantReasonSub: "uid 1000 is not authorized",
		},
		{
			name:          "sudo root denied by loginuid",
			cred:          peerCred{uid: 0, gid: 0, pid: 113},
			loginUID:      1000,
			policy:        policy.SelfProtection{Enabled: true, ShutdownEnabled: true},
			wantStatus:    http.StatusForbidden,
			wantDecision:  "deny",
			wantReasonSub: "loginuid 1000",
		},
		{
			name:         "root login allowed",
			cred:         peerCred{uid: 0, gid: 0, pid: 114},
			loginUID:     0,
			policy:       policy.SelfProtection{Enabled: true, ShutdownEnabled: true},
			wantStatus:   http.StatusOK,
			wantShutdown: true,
			wantDecision: "allow",
		},
		{
			name:         "system context allowed",
			cred:         peerCred{uid: 0, gid: 0, pid: 115},
			loginUID:     auditLoginUIDUnset,
			policy:       policy.SelfProtection{Enabled: true, ShutdownEnabled: true},
			wantStatus:   http.StatusOK,
			wantShutdown: true,
			wantDecision: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			eventPath := filepath.Join(dir, "events.jsonl")
			logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{Integrity: eventlog.IntegrityOptions{EnableChain: true}})
			if err != nil {
				t.Fatal(err)
			}
			shutdownCalled := false
			agent := &Agent{
				Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion, SelfProtection: tt.policy},
				Logger:    logger,
				Collector: &collector.ProcfsCollector{},
				Responder: response.SoftResponder{DryRun: true},
			}
			h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}, Shutdown: func() { shutdownCalled = true }})
			readPeerLoginUID = func(pid int32) (uint32, error) {
				if pid != tt.cred.pid {
					t.Fatalf("unexpected pid lookup: got %d want %d", pid, tt.cred.pid)
				}
				return tt.loginUID, nil
			}

			req := httptest.NewRequest(http.MethodPost, "/v0/shutdown", nil)
			req = req.WithContext(context.WithValue(req.Context(), peerCredKey{}, tt.cred))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
			}
			if shutdownCalled != tt.wantShutdown {
				t.Fatalf("shutdown called: got %v want %v", shutdownCalled, tt.wantShutdown)
			}
			raw, err := os.ReadFile(eventPath)
			if err != nil {
				t.Fatal(err)
			}
			var ev eventlog.Event
			lines := splitLinesS(raw)
			if len(lines) == 0 {
				t.Fatal("expected shutdown audit event")
			}
			if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
				t.Fatal(err)
			}
			if ev.RuleID != "self-protect-shutdown" || ev.Decision != tt.wantDecision {
				t.Fatalf("unexpected audit event: %+v", ev)
			}
			if got := ev.Subject["peer_loginuid"]; got != float64(tt.loginUID) {
				t.Fatalf("peer_loginuid audit: got %v want %d", got, tt.loginUID)
			}
			if tt.wantReasonSub != "" {
				reason, _ := ev.Evidence["reason"].(string)
				if !strings.Contains(reason, tt.wantReasonSub) {
					t.Fatalf("reason %q does not contain %q", reason, tt.wantReasonSub)
				}
			}
		})
	}
}

func TestShutdownRejectsMissingLoginUID(t *testing.T) {
	orig := readPeerLoginUID
	defer func() { readPeerLoginUID = orig }()
	readPeerLoginUID = func(pid int32) (uint32, error) { return 0, os.ErrNotExist }

	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, SelfProtection: policy.SelfProtection{Enabled: true, ShutdownEnabled: true}},
		Logger: logger,
	}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}, Shutdown: func() { t.Fatal("shutdown should not be called") }})
	req := httptest.NewRequest(http.MethodPost, "/v0/shutdown", nil)
	req = req.WithContext(context.WithValue(req.Context(), peerCredKey{}, peerCred{uid: 0, gid: 0, pid: 200}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHealthSuppressorState(t *testing.T) {
	agent := &Agent{
		Policy:     &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Suppressor: NewSuppressor(SuppressorOptions{RatePerSec: 0}),
		Collector:  &collector.ProcfsCollector{},
		Responder:  response.SoftResponder{DryRun: true},
	}
	agent.Init()
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/health"))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		OK              bool           `json:"ok"`
		SuppressorState map[string]any `json:"suppressor_state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK {
		t.Fatal("expected ok=true")
	}
	if body.SuppressorState["active"] != true {
		t.Fatalf("expected suppressor active, got %v", body.SuppressorState)
	}
}

func TestVerifyEventSeqFound(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{
		Integrity: eventlog.IntegrityOptions{EnableChain: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.Write(eventlog.Event{EventID: "e" + itoaS(i), Category: "process", Action: "observe", Decision: "alert"}); err != nil {
			t.Fatal(err)
		}
	}

	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Logger:    logger,
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	h := NewServerWithOptions(agent, ServerOptions{EventPath: eventPath, AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/events/verify?seq=2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify seq returned %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("expected ok=true for seq=2, got %v", body)
	}
	if body["seq"] != float64(2) {
		t.Fatalf("expected seq=2, got %v", body["seq"])
	}
}

func TestVerifyEventSeqNotFound(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.NewWithOptions(eventPath, eventlog.Options{
		Integrity: eventlog.IntegrityOptions{EnableChain: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = logger.Write(eventlog.Event{EventID: "e0", Category: "process", Action: "observe", Decision: "alert"})

	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Logger:    logger,
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	h := NewServerWithOptions(agent, ServerOptions{EventPath: eventPath, AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/events/verify?seq=999"))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify seq returned %d: %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != false {
		t.Fatalf("expected ok=false for missing seq, got %v", body)
	}
}

func TestVerifyEventSeqInvalidParam(t *testing.T) {
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Collector: &collector.ProcfsCollector{},
		Responder: response.SoftResponder{DryRun: true},
	}
	h := NewServerWithOptions(agent, ServerOptions{AllowedUIDs: []int{0}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedRequest(http.MethodGet, "/v0/events/verify?seq=abc"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad seq, got %d", rr.Code)
	}
}
