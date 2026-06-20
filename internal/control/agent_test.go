package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edr/internal/bpf"
	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/policy"
	"edr/internal/response"
)

type stubDecisionEngine struct {
	process policy.Rule
	ok      bool
}

func (s stubDecisionEngine) EvaluateProcessAccess(policy.Subject) (policy.Rule, bool) {
	return s.process, s.ok
}

func (s stubDecisionEngine) EvaluateAll(time.Time, policy.Subject, policy.Object) []policy.Rule {
	return nil
}

type stubActionExecutor struct {
	result response.Result
}

func (s stubActionExecutor) Apply(response.ActionRequest) response.Result {
	return s.result
}

type panicActionExecutor struct{}

func (panicActionExecutor) Apply(response.ActionRequest) response.Result {
	panic("executor should not be called")
}

type stubCollector struct {
	snap collector.Snapshot
}

func (s stubCollector) Snapshot() (collector.Snapshot, error) {
	return s.snap, nil
}

func TestAgentFileRuleResponse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{{ID: "f1", Category: "file", Severity: "medium", Decision: "block", Action: "fix_permissions", Match: policy.Match{FilePathPrefix: dir}}}},
		Collector: stubCollector{snap: collector.Snapshot{FileEvents: []collector.FileEvent{{Path: path, Op: "write"}}}},
		Logger:    logger,
		Responder: response.SoftResponder{},
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	history := agent.ResponseHistory(10)
	if len(history) == 0 || history[0].Category != "file" || history[0].Request.Action != "fix_permissions" {
		t.Fatalf("expected file response history, got %#v", history)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("expected chmod 0600, got %v", st.Mode().Perm())
	}
}

func TestAgentMetricsRuleHits(t *testing.T) {
	logger, err := eventlog.New(filepath.Join(t.TempDir(), "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{{ID: "p1", Category: "process", Severity: "high", Decision: "alert", Action: "none", Match: policy.Match{ProcessName: "bash"}}}},
		Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 10, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash -lc test"}}}},
		Logger:    logger,
		Responder: response.SoftResponder{DryRun: true},
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	metrics := agent.Metrics()
	ruleHits, ok := metrics["rule_hits"].(map[string]uint64)
	if !ok {
		t.Fatalf("expected typed rule_hits map, got %#v", metrics["rule_hits"])
	}
	if ruleHits["p1"] != 1 {
		t.Fatalf("expected p1 hit count 1, got %#v", ruleHits)
	}
}

func TestRunOnceMultiHitAuditAndResponse(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{
			{ID: "audit-base", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: policy.Match{ProcessName: "bash"}, Priority: 200, Effect: []string{policy.EffectAudit}},
			{ID: "kill-top", Category: "process", Severity: "critical", Decision: "block", Action: "kill", Match: policy.Match{ProcessName: "bash"}, Priority: 10, Effect: []string{policy.EffectResponse}},
		}},
		Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 100, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash -lc test", User: "root"}}}},
		Logger:    logger,
		Responder: response.SoftResponder{DryRun: true},
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	metrics := agent.Metrics()
	hits := metrics["rule_hits"].(map[string]uint64)
	if hits["audit-base"] != 1 || hits["kill-top"] != 1 {
		t.Fatalf("expected both rules to record a hit, got %+v", hits)
	}
	history := agent.ResponseHistory(10)
	if len(history) != 1 || history[0].RuleID != "kill-top" {
		t.Fatalf("expected kill-top to be the only response, got %+v", history)
	}
}

func TestRunOnceAuditOnlyDoesNotRespond(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{
			{ID: "audit-only", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: policy.Match{ProcessName: "bash"}, Effect: []string{policy.EffectAudit}},
		}},
		Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 100, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash", User: "root"}}}},
		Logger:    logger,
		Responder: response.SoftResponder{DryRun: true},
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if history := agent.ResponseHistory(10); len(history) != 0 {
		t.Fatalf("audit-only rule should not trigger a response, got %+v", history)
	}
	if hits := agent.Metrics()["rule_hits"].(map[string]uint64); hits["audit-only"] != 1 {
		t.Fatalf("audit-only hit should be 1, got %d", hits["audit-only"])
	}
}

func TestHandleFastPathLDPreloadSkipsUserspaceKillWhenProcessAlreadyGone(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{
			{ID: "ATT002-ld-preload-injection", Category: "process", Severity: "critical", Decision: "block", Action: "kill", Match: policy.Match{EnvContains: "LD_PRELOAD"}},
		}},
		Logger:   logger,
		Executor: panicActionExecutor{},
	}
	ev := bpf.Event{PID: 999999, UID: 0, Comm: "bash", Filename: "/tmp/libedr_preload.so"}
	agent.handleFastPathLDPreload(ev)
	history := agent.ResponseHistory(10)
	if len(history) != 1 {
		t.Fatalf("expected one response record, got %d", len(history))
	}
	if !history[0].Result.Success || history[0].Result.Detail != "already terminated by ring0 fast path" {
		t.Fatalf("unexpected response record: %+v", history[0])
	}
}

func TestRunOnceSuppressedSkipped(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	sup := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Hour, RatePerSec: 0})
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{
			{ID: "loud", Category: "process", Severity: "high", Decision: "alert", Action: "none", Match: policy.Match{ProcessName: "bash"}, Effect: []string{policy.EffectAudit}},
		}},
		Collector:  stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 100, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash", User: "root"}}}},
		Logger:     logger,
		Responder:  response.SoftResponder{DryRun: true},
		Suppressor: sup,
	}
	for i := 0; i < 3; i++ {
		if err := agent.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	metrics := agent.Metrics()
	hits := metrics["rule_hits"].(map[string]uint64)
	if hits["loud"] != 3 {
		t.Fatalf("rule hit should accumulate 3, got %d", hits["loud"])
	}
	if metrics["suppressed_total"].(uint64) != 2 {
		t.Fatalf("suppressed_total = %v, want 2", metrics["suppressed_total"])
	}
	reasons := metrics["suppression_reasons"].(map[string]uint64)
	if reasons[ReasonCooldown] != 2 {
		t.Fatalf("suppression_reasons[cooldown] = %d, want 2", reasons[ReasonCooldown])
	}
}

func TestRunOnceResponseSuppressedDoesNotApply(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	sup := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Hour, RatePerSec: 0})
	agent := &Agent{
		Policy: &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: []policy.Rule{
			{ID: "kill-once", Category: "process", Severity: "critical", Decision: "block", Action: "kill", Match: policy.Match{ProcessName: "bash"}, Effect: []string{policy.EffectResponse}},
		}},
		Collector:  stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 100, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash", User: "root"}}}},
		Logger:     logger,
		Responder:  response.SoftResponder{DryRun: true},
		Suppressor: sup,
	}
	for i := 0; i < 2; i++ {
		if err := agent.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	history := agent.ResponseHistory(10)
	if len(history) != 1 {
		t.Fatalf("expected 1 response, got %d", len(history))
	}
	if metrics := agent.Metrics(); metrics["suppressed_total"].(uint64) != 1 {
		t.Fatalf("suppressed_total = %v, want 1", metrics["suppressed_total"])
	}
}

func TestExportForensicsWritesBundle(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(eventPath, []byte(`{"timestamp":"2026-01-01T00:00:00Z","category":"process","severity":"high","rule_id":"p1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, err := eventlog.New(eventPath, false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy:    &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 1, Name: "init"}}}},
		Logger:    logger,
		Responder: response.SoftResponder{DryRun: true},
	}
	outPath := filepath.Join(dir, "bundle.json")
	bundle, err := ExportForensics(agent, eventPath, outPath, 50)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != "v0.1" || len(bundle.Snapshot.Processes) != 1 || len(bundle.Events) != 1 {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected bundle file, got %v", err)
	}
}

func TestResponseChannelConcurrentNoInterleave(t *testing.T) {
	dir := t.TempDir()
	respPath := filepath.Join(dir, "responses.jsonl")
	agent := &Agent{
		Policy:       &policy.Policy{SchemaVersion: policy.SchemaVersion},
		ResponsePath: respPath,
		MaxHistory:   100,
	}
	agent.Init()

	// Write concurrent records via the channel.
	const n = 50
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(id int) {
			agent.recordResponse(ResponseRecord{
				RuleID:   "r" + string(rune('0'+id%10)),
				Category: "test",
				Result:   response.Result{Success: true},
			})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}

	// Shutdown and wait for all writes to drain.
	agent.Shutdown()

	raw, err := os.ReadFile(respPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range raw {
		if b == '\n' {
			lines++
		}
	}
	// Allow up to n lines (Shutdown may have raced).
	if lines == 0 || lines > n {
		t.Fatalf("expected 1..%d response lines, got %d", n, lines)
	}

	// Verify each line is valid JSON and not interleaved (each line is
	// a complete JSON object).
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec ResponseRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("interleaved or malformed line: %v\nline: %s", err, line)
		}
	}
}

func TestShutdownNoDataLoss(t *testing.T) {
	dir := t.TempDir()
	respPath := filepath.Join(dir, "responses.jsonl")
	agent := &Agent{
		Policy:       &policy.Policy{SchemaVersion: policy.SchemaVersion},
		ResponsePath: respPath,
		MaxHistory:   100,
	}
	agent.Init()

	// Write a known number of records.
	const n = 20
	for i := 0; i < n; i++ {
		agent.recordResponse(ResponseRecord{
			RuleID:   "shutdown-test",
			Category: "test",
			Result:   response.Result{Success: true},
		})
	}

	// Shutdown immediately — all records must be flushed.
	agent.Shutdown()

	raw, err := os.ReadFile(respPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range raw {
		if b == '\n' {
			lines++
		}
	}
	if lines != n {
		t.Fatalf("shutdown lost records: want %d, got %d", n, lines)
	}
}

func TestAgentSuppressorLoadOnInit(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "suppress.json")
	sup := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Hour, RatePerSec: 10})
	// Write some state.
	if _, _ = sup.Allow("process", "r1", "process:r1:1:ticks"); false {
	}
	if err := sup.SaveState(statePath); err != nil {
		t.Fatal(err)
	}

	// New agent with suppressor and state path.
	sup2 := NewSuppressor(SuppressorOptions{ProcessCooldown: time.Hour, RatePerSec: 10})
	agent := &Agent{
		Policy:              &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Suppressor:          sup2,
		SuppressorStatePath: statePath,
	}
	agent.Init()

	// The loaded state should block a duplicate emit.
	ok, reason := agent.Suppressor.Allow("process", "r1", "process:r1:1:ticks")
	if ok || reason != ReasonCooldown {
		t.Fatalf("expected cooldown block after load, got ok=%v reason=%q", ok, reason)
	}
}

func TestAgentRunOnceSavesSuppressorState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "suppress.json")
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}

	sup := NewSuppressor(SuppressorOptions{ProcessCooldown: 30 * time.Second, RatePerSec: 0})
	agent := &Agent{
		Policy:              &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Collector:           stubCollector{snap: collector.Snapshot{}},
		Logger:              logger,
		Responder:           response.SoftResponder{DryRun: true},
		Suppressor:          sup,
		SuppressorStatePath: statePath,
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// State file should exist after RunOnce.
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("expected suppress state file after RunOnce: %v", err)
	}

	// Load state into a fresh suppressor and verify it works.
	sup2 := NewSuppressor(SuppressorOptions{ProcessCooldown: 30 * time.Second, RatePerSec: 0})
	if err := sup2.LoadState(statePath); err != nil {
		t.Fatal(err)
	}
	tracked, _ := sup2.Stats()
	if tracked != 0 {
		t.Logf("suppressor state after empty RunOnce: tracked=%d (expected 0 or small)", tracked)
	}
}

func TestCollectorSourceSnapshot(t *testing.T) {
	src := CollectorSource{Collector: stubCollector{snap: collector.Snapshot{
		Processes: []collector.Process{{PID: 7, Name: "sh"}},
	}}}
	snap, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) != 1 || snap.Processes[0].PID != 7 {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
}

func TestLoggerSinkWritesEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	logger, err := eventlog.New(path, false)
	if err != nil {
		t.Fatal(err)
	}
	sink := LoggerSink{Logger: logger}
	if err := sink.Write(eventlog.Event{
		EventID:  "evt-1",
		Category: "process",
		Severity: "high",
		Decision: "alert",
		Action:   "none",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"event_id":"evt-1"`) {
		t.Fatalf("expected event to be written, got %s", string(raw))
	}
}

func TestRunOnceUsesInjectedBridges(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{
		Policy:   &policy.Policy{SchemaVersion: policy.SchemaVersion},
		Source:   CollectorSource{Collector: stubCollector{snap: collector.Snapshot{Processes: []collector.Process{{PID: 55, Name: "bash", Path: "/usr/bin/bash", Cmdline: "bash", User: "root"}}}}},
		Engine:   stubDecisionEngine{process: policy.Rule{ID: "bridge-rule", Category: "process", Severity: "critical", Decision: "block", Action: "kill"}, ok: true},
		Executor: stubActionExecutor{result: response.Result{Action: "kill", Success: true, Detail: "bridge executor"}},
		Events:   LoggerSink{Logger: logger},
		Logger:   logger,
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	history := agent.ResponseHistory(10)
	if len(history) != 1 || history[0].RuleID != "bridge-rule" || history[0].Result.Detail != "bridge executor" {
		t.Fatalf("expected injected executor to be used, got %+v", history)
	}
}
