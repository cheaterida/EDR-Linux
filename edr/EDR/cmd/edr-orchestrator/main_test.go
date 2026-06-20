package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edr/internal/eventlog"
	"edr/internal/lease"
	"edr/internal/liveness"
	iruntime "edr/internal/runtime"
	"edr/internal/supervisor"
)

type stubRestartRunner struct {
	argv [][]string
	err  error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func (s *stubRestartRunner) Run(_ context.Context, argv []string) error {
	copied := append([]string(nil), argv...)
	s.argv = append(s.argv, copied)
	return s.err
}

func TestBuildRestartCommandExpandsPlaceholders(t *testing.T) {
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RestartCommand = []string{
		"systemctl",
		"restart",
		"edr-sensor@{{peer_instance_id}}.service",
		"LEASE={{lease_id}}",
		"GEN={{generation}}",
		"REQ={{request_id}}",
		"PID={{peer_pid}}",
	}
	l := lease.Lease{
		LeaseID:    "lease-1",
		RequestID:  "req-1",
		Generation: 7,
	}
	hb := liveness.Heartbeat{PID: 4321, RestartGeneration: 6}
	got, err := buildRestartCommand(cfg, l, hb)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl",
		"restart",
		"edr-sensor@edr-b.service",
		"LEASE=lease-1",
		"GEN=7",
		"REQ=req-1",
		"PID=4321",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestCheckPeerLivenessRunsRestartAndWritesLease(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.SuspectAfter = 1
	cfg.HA.DownAfter = 2
	cfg.HA.RestartCooldownSec = 30
	cfg.HA.LeaseTTLSec = 10
	cfg.HA.RestartTimeoutSec = 1
	cfg.HA.RestartCommand = []string{
		"systemctl",
		"restart",
		"edr-sensor@{{peer_instance_id}}.service",
		"edr-enforcer@{{peer_instance_id}}.service",
		"edr-orchestrator@{{peer_instance_id}}.service",
	}
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		PID:               88,
		RestartGeneration: 3,
		UpdatedAt:         now.Add(-3 * time.Second),
	})
	runner := &stubRestartRunner{}
	gotRestart := checkPeerLiveness(dir, cfg, logger, nil, runner, now.Add(-10*time.Second), time.Time{}, now)
	if !gotRestart.Equal(now) {
		t.Fatalf("lastRestart = %v, want %v", gotRestart, now)
	}
	if len(runner.argv) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.argv))
	}
	if got := strings.Join(runner.argv[0], " "); !strings.Contains(got, "edr-orchestrator@edr-b.service") {
		t.Fatalf("unexpected restart command %q", got)
	}
	leaseState, err := lease.Read(dir, "edr-b")
	if err != nil {
		t.Fatal(err)
	}
	if leaseState.Generation != 4 {
		t.Fatalf("lease generation = %d, want 4", leaseState.Generation)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "\"action\":\"restart_peer\"") {
		t.Fatalf("expected restart_peer audit event, got %s", text)
	}
	if !strings.Contains(text, "\"lease_id\":\""+leaseState.LeaseID+"\"") {
		t.Fatalf("expected lease id in audit event, got %s", text)
	}
}

func TestRootSessionLeaseActiveHonorsPriority(t *testing.T) {
	dir := t.TempDir()
	cfgA := iruntime.DefaultConfig()
	cfgA.HA.InstanceID = "edr-a"
	cfgA.HA.Priority = 100
	cfgB := iruntime.DefaultConfig()
	cfgB.HA.InstanceID = "edr-b"
	cfgB.HA.Priority = 90

	if !rootSessionLeaseActive(dir, cfgA, 5*time.Second) {
		t.Fatal("expected higher-priority instance to acquire root session lease")
	}
	if rootSessionLeaseActive(dir, cfgB, 5*time.Second) {
		t.Fatal("expected lower-priority instance to stay standby")
	}
}

func TestCheckPeerLivenessReleasesLeaseOnFailure(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.SuspectAfter = 1
	cfg.HA.DownAfter = 2
	cfg.HA.RestartCooldownSec = 30
	cfg.HA.LeaseTTLSec = 10
	cfg.HA.RestartTimeoutSec = 1
	cfg.HA.RestartCommand = []string{
		"systemctl",
		"restart",
		"edr-sensor@{{peer_instance_id}}.service",
		"edr-enforcer@{{peer_instance_id}}.service",
		"edr-orchestrator@{{peer_instance_id}}.service",
	}
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		PID:               99,
		RestartGeneration: 8,
		UpdatedAt:         now.Add(-3 * time.Second),
	})
	runner := &stubRestartRunner{err: errors.New("restart failed")}
	gotRestart := checkPeerLiveness(dir, cfg, logger, nil, runner, now.Add(-10*time.Second), time.Time{}, now)
	if !gotRestart.Equal(now) {
		t.Fatalf("lastRestart = %v, want %v", gotRestart, now)
	}
	if _, err := lease.Read(dir, "edr-b"); !os.IsNotExist(err) {
		t.Fatalf("expected lease to be released, err=%v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\"action\":\"restart_peer_failed\"") {
		t.Fatalf("expected restart_peer_failed audit event, got %s", string(raw))
	}
}

type stubSupervisorClient struct {
	resp supervisor.HeartbeatResponse
	err  error
	reqs []supervisor.HeartbeatRequest
	evs  []supervisor.EvidenceRecord
}

func (s *stubSupervisorClient) PushHeartbeat(_ context.Context, req supervisor.HeartbeatRequest) (supervisor.HeartbeatResponse, error) {
	s.reqs = append(s.reqs, req)
	return s.resp, s.err
}

func (s *stubSupervisorClient) PushEvidence(_ context.Context, rec supervisor.EvidenceRecord) error {
	s.evs = append(s.evs, rec)
	return nil
}

func TestSyncSupervisorAppliesRemoteIntentViaLease(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.Supervisor.Enabled = true
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.SuspectAfter = 1
	cfg.HA.DownAfter = 2
	cfg.HA.LeaseTTLSec = 10
	cfg.HA.RestartCooldownSec = 30
	cfg.HA.RestartTimeoutSec = 1
	cfg.HA.RestartCommand = []string{
		"systemctl",
		"restart",
		"edr-sensor@{{peer_instance_id}}.service",
		"edr-enforcer@{{peer_instance_id}}.service",
		"edr-orchestrator@{{peer_instance_id}}.service",
	}
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-a",
		RestartGeneration: 2,
		UpdatedAt:         now,
	})
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		RestartGeneration: 3,
		UpdatedAt:         now.Add(-3 * time.Second),
	})
	supervisorClient := &stubSupervisorClient{
		resp: supervisor.HeartbeatResponse{
			OK:         true,
			DecisionID: "decision-1",
			RestartIntent: supervisor.RestartIntent{
				RequestID:  "remote-req-1",
				Target:     "edr-b",
				Generation: 4,
				Reason:     "peer_down",
			},
		},
	}
	runner := &stubRestartRunner{}
	state := &supervisorSyncState{}
	activity := &haActivityState{}
	gotRestart := syncSupervisor(dir, cfg, logger, state, activity, supervisorClient, runner, time.Time{}, now)
	if !gotRestart.Equal(now) {
		t.Fatalf("lastRestart = %v, want %v", gotRestart, now)
	}
	if len(supervisorClient.reqs) != 1 {
		t.Fatalf("expected 1 heartbeat push, got %d", len(supervisorClient.reqs))
	}
	if len(runner.argv) != 1 {
		t.Fatalf("expected 1 restart command, got %d", len(runner.argv))
	}
	if len(supervisorClient.evs) == 0 {
		t.Fatal("expected evidence push for remote decision")
	}
	leaseState, err := lease.Read(dir, "edr-b")
	if err != nil {
		t.Fatal(err)
	}
	if leaseState.Source != "remote-supervisor" {
		t.Fatalf("lease source = %q, want remote-supervisor", leaseState.Source)
	}
	if snap := state.Snapshot(); snap.Status != "ok" || snap.Action != "restart_intent" || snap.DecisionID != "decision-1" || snap.LastSuccessAt.IsZero() {
		t.Fatalf("unexpected supervisor sync snapshot: %+v", snap)
	}
	if act := activity.Snapshot(); act.Action != "restart_peer" || act.Source != "remote-supervisor" {
		t.Fatalf("unexpected ha activity snapshot: %+v", act)
	}
	if leaseState.Generation != 4 {
		t.Fatalf("lease generation = %d, want 4", leaseState.Generation)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"rule_id":"supervisor-restart"`) {
		t.Fatalf("expected supervisor-restart audit event, got %s", text)
	}
	if !strings.Contains(text, `"source":"remote-supervisor"`) {
		t.Fatalf("expected remote-supervisor source, got %s", text)
	}
}

func TestSyncSupervisorSkipsIntentDuringCooldown(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.Supervisor.Enabled = true
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.RestartCooldownSec = 30
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-a",
		RestartGeneration: 2,
		UpdatedAt:         now,
	})
	supervisorClient := &stubSupervisorClient{
		resp: supervisor.HeartbeatResponse{
			OK:         true,
			DecisionID: "decision-cooldown",
			RestartIntent: supervisor.RestartIntent{
				RequestID:  "remote-req-cooldown",
				Target:     "edr-b",
				Generation: 4,
				Reason:     "peer_down",
			},
		},
	}
	activity := &haActivityState{}
	gotRestart := syncSupervisor(dir, cfg, logger, &supervisorSyncState{}, activity, supervisorClient, &stubRestartRunner{}, now.Add(-5*time.Second), now)
	if !gotRestart.Equal(now.Add(-5 * time.Second)) {
		t.Fatalf("lastRestart changed unexpectedly: %v", gotRestart)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rule_id":"supervisor-intent-cooldown"`) {
		t.Fatalf("expected cooldown audit event, got %s", string(raw))
	}
	if len(supervisorClient.evs) == 0 {
		t.Fatal("expected evidence push for cooldown skip")
	}
	if act := activity.Snapshot(); act.Action != "skip_restart_intent" || act.RuleID != "supervisor-intent-cooldown" {
		t.Fatalf("unexpected ha activity snapshot: %+v", act)
	}
}

func TestAttemptRestartWritesLeaseConflictAudit(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.Priority = 100
	cfg.HA.LeaseTTLSec = 10
	cfg.HA.RestartTimeoutSec = 1
	cfg.HA.RestartCommand = []string{"systemctl", "restart", "edr-sensor@{{peer_instance_id}}.service"}
	now := time.Now().UTC()
	_, _, err = lease.Acquire(dir, lease.Lease{
		LeaseID:    "higher",
		Target:     "edr-b",
		RequestID:  "existing",
		Source:     "remote-supervisor",
		Generation: 9,
		Priority:   200,
		AcquiredAt: now,
		ExpiresAt:  now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	gotRestart := attemptRestart(dir, cfg, logger, nil, &stubRestartRunner{}, time.Time{}, now, liveness.Heartbeat{InstanceID: "edr-b", RestartGeneration: 8}, 9, "remote-supervisor", "supervisor-restart", map[string]any{"decision_id": "d1"}, nil)
	if !gotRestart.IsZero() {
		t.Fatalf("expected no restart timestamp on lease conflict, got %v", gotRestart)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rule_id":"supervisor-restart-lease-conflict"`) {
		t.Fatalf("expected lease conflict audit event, got %s", string(raw))
	}
}

func TestWriteHeartbeatWritesImmediately(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.RunDir = dir
	writeHeartbeat(dir, cfg, logger, componentHealth{}, time.Now().UTC(), 1)
	if _, err := os.Stat(liveness.Path(dir, "edr-a")); err != nil {
		t.Fatalf("expected heartbeat file %s to be written immediately: %v", liveness.Path(dir, "edr-a"), err)
	}
}

func TestWriteHeartbeatCreatesLocalHeartbeatBeforeSupervisorSync(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.Supervisor.Enabled = true
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	now := time.Now().UTC()
	writeHeartbeat(dir, cfg, logger, componentHealth{}, now, 1)
	client := &stubSupervisorClient{resp: supervisor.HeartbeatResponse{OK: true}}
	state := &supervisorSyncState{}
	activity := &haActivityState{}
	got := syncSupervisor(dir, cfg, logger, state, activity, client, &stubRestartRunner{}, time.Time{}, now)
	if !got.IsZero() {
		t.Fatalf("expected no restart when no intent is returned, got %v", got)
	}
	snap := state.Snapshot()
	if snap.Status != "ok" || snap.Action != "no_valid_intent" {
		t.Fatalf("unexpected supervisor sync snapshot after initial heartbeat: %+v", snap)
	}
	if act := activity.Snapshot(); act.Action != "" {
		t.Fatalf("unexpected ha activity snapshot for empty intent: %+v", act)
	}
}

func TestSyncSupervisorSkipsWhenLocalHeartbeatMissing(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.Supervisor.Enabled = true
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.Supervisor.HeartbeatEverySec = 60
	state := &supervisorSyncState{}
	client := &stubSupervisorClient{resp: supervisor.HeartbeatResponse{OK: true}}
	activity := &haActivityState{}
	got := syncSupervisor(dir, cfg, logger, state, activity, client, &stubRestartRunner{}, time.Time{}, time.Now().UTC())
	if !got.IsZero() {
		t.Fatalf("expected zero restart time when local heartbeat missing, got %v", got)
	}
	if len(client.reqs) != 0 {
		t.Fatalf("expected no heartbeat push without local heartbeat, got %d", len(client.reqs))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rule_id":"supervisor-local-heartbeat-missing"`) {
		t.Fatalf("expected missing-heartbeat audit event, got %s", string(raw))
	}
	if snap := state.Snapshot(); snap.Status != "skipped" || snap.Action != "local_heartbeat_missing" || !snap.LastSuccessAt.IsZero() {
		t.Fatalf("unexpected supervisor sync snapshot: %+v", snap)
	}
	if act := activity.Snapshot(); act.Action != "sync_skipped" || act.Error == "" {
		t.Fatalf("unexpected ha activity snapshot: %+v", act)
	}
}

func TestBuildHAStatusIncludesHeartbeatAndLease(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.Supervisor.Enabled = true
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-a",
		RestartGeneration: 2,
		UpdatedAt:         now,
	})
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		RestartGeneration: 3,
		UpdatedAt:         now,
	})
	_, _, err = lease.Acquire(dir, lease.Lease{
		LeaseID:    "lease-1",
		Target:     "edr-b",
		RequestID:  "req-1",
		Source:     "remote-supervisor",
		Generation: 4,
		Priority:   100,
		AcquiredAt: now,
		ExpiresAt:  now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &supervisorSyncState{}
	state.Record(supervisorSyncSnapshot{
		AttemptedAt: now,
		Status:      "ok",
		Action:      "restart_intent",
		DecisionID:  "decision-1",
		PeerState:   "down",
	})
	activity := &haActivityState{}
	activity.Record(haActivitySnapshot{
		RecordedAt: now,
		Action:     "release_peer_lease",
		RuleID:     "peer-lease-release",
		Peer:       "edr-b",
		LeaseID:    "lease-1",
	})
	status, err := buildHAStatus(dir, cfg, logger, state, activity, now)
	if err != nil {
		t.Fatal(err)
	}
	if status["instance_id"] != "edr-a" {
		t.Fatalf("unexpected instance_id: %#v", status)
	}
	if status["peer_state"] != "healthy" {
		t.Fatalf("unexpected peer_state: %#v", status)
	}
	if _, ok := status["local_heartbeat"]; !ok {
		t.Fatalf("expected local_heartbeat in status: %#v", status)
	}
	if _, ok := status["peer_lease"]; !ok {
		t.Fatalf("expected peer_lease in status: %#v", status)
	}
	if _, ok := status["supervisor_sync"]; !ok {
		t.Fatalf("expected supervisor_sync in status: %#v", status)
	}
	if _, ok := status["ha_activity"]; !ok {
		t.Fatalf("expected ha_activity in status: %#v", status)
	}
}

func TestWriteHeartbeatIncludesComponentHealth(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.RunDir = dir

	writeHeartbeat(dir, cfg, logger, componentHealth{
		sensorClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Header:     make(http.Header),
			}, nil
		})},
		enforcerClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`boom`)),
				Header:     make(http.Header),
			}, nil
		})},
	}, time.Now().UTC(), 1)

	hb, err := liveness.Read(dir, "edr-a")
	if err != nil {
		t.Fatal(err)
	}
	if hb.State != "starting" {
		t.Fatalf("heartbeat state = %q, want starting", hb.State)
	}
	if hb.Components["sensor"] != "healthy" {
		t.Fatalf("sensor state = %q, want healthy", hb.Components["sensor"])
	}
	if hb.Components["enforcer"] != "suspect" {
		t.Fatalf("enforcer state = %q, want suspect", hb.Components["enforcer"])
	}
}

func TestCheckPeerLivenessRestartsWhenPeerHeartbeatStateIsDown(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.SuspectAfter = 3
	cfg.HA.DownAfter = 5
	cfg.HA.RestartCooldownSec = 30
	cfg.HA.LeaseTTLSec = 10
	cfg.HA.RestartTimeoutSec = 1
	cfg.HA.RestartCommand = []string{"systemctl", "restart", "edr-sensor@{{peer_instance_id}}.service"}
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		PID:               88,
		State:             "down",
		RestartGeneration: 3,
		UpdatedAt:         now,
	})
	runner := &stubRestartRunner{}
	gotRestart := checkPeerLiveness(dir, cfg, logger, nil, runner, now.Add(-10*time.Second), time.Time{}, now)
	if !gotRestart.Equal(now) {
		t.Fatalf("lastRestart = %v, want %v", gotRestart, now)
	}
	if len(runner.argv) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(runner.argv))
	}
}

func TestCheckPeerLivenessSkipsDuringStartupGrace(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	cfg.HA.StartupGraceSec = 5
	cfg.HA.SuspectAfter = 1
	cfg.HA.DownAfter = 2
	cfg.HA.RestartCommand = []string{"systemctl", "restart", "edr-sensor@{{peer_instance_id}}.service"}
	now := time.Now().UTC()
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		PID:               88,
		State:             "down",
		RestartGeneration: 3,
		UpdatedAt:         now,
	})
	runner := &stubRestartRunner{}
	gotRestart := checkPeerLiveness(dir, cfg, logger, nil, runner, now.Add(-2*time.Second), time.Time{}, now)
	if !gotRestart.IsZero() {
		t.Fatalf("expected no restart during startup grace, got %v", gotRestart)
	}
	if len(runner.argv) != 0 {
		t.Fatalf("expected no restart command during startup grace, got %d", len(runner.argv))
	}
}

func TestReconcilePeerLeaseReleasesRecoveredPeerLease(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	now := time.Now().UTC()
	_, _, err = lease.Acquire(dir, lease.Lease{
		LeaseID:    "lease-1",
		Target:     "edr-b",
		RequestID:  "req-1",
		Source:     "local-peer-down",
		Generation: 4,
		Priority:   100,
		AcquiredAt: now.Add(-2 * time.Second),
		ExpiresAt:  now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		State:             "healthy",
		LeaseID:           "lease-1",
		RestartGeneration: 4,
		UpdatedAt:         now,
	})

	reconcilePeerLease(dir, cfg, logger, &haActivityState{}, now)

	if _, err := lease.Read(dir, "edr-b"); !os.IsNotExist(err) {
		t.Fatalf("expected peer lease to be released, err=%v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"action":"release_peer_lease"`) {
		t.Fatalf("expected lease release audit event, got %s", string(raw))
	}
}

func TestReconcilePeerLeaseKeepsLeaseWhenPeerGenerationBehind(t *testing.T) {
	dir := t.TempDir()
	logger, err := eventlog.New(filepath.Join(dir, "events.jsonl"), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iruntime.DefaultConfig()
	cfg.HA.InstanceID = "edr-a"
	cfg.HA.PeerInstanceID = "edr-b"
	cfg.HA.RunDir = dir
	cfg.HA.HeartbeatEverySec = 1
	now := time.Now().UTC()
	_, _, err = lease.Acquire(dir, lease.Lease{
		LeaseID:    "lease-1",
		Target:     "edr-b",
		RequestID:  "req-1",
		Source:     "local-peer-down",
		Generation: 4,
		Priority:   100,
		AcquiredAt: now.Add(-2 * time.Second),
		ExpiresAt:  now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeHeartbeatFixture(t, dir, liveness.Heartbeat{
		InstanceID:        "edr-b",
		State:             "healthy",
		RestartGeneration: 3,
		UpdatedAt:         now,
	})

	reconcilePeerLease(dir, cfg, logger, &haActivityState{}, now)

	if _, err := lease.Read(dir, "edr-b"); err != nil {
		t.Fatalf("expected peer lease to remain, err=%v", err)
	}
}

func TestHAActivityStatePersistsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha", "activity.json")
	state := newHAActivityState(path)
	now := time.Now().UTC()
	state.Record(haActivitySnapshot{
		RecordedAt: now,
		Action:     "restart_peer",
		RuleID:     "peer-down",
		Peer:       "edr-b",
		LeaseID:    "lease-1",
	})

	loaded := newHAActivityState(path)
	snap := loaded.Snapshot()
	if snap.Action != "restart_peer" || snap.RuleID != "peer-down" || snap.LeaseID != "lease-1" {
		t.Fatalf("unexpected persisted snapshot: %+v", snap)
	}
}

func writeHeartbeatFixture(t *testing.T, runDir string, hb liveness.Heartbeat) {
	t.Helper()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(liveness.Path(runDir, hb.InstanceID), append(raw, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
}
