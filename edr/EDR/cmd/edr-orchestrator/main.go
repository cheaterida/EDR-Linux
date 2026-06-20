package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"edr/internal/app"
	"edr/internal/collector"
	"edr/internal/control"
	"edr/internal/eventlog"
	"edr/internal/lease"
	"edr/internal/liveness"
	"edr/internal/policy"
	"edr/internal/response"
	"edr/internal/rootsession"
	iruntime "edr/internal/runtime"
	"edr/internal/supervisor"
	"edr/internal/transport"
)

func main() {
	app.CacheRuntimeVars()

	cfgPath := flag.String("config", "configs/orchestrator.json", "config path")
	flag.Parse()

	cfg, err := iruntime.LoadConfig(*cfgPath)
	if err != nil {
		app.Fatal(err)
	}
	if err := app.ValidateConfigPaths(cfg); err != nil {
		app.Fatal(err)
	}
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		app.Fatal(err)
	}
	logger, err := eventlog.NewWithOptions(cfg.EventPath, eventlog.Options{
		EnableSyslog: cfg.Syslog,
		MaxBytes:     cfg.Retention.MaxBytes,
		MaxBackups:   cfg.Retention.MaxBackups,
	})
	if err != nil {
		app.Fatal(err)
	}
	suppressor := control.NewSuppressor(control.SuppressorOptions{
		ProcessCooldown: time.Duration(cfg.Suppression.ProcessCooldownSec) * time.Second,
		FileCooldown:    time.Duration(cfg.Suppression.FileCooldownSec) * time.Second,
		NetworkCooldown: time.Duration(cfg.Suppression.NetworkCooldownSec) * time.Second,
		RatePerSec:      cfg.Suppression.RatePerSec,
		Burst:           cfg.Suppression.Burst,
	})
	localAuth := transport.NewAuthenticator(iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret), 30*time.Second)

	sensorClient := transport.NewUnixHTTPClient(iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.SensorSocket))
	enforcerClient := transport.NewUnixHTTPClient(iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.EnforcerSocket))
	remoteCollector := transport.RemoteCollector{Client: sensorClient, BaseURL: "http://unix", Auth: localAuth}
	remoteResponder := transport.RemoteResponder{
		Client:     enforcerClient,
		BaseURL:    "http://unix",
		InstanceID: cfg.HA.InstanceID,
		Generation: 1,
		Secret:     iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret),
	}

	agent := &control.Agent{
		Policy:              pol,
		Collector:           collector.UnsupportedKernelCollector{},
		Logger:              logger,
		Responder:           response.SoftResponder{DryRun: true},
		ResponsePath:        cfg.ResponsePath,
		Suppressor:          suppressor,
		SuppressorStatePath: cfg.Suppression.StatePath,
	}
	agent.Source = control.CollectorSource{Collector: remoteCollector}
	agent.Engine = control.PolicyEngine{Policy: pol}
	agent.Executor = control.ResponderExecutor{Responder: remoteResponder}
	agent.Events = control.LoggerSink{Logger: logger}
	agent.Init()

	health := componentHealth{
		sensorClient:   sensorClient,
		enforcerClient: enforcerClient,
		auth:           localAuth,
	}
	socketPath := iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.OrchestratorSocket)
	if err := app.PrepareSocketPath(socketPath); err != nil {
		app.Fatal(err)
	}
	if err := app.PrepareRuntimeDir(cfg.HA.RunDir); err != nil {
		app.Fatal(err)
	}
	runDir := cfg.HA.RunDir
	supervisorState := &supervisorSyncState{}
	haState := newHAActivityState(filepath.Join(runDir, fmt.Sprintf("%s.ha_activity.json", cfg.HA.InstanceID)))
	rootSessionMgr := rootsession.NewManager(rootsession.Config{
		Mode:         cfg.RootSession.Mode,
		Secret:       iruntime.ParseHexOrRawSecret(cfg.RootSession.Secret),
		StatePath:    iruntime.ResolveFromConfigPath(*cfgPath, cfg.RootSession.StatePath),
		ScanEvery:    time.Duration(cfg.RootSession.ScanEverySec) * time.Second,
		ChallengeTTL: time.Duration(cfg.RootSession.ChallengeTTLSec) * time.Second,
		GracePeriod:  time.Duration(cfg.RootSession.GraceSec) * time.Second,
		BypassToken:  cfg.RootSession.BypassToken,
		BypassTTL:    time.Duration(cfg.RootSession.BypassTTLSec) * time.Second,
		SystemNames:  cfg.RootSession.SystemNames,
		ShellNames:   cfg.RootSession.ShellNames,
		ToolingNames: cfg.RootSession.ToolingNames,
	}, logger)

	shutdownCh := make(chan struct{}, 1)
	srv := control.NewServerWithOptions(agent, control.ServerOptions{
		BaselinePath:   cfg.BaselinePath,
		PolicyPath:     cfg.PolicyPath,
		EventPath:      cfg.EventPath,
		ArtifactDir:    cfg.ArtifactDir,
		AllowedUIDs:    cfg.AllowedUIDs,
		IngestKey:      iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret),
		SigningKeyPath: cfg.SigningKeyPath,
		HAStatus: func() (any, error) {
			return buildHAStatus(runDir, cfg, logger, supervisorState, haState, time.Now().UTC())
		},
		RootSessionStatus: func() (any, error) {
			return rootSessionMgr.Snapshot(), nil
		},
		RootSessionChallenge: func(pid int) (any, error) {
			return rootSessionMgr.IssueChallenge(pid)
		},
		RootSessionRespond: func(req map[string]any) (any, error) {
			pid, _ := req["pid"].(float64)
			sessionID, _ := req["session_id"].(string)
			tty, _ := req["tty"].(string)
			nonce, _ := req["nonce"].(string)
			deadlineRaw, _ := req["deadline"].(string)
			responseText, _ := req["response"].(string)
			deadline, err := time.Parse(time.RFC3339Nano, deadlineRaw)
			if err != nil {
				return nil, fmt.Errorf("invalid deadline: %w", err)
			}
			return rootSessionMgr.Validate(rootsession.Response{
				PID:       int(pid),
				SessionID: sessionID,
				TTY:       tty,
				Nonce:     nonce,
				Deadline:  deadline,
				Response:  responseText,
			})
		},
		RootSessionBypass: func(token string, ttl time.Duration) (any, error) {
			until, err := rootSessionMgr.ActivateBypass(token, ttl)
			if err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "bypass_until": until}, nil
		},
		RootSessionClearBypass: func() (any, error) {
			if err := rootSessionMgr.RevokeBypass(); err != nil {
				return nil, err
			}
			return map[string]any{"ok": true}, nil
		},
		Shutdown: func() {
			select {
			case shutdownCh <- struct{}{}:
			default:
			}
		},
	})
	httpSrv, ln, err := transport.ListenUnix(socketPath, srv, control.ConnContext)
	if err != nil {
		app.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = httpSrv.Serve(ln) }()

	started := time.Now().UTC()
	writeHeartbeat(runDir, cfg, logger, health, started, 1)
	go heartbeatLoop(runDir, cfg, logger, health, started)
	go peerWatchLoop(runDir, cfg, logger, haState, started)
	if cfg.Supervisor.Enabled {
		go supervisorLoop(runDir, cfg, logger, supervisorState, haState)
	}
	if cfg.RootSession.Mode != rootsession.ModeOff {
		go rootSessionLoop(runDir, cfg, rootSessionMgr)
	}

	ticker := time.NewTicker(time.Duration(cfg.IntervalSec) * time.Second)
	defer ticker.Stop()
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ticker.C:
			_ = agent.RunOnce(context.Background())
		case <-shutdownCh:
			_ = httpSrv.Shutdown(context.Background())
			agent.Shutdown()
			return
		case <-sigCh:
			_ = httpSrv.Shutdown(context.Background())
			agent.Shutdown()
			return
		}
	}
}

func rootSessionLoop(runDir string, cfg iruntime.Config, mgr *rootsession.Manager) {
	if mgr == nil {
		return
	}
	if rootSessionLeaseActive(runDir, cfg, mgr.ScanEvery()) {
		_ = mgr.Scan()
	}
	t := time.NewTicker(mgr.ScanEvery())
	defer t.Stop()
	for range t.C {
		if !rootSessionLeaseActive(runDir, cfg, mgr.ScanEvery()) {
			continue
		}
		_ = mgr.Scan()
	}
}

func rootSessionLeaseActive(runDir string, cfg iruntime.Config, interval time.Duration) bool {
	now := time.Now().UTC()
	ttl := interval * 2
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	_, ok, err := lease.Acquire(runDir, lease.Lease{
		LeaseID:    fmt.Sprintf("%s-root-session", cfg.HA.InstanceID),
		Target:     "root-session.guard",
		RequestID:  fmt.Sprintf("root-session-%s", cfg.HA.InstanceID),
		Source:     "root-session",
		Generation: 1,
		Priority:   cfg.HA.Priority,
		AcquiredAt: now,
		ExpiresAt:  now.Add(ttl),
	})
	return err == nil && ok
}

type componentHealth struct {
	sensorClient   *http.Client
	enforcerClient *http.Client
	auth           *transport.Authenticator
}

func heartbeatLoop(runDir string, cfg iruntime.Config, logger *eventlog.Logger, health componentHealth, started time.Time) {
	t := time.NewTicker(time.Duration(cfg.HA.HeartbeatEverySec) * time.Second)
	defer t.Stop()
	seq := uint64(1)
	for range t.C {
		seq++
		writeHeartbeat(runDir, cfg, logger, health, started, seq)
	}
}

func writeHeartbeat(runDir string, cfg iruntime.Config, logger *eventlog.Logger, health componentHealth, started time.Time, seq uint64) {
	state, components := health.snapshot()
	if withinStartupGrace(cfg, started, time.Now().UTC()) && state != "healthy" {
		state = "starting"
	}
	hb := liveness.Heartbeat{
		InstanceID:        cfg.HA.InstanceID,
		BootID:            app.CachedBootID,
		PID:               os.Getpid(),
		StartTime:         started,
		Seq:               seq,
		State:             state,
		Components:        components,
		RestartGeneration: 1,
	}
	if currentLease, err := lease.Read(runDir, cfg.HA.InstanceID); err == nil && currentLease.ExpiresAt.After(time.Now().UTC()) {
		hb.LeaseID = currentLease.LeaseID
		hb.RestartGeneration = currentLease.Generation
	}
	if err := liveness.Write(runDir, hb); err != nil && logger != nil {
		_ = logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("heartbeat-write-%s-%d", cfg.HA.InstanceID, time.Now().UTC().UnixNano()),
			Category: "liveness",
			Severity: "high",
			Action:   "heartbeat_write_failed",
			Decision: "alert",
			RuleID:   "ha-heartbeat-write",
			Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "run_dir": runDir},
			Evidence: map[string]any{"error": err.Error()},
		})
	}
}

func (h componentHealth) snapshot() (string, map[string]string) {
	components := map[string]string{
		"orchestrator": "healthy",
		"sensor":       probeComponentHealth(h.sensorClient, h.auth),
		"enforcer":     probeComponentHealth(h.enforcerClient, h.auth),
	}
	state := "healthy"
	for _, status := range components {
		switch status {
		case "down":
			return "down", components
		case "suspect", "unknown":
			state = "suspect"
		}
	}
	return state, components
}

func probeComponentHealth(client *http.Client, auth *transport.Authenticator) string {
	if client == nil {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v0/health", nil)
	if err != nil {
		return "unknown"
	}
	return probeComponentHealthRequest(client, req, auth)
}

func probeComponentHealthRequest(client *http.Client, req *http.Request, auth *transport.Authenticator) string {
	if auth != nil {
		auth.Sign(req, nil, transport.NewRequestID("health"), time.Now().UTC())
	}
	resp, err := client.Do(req)
	if err != nil {
		return "down"
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "suspect"
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "suspect"
	}
	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "suspect"
	}
	if body.OK {
		return "healthy"
	}
	return "suspect"
}

func peerWatchLoop(runDir string, cfg iruntime.Config, logger *eventlog.Logger, activity *haActivityState, started time.Time) {
	t := time.NewTicker(time.Duration(cfg.HA.HeartbeatEverySec) * time.Second)
	defer t.Stop()
	lastRestart := time.Time{}
	runner := execRestartRunner{}
	checkOnce := func() {
		reconcilePeerLease(runDir, cfg, logger, activity, time.Now().UTC())
		lastRestart = checkPeerLiveness(runDir, cfg, logger, activity, runner, started, lastRestart, time.Now().UTC())
	}
	checkOnce()
	for range t.C {
		checkOnce()
	}
}

func supervisorLoop(runDir string, cfg iruntime.Config, logger *eventlog.Logger, state *supervisorSyncState, activity *haActivityState) {
	httpClient := transport.NewHTTPClient(time.Duration(cfg.Supervisor.RequestTimeoutSec) * time.Second)
	if strings.HasPrefix(strings.ToLower(cfg.Supervisor.URL), "https://") {
		tlsClient, err := supervisor.NewHTTPClientWithTLS(time.Duration(cfg.Supervisor.RequestTimeoutSec)*time.Second, supervisor.TLSOptions{
			CertPath:   cfg.Supervisor.TLSCertPath,
			KeyPath:    cfg.Supervisor.TLSKeyPath,
			CAPath:     cfg.Supervisor.TLSCAPath,
			ServerName: cfg.Supervisor.TLSServerName,
		})
		if err == nil {
			httpClient = tlsClient
		} else if logger != nil {
			_ = logger.Write(eventlog.Event{
				EventID:  fmt.Sprintf("supervisor-client-tls-%d", time.Now().UTC().UnixNano()),
				Category: "supervisor",
				Severity: "high",
				Action:   "tls_client_init_failed",
				Decision: "alert",
				RuleID:   "supervisor-client-tls",
				Evidence: map[string]any{"error": err.Error()},
			})
		}
	}
	client := supervisor.Client{
		BaseURL: cfg.Supervisor.URL,
		Secret:  iruntime.ParseHexOrRawSecret(cfg.Supervisor.SharedSecret),
		HTTP:    httpClient,
	}
	supervisorLoopWithClient(runDir, cfg, logger, state, activity, client, execRestartRunner{})
}

func supervisorLoopWithClient(runDir string, cfg iruntime.Config, logger *eventlog.Logger, state *supervisorSyncState, activity *haActivityState, client supervisorClient, runner restartRunner) {
	t := time.NewTicker(time.Duration(cfg.Supervisor.HeartbeatEverySec) * time.Second)
	defer t.Stop()
	lastRestart := time.Time{}
	syncOnce := func() {
		lastRestart = syncSupervisor(runDir, cfg, logger, state, activity, client, runner, lastRestart, time.Now().UTC())
	}
	syncOnce()
	for range t.C {
		syncOnce()
	}
}

type restartRunner interface {
	Run(context.Context, []string) error
}

type supervisorClient interface {
	PushHeartbeat(context.Context, supervisor.HeartbeatRequest) (supervisor.HeartbeatResponse, error)
	PushEvidence(context.Context, supervisor.EvidenceRecord) error
}

type execRestartRunner struct{}

type supervisorSyncSnapshot struct {
	AttemptedAt   time.Time `json:"attempted_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	Status        string    `json:"status,omitempty"`
	Action        string    `json:"action,omitempty"`
	Error         string    `json:"error,omitempty"`
	DecisionID    string    `json:"decision_id,omitempty"`
	PeerState     string    `json:"peer_state,omitempty"`
}

type haActivitySnapshot struct {
	RecordedAt time.Time `json:"recorded_at,omitempty"`
	Action     string    `json:"action,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	Peer       string    `json:"peer,omitempty"`
	LeaseID    string    `json:"lease_id,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	Generation uint64    `json:"generation,omitempty"`
	Source     string    `json:"source,omitempty"`
	PeerState  string    `json:"peer_state,omitempty"`
	Error      string    `json:"error,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

type supervisorSyncState struct {
	mu       sync.RWMutex
	snapshot supervisorSyncSnapshot
}

func (s *supervisorSyncState) Record(next supervisorSyncSnapshot) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if next.AttemptedAt.IsZero() {
		next.AttemptedAt = time.Now().UTC()
	}
	if next.Status == "ok" {
		next.LastSuccessAt = next.AttemptedAt
	} else {
		next.LastSuccessAt = s.snapshot.LastSuccessAt
	}
	s.snapshot = next
}

func (s *supervisorSyncState) Snapshot() supervisorSyncSnapshot {
	if s == nil {
		return supervisorSyncSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

type haActivityState struct {
	mu       sync.RWMutex
	path     string
	snapshot haActivitySnapshot
}

func newHAActivityState(path string) *haActivityState {
	state := &haActivityState{path: path}
	_ = state.Load()
	return state
}

func (s *haActivityState) Record(next haActivitySnapshot) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if next.RecordedAt.IsZero() {
		next.RecordedAt = time.Now().UTC()
	}
	s.snapshot = next
	_ = s.saveLocked()
}

func (s *haActivityState) Snapshot() haActivitySnapshot {
	if s == nil {
		return haActivitySnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func (s *haActivityState) Load() error {
	if s == nil || s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap haActivitySnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snap
	return nil
}

func (s *haActivityState) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(s.snapshot)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (execRestartRunner) Run(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty restart command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if len(output) == 0 {
		return err
	}
	return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
}

func checkPeerLiveness(runDir string, cfg iruntime.Config, logger *eventlog.Logger, activity *haActivityState, runner restartRunner, started, lastRestart, now time.Time) time.Time {
	if withinStartupGrace(cfg, started, now) {
		return lastRestart
	}
	hb, err := liveness.Read(runDir, cfg.HA.PeerInstanceID)
	if err != nil {
		return lastRestart
	}
	state := liveness.State(now, hb, cfg.HA.SuspectAfter, cfg.HA.DownAfter, time.Duration(cfg.HA.HeartbeatEverySec)*time.Second)
	if state == "starting" {
		return lastRestart
	}
	if state != "down" {
		return lastRestart
	}
	if !lastRestart.IsZero() && now.Sub(lastRestart) < time.Duration(cfg.HA.RestartCooldownSec)*time.Second {
		return lastRestart
	}
	return attemptRestart(runDir, cfg, logger, activity, runner, lastRestart, now, hb, hb.RestartGeneration+1, "local-peer-down", "peer-down", map[string]any{
		"state":     state,
		"heartbeat": hb,
	}, nil)
}

func withinStartupGrace(cfg iruntime.Config, started, now time.Time) bool {
	if cfg.HA.StartupGraceSec <= 0 || started.IsZero() {
		return false
	}
	return now.Sub(started) < time.Duration(cfg.HA.StartupGraceSec)*time.Second
}

func reconcilePeerLease(runDir string, cfg iruntime.Config, logger *eventlog.Logger, activity *haActivityState, now time.Time) {
	current, err := lease.Read(runDir, cfg.HA.PeerInstanceID)
	if err != nil || current.ExpiresAt.Before(now) {
		return
	}
	peerHB, err := liveness.Read(runDir, cfg.HA.PeerInstanceID)
	if err != nil {
		return
	}
	peerState := liveness.State(now, peerHB, cfg.HA.SuspectAfter, cfg.HA.DownAfter, time.Duration(cfg.HA.HeartbeatEverySec)*time.Second)
	if peerState != "healthy" {
		return
	}
	if peerHB.RestartGeneration < current.Generation {
		return
	}
	if peerHB.LeaseID != "" && peerHB.LeaseID != current.LeaseID {
		return
	}
	if err := lease.Release(runDir, current.Target, current.LeaseID); err != nil {
		return
	}
	activity.Record(haActivitySnapshot{
		RecordedAt: now,
		Action:     "release_peer_lease",
		RuleID:     "peer-lease-release",
		Peer:       current.Target,
		LeaseID:    current.LeaseID,
		RequestID:  current.RequestID,
		Generation: current.Generation,
		Source:     current.Source,
		PeerState:  peerState,
	})
	if logger != nil {
		_ = logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("lease-release-%s-%d", cfg.HA.PeerInstanceID, now.UnixNano()),
			Category: "liveness",
			Severity: "info",
			Action:   "release_peer_lease",
			Decision: "alert",
			RuleID:   "peer-lease-release",
			Subject: map[string]any{
				"instance_id": cfg.HA.InstanceID,
				"peer":        current.Target,
				"lease_id":    current.LeaseID,
				"generation":  current.Generation,
			},
			Evidence: map[string]any{
				"peer_state":           peerState,
				"peer_generation":      peerHB.RestartGeneration,
				"peer_heartbeat_lease": peerHB.LeaseID,
			},
		})
	}
}

func syncSupervisor(runDir string, cfg iruntime.Config, logger *eventlog.Logger, state *supervisorSyncState, activity *haActivityState, client supervisorClient, runner restartRunner, lastRestart, now time.Time) time.Time {
	localHB, err := liveness.Read(runDir, cfg.HA.InstanceID)
	if err != nil {
		recordSimpleHAActivity(activity, now, "sync_skipped", "supervisor-local-heartbeat-missing", cfg.HA.PeerInstanceID, "supervisor", map[string]any{
			"error": err.Error(),
		})
		state.Record(supervisorSyncSnapshot{
			AttemptedAt: now,
			Status:      "skipped",
			Action:      "local_heartbeat_missing",
			Error:       err.Error(),
		})
		if logger != nil {
			_ = logger.Write(eventlog.Event{
				EventID:  fmt.Sprintf("supervisor-sync-%s-%d", cfg.HA.InstanceID, now.UnixNano()),
				Category: "supervisor",
				Severity: "medium",
				Action:   "sync_skipped",
				Decision: "alert",
				RuleID:   "supervisor-local-heartbeat-missing",
				Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
				Evidence: map[string]any{"error": err.Error(), "run_dir": runDir},
			})
		}
		pushSupervisorEvidence(cfg, client, supervisor.EvidenceRecord{
			Host:       app.CachedHostname,
			InstanceID: cfg.HA.InstanceID,
			Category:   "supervisor",
			Action:     "sync_skipped",
			RuleID:     "supervisor-local-heartbeat-missing",
			RecordedAt: now,
			Subject:    map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
			Evidence:   map[string]any{"error": err.Error(), "run_dir": runDir},
		})
		return lastRestart
	}
	var peerHB *liveness.Heartbeat
	peerState := ""
	if hb, err := liveness.Read(runDir, cfg.HA.PeerInstanceID); err == nil {
		peerHB = &hb
		peerState = liveness.State(now, hb, cfg.HA.SuspectAfter, cfg.HA.DownAfter, time.Duration(cfg.HA.HeartbeatEverySec)*time.Second)
	}
	var currentLease *lease.Lease
	if l, err := lease.Read(runDir, cfg.HA.PeerInstanceID); err == nil && l.ExpiresAt.After(now) {
		currentLease = &l
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Supervisor.RequestTimeoutSec)*time.Second)
	defer cancel()
	resp, err := client.PushHeartbeat(ctx, supervisor.HeartbeatRequest{
		InstanceID:        cfg.HA.InstanceID,
		PeerInstanceID:    cfg.HA.PeerInstanceID,
		BootID:            app.CachedBootID,
		Hostname:          app.CachedHostname,
		Priority:          cfg.HA.Priority,
		HeartbeatEverySec: cfg.HA.HeartbeatEverySec,
		SentAt:            now,
		Local:             localHB,
		Peer:              peerHB,
		PeerState:         peerState,
		Lease:             currentLease,
		Chain:             logger.ChainSnapshot(),
	})
	if err != nil {
		recordSimpleHAActivity(activity, now, "sync_failed", "supervisor-heartbeat", cfg.HA.PeerInstanceID, "supervisor", map[string]any{
			"error":      err.Error(),
			"peer_state": peerState,
		})
		state.Record(supervisorSyncSnapshot{
			AttemptedAt: now,
			Status:      "failed",
			Action:      "heartbeat_error",
			Error:       err.Error(),
			PeerState:   peerState,
		})
		_ = logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("supervisor-sync-%s-%d", cfg.HA.InstanceID, now.UnixNano()),
			Category: "supervisor",
			Severity: "medium",
			Action:   "sync_failed",
			Decision: "alert",
			RuleID:   "supervisor-heartbeat",
			Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
			Evidence: map[string]any{"error": err.Error(), "peer_state": peerState},
		})
		pushSupervisorEvidence(cfg, client, supervisor.EvidenceRecord{
			Host:       app.CachedHostname,
			InstanceID: cfg.HA.InstanceID,
			Category:   "supervisor",
			Action:     "sync_failed",
			RuleID:     "supervisor-heartbeat",
			RecordedAt: now,
			Subject:    map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
			Evidence:   map[string]any{"error": err.Error(), "peer_state": peerState},
		})
		return lastRestart
	}
	intent := resp.RestartIntent
	if intent.RequestID == "" || intent.Target != cfg.HA.PeerInstanceID {
		state.Record(supervisorSyncSnapshot{
			AttemptedAt: now,
			Status:      "ok",
			Action:      "no_valid_intent",
			DecisionID:  resp.DecisionID,
			PeerState:   peerState,
		})
		if resp.DecisionID != "" {
			recordSimpleHAActivity(activity, now, "ignore_restart_intent", "supervisor-intent-invalid", cfg.HA.PeerInstanceID, "remote-supervisor", map[string]any{
				"detail":     intent.Reason,
				"peer_state": peerState,
			})
			_ = logger.Write(eventlog.Event{
				EventID:  resp.DecisionID + "-ignored",
				Category: "supervisor",
				Severity: "medium",
				Action:   "ignore_restart_intent",
				Decision: "alert",
				RuleID:   "supervisor-intent-invalid",
				Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
				Evidence: map[string]any{"target": intent.Target, "request_id": intent.RequestID},
			})
			pushSupervisorEvidence(cfg, client, supervisor.EvidenceRecord{
				DecisionID: resp.DecisionID,
				Host:       app.CachedHostname,
				InstanceID: cfg.HA.InstanceID,
				Category:   "supervisor",
				Action:     "ignore_restart_intent",
				RuleID:     "supervisor-intent-invalid",
				RecordedAt: now,
				Subject:    map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
				Evidence:   map[string]any{"target": intent.Target, "request_id": intent.RequestID},
			})
		}
		return lastRestart
	}
	if !lastRestart.IsZero() && now.Sub(lastRestart) < time.Duration(cfg.HA.RestartCooldownSec)*time.Second {
		recordSimpleHAActivity(activity, now, "skip_restart_intent", "supervisor-intent-cooldown", cfg.HA.PeerInstanceID, "remote-supervisor", map[string]any{
			"detail":     intent.Reason,
			"peer_state": peerState,
		})
		state.Record(supervisorSyncSnapshot{
			AttemptedAt: now,
			Status:      "ok",
			Action:      "intent_cooldown",
			DecisionID:  resp.DecisionID,
			PeerState:   peerState,
		})
		_ = logger.Write(eventlog.Event{
			EventID:  resp.DecisionID + "-cooldown",
			Category: "supervisor",
			Severity: "medium",
			Action:   "skip_restart_intent",
			Decision: "alert",
			RuleID:   "supervisor-intent-cooldown",
			Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
			Evidence: map[string]any{"decision_id": resp.DecisionID, "reason": intent.Reason, "peer_state": peerState},
		})
		pushSupervisorEvidence(cfg, client, supervisor.EvidenceRecord{
			DecisionID: resp.DecisionID,
			Host:       app.CachedHostname,
			InstanceID: cfg.HA.InstanceID,
			Category:   "supervisor",
			Action:     "skip_restart_intent",
			RuleID:     "supervisor-intent-cooldown",
			RecordedAt: now,
			Subject:    map[string]any{"instance_id": cfg.HA.InstanceID, "peer": cfg.HA.PeerInstanceID},
			Evidence:   map[string]any{"decision_id": resp.DecisionID, "reason": intent.Reason, "peer_state": peerState},
		})
		return lastRestart
	}
	hb := liveness.Heartbeat{InstanceID: cfg.HA.PeerInstanceID}
	if peerHB != nil {
		hb = *peerHB
	}
	gen := intent.Generation
	if gen == 0 {
		gen = hb.RestartGeneration + 1
	}
	state.Record(supervisorSyncSnapshot{
		AttemptedAt: now,
		Status:      "ok",
		Action:      "restart_intent",
		DecisionID:  resp.DecisionID,
		PeerState:   peerState,
	})
	return attemptRestart(runDir, cfg, logger, activity, runner, lastRestart, now, hb, gen, "remote-supervisor", "supervisor-restart", map[string]any{
		"decision_id": resp.DecisionID,
		"reason":      intent.Reason,
		"peer_state":  peerState,
	}, client)
}

func attemptRestart(runDir string, cfg iruntime.Config, logger *eventlog.Logger, activity *haActivityState, runner restartRunner, lastRestart, now time.Time, hb liveness.Heartbeat, generation uint64, source, ruleID string, evidence map[string]any, reporter supervisorClient) time.Time {
	l := lease.Lease{
		LeaseID:    fmt.Sprintf("%s-%d", cfg.HA.InstanceID, now.UnixNano()),
		Target:     cfg.HA.PeerInstanceID,
		RequestID:  fmt.Sprintf("restart-%s-%d", cfg.HA.PeerInstanceID, now.UnixNano()),
		Source:     source,
		Generation: generation,
		Priority:   cfg.HA.Priority,
		AcquiredAt: now,
		ExpiresAt:  now.Add(time.Duration(cfg.HA.LeaseTTLSec) * time.Second),
	}
	if current, ok, err := lease.Acquire(runDir, l); err != nil || !ok {
		rejectEvidence := cloneEvidence(evidence)
		if err != nil {
			rejectEvidence["error"] = err.Error()
			recordHAActivity(activity, now, "restart_peer_skipped", ruleID+"-lease-error", l, rejectEvidence)
			writeRestartEvent(logger, cfg.HA.InstanceID, l, hb, rejectEvidence, "restart_peer_skipped", ruleID+"-lease-error", "medium")
			pushSupervisorEvidence(cfg, reporter, evidenceRecordFromRestart(cfg, l, "restart_peer_skipped", ruleID+"-lease-error", rejectEvidence))
			return lastRestart
		}
		rejectEvidence["current_lease"] = current
		recordHAActivity(activity, now, "restart_peer_skipped", ruleID+"-lease-conflict", l, rejectEvidence)
		writeRestartEvent(logger, cfg.HA.InstanceID, l, hb, rejectEvidence, "restart_peer_skipped", ruleID+"-lease-conflict", "medium")
		pushSupervisorEvidence(cfg, reporter, evidenceRecordFromRestart(cfg, l, "restart_peer_skipped", ruleID+"-lease-conflict", rejectEvidence))
		return lastRestart
	}
	command, err := buildRestartCommand(cfg, l, hb)
	if err != nil {
		_ = lease.Release(runDir, l.Target, l.LeaseID)
		failedEvidence := cloneEvidence(evidence)
		failedEvidence["error"] = err.Error()
		recordHAActivity(activity, now, "restart_peer_failed", ruleID+"-command", l, failedEvidence)
		writeRestartEvent(logger, cfg.HA.InstanceID, l, hb, failedEvidence, "restart_peer_failed", ruleID+"-command", "critical")
		pushSupervisorEvidence(cfg, reporter, evidenceRecordFromRestart(cfg, l, "restart_peer_failed", ruleID+"-command", failedEvidence))
		return now
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.HA.RestartTimeoutSec)*time.Second)
	defer cancel()
	if err := runner.Run(ctx, command); err != nil {
		_ = lease.Release(runDir, l.Target, l.LeaseID)
		failedEvidence := cloneEvidence(evidence)
		failedEvidence["error"] = err.Error()
		failedEvidence["restart_command"] = command
		recordHAActivity(activity, now, "restart_peer_failed", ruleID+"-failed", l, failedEvidence)
		writeRestartEvent(logger, cfg.HA.InstanceID, l, hb, failedEvidence, "restart_peer_failed", ruleID+"-failed", "critical")
		pushSupervisorEvidence(cfg, reporter, evidenceRecordFromRestart(cfg, l, "restart_peer_failed", ruleID+"-failed", failedEvidence))
		return now
	}
	successEvidence := cloneEvidence(evidence)
	successEvidence["restart_command"] = command
	recordHAActivity(activity, now, "restart_peer", ruleID, l, successEvidence)
	writeRestartEvent(logger, cfg.HA.InstanceID, l, hb, successEvidence, "restart_peer", ruleID, "critical")
	pushSupervisorEvidence(cfg, reporter, evidenceRecordFromRestart(cfg, l, "restart_peer", ruleID, successEvidence))
	return now
}

func recordHAActivity(state *haActivityState, recordedAt time.Time, action, ruleID string, l lease.Lease, evidence map[string]any) {
	if state == nil {
		return
	}
	state.Record(haActivitySnapshot{
		RecordedAt: recordedAt,
		Action:     action,
		RuleID:     ruleID,
		Peer:       l.Target,
		LeaseID:    l.LeaseID,
		RequestID:  l.RequestID,
		Generation: l.Generation,
		Source:     l.Source,
		PeerState:  strFromEvidence(evidence, "peer_state", "state"),
		Error:      strFromEvidence(evidence, "error"),
		Detail:     strFromEvidence(evidence, "reason"),
	})
}

func recordSimpleHAActivity(state *haActivityState, recordedAt time.Time, action, ruleID, peer, source string, evidence map[string]any) {
	if state == nil {
		return
	}
	state.Record(haActivitySnapshot{
		RecordedAt: recordedAt,
		Action:     action,
		RuleID:     ruleID,
		Peer:       peer,
		Source:     source,
		PeerState:  strFromEvidence(evidence, "peer_state", "state"),
		Error:      strFromEvidence(evidence, "error"),
		Detail:     strFromEvidence(evidence, "detail", "reason"),
	})
}

func strFromEvidence(evidence map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := evidence[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func buildRestartCommand(cfg iruntime.Config, l lease.Lease, hb liveness.Heartbeat) ([]string, error) {
	if len(cfg.HA.RestartCommand) == 0 {
		return nil, fmt.Errorf("ha.restart_command is empty")
	}
	replacer := strings.NewReplacer(
		"{{instance_id}}", cfg.HA.InstanceID,
		"{{peer_instance_id}}", cfg.HA.PeerInstanceID,
		"{{lease_id}}", l.LeaseID,
		"{{request_id}}", l.RequestID,
		"{{generation}}", strconv.FormatUint(l.Generation, 10),
		"{{peer_generation}}", strconv.FormatUint(hb.RestartGeneration, 10),
		"{{peer_pid}}", strconv.Itoa(hb.PID),
	)
	command := make([]string, 0, len(cfg.HA.RestartCommand))
	for _, arg := range cfg.HA.RestartCommand {
		expanded := replacer.Replace(arg)
		if expanded == "" {
			return nil, fmt.Errorf("ha.restart_command contains empty argv after expansion")
		}
		command = append(command, expanded)
	}
	return command, nil
}

func writeRestartEvent(logger *eventlog.Logger, instanceID string, l lease.Lease, hb liveness.Heartbeat, extra map[string]any, action, ruleID, severity string) {
	if logger == nil {
		return
	}
	evidence := map[string]any{
		"heartbeat": hb,
	}
	for k, v := range extra {
		evidence[k] = v
	}
	_ = logger.Write(eventlog.Event{
		EventID:  l.RequestID,
		Category: "liveness",
		Severity: severity,
		Action:   action,
		Decision: "alert",
		RuleID:   ruleID,
		Subject: map[string]any{
			"instance_id": instanceID,
			"peer":        l.Target,
			"lease_id":    l.LeaseID,
			"request_id":  l.RequestID,
			"generation":  l.Generation,
			"source":      l.Source,
		},
		Evidence: evidence,
	})
}

func cloneEvidence(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func evidenceRecordFromRestart(cfg iruntime.Config, l lease.Lease, action, ruleID string, evidence map[string]any) supervisor.EvidenceRecord {
	return supervisor.EvidenceRecord{
		DecisionID: decisionIDFromEvidence(evidence),
		Host:       app.CachedHostname,
		InstanceID: cfg.HA.InstanceID,
		Category:   "liveness",
		Action:     action,
		RuleID:     ruleID,
		RecordedAt: time.Now().UTC(),
		Subject: map[string]any{
			"instance_id": cfg.HA.InstanceID,
			"peer":        l.Target,
			"lease_id":    l.LeaseID,
			"request_id":  l.RequestID,
			"generation":  l.Generation,
			"source":      l.Source,
		},
		Evidence: cloneEvidence(evidence),
	}
}

func decisionIDFromEvidence(evidence map[string]any) string {
	if v, ok := evidence["decision_id"].(string); ok {
		return v
	}
	return ""
}

func pushSupervisorEvidence(cfg iruntime.Config, reporter supervisorClient, rec supervisor.EvidenceRecord) {
	if !cfg.Supervisor.Enabled || reporter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Supervisor.RequestTimeoutSec)*time.Second)
	defer cancel()
	_ = reporter.PushEvidence(ctx, rec)
}

func buildHAStatus(runDir string, cfg iruntime.Config, logger *eventlog.Logger, syncState *supervisorSyncState, activity *haActivityState, now time.Time) (map[string]any, error) {
	status := map[string]any{
		"ok":                  true,
		"instance_id":         cfg.HA.InstanceID,
		"peer_instance_id":    cfg.HA.PeerInstanceID,
		"run_dir":             runDir,
		"supervisor_enabled":  cfg.Supervisor.Enabled,
		"heartbeat_every_sec": cfg.HA.HeartbeatEverySec,
	}

	localHB, localErr := liveness.Read(runDir, cfg.HA.InstanceID)
	if localErr == nil {
		status["local_heartbeat"] = localHB
		status["local_state"] = liveness.State(now, localHB, cfg.HA.SuspectAfter, cfg.HA.DownAfter, time.Duration(cfg.HA.HeartbeatEverySec)*time.Second)
	} else {
		status["local_heartbeat_error"] = localErr.Error()
		status["local_state"] = "missing"
	}

	peerHB, peerErr := liveness.Read(runDir, cfg.HA.PeerInstanceID)
	if peerErr == nil {
		status["peer_heartbeat"] = peerHB
		status["peer_state"] = liveness.State(now, peerHB, cfg.HA.SuspectAfter, cfg.HA.DownAfter, time.Duration(cfg.HA.HeartbeatEverySec)*time.Second)
	} else {
		status["peer_heartbeat_error"] = peerErr.Error()
		status["peer_state"] = "missing"
	}

	currentLease, leaseErr := lease.Read(runDir, cfg.HA.PeerInstanceID)
	if leaseErr == nil {
		status["peer_lease"] = currentLease
	} else if !errors.Is(leaseErr, os.ErrNotExist) {
		status["peer_lease_error"] = leaseErr.Error()
	}

	if logger != nil {
		status["event_chain"] = logger.ChainSnapshot()
	}
	if cfg.Supervisor.Enabled && syncState != nil {
		status["supervisor_sync"] = syncState.Snapshot()
	}
	if activity != nil {
		if snap := activity.Snapshot(); snap.Action != "" {
			status["ha_activity"] = snap
		}
	}
	return status, nil
}
