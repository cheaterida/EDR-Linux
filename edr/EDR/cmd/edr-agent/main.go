package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"edr/internal/bpf"
	"edr/internal/collector"
	"edr/internal/control"
	"edr/internal/eventlog"
	"edr/internal/fanotify"
	"edr/internal/integrity"
	"edr/internal/notify"
	"edr/internal/policy"
	"edr/internal/response"
	"edr/internal/rootkit"
)

// R-K4: runtime variables sampled once at startup and frozen for the
// lifetime of the agent. Avoids per-event os.Hostname() / os.Getuid()
// calls that could drift across DHCP renewals, and keeps the audit
// chain stable. Agent C reads these via its own cached fields.
var (
	cachedHostname string
	cachedUID      int
	cachedBootID   string
)

func cacheRuntimeVars() {
	if host, err := os.Hostname(); err == nil {
		cachedHostname = host
	}
	cachedUID = os.Getuid()
	if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		cachedBootID = strings.TrimSpace(string(raw))
	}
}

type retentionConfig struct {
	MaxBytes   int64 `json:"max_bytes"`
	MaxBackups int   `json:"max_backups"`
}

type fileWatchConfig struct {
	Mode  string   `json:"mode"`
	Paths []string `json:"paths"`
}

type nftConfig struct {
	Enabled bool   `json:"enabled"`
	DryRun  bool   `json:"dry_run"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
}

type integrityConfig struct {
	EnableChain bool   `json:"enable_chain"`
	KeyPath     string `json:"key_path"`
	StatePath   string `json:"state_path"`
	Algorithm   string `json:"algorithm"`
}

type suppressionConfig struct {
	ProcessCooldownSec int    `json:"process_cooldown_sec"`
	FileCooldownSec    int    `json:"file_cooldown_sec"`
	NetworkCooldownSec int    `json:"network_cooldown_sec"`
	RatePerSec         uint64 `json:"rate_per_sec"`
	Burst              uint64 `json:"burst"`
	StatePath          string `json:"state_path"`
}

type rootkitConfig struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"interval_sec"`
	MonitorOnly bool `json:"monitor_only"`
}

// bpfConfig is the v0.2 ring0 surface. R-P2: enabled defaults to
// false; the agent must keep working as a pure procfs collector
// until deployment flips the switch. R-C1: every field is
// explicit — there is no "auto-detect" path that quietly turns
// BPF on.
type bpfConfig struct {
	Enabled      bool   `json:"enabled"`
	ObjDir       string `json:"obj_dir"`
	RingbufPages int    `json:"ringbuf_pages"`
	RingbufPath  string `json:"ringbuf_path"`
}

// anchorConfig is the v0.16 remote log-anchor configuration.
// The anchor periodically pushes the latest chain head to an external
// endpoint so log truncation by root can be detected during verify.
type anchorConfig struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	FilePath string `json:"file_path"`
	Interval int    `json:"interval_sec"`
}

// fanotifyConfig is the v0.3 file-access interposition surface.
// Defaults to disabled. Requires CAP_SYS_ADMIN and a kernel with
// CONFIG_FANOTIFY=y. When enabled, the agent intercepts file-open
// attempts on the configured paths and can deny them synchronously
// before the kernel grants access.
type fanotifyConfig struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths"`
}

type config struct {
	PolicyPath     string            `json:"policy_path"`
	BaselinePath   string            `json:"baseline_path"`
	EventPath      string            `json:"event_path"`
	ResponsePath   string            `json:"response_path"`
	ArtifactDir    string            `json:"artifact_dir"`
	SocketPath     string            `json:"socket_path"`
	IntervalSec    int               `json:"interval_sec"`
	Syslog         bool              `json:"syslog"`
	DryRun         bool              `json:"dry_run"`
	Retention      retentionConfig   `json:"retention"`
	FileWatch      fileWatchConfig   `json:"file_watch"`
	NFT            nftConfig         `json:"nft"`
	AllowedUIDs    []int             `json:"allowed_uids"`
	Integrity      integrityConfig   `json:"integrity"`
	Suppression    suppressionConfig `json:"suppression"`
	BPF            bpfConfig         `json:"bpf"`
	Fanotify       fanotifyConfig    `json:"fanotify"`
	Anchor         anchorConfig      `json:"anchor"`
	SigningKeyPath string            `json:"signing_key_path"`

	// v0.5 additions
	Quarantine   quarantineConfig   `json:"quarantine"`
	Webhooks     []webhookConfig    `json:"webhooks"`
	EmailAlerts  emailAlertConfig   `json:"email_alerts"`
	SyslogRemote syslogRemoteConfig `json:"syslog_remote"`

	// v0.6 exercise hardening
	CriticalProcesses []string `json:"critical_processes"`

	// v0.7 rootkit detection
	Rootkit rootkitConfig `json:"rootkit_detection"`
}

// v0.5 config types

type quarantineConfig struct {
	Dir    string `json:"dir"`
	DryRun bool   `json:"dry_run"`
}

type webhookConfig struct {
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	TimeoutSec   int               `json:"timeout_sec,omitempty"`
	Format       string            `json:"format"`                 // "generic", "dingtalk", "wechat_work", "feishu"
	MinSeverity  string            `json:"min_severity,omitempty"` // only notify for this severity and above
	SharedSecret string            `json:"shared_secret,omitempty"`
}

type emailAlertConfig struct {
	Enabled     bool     `json:"enabled"`
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"` // env var reference: $ENV_VAR_NAME
	From        string   `json:"from"`
	To          []string `json:"to"`
	UseTLS      bool     `json:"use_tls"`
	MinSeverity string   `json:"min_severity"`
}

type syslogRemoteConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // "tcp" or "udp"
	Facility string `json:"facility,omitempty"` // "daemon", "local0"-"local7"
}

const defaultIntegrityKeyPath = "/var/lib/edr/log.key"

// resourceTracker computes agent process resource usage from Go runtime
// and fanotify performance when available.
type resourceTracker struct {
	fp *fanotify.Provider
}

func newResourceTracker(fp *fanotify.Provider) *resourceTracker {
	return &resourceTracker{fp: fp}
}

func (rt *resourceTracker) snapshot() control.ResourceInfo {
	var r control.ResourceInfo

	// Memory from Go runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	r.RSSMB = float64(m.Sys) / (1024 * 1024)

	// Fanotify
	if rt.fp != nil {
		r.FanotifyLatencyUs, r.FanotifyAllows, r.FanotifyDenies = rt.fp.Perf()
	}

	return r
}

func main() {
	cacheRuntimeVars()

	cfgPath := flag.String("config", "configs/agent.json", "agent config path")
	once := flag.Bool("once", false, "run one collection cycle and exit")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	// S12: validate that all security-sensitive paths are not symlinks
	// to prevent containment escapes and path traversal attacks.
	for _, p := range []string{
		cfg.ArtifactDir,
		filepath.Dir(cfg.EventPath),
		filepath.Dir(cfg.ResponsePath),
		filepath.Dir(cfg.SocketPath),
		filepath.Dir(cfg.PolicyPath),
		filepath.Dir(cfg.BaselinePath),
		filepath.Dir(cfg.Integrity.KeyPath),
		filepath.Dir(cfg.Suppression.StatePath),
	} {
		if p == "" || p == "." {
			continue
		}
		if err := control.ValidateBaseNotSymlink(p); err != nil {
			fatal(fmt.Errorf("config security: %w", err))
		}
	}
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		fatal(err)
	}

	key, keySource, err := resolveSigningKey(cfg.Integrity)
	if err != nil {
		fatal(err)
	}
	logger, err := eventlog.NewWithOptions(cfg.EventPath, eventlog.Options{
		EnableSyslog: cfg.Syslog,
		MaxBytes:     cfg.Retention.MaxBytes,
		MaxBackups:   cfg.Retention.MaxBackups,
		Integrity: eventlog.IntegrityOptions{
			EnableChain: cfg.Integrity.EnableChain,
			Key:         key,
			StatePath:   cfg.Integrity.StatePath,
			Algorithm:   cfg.Integrity.Algorithm,
		},
	})
	if err != nil {
		fatal(err)
	}

	suppressor := control.NewSuppressor(control.SuppressorOptions{
		ProcessCooldown: time.Duration(cfg.Suppression.ProcessCooldownSec) * time.Second,
		FileCooldown:    time.Duration(cfg.Suppression.FileCooldownSec) * time.Second,
		NetworkCooldown: time.Duration(cfg.Suppression.NetworkCooldownSec) * time.Second,
		RatePerSec:      cfg.Suppression.RatePerSec,
		Burst:           cfg.Suppression.Burst,
	})

	procfs := &collector.ProcfsCollector{WatchPaths: cfg.FileWatch.Paths, WatchMode: cfg.FileWatch.Mode}
	loader, err := startBPFLoader(cfg.BPF)
	if err != nil {
		fatal(err)
	}
	if loader != nil {
		defer func() { _ = loader.Close() }()
	}
	col := collector.NewMergedCollector(procfs, loader)

	// Populate BPF maps if the loader supports the MapFiller interface.
	// Only process_name is synced to the ring0 blacklist_comm map
	// (16-byte comm match). Entries that rely solely on process_path,
	// cmdline_contains, or user will only be enforced via userspace
	// polling and fanotify — not by the BPF SIGKILL fast-path.
	var mapFiller bpf.MapFiller
	if mf, ok := loader.(bpf.MapFiller); ok {
		mapFiller = mf
		// In --once mode, skip agent_pid to avoid self-triggering
		// the selfprotect probe (Go runtime tgkill creates a feedback loop).
		if !*once {
			if err := mf.SetAgentPID(uint32(os.Getpid())); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: set agent_pid BPF map: %v\n", err)
			}
		}
		for _, bl := range pol.ProcessAccess.Blacklist {
			if bl.ProcessName != "" {
				if err := mf.BlacklistAdd(bl.ProcessName); err != nil {
					fmt.Fprintf(os.Stderr, "edr-agent: blacklist_add(%q): %v\n", bl.ProcessName, err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "edr-agent: blacklist entry has no process_name; will not be enforced at ring0 (userspace-only)\n")
			}
		}
	}

	agent := &control.Agent{
		Policy:              pol,
		Collector:           col,
		Logger:              logger,
		Responder:           response.SoftResponder{DryRun: cfg.DryRun, NFT: response.NFTProvider{Enabled: cfg.NFT.Enabled, DryRun: cfg.NFT.DryRun, Table: cfg.NFT.Table, Chain: cfg.NFT.Chain}},
		ResponsePath:        cfg.ResponsePath,
		Suppressor:          suppressor,
		SuppressorStatePath: cfg.Suppression.StatePath,
	}
	agent.Source = control.CollectorSource{Collector: col}
	agent.Engine = control.PolicyEngine{Policy: pol}
	agent.Executor = control.ResponderExecutor{Responder: agent.Responder}
	agent.Events = control.LoggerSink{Logger: logger}
	// v0.7 rootkit: wire cross-source detector. The merged collector is
	// the only collector that tracks BPF-observed PIDs.
	if cfg.Rootkit.Enabled {
		det := rootkit.NewDetector(col, logger, agent.Responder)
		det.Interval = time.Duration(cfg.Rootkit.IntervalSec) * time.Second
		det.MonitorOnly = cfg.Rootkit.MonitorOnly
		agent.RootkitDetector = det
	}
	agent.SetMapFiller(mapFiller)
	agent.SetBPFHealthProvider(col.BPFHealth)
	agent.Init()

	// Start the ring0 fast-path for low-latency exec/selfprotect
	// enforcement. No-op if loader is nil or doesn't support it.
	// Skip in --once mode to avoid feedback loops.
	if !*once {
		agent.StartFastPath(loader)
	}

	if *once {
		if err := agent.RunOnce(context.Background()); err != nil {
			fatal(err)
		}
		return
	}

	// Create the HTTP server and Unix socket BEFORE fanotify so that
	// edrctl can reach the agent even while fanotify is recursively
	// marking directories (which can take 30+ seconds on large /etc,
	// /home, /root subtrees at depth 16).
	shutdownCh := make(chan struct{})
	requestShutdown := func() {
		select {
		case shutdownCh <- struct{}{}:
		default:
		}
	}
	// Declare anchor before server creation so Anchor field can reference it.
	var anchor *eventlog.Anchor
	var anchorStop func()
	if cfg.SigningKeyPath == "" {
		fmt.Fprintf(os.Stderr, "edr-agent: WARNING: signing_key_path not configured; policy reload endpoint will be disabled\n")
	}
	srv := control.NewServerWithOptions(agent, control.ServerOptions{
		BaselinePath:   cfg.BaselinePath,
		PolicyPath:     cfg.PolicyPath,
		EventPath:      cfg.EventPath,
		ArtifactDir:    cfg.ArtifactDir,
		AllowedUIDs:    cfg.AllowedUIDs,
		IntegrityKey:   key,
		IngestKey:      key,
		Anchor:         anchor,
		SigningKeyPath: cfg.SigningKeyPath,
		Shutdown:       requestShutdown,
	})
	if err := prepareSocketPath(cfg.SocketPath); err != nil {
		fatal(err)
	}
	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		fatal(err)
	}
	_ = os.Chmod(cfg.SocketPath, 0o600)
	httpSrv := &http.Server{Handler: srv, ConnContext: control.ConnContext}
	go func() { _ = httpSrv.Serve(ln) }()

	// Start the fanotify file-access interposition provider. Runs
	// a dedicated goroutine that intercepts file-open attempts and
	// can deny them synchronously before the kernel grants access.
	// No-op if fanotify.enabled is false or paths are empty.
	if cfg.Fanotify.Enabled && len(cfg.Fanotify.Paths) > 0 {
		fh := &fanotifyHandler{agent: agent}
		fl := &fanotifyLogAdapter{logger: logger, hostname: cachedHostname}
		fp, err := fanotify.New(cfg.Fanotify.Paths, fh, fl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "edr-agent: fanotify: %v\n", err)
			_ = logger.Write(eventlog.Event{
				EventID:  "fanotify-init-failed",
				Category: "audit",
				Severity: "high",
				Action:   "startup",
				Decision: "alert",
				RuleID:   "agent-self-check",
				Host:     cachedHostname,
				Evidence: map[string]any{
					"error":  err.Error(),
					"reason": "fanotify initialization failed; file-access interposition is not active",
				},
			})
		} else {
			fp.Start()
			defer func() { _ = fp.Stop() }()
			rt := newResourceTracker(fp)
			agent.SetResourceInfoProvider(rt.snapshot)
		}
	}

	if cfg.Integrity.EnableChain {
		emitStartupVerify(logger, key, keySource)
	}

	// Start the remote log anchor if configured. The anchor
	// periodically pushes the chain head to an HTTP endpoint
	// or file mirror so log truncation can be cross-verified.
	if cfg.Anchor.Enabled {
		anchor = eventlog.NewAnchor(eventlog.AnchorOptions{
			URL:      cfg.Anchor.URL,
			FilePath: cfg.Anchor.FilePath,
			Interval: time.Duration(cfg.Anchor.Interval) * time.Second,
			Hostname: cachedHostname,
			BootID:   cachedBootID,
		})
		if anchor != nil {
			anchorStop = anchor.Start(func() (string, uint64, string, string) {
				snap := logger.ChainSnapshot()
				return snap.ChainID, snap.LastSeq, snap.LastHash, snap.LastHMAC
			})
			defer anchorStop()
		}
	}

	if *once {
		if err := agent.RunOnce(context.Background()); err != nil {
			fatal(err)
		}
		return
	}

	var whDispatcher *notify.WebhookDispatcher
	if len(cfg.Webhooks) > 0 {
		cfgs := make([]notify.WebhookConfig, len(cfg.Webhooks))
		for i, wh := range cfg.Webhooks {
			cfgs[i] = notify.WebhookConfig{
				URL:          wh.URL,
				Headers:      wh.Headers,
				TimeoutSec:   wh.TimeoutSec,
				Format:       wh.Format,
				MinSeverity:  wh.MinSeverity,
				SharedSecret: wh.SharedSecret,
			}
		}
		whDispatcher = notify.NewWebhookDispatcher(cfgs)
		defer whDispatcher.Stop()
	}

	// Wire webhook forwarding for multi-machine event concentration (v0.6).
	// OnResponse publishes response events to peer collectors via webhook.
	// v0.7: Merger collapses same-PID alert bursts to reduce fatigue.
	merger := control.NewMerger(5 * time.Second)
	if whDispatcher != nil {
		agent.OnResponse = func(rec control.ResponseRecord) {
			// Extract PID from subject for merging.
			pid := 0
			if subj := rec.Subject; subj != nil {
				if p, ok := subj["pid"]; ok {
					switch v := p.(type) {
					case float64:
						pid = int(v)
					case int:
						pid = v
					}
				}
			}
			// Determine severity from rule match context.
			sev := "medium"
			if rec.Result.Action == "kill" || rec.Result.Action == "kill_tree" {
				sev = "high"
			}
			if rec.Category == "self_protection" {
				sev = "critical"
			}

			// Try merge; if a previous group flushed, dispatch merged event.
			if pid > 0 {
				if merged := merger.Merge(pid, rec.RuleID, cachedHostname, rec.Category, sev, time.Now()); merged != nil {
					whDispatcher.Dispatch(notify.WebhookEvent{
						RuleID:    merged.RuleIDs[0],
						Severity:  merged.Severity,
						Category:  merged.Category,
						Decision:  "alert",
						Action:    "merged_alert",
						Subject:   map[string]any{"pid": merged.PID, "merged_rules": merged.RuleIDs, "merged_count": merged.MergedCount, "summary": merged.Summary},
						Timestamp: merged.LastSeen,
						Host:      cachedHostname,
					})
				}
			}
			// Always dispatch the individual event too (merged events are additive).
			whDispatcher.Dispatch(notify.WebhookEvent{
				RuleID:    rec.RuleID,
				Severity:  sev,
				Category:  rec.Category,
				Decision:  rec.Result.Action,
				Action:    rec.Result.Action,
				Subject:   rec.Subject,
				Timestamp: rec.Timestamp,
				Host:      cachedHostname,
			})
		}
	}

	ctx := context.Background()
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	ticker := time.NewTicker(time.Duration(cfg.IntervalSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case sig := <-sigCh:
			auditSignalDenied(logger, sig)
		case <-shutdownCh:
			agent.ClearAgentPID()
			_ = httpSrv.Shutdown(context.Background())
			cleanupNFT(cfg.NFT)
			agent.Shutdown()
			return
		case <-ticker.C:
			_ = agent.RunOnce(ctx)
			agent.CheckCriticalProcesses(cfg.CriticalProcesses)
		}
	}
}

func auditSignalDenied(logger *eventlog.Logger, sig os.Signal) {
	name := fmt.Sprint(sig)
	if s, ok := sig.(syscall.Signal); ok {
		name = s.String()
	}
	_ = logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("signal-deny-%d", time.Now().UnixNano()),
		Category: "self_protection",
		Severity: "critical",
		Subject: map[string]any{
			"pid":    os.Getpid(),
			"signal": name,
		},
		Action:   "signal_denied",
		Decision: "deny",
		RuleID:   "self-protect-signal",
		Evidence: map[string]any{
			"boundary": "external stop signals are denied; use /v0/shutdown with root-login boundary",
		},
	})
}

// cleanupNFT removes the nftables table created by nft_block actions.
// This prevents leftover firewall rules from persisting in the kernel
// after the agent exits, which could block VM network traffic.
func cleanupNFT(cfg nftConfig) {
	if !cfg.Enabled || cfg.DryRun {
		return
	}
	p := response.NFTProvider{Enabled: cfg.Enabled, DryRun: false, Table: cfg.Table, Chain: cfg.Chain}
	res := p.Rollback()
	if !res.Success {
		fmt.Fprintf(os.Stderr, "edr-agent: nft cleanup: %s\n", res.Detail)
	}
}

func loadConfig(path string) (config, error) {
	cfg := config{
		PolicyPath:   "configs/policy.json",
		BaselinePath: "configs/baseline.json",
		EventPath:    "var/events.jsonl",
		ResponsePath: "var/responses.jsonl",
		ArtifactDir:  "var/forensics",
		SocketPath:   "var/run/edr-agent.sock",
		IntervalSec:  1,    // S10: 1s default; BPF fast-path is unaffected by this interval
		DryRun:       true, // R-P2: kill/chmod default to dry-run until deployment flips the switch
		Retention:    retentionConfig{MaxBytes: 1048576, MaxBackups: 3},
		// S8: expanded default watch paths covering common attack surfaces
		FileWatch:   fileWatchConfig{Mode: "inotify", Paths: []string{"configs", "/etc/ld.so.preload", "/etc/ld.so.conf.d", "/usr/lib", "/tmp", "/dev/shm", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/var/spool/cron", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system", "/root/.ssh", "/var/log"}},
		NFT:         nftConfig{DryRun: true, Table: "edr", Chain: "blocklist"},
		AllowedUIDs: []int{0},
		Integrity:   integrityConfig{EnableChain: true, KeyPath: defaultIntegrityKeyPath, Algorithm: "sha256"},
		Suppression: suppressionConfig{ProcessCooldownSec: 30, FileCooldownSec: 60, NetworkCooldownSec: 30, RatePerSec: 10, Burst: 10, StatePath: "var/suppressor.json"},
		// S9: fanotify enabled by default in audit mode; enforce via policy rules
		Fanotify:       fanotifyConfig{Enabled: true, Paths: []string{"/etc", "/tmp", "/dev/shm", "/var/spool/cron", "/usr/local/bin", "/usr/bin", "/usr/sbin", "/root/.ssh", "/home", "/etc/systemd/system", "/etc/cron.d", "/etc/cron.daily"}},
		Anchor:         anchorConfig{Enabled: false, URL: "", FilePath: "", Interval: 60},
		SigningKeyPath: "/var/lib/edr/signing.key",

		// v0.5 defaults: all disabled by default for safe upgrade
		Quarantine:   quarantineConfig{Dir: "var/quarantine", DryRun: true},
		Webhooks:     nil,
		EmailAlerts:  emailAlertConfig{Enabled: false, SMTPPort: 587, UseTLS: true, MinSeverity: "high"},
		SyslogRemote: syslogRemoteConfig{Enabled: false, Port: 514, Protocol: "udp", Facility: "daemon"},

		// v0.6 defaults: common critical services
		CriticalProcesses: []string{"sshd", "nginx", "mysqld", "apache2"},

		// v0.7 defaults: rootkit detection enabled, monitor-only, 30s interval
		Rootkit: rootkitConfig{Enabled: true, IntervalSec: 30, MonitorOnly: true},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	dec := json.NewDecoder(strings.NewReader(cleanJSON(string(raw))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 1
	}
	if cfg.Rootkit.IntervalSec <= 0 {
		cfg.Rootkit.IntervalSec = 30
	}
	return cfg, nil
}

func resolveSigningKey(cfg integrityConfig) ([]byte, string, error) {
	if !cfg.EnableChain {
		return nil, "disabled", nil
	}
	if path := strings.TrimSpace(cfg.KeyPath); path != "" {
		key, source, err := integrity.LoadOrCreate(path)
		if err != nil {
			return nil, "", fmt.Errorf("integrity key: %w", err)
		}
		label := string(source)
		if source == integrity.SourceFile || source == integrity.SourceGenFile {
			label = "file:" + path
		}
		return key, label, nil
	}
	return nil, "", fmt.Errorf("integrity.enable_chain is true but key_path is empty")
}

func emitStartupVerify(logger *eventlog.Logger, hmacKey []byte, keySource string) {
	res, err := eventlog.Verify(logger.Path(), hmacKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: startup verify: %v\n", err)
		return
	}
	severity := "info"
	if !res.OK {
		severity = "critical"
	} else if len(res.LegacySegment) > 0 {
		severity = "warning"
	}
	evidence := map[string]any{
		"ok":              res.OK,
		"chain_id":        res.ChainID,
		"last_seq":        res.LastSeq,
		"chain_lines":     res.ChainLines,
		"legacy_lines":    res.LegacyLines,
		"issues":          res.Issues,
		"legacy_segments": res.LegacySegment,
		"key_source":      keySource,
		"hmac_enabled":    len(hmacKey) > 0,
		"agent_uid":       cachedUID,
		"boot_id":         cachedBootID,
	}
	if err := logger.Write(eventlog.Event{
		EventID:  "log-verify-startup",
		Category: "audit",
		Severity: severity,
		Action:   "verify",
		Decision: "alert",
		RuleID:   "log-verify",
		Host:     cachedHostname,
		Evidence: evidence,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: write startup verify: %v\n", err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "edr-agent:", err)
	os.Exit(1)
}

// cleanJSON strips // line-comments and /* */ block-comments while
// respecting JSON string context so that comment-like sequences
// inside string values are left untouched (R-P1).
func cleanJSON(raw string) string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		var cleaned string
		cleaned, inBlock = stripComments(line, inBlock)
		trimmed := strings.TrimSpace(cleaned)
		if trimmed == "" {
			continue
		}
		out = append(out, cleaned)
	}
	return strings.Join(out, "\n")
}

// stripComments removes // and /* */ comments from a single line,
// tracking whether we are inside a block comment that started on a
// previous line (inBlock). It returns the cleaned line and whether
// the block comment continues to the next line.
func stripComments(line string, inBlock bool) (string, bool) {
	inString := false
	escape := false
	i := 0
	out := make([]byte, 0, len(line))

	for i < len(line) {
		ch := line[i]

		if inBlock {
			if ch == '*' && i+1 < len(line) && line[i+1] == '/' {
				inBlock = false
				i += 2
				continue
			}
			i++
			continue
		}

		if escape {
			out = append(out, ch)
			escape = false
			i++
			continue
		}

		if inString {
			if ch == '\\' {
				escape = true
			} else if ch == '"' {
				inString = false
			}
			out = append(out, ch)
			i++
			continue
		}

		if ch == '"' {
			inString = true
			out = append(out, ch)
			i++
			continue
		}

		if ch == '/' && i+1 < len(line) {
			if line[i+1] == '/' {
				// rest of line is a comment
				break
			}
			if line[i+1] == '*' {
				inBlock = true
				i += 2
				continue
			}
		}

		out = append(out, ch)
		i++
	}

	return string(out), inBlock
}

// fanotifyHandler implements fanotify.Handler by evaluating file
// access events against the agent's current policy. The handler
// captures a reference to the Agent and retrieves the latest policy
// on each call, so policy reloads take effect immediately.
type fanotifyHandler struct {
	agent *control.Agent
}

func (h *fanotifyHandler) HandleFileAccess(info fanotify.AccessInfo) (allow bool, ruleID string) {
	pol := h.agent.CurrentPolicy()
	subj := policy.Subject{
		ProcessName: info.Comm,
		ProcessPath: info.Exe,
		Cmdline:     info.Cmdline,
		User:        fmt.Sprintf("%d", info.UID),
	}
	obj := policy.Object{
		FilePath: info.Path,
		FileOp:   "open",
	}
	matches := pol.EvaluateAll(time.Now(), subj, obj)
	resp, _ := policy.AggregatedDecision(matches)
	if resp != nil && resp.Decision == "block" {
		return false, resp.ID
	}
	return true, ""
}

// fanotifyLogAdapter converts fanotify.Event to eventlog.Event and
// writes through the standard event logger.
type fanotifyLogAdapter struct {
	logger   *eventlog.Logger
	hostname string
}

func (a *fanotifyLogAdapter) Write(ev fanotify.Event) error {
	return a.logger.Write(eventlog.Event{
		EventID:  ev.EventID,
		Category: ev.Category,
		Severity: ev.Severity,
		Subject:  ev.Subject,
		Object:   ev.Object,
		Action:   ev.Action,
		Decision: ev.Decision,
		RuleID:   ev.RuleID,
		Host:     a.hostname,
	})
}

func prepareSocketPath(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink socket path %q", path)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %q", path)
	}
	return os.Remove(path)
}
