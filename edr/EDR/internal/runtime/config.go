package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const DefaultIntegrityKeyPath = "/var/lib/edr/log.key"

type RetentionConfig struct {
	MaxBytes   int64 `json:"max_bytes"`
	MaxBackups int   `json:"max_backups"`
}

type FileWatchConfig struct {
	Mode  string   `json:"mode"`
	Paths []string `json:"paths"`
}

type NFTConfig struct {
	Enabled bool   `json:"enabled"`
	DryRun  bool   `json:"dry_run"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
}

type IntegrityConfig struct {
	EnableChain bool   `json:"enable_chain"`
	KeyPath     string `json:"key_path"`
	StatePath   string `json:"state_path"`
	Algorithm   string `json:"algorithm"`
}

type SuppressionConfig struct {
	ProcessCooldownSec int    `json:"process_cooldown_sec"`
	FileCooldownSec    int    `json:"file_cooldown_sec"`
	NetworkCooldownSec int    `json:"network_cooldown_sec"`
	RatePerSec         uint64 `json:"rate_per_sec"`
	Burst              uint64 `json:"burst"`
	StatePath          string `json:"state_path"`
}

type RootkitConfig struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"interval_sec"`
	MonitorOnly bool `json:"monitor_only"`
}

type BPFConfig struct {
	Enabled      bool   `json:"enabled"`
	ObjDir       string `json:"obj_dir"`
	RingbufPages int    `json:"ringbuf_pages"`
	RingbufPath  string `json:"ringbuf_path"`
}

type AnchorConfig struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`
	FilePath string `json:"file_path"`
	Interval int    `json:"interval_sec"`
}

type FanotifyConfig struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths"`
}

type QuarantineConfig struct {
	Dir    string `json:"dir"`
	DryRun bool   `json:"dry_run"`
}

type WebhookConfig struct {
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	TimeoutSec   int               `json:"timeout_sec,omitempty"`
	Format       string            `json:"format"`
	MinSeverity  string            `json:"min_severity,omitempty"`
	SharedSecret string            `json:"shared_secret,omitempty"`
}

type EmailAlertConfig struct {
	Enabled     bool     `json:"enabled"`
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	UseTLS      bool     `json:"use_tls"`
	MinSeverity string   `json:"min_severity"`
}

type SyslogRemoteConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Facility string `json:"facility,omitempty"`
}

type TransportConfig struct {
	SensorSocket       string `json:"sensor_socket"`
	OrchestratorSocket string `json:"orchestrator_socket"`
	EnforcerSocket     string `json:"enforcer_socket"`
	SharedSecret       string `json:"shared_secret"`
	EventPushEverySec  int    `json:"event_push_every_sec"`
}

type HAConfig struct {
	InstanceID         string   `json:"instance_id"`
	PeerInstanceID     string   `json:"peer_instance_id"`
	Priority           int      `json:"priority"`
	RunDir             string   `json:"run_dir"`
	HeartbeatEverySec  int      `json:"heartbeat_every_sec"`
	StartupGraceSec    int      `json:"startup_grace_sec"`
	SuspectAfter       int      `json:"suspect_after"`
	DownAfter          int      `json:"down_after"`
	LeaseTTLSec        int      `json:"lease_ttl_sec"`
	RestartCooldownSec int      `json:"restart_cooldown_sec"`
	RestartTimeoutSec  int      `json:"restart_timeout_sec"`
	RestartCommand     []string `json:"restart_command"`
}

type SupervisorConfig struct {
	Enabled             bool   `json:"enabled"`
	URL                 string `json:"url"`
	SharedSecret        string `json:"shared_secret"`
	HeartbeatEverySec   int    `json:"heartbeat_every_sec"`
	RequestTimeoutSec   int    `json:"request_timeout_sec"`
	TLSCertPath         string `json:"tls_cert_path"`
	TLSKeyPath          string `json:"tls_key_path"`
	TLSCAPath           string `json:"tls_ca_path"`
	TLSServerName       string `json:"tls_server_name"`
	RequireClientCert   bool   `json:"require_client_cert"`
	StatePath           string `json:"state_path"`
	EvidenceDir         string `json:"evidence_dir"`
	DecisionCooldownSec int    `json:"decision_cooldown_sec"`
	HostStaleAfterSec   int    `json:"host_stale_after_sec"`
	MaxDecisionHistory  int    `json:"max_decision_history"`
}

type RootSessionConfig struct {
	Mode            string   `json:"mode"`
	Secret          string   `json:"secret"`
	StatePath       string   `json:"state_path"`
	ScanEverySec    int      `json:"scan_every_sec"`
	ChallengeTTLSec int      `json:"challenge_ttl_sec"`
	GraceSec        int      `json:"grace_sec"`
	BypassToken     string   `json:"bypass_token"`
	BypassTTLSec    int      `json:"bypass_ttl_sec"`
	SystemNames     []string `json:"system_names"`
	ShellNames      []string `json:"shell_names"`
	ToolingNames    []string `json:"tooling_names"`
}

type Config struct {
	PolicyPath        string             `json:"policy_path"`
	BaselinePath      string             `json:"baseline_path"`
	EventPath         string             `json:"event_path"`
	ResponsePath      string             `json:"response_path"`
	ArtifactDir       string             `json:"artifact_dir"`
	SocketPath        string             `json:"socket_path"`
	IntervalSec       int                `json:"interval_sec"`
	Syslog            bool               `json:"syslog"`
	DryRun            bool               `json:"dry_run"`
	Retention         RetentionConfig    `json:"retention"`
	FileWatch         FileWatchConfig    `json:"file_watch"`
	NFT               NFTConfig          `json:"nft"`
	AllowedUIDs       []int              `json:"allowed_uids"`
	Integrity         IntegrityConfig    `json:"integrity"`
	Suppression       SuppressionConfig  `json:"suppression"`
	BPF               BPFConfig          `json:"bpf"`
	Fanotify          FanotifyConfig     `json:"fanotify"`
	Anchor            AnchorConfig       `json:"anchor"`
	SigningKeyPath    string             `json:"signing_key_path"`
	Quarantine        QuarantineConfig   `json:"quarantine"`
	Webhooks          []WebhookConfig    `json:"webhooks"`
	EmailAlerts       EmailAlertConfig   `json:"email_alerts"`
	SyslogRemote      SyslogRemoteConfig `json:"syslog_remote"`
	CriticalProcesses []string           `json:"critical_processes"`
	Rootkit           RootkitConfig      `json:"rootkit_detection"`
	Transport         TransportConfig    `json:"transport"`
	HA                HAConfig           `json:"ha"`
	Supervisor        SupervisorConfig   `json:"supervisor"`
	RootSession       RootSessionConfig  `json:"root_session"`
}

func DefaultConfig() Config {
	return Config{
		PolicyPath:        "configs/policy.json",
		BaselinePath:      "configs/baseline.json",
		EventPath:         "var/events.jsonl",
		ResponsePath:      "var/responses.jsonl",
		ArtifactDir:       "var/forensics",
		SocketPath:        "var/run/edr-agent.sock",
		IntervalSec:       1,
		DryRun:            true,
		Retention:         RetentionConfig{MaxBytes: 1048576, MaxBackups: 3},
		FileWatch:         FileWatchConfig{Mode: "inotify", Paths: []string{"configs", "/etc/ld.so.preload", "/etc/ld.so.conf.d", "/usr/lib", "/tmp", "/dev/shm", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/var/spool/cron", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system", "/root/.ssh", "/var/log"}},
		NFT:               NFTConfig{DryRun: true, Table: "edr", Chain: "blocklist"},
		AllowedUIDs:       []int{0},
		Integrity:         IntegrityConfig{EnableChain: true, KeyPath: DefaultIntegrityKeyPath, Algorithm: "sha256"},
		Suppression:       SuppressionConfig{ProcessCooldownSec: 30, FileCooldownSec: 60, NetworkCooldownSec: 30, RatePerSec: 10, Burst: 10, StatePath: "var/suppressor.json"},
		Fanotify:          FanotifyConfig{Enabled: true, Paths: []string{"/etc", "/tmp", "/dev/shm", "/var/spool/cron", "/usr/local/bin", "/usr/bin", "/usr/sbin", "/root/.ssh", "/home", "/etc/systemd/system", "/etc/cron.d", "/etc/cron.daily"}},
		Anchor:            AnchorConfig{Interval: 60},
		SigningKeyPath:    "/var/lib/edr/signing.key",
		Quarantine:        QuarantineConfig{Dir: "var/quarantine", DryRun: true},
		EmailAlerts:       EmailAlertConfig{SMTPPort: 587, UseTLS: true, MinSeverity: "high"},
		SyslogRemote:      SyslogRemoteConfig{Port: 514, Protocol: "udp", Facility: "daemon"},
		CriticalProcesses: []string{"sshd", "nginx", "mysqld", "apache2"},
		Rootkit:           RootkitConfig{Enabled: true, IntervalSec: 30, MonitorOnly: true},
		Transport: TransportConfig{
			SensorSocket:       "var/run/edr-sensor.sock",
			OrchestratorSocket: "var/run/edr-orchestrator.sock",
			EnforcerSocket:     "var/run/edr-enforcer.sock",
			SharedSecret:       "local-dev-secret",
			EventPushEverySec:  2,
		},
		HA: HAConfig{
			InstanceID:         "edr-a",
			PeerInstanceID:     "edr-b",
			Priority:           100,
			RunDir:             "/run/edr",
			HeartbeatEverySec:  1,
			StartupGraceSec:    5,
			SuspectAfter:       3,
			DownAfter:          5,
			LeaseTTLSec:        10,
			RestartCooldownSec: 30,
			RestartTimeoutSec:  15,
		},
		Supervisor: SupervisorConfig{
			Enabled:             true,
			HeartbeatEverySec:   5,
			RequestTimeoutSec:   10,
			StatePath:           "var/supervisor-state.json",
			EvidenceDir:         "var/supervisor-evidence",
			DecisionCooldownSec: 30,
			HostStaleAfterSec:   10,
			MaxDecisionHistory:  128,
		},
		RootSession: RootSessionConfig{
			Mode:            "audit",
			Secret:          "local-dev-secret",
			StatePath:       "var/root-session-state.json",
			ScanEverySec:    5,
			ChallengeTTLSec: 30,
			GraceSec:        30,
			BypassTTLSec:    300,
			SystemNames: []string{
				"systemd", "systemd-logind", "systemd-journald", "sshd", "cron", "crond",
				"dbus-daemon", "dbus-broker", "apt", "apt-get", "dpkg", "unattended-upgrade",
			},
			ShellNames:   []string{"bash", "sh", "dash", "zsh", "fish", "tmux", "screen"},
			ToolingNames: []string{"sudo", "su", "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "busybox"},
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	cfg.Normalize()
	return cfg, nil
}

func (c *Config) Normalize() {
	if c.Integrity.KeyPath == "" {
		c.Integrity.KeyPath = DefaultIntegrityKeyPath
	}
	if c.Transport.SensorSocket == "" {
		c.Transport.SensorSocket = "var/run/edr-sensor.sock"
	}
	if c.Transport.OrchestratorSocket == "" {
		c.Transport.OrchestratorSocket = "var/run/edr-orchestrator.sock"
	}
	if c.Transport.EnforcerSocket == "" {
		c.Transport.EnforcerSocket = "var/run/edr-enforcer.sock"
	}
	if c.Transport.EventPushEverySec <= 0 {
		c.Transport.EventPushEverySec = 2
	}
	if c.HA.InstanceID == "" {
		c.HA.InstanceID = "edr-a"
	}
	if c.HA.PeerInstanceID == "" {
		c.HA.PeerInstanceID = "edr-b"
	}
	if c.HA.RunDir == "" {
		c.HA.RunDir = "/run/edr"
	}
	if c.HA.HeartbeatEverySec <= 0 {
		c.HA.HeartbeatEverySec = 1
	}
	if c.HA.StartupGraceSec < 0 {
		c.HA.StartupGraceSec = 0
	}
	if c.HA.SuspectAfter <= 0 {
		c.HA.SuspectAfter = 3
	}
	if c.HA.DownAfter <= 0 {
		c.HA.DownAfter = 5
	}
	if c.HA.LeaseTTLSec <= 0 {
		c.HA.LeaseTTLSec = 10
	}
	if c.HA.RestartCooldownSec <= 0 {
		c.HA.RestartCooldownSec = 30
	}
	if c.HA.RestartTimeoutSec <= 0 {
		c.HA.RestartTimeoutSec = 15
	}
	if c.Supervisor.HeartbeatEverySec <= 0 {
		c.Supervisor.HeartbeatEverySec = 5
	}
	if c.Supervisor.RequestTimeoutSec <= 0 {
		c.Supervisor.RequestTimeoutSec = 10
	}
	if c.Supervisor.StatePath == "" {
		c.Supervisor.StatePath = "var/supervisor-state.json"
	}
	if c.Supervisor.EvidenceDir == "" {
		c.Supervisor.EvidenceDir = "var/supervisor-evidence"
	}
	if c.Supervisor.DecisionCooldownSec <= 0 {
		c.Supervisor.DecisionCooldownSec = 30
	}
	if c.Supervisor.HostStaleAfterSec <= 0 {
		c.Supervisor.HostStaleAfterSec = 10
	}
	if c.Supervisor.MaxDecisionHistory <= 0 {
		c.Supervisor.MaxDecisionHistory = 128
	}
	if c.RootSession.Mode == "" {
		c.RootSession.Mode = "audit"
	}
	if c.RootSession.StatePath == "" {
		c.RootSession.StatePath = "var/root-session-state.json"
	}
	if c.RootSession.ScanEverySec <= 0 {
		c.RootSession.ScanEverySec = 5
	}
	if c.RootSession.ChallengeTTLSec <= 0 {
		c.RootSession.ChallengeTTLSec = 30
	}
	if c.RootSession.GraceSec <= 0 {
		c.RootSession.GraceSec = 30
	}
	if c.RootSession.BypassTTLSec <= 0 {
		c.RootSession.BypassTTLSec = 300
	}
	if len(c.RootSession.SystemNames) == 0 {
		c.RootSession.SystemNames = []string{
			"systemd", "systemd-logind", "systemd-journald", "sshd", "cron", "crond",
			"dbus-daemon", "dbus-broker", "apt", "apt-get", "dpkg", "unattended-upgrade",
		}
	}
	if len(c.RootSession.ShellNames) == 0 {
		c.RootSession.ShellNames = []string{"bash", "sh", "dash", "zsh", "fish", "tmux", "screen"}
	}
	if len(c.RootSession.ToolingNames) == 0 {
		c.RootSession.ToolingNames = []string{"sudo", "su", "bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "busybox"}
	}
}

func ResolveRuntimePath(base, p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

func ResolveFromConfigPath(configPath, p string) string {
	base := filepath.Dir(configPath)
	return ResolveRuntimePath(base, p)
}

func ParseHexOrRawSecret(s string) []byte {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil
	}
	return []byte(trimmed)
}
