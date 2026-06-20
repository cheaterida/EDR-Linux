package runtime

import "testing"

func TestDefaultConfigHASaneDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.HA.InstanceID != "edr-a" {
		t.Fatalf("instance_id = %q, want edr-a", cfg.HA.InstanceID)
	}
	if cfg.HA.PeerInstanceID != "edr-b" {
		t.Fatalf("peer_instance_id = %q, want edr-b", cfg.HA.PeerInstanceID)
	}
	if cfg.HA.RestartTimeoutSec <= 0 {
		t.Fatalf("restart_timeout_sec = %d, want > 0", cfg.HA.RestartTimeoutSec)
	}
	if cfg.HA.StartupGraceSec != 5 {
		t.Fatalf("startup_grace_sec = %d, want 5", cfg.HA.StartupGraceSec)
	}
	if cfg.RootSession.Mode != "audit" {
		t.Fatalf("root_session.mode = %q, want audit", cfg.RootSession.Mode)
	}
	if cfg.RootSession.Secret != "local-dev-secret" {
		t.Fatalf("root_session.secret = %q, want local-dev-secret", cfg.RootSession.Secret)
	}
	if cfg.RootSession.StatePath != "var/root-session-state.json" {
		t.Fatalf("root_session.state_path = %q, want var/root-session-state.json", cfg.RootSession.StatePath)
	}
	if cfg.RootSession.ChallengeTTLSec != 30 {
		t.Fatalf("root_session.challenge_ttl_sec = %d, want 30", cfg.RootSession.ChallengeTTLSec)
	}
}

func TestNormalizeFillsHAMissingValues(t *testing.T) {
	var cfg Config
	cfg.Normalize()
	if cfg.HA.InstanceID != "edr-a" {
		t.Fatalf("instance_id = %q, want edr-a", cfg.HA.InstanceID)
	}
	if cfg.HA.PeerInstanceID != "edr-b" {
		t.Fatalf("peer_instance_id = %q, want edr-b", cfg.HA.PeerInstanceID)
	}
	if cfg.HA.LeaseTTLSec != 10 {
		t.Fatalf("lease_ttl_sec = %d, want 10", cfg.HA.LeaseTTLSec)
	}
	if cfg.HA.RestartCooldownSec != 30 {
		t.Fatalf("restart_cooldown_sec = %d, want 30", cfg.HA.RestartCooldownSec)
	}
	if cfg.HA.RestartTimeoutSec != 15 {
		t.Fatalf("restart_timeout_sec = %d, want 15", cfg.HA.RestartTimeoutSec)
	}
	if cfg.HA.StartupGraceSec != 0 {
		t.Fatalf("startup_grace_sec = %d, want 0 default for zero-value config", cfg.HA.StartupGraceSec)
	}
	if cfg.RootSession.Mode != "audit" {
		t.Fatalf("root_session.mode = %q, want audit", cfg.RootSession.Mode)
	}
	if cfg.RootSession.StatePath != "var/root-session-state.json" {
		t.Fatalf("root_session.state_path = %q, want var/root-session-state.json", cfg.RootSession.StatePath)
	}
	if cfg.RootSession.BypassTTLSec != 300 {
		t.Fatalf("root_session.bypass_ttl_sec = %d, want 300", cfg.RootSession.BypassTTLSec)
	}
	if len(cfg.RootSession.SystemNames) == 0 || len(cfg.RootSession.ToolingNames) == 0 {
		t.Fatalf("expected default root session class lists, got %+v", cfg.RootSession)
	}
}
