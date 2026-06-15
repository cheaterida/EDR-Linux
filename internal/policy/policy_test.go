package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEvaluateWhitelistOverridesBlock(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r1", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{CmdlineContains: "curl http"}, Whitelist: []Match{{CmdlineContains: "apt"}}}}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rule, ok := p.Evaluate(time.Now(), Subject{Cmdline: "apt update curl http mirror"}, Object{})
	if !ok || rule.Decision != "allow" || rule.Action != "none" {
		t.Fatalf("expected allow override, got %#v ok=%v", rule, ok)
	}
}

func TestEvaluateNetworkRule(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "n1", Category: "network", Severity: "high", Decision: "alert", Action: "nft_block", Match: Match{Protocol: "tcp", LocalPort: 4444}}}}
	rule, ok := p.Evaluate(time.Now(), Subject{}, Object{Protocol: "TCP", LocalPort: 4444})
	if !ok || rule.ID != "n1" {
		t.Fatalf("expected n1, got %#v ok=%v", rule, ok)
	}
}

func TestProcessAccessBlacklistAndWhitelist(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, ProcessAccess: ProcessAccess{Mode: "enforce", Action: "kill", Severity: "high", Whitelist: []Match{{ProcessPath: "/usr/bin/python3", CmdlineContains: "app.py"}}, Blacklist: []Match{{ProcessPath: "/tmp/denied"}}}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rule, ok := p.EvaluateProcessAccess(Subject{ProcessName: "python3", ProcessPath: "/usr/bin/python3", Cmdline: "python3 app.py"})
	if !ok || rule.Decision != "allow" {
		t.Fatalf("expected whitelist allow, got %#v ok=%v", rule, ok)
	}
	rule, ok = p.EvaluateProcessAccess(Subject{ProcessName: "denied", ProcessPath: "/tmp/denied"})
	if !ok || rule.Decision != "block" || rule.Action != "kill" {
		t.Fatalf("expected blacklist block, got %#v ok=%v", rule, ok)
	}
	rule, ok = p.EvaluateProcessAccess(Subject{ProcessName: "unknown", ProcessPath: "/opt/unknown"})
	if !ok || rule.ID != "process-access-default-deny" {
		t.Fatalf("expected default deny, got %#v ok=%v", rule, ok)
	}
}

func TestEvaluateFileRule(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "f1", Category: "file", Severity: "medium", Decision: "block", Action: "fix_permissions", Match: Match{FilePathPrefix: "configs/"}}}}
	rule, ok := p.Evaluate(time.Now(), Subject{}, Object{FilePath: "configs/policy.json"})
	if !ok || rule.ID != "f1" || rule.Action != "fix_permissions" {
		t.Fatalf("expected file rule match, got %#v ok=%v", rule, ok)
	}
}

func TestEvaluateFileRuleByOp(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "fop", Category: "file", Severity: "medium", Decision: "block", Action: "fix_permissions", Match: Match{FilePathPrefix: "configs/", FileOp: "write"}}}}
	if _, ok := p.Evaluate(time.Now(), Subject{}, Object{FilePath: "configs/policy.json", FileOp: "create"}); ok {
		t.Fatal("did not expect create op to match write-only rule")
	}
	rule, ok := p.Evaluate(time.Now(), Subject{}, Object{FilePath: "configs/policy.json", FileOp: "write"})
	if !ok || rule.ID != "fop" {
		t.Fatalf("expected write op match, got %#v ok=%v", rule, ok)
	}
}

func TestPriorityOrderingOverridesFileOrder(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{
		{ID: "low", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{CmdlineContains: "x"}, Priority: 100},
		{ID: "high", Category: "process", Severity: "critical", Decision: "block", Action: "kill", Match: Match{CmdlineContains: "x"}, Priority: 10},
	}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rule, ok := p.Evaluate(time.Now(), Subject{Cmdline: "x"}, Object{})
	if !ok || rule.ID != "high" {
		t.Fatalf("expected high-priority rule first, got %s ok=%v", rule.ID, ok)
	}
}

func TestPriorityRejectsOutOfRange(t *testing.T) {
	for _, prio := range []int{-1, 9999} {
		p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Priority: prio}}}
		if _, err := p.Validate(); err == nil {
			t.Fatalf("expected error for priority %d", prio)
		}
	}
}

func TestEvaluateAllReturnsAllMatches(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{
		{ID: "a", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{CmdlineContains: "x"}, Priority: 200},
		{ID: "b", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{CmdlineContains: "x"}, Priority: 50},
		{ID: "c", Category: "process", Severity: "medium", Decision: "alert", Action: "none", Match: Match{CmdlineContains: "y"}, Priority: 100},
	}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	matches := p.EvaluateAll(time.Now(), Subject{Cmdline: "x"}, Object{})
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].ID != "b" || matches[1].ID != "a" {
		t.Fatalf("expected [b a] in priority order, got [%s %s]", matches[0].ID, matches[1].ID)
	}
}

func TestEvaluateAllWhitelistOverrideKeptInResult(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{CmdlineContains: "curl"}, Whitelist: []Match{{CmdlineContains: "apt"}}}}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	matches := p.EvaluateAll(time.Now(), Subject{Cmdline: "apt update curl x"}, Object{})
	if len(matches) != 1 || matches[0].Decision != "allow" {
		t.Fatalf("expected allow-override match, got %+v", matches)
	}
}

func TestAggregatedDecisionAuditOnly(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{
		{ID: "audit-only", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Effect: []string{EffectAudit}},
	}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	matches := p.EvaluateAll(time.Now(), Subject{ProcessName: "x"}, Object{})
	resp, audit := AggregatedDecision(matches)
	if resp != nil {
		t.Fatalf("audit-only rule must not yield response, got %+v", resp)
	}
	if len(audit) != 1 || audit[0].ID != "audit-only" {
		t.Fatalf("expected audit-only, got %+v", audit)
	}
}

func TestAggregatedDecisionResponseOnly(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{
		{ID: "silent-kill", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{ProcessName: "x"}, Effect: []string{EffectResponse}},
	}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	matches := p.EvaluateAll(time.Now(), Subject{ProcessName: "x"}, Object{})
	resp, audit := AggregatedDecision(matches)
	if resp == nil || resp.ID != "silent-kill" {
		t.Fatalf("expected silent-kill as response, got %+v", resp)
	}
	if len(audit) != 0 {
		t.Fatalf("response-only rule must not produce audit events, got %+v", audit)
	}
}

func TestAggregatedDecisionAuditAndResponseSeparated(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{
		{ID: "audit-base", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Priority: 200, Effect: []string{EffectAudit}},
		{ID: "respond-top", Category: "process", Severity: "critical", Decision: "block", Action: "kill", Match: Match{ProcessName: "x"}, Priority: 10, Effect: []string{EffectResponse}},
	}}
	if _, err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	matches := p.EvaluateAll(time.Now(), Subject{ProcessName: "x"}, Object{})
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	resp, audit := AggregatedDecision(matches)
	if resp == nil || resp.ID != "respond-top" {
		t.Fatalf("expected respond-top as response, got %+v", resp)
	}
	if len(audit) != 1 || audit[0].ID != "audit-base" {
		t.Fatalf("expected audit-base as audit, got %+v", audit)
	}
}

func TestEffectValidation(t *testing.T) {
	for _, eff := range [][]string{{"bogus"}, {EffectAudit, "nope"}} {
		p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Effect: eff}}}
		if _, err := p.Validate(); err == nil {
			t.Fatalf("expected error for effect %v", eff)
		}
	}
	// Empty effect is valid and means "both".
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}}}}
	if _, err := p.Validate(); err != nil {
		t.Fatalf("empty effect should be valid: %v", err)
	}
}

func TestEvaluateAllowDoesNotBecomeResponse(t *testing.T) {
	p := Policy{SchemaVersion: SchemaVersion, Rules: []Rule{{ID: "r", Category: "process", Severity: "low", Decision: "allow", Action: "none", Match: Match{ProcessName: "x"}}}}
	matches := p.EvaluateAll(time.Now(), Subject{ProcessName: "x"}, Object{})
	resp, audit := AggregatedDecision(matches)
	if resp != nil {
		t.Fatalf("allow-decision rule must never be a response, got %+v", resp)
	}
	if len(audit) != 1 {
		t.Fatalf("allow rule should still audit, got %+v", audit)
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	// Create a file larger than maxPolicyBytes
	big := make([]byte, maxPolicyBytes+1024)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected 'exceeds' in error, got: %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.json")
	data := []byte(`{"schema_version":"v0.1","rules":[],"bogus_field":true}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidateRejectsAlwaysTrueTimeWindow(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{{
			ID: "r1", Category: "process", Severity: "low", Decision: "alert", Action: "log",
			Match:      Match{ProcessName: "x"},
			TimeWindow: &TimeWindow{Start: "00:00", End: "23:59"},
		}},
	}
	_, err := p.Validate()
	if err == nil {
		t.Fatal("expected error for always-true time window")
	}
	if !strings.Contains(err.Error(), "always-true") {
		t.Fatalf("error should mention always-true, got: %v", err)
	}
}

func TestValidateRejectsZeroLengthTimeWindow(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{{
			ID: "r1", Category: "process", Severity: "low", Decision: "alert", Action: "log",
			Match:      Match{ProcessName: "x"},
			TimeWindow: &TimeWindow{Start: "12:00", End: "12:00"},
		}},
	}
	_, err := p.Validate()
	if err == nil {
		t.Fatal("expected error for zero-length time window")
	}
	if !strings.Contains(err.Error(), "zero length") {
		t.Fatalf("error should mention zero length, got: %v", err)
	}
}

func TestValidateRejectsIllegalDecisionAction(t *testing.T) {
	tests := []struct {
		name     string
		decision string
		action   string
	}{
		{"allow with kill", "allow", "kill"},
		{"allow with log", "allow", "log"},
		{"allow with quarantine", "allow", "quarantine"},
		{"alert with kill", "alert", "kill"},
		{"alert with quarantine", "alert", "quarantine"},
		{"block with none", "block", "none"},
		{"block with log", "block", "log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{
				SchemaVersion: SchemaVersion,
				Rules: []Rule{{
					ID: "r1", Category: "process", Severity: "low",
					Decision: tt.decision, Action: tt.action,
					Match: Match{ProcessName: "x"},
				}},
			}
			_, err := p.Validate()
			if err == nil {
				t.Fatalf("expected error for decision=%s action=%s", tt.decision, tt.action)
			}
		})
	}
}

func TestValidateAllowsValidDecisionAction(t *testing.T) {
	tests := []struct {
		name     string
		decision string
		action   string
	}{
		{"allow with none", "allow", "none"},
		{"alert with none", "alert", "none"},
		{"alert with log", "alert", "log"},
		{"block with kill", "block", "kill"},
		{"block with fix_permissions", "block", "fix_permissions"},
		{"block with nft_block", "block", "nft_block"},
		{"block with quarantine", "block", "quarantine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{
				SchemaVersion: SchemaVersion,
				Rules: []Rule{{
					ID: "r1", Category: "process", Severity: "low",
					Decision: tt.decision, Action: tt.action,
					Match: Match{ProcessName: "x"},
				}},
			}
			_, err := p.Validate()
			if err != nil {
				t.Fatalf("unexpected error for decision=%s action=%s: %v", tt.decision, tt.action, err)
			}
		})
	}
}

func TestValidateWarnsPriorityTieBreaker(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{
			{ID: "a", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Priority: 50},
			{ID: "b", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{ProcessName: "y"}, Priority: 50},
		},
	}
	warnings, err := p.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "priority 50 is shared") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected priority tie-breaker warning, got: %v", warnings)
	}
}

func TestValidateNoWarningForUniquePriority(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{
			{ID: "a", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}, Priority: 50},
			{ID: "b", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{ProcessName: "y"}, Priority: 100},
		},
	}
	warnings, err := p.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for unique priorities, got: %v", warnings)
	}
}

func TestValidateNoWarningForDefaultPriority(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{
			{ID: "a", Category: "process", Severity: "low", Decision: "alert", Action: "none", Match: Match{ProcessName: "x"}},
			{ID: "b", Category: "process", Severity: "high", Decision: "block", Action: "kill", Match: Match{ProcessName: "y"}},
		},
	}
	warnings, err := p.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for default priority, got: %v", warnings)
	}
}
