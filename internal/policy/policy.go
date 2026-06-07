package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "v0.1"

const maxPolicyBytes = 1 << 20 // 1 MiB

type Policy struct {
	SchemaVersion  string         `json:"schema_version"`
	ProcessAccess  ProcessAccess  `json:"process_access,omitempty"`
	SelfProtection SelfProtection `json:"self_protection,omitempty"`
	Rules          []Rule         `json:"rules"`
}

// SelfProtection configures the ring0 agent self-protection kprobes.
type SelfProtection struct {
	Enabled         bool   `json:"enabled"`
	AuditSeverity   string `json:"audit_severity"`
	EnforceMode     string `json:"enforce_mode,omitempty"`     // "kill" = kill attacker on self-protect event
	ShutdownEnabled bool   `json:"shutdown_enabled,omitempty"` // allow root-login controlled shutdown endpoint
}

type ProcessAccess struct {
	Mode      string  `json:"mode"`
	Whitelist []Match `json:"whitelist,omitempty"`
	Blacklist []Match `json:"blacklist,omitempty"`
	Action    string  `json:"action"`
	Severity  string  `json:"severity"`
}

type Rule struct {
	ID          string      `json:"id"`
	Description string      `json:"description,omitempty"`
	Enabled     *bool       `json:"enabled,omitempty"`
	Category    string      `json:"category"`
	Severity    string      `json:"severity"`
	Decision    string      `json:"decision"`
	Action      string      `json:"action"`
	Match       Match       `json:"match"`
	TimeWindow  *TimeWindow `json:"time_window,omitempty"`
	Whitelist   []Match     `json:"whitelist,omitempty"`
	Priority    int         `json:"priority,omitempty"`
	Effect      []string    `json:"effect,omitempty"`
}

// Defaults for v0.15 priority and effect fields. Lower priority value
// means higher precedence. The values are chosen so an old v0.1 rule
// file (with no priority/effect) behaves identically to the previous
// engine.
const (
	DefaultPriority  = 100
	MinPriority      = 0
	MaxPriority      = 1000
	EffectAudit      = "audit"
	EffectResponse   = "response"
	defaultEffectCSV = EffectAudit + "," + EffectResponse
)

// EffectivePriority returns the rule's priority, defaulting to
// DefaultPriority for rules that omit the field. Callers should use
// this rather than reading Priority directly when computing order.
func (r Rule) EffectivePriority() int {
	if r.Priority == 0 {
		return DefaultPriority
	}
	return r.Priority
}

// EffectiveEffect returns the rule's effect, defaulting to
// {audit, response} when the field is empty.
func (r Rule) EffectiveEffect() []string {
	if len(r.Effect) == 0 {
		return []string{EffectAudit, EffectResponse}
	}
	return r.Effect
}

// HasEffect reports whether the rule's effect set contains name.
func (r Rule) HasEffect(name string) bool {
	for _, e := range r.EffectiveEffect() {
		if e == name {
			return true
		}
	}
	return false
}

type Match struct {
	ProcessName     string `json:"process_name,omitempty"`
	ProcessPath     string `json:"process_path,omitempty"`
	CmdlineContains string `json:"cmdline_contains,omitempty"`
	User            string `json:"user,omitempty"`
	FilePath        string `json:"file_path,omitempty"`
	FilePathPrefix  string `json:"file_path_prefix,omitempty"`
	FileOp          string `json:"file_op,omitempty"`
	RemoteAddr      string `json:"remote_addr,omitempty"`
	LocalPort       int    `json:"local_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	// v0.4 anti-attack matchers
	EnvContains     string `json:"env_contains,omitempty"`      // substring match on environ vars
	MapsContains    string `json:"maps_contains,omitempty"`     // substring match on /proc/pid/maps
	PtraceSelfCheck *bool  `json:"ptrace_self_check,omitempty"` // true = process uses ptrace self-check
}

type TimeWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type Subject struct {
	ProcessName     string `json:"process_name,omitempty"`
	ProcessPath     string `json:"process_path,omitempty"`
	Cmdline         string `json:"cmdline,omitempty"`
	User            string `json:"user,omitempty"`
	Environ         string `json:"environ,omitempty"`           // raw environ string for env_contains matching
	MapsLibs        string `json:"maps_libs,omitempty"`         // /proc/pid/maps content for maps_contains matching
	PtraceSelfCheck bool   `json:"ptrace_self_check,omitempty"` // process detected doing ptrace self-check
}

type Object struct {
	FilePath   string `json:"file_path,omitempty"`
	FileOp     string `json:"file_op,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxPolicyBytes {
		return nil, fmt.Errorf("policy file size %d exceeds limit of %d bytes", fi.Size(), maxPolicyBytes)
	}

	dec := json.NewDecoder(io.LimitReader(f, maxPolicyBytes+1))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}

	warnings, err := p.Validate()
	_ = warnings
	return &p, err
}

func (p Policy) Validate() (warnings []string, err error) {
	if p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported schema_version %q", p.SchemaVersion)
	}
	if err := p.ProcessAccess.Validate(); err != nil {
		return nil, err
	}
	if p.SelfProtection.Enabled {
		if p.SelfProtection.AuditSeverity != "" && !oneOf(p.SelfProtection.AuditSeverity, "low", "medium", "high", "critical") {
			return nil, fmt.Errorf("self_protection.audit_severity is invalid")
		}
		if p.SelfProtection.EnforceMode != "" && !oneOf(p.SelfProtection.EnforceMode, "kill") {
			return nil, fmt.Errorf("self_protection.enforce_mode must be 'kill' or empty")
		}
	}
	seen := map[string]bool{}
	prioCount := map[int]int{}
	for i, r := range p.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("rules[%d].id is required", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if !oneOf(r.Category, "process", "file", "network") {
			return nil, fmt.Errorf("rule %s has invalid category %q", r.ID, r.Category)
		}
		if !oneOf(r.Decision, "allow", "alert", "block") {
			return nil, fmt.Errorf("rule %s has invalid decision %q", r.ID, r.Decision)
		}
		if !oneOf(r.Action, "none", "kill", "quarantine", "fix_permissions", "nft_block", "log", "fanotify_deny") {
			return nil, fmt.Errorf("rule %s has invalid action %q", r.ID, r.Action)
		}

		// Decision-action matrix validation
		switch r.Decision {
		case "allow":
			if r.Action != "none" {
				return nil, fmt.Errorf("rule %s: decision=allow requires action=none, got %q", r.ID, r.Action)
			}
		case "alert":
			if !oneOf(r.Action, "none", "log") {
				return nil, fmt.Errorf("rule %s: decision=alert requires action=none or log, got %q", r.ID, r.Action)
			}
		case "block":
			if !oneOf(r.Action, "kill", "fix_permissions", "nft_block", "quarantine", "fanotify_deny") {
				return nil, fmt.Errorf("rule %s: decision=block requires action in {kill, fix_permissions, nft_block, quarantine}, got %q", r.ID, r.Action)
			}
		}

		if r.TimeWindow != nil {
			if _, err := parseClock(r.TimeWindow.Start); err != nil {
				return nil, fmt.Errorf("rule %s invalid time_window.start: %w", r.ID, err)
			}
			if _, err := parseClock(r.TimeWindow.End); err != nil {
				return nil, fmt.Errorf("rule %s invalid time_window.end: %w", r.ID, err)
			}
			if r.TimeWindow.Start == "00:00" && r.TimeWindow.End == "23:59" {
				return nil, fmt.Errorf("rule %s: time_window start=00:00 end=23:59 is always-true and not allowed", r.ID)
			}
			if r.TimeWindow.Start == r.TimeWindow.End {
				return nil, fmt.Errorf("rule %s: time_window has zero length (start == end == %s)", r.ID, r.TimeWindow.Start)
			}
		}
		if r.Priority < 0 || r.Priority > MaxPriority {
			return nil, fmt.Errorf("rule %s priority %d out of range [%d,%d]", r.ID, r.Priority, MinPriority, MaxPriority)
		}
		for _, e := range r.Effect {
			if !oneOf(e, EffectAudit, EffectResponse) {
				return nil, fmt.Errorf("rule %s has invalid effect %q (want %s or %s)", r.ID, e, EffectAudit, EffectResponse)
			}
		}

		if r.EffectivePriority() != DefaultPriority {
			prioCount[r.EffectivePriority()]++
		}
	}

	for pri, count := range prioCount {
		if count > 1 {
			warnings = append(warnings, fmt.Sprintf("priority %d is shared by %d rules; tie-breaking relies on original rule order", pri, count))
		}
	}

	return warnings, nil
}

func (pa ProcessAccess) Validate() error {
	if pa.Mode == "" && len(pa.Whitelist) == 0 && len(pa.Blacklist) == 0 {
		return nil
	}
	if !oneOf(pa.Mode, "monitor", "enforce") {
		return fmt.Errorf("process_access.mode must be monitor or enforce")
	}
	if pa.Action == "" {
		pa.Action = "kill"
	}
	if !oneOf(pa.Action, "none", "kill") {
		return fmt.Errorf("process_access.action must be none or kill")
	}
	if pa.Severity != "" && !oneOf(pa.Severity, "low", "medium", "high", "critical") {
		return fmt.Errorf("process_access.severity is invalid")
	}
	return nil
}

func (p Policy) EvaluateProcessAccess(subj Subject) (Rule, bool) {
	pa := p.ProcessAccess
	if pa.Mode == "" && len(pa.Whitelist) == 0 && len(pa.Blacklist) == 0 {
		return Rule{}, false
	}
	for _, wl := range pa.Whitelist {
		if matches(wl, subj, Object{}) {
			return Rule{ID: "process-access-whitelist", Category: "process", Severity: severityOr(pa.Severity, "low"), Decision: "allow", Action: "none", Match: wl}, true
		}
	}
	for _, bl := range pa.Blacklist {
		if matches(bl, subj, Object{}) {
			return Rule{ID: "process-access-blacklist", Category: "process", Severity: severityOr(pa.Severity, "high"), Decision: decisionFor(pa.Mode), Action: actionFor(pa.Mode, pa.Action), Match: bl}, true
		}
	}
	if pa.Mode == "enforce" && len(pa.Whitelist) > 0 {
		return Rule{ID: "process-access-default-deny", Category: "process", Severity: severityOr(pa.Severity, "high"), Decision: "block", Action: actionFor(pa.Mode, pa.Action)}, true
	}
	return Rule{}, false
}

func (p Policy) Evaluate(now time.Time, subj Subject, obj Object) (Rule, bool) {
	for _, r := range p.evaluateAll(now, subj, obj) {
		return r, true
	}
	return Rule{}, false
}

// EvaluateAll returns every rule that matches now/subj/obj, sorted by
// ascending priority. Within the same priority the original rule
// order is preserved (stable sort). A rule that is overridden by its
// own Whitelist is still returned, with Decision and Action rewritten
// to "allow"/"none" — callers that need to suppress it must inspect
// the Decision.
//
// The function is the workhorse of the v0.15 multi-hit pipeline: it
// feeds AggregatedDecision, which then splits the matches into audit
// events and a single response action.
func (p Policy) EvaluateAll(now time.Time, subj Subject, obj Object) []Rule {
	return p.evaluateAll(now, subj, obj)
}

func (p Policy) evaluateAll(now time.Time, subj Subject, obj Object) []Rule {
	ordered := make([]Rule, len(p.Rules))
	copy(ordered, p.Rules)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].EffectivePriority() < ordered[j].EffectivePriority()
	})
	var out []Rule
	for _, r := range ordered {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		if !inWindow(now, r.TimeWindow) {
			continue
		}
		if !matches(r.Match, subj, obj) {
			continue
		}
		candidate := r
		for _, wl := range r.Whitelist {
			if matches(wl, subj, obj) {
				candidate.Decision = "allow"
				candidate.Action = "none"
				break
			}
		}
		out = append(out, candidate)
	}
	return out
}

// AggregatedDecision splits a slice of matching rules (typically the
// output of EvaluateAll) into the audit and response pipelines:
//
//   - ResponseRule: the highest-priority rule whose Effect contains
//     "response" and whose Decision is "block" or "alert" with a
//     non-"none" Action. nil if no such rule exists.
//   - AuditRules: every rule whose Effect contains "audit", in the
//     same order they came in. Allow-overridden rules are still
//     included — the override is itself useful evidence.
//
// The function is pure: it never reads global state and never
// mutates the input slice.
func AggregatedDecision(matches []Rule) (response *Rule, audit []Rule) {
	for i := range matches {
		r := &matches[i]
		if r.HasEffect(EffectAudit) {
			audit = append(audit, *r)
		}
		if response == nil && r.HasEffect(EffectResponse) && r.Decision != "allow" && r.Action != "none" {
			response = r
		}
	}
	return response, audit
}

func Save(path string, p Policy) error {
	if _, err := p.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o640)
}

func matches(m Match, subj Subject, obj Object) bool {
	if m.ProcessName != "" && !strings.EqualFold(m.ProcessName, subj.ProcessName) {
		return false
	}
	if m.ProcessPath != "" && m.ProcessPath != subj.ProcessPath {
		return false
	}
	if m.CmdlineContains != "" && !strings.Contains(subj.Cmdline, m.CmdlineContains) {
		return false
	}
	if m.User != "" && m.User != subj.User {
		return false
	}
	if m.FilePath != "" && m.FilePath != obj.FilePath {
		return false
	}
	if m.FilePathPrefix != "" && !strings.HasPrefix(obj.FilePath, m.FilePathPrefix) {
		return false
	}
	if m.FileOp != "" && !strings.EqualFold(m.FileOp, obj.FileOp) {
		return false
	}
	if m.RemoteAddr != "" && m.RemoteAddr != obj.RemoteAddr {
		return false
	}
	if m.LocalPort != 0 && m.LocalPort != obj.LocalPort {
		return false
	}
	if m.Protocol != "" && !strings.EqualFold(m.Protocol, obj.Protocol) {
		return false
	}
	// v0.4 anti-attack matchers
	if m.EnvContains != "" && !strings.Contains(subj.Environ, m.EnvContains) {
		return false
	}
	if m.MapsContains != "" && !strings.Contains(subj.MapsLibs, m.MapsContains) {
		return false
	}
	if m.PtraceSelfCheck != nil && *m.PtraceSelfCheck != subj.PtraceSelfCheck {
		return false
	}
	return true
}

func inWindow(now time.Time, tw *TimeWindow) bool {
	if tw == nil {
		return true
	}
	start, err := parseClock(tw.Start)
	end, err := parseClock(tw.End)
	if err != nil {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		return cur >= start && cur <= end
	}
	return cur >= start || cur <= end
}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

func decisionFor(mode string) string {
	if mode == "enforce" {
		return "block"
	}
	return "alert"
}

func actionFor(mode, action string) string {
	if mode != "enforce" || action == "" {
		return "none"
	}
	return action
}

func severityOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
