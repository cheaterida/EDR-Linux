// Package rootkit implements cross-source consistency checks that
// detect common Ring0 hiding techniques: DKOM hidden processes,
// hidden kernel modules, and (optionally) hidden network state.
//
// The detector does not rely on new eBPF probes for hidden-process
// detection; instead it compares the authoritative /proc view with
// the set of PIDs observed by the agent's BPF event stream. Any PID
// that BPF saw recently but no longer appears in /proc is flagged as
// a potential DKOM rootkit.
package rootkit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/response"
)

// Finding is a single rootkit indicator produced by the detector.
type Finding struct {
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	RuleID   string         `json:"rule_id"`
	Action   string         `json:"action"`
	Subject  map[string]any `json:"subject,omitempty"`
	Object   map[string]any `json:"object,omitempty"`
}

// Detector runs periodic cross-source consistency checks.
type Detector struct {
	Collector  *collector.MergedCollector
	Logger     *eventlog.Logger
	Responder  response.Responder
	ProcRoot   string
	SysRoot    string
	Interval   time.Duration
	Grace      time.Duration // allow recently-exited PIDs to leave /proc
	MinLifetime time.Duration
	MonitorOnly bool

	checks   uint64
	findings uint64
}

// NewDetector creates a detector with sensible defaults.
func NewDetector(c *collector.MergedCollector, l *eventlog.Logger, r response.Responder) *Detector {
	return &Detector{
		Collector:   c,
		Logger:      l,
		Responder:   r,
		ProcRoot:    "/proc",
		SysRoot:     "/sys",
		Interval:    30 * time.Second,
		Grace:       3 * time.Second,
		MinLifetime: 5 * time.Second,
		MonitorOnly: true,
	}
}

// RunOnce executes all enabled checks and returns the findings.
// It is safe to call from the agent's main loop or a dedicated goroutine.
func (d *Detector) RunOnce() ([]Finding, error) {
	var findings []Finding

	if hp, err := d.DetectHiddenProcesses(); err == nil {
		findings = append(findings, hp...)
	}
	if hm, err := d.DetectHiddenModules(); err == nil {
		findings = append(findings, hm...)
	}
	if hc, err := d.DetectHiddenConnections(); err == nil {
		findings = append(findings, hc...)
	}
	if si, err := d.CheckSyscallIntegrity(); err == nil {
		findings = append(findings, si...)
	}

	d.checks++
	d.findings += uint64(len(findings))
	return findings, nil
}

// DetectHiddenProcesses compares the current /proc enumeration with
// the set of PIDs observed by BPF events. A PID seen by BPF but
// missing from /proc is suspicious, but we require additional context
// to avoid flagging ordinary short-lived processes.
func (d *Detector) DetectHiddenProcesses() ([]Finding, error) {
	if d.Collector == nil {
		return nil, nil
	}

	seen := d.Collector.SeenPIDs()
	if len(seen) == 0 {
		return nil, nil
	}

	procPIDs, err := readProcPIDs(d.ProcRoot)
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().UTC().Add(-d.Grace)
	tree := d.Collector.ProcTree()
	var findings []Finding
	for pid, lastSeen := range seen {
		if lastSeen.Before(cutoff) {
			continue
		}
		if procPIDs[pid] {
			continue
		}
		if tree != nil {
			if node := tree.Get(pid); node != nil {
				if !node.ExitTime.IsZero() {
					continue
				}
				findings = append(findings, Finding{
					Type:     "hidden_process",
					Severity: "high",
					RuleID:   "ROOTKIT-002",
					Action:   "observe",
					Subject: map[string]any{
						"pid":         pid,
						"last_seen":   lastSeen.Format(time.RFC3339Nano),
						"proc_root":   d.ProcRoot,
						"start_ticks": node.StartTicks,
					},
					Object: map[string]any{
						"signal_set": "bpf_seen_missing_from_proc_no_exit",
					},
				})
				continue
			}
		}
		findings = append(findings, Finding{
			Type:     "hidden_process",
			Severity: "high",
			RuleID:   "ROOTKIT-002",
			Action:   "observe",
			Subject: map[string]any{
				"pid":       pid,
				"last_seen": lastSeen.Format(time.RFC3339Nano),
				"proc_root": d.ProcRoot,
			},
			Object: map[string]any{
				"signal_set": "bpf_seen_missing_from_proc",
			},
		})
	}
	return findings, nil
}

// DetectHiddenModules compares /sys/module (kernel's module sysfs)
// with /proc/modules (lsmod output). A module present in sysfs but
// absent from lsmod is a strong indicator of module hiding.
func (d *Detector) DetectHiddenModules() ([]Finding, error) {
	sysModules, err := readSysModules(d.SysRoot)
	if err != nil {
		return nil, err
	}
	procModules, err := readProcModules(d.ProcRoot)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for name := range sysModules {
		if procModules[name] {
			continue
		}
		findings = append(findings, Finding{
			Type:     "hidden_module",
			Severity: "critical",
			RuleID:   "ROOTKIT-004",
			Action:   "network_isolate",
			Object: map[string]any{
				"module":     name,
				"sys_root":   d.SysRoot,
				"proc_root":  d.ProcRoot,
			},
		})
	}
	return findings, nil
}

// Checks returns the number of detector runs performed.
func (d *Detector) Checks() uint64 { return d.checks }

// Findings returns the total number of findings produced.
func (d *Detector) Findings() uint64 { return d.findings }

func readProcPIDs(root string) (map[int]bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		out[pid] = true
	}
	return out, nil
}

func readSysModules(sysRoot string) (map[string]bool, error) {
	dir := filepath.Join(sysRoot, "module")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		modDir := filepath.Join(dir, name)
		// Built-in modules have a sysfs directory but no refcnt/initstate
		// files. Only modules loaded at runtime (including hidden ones)
		// have these attributes.
		if !hasModuleState(modDir) {
			continue
		}
		// Skip well-known built-in / pseudo modules that do not appear
		// in /proc/modules by design.
		if isBuiltinPseudoModule(name) {
			continue
		}
		out[name] = true
	}
	return out, nil
}

func hasModuleState(modDir string) bool {
	_, err1 := os.Stat(filepath.Join(modDir, "refcnt"))
	_, err2 := os.Stat(filepath.Join(modDir, "initstate"))
	return err1 == nil || err2 == nil
}

func readProcModules(procRoot string) (map[string]bool, error) {
	path := filepath.Join(procRoot, "modules")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = true
	}
	return out, sc.Err()
}

func isBuiltinPseudoModule(name string) bool {
	// Modules loaded before /proc/modules exists, or kernel internals
	// exposed via sysfs for ABI compatibility, are not rootkits.
	switch name {
	case "kernel", "block", "firmware", "fs", "net", "crypto",
		"drivers", "arch", "lib", "sound", "virt", "power":
		return true
	}
	return false
}

// Helper to build a human-readable summary from a list of findings.
func Summarize(findings []Finding) string {
	byType := map[string]int{}
	for _, f := range findings {
		byType[f.Type]++
	}
	parts := make([]string, 0, len(byType))
	for t, n := range byType {
		parts = append(parts, fmt.Sprintf("%s=%d", t, n))
	}
	return strings.Join(parts, " ")
}

// DetectHiddenConnections compares BPF-observed remote addresses
// (via MergedCollector.SeenAddrs) with /proc/net/tcp. A remote
// address seen by BPF but absent from /proc/net/tcp indicates a
// rootkit is hooking /proc/net/tcp to hide connections.
func (d *Detector) DetectHiddenConnections() ([]Finding, error) {
	if d.Collector == nil {
		return nil, nil
	}
	seen := d.Collector.SeenAddrs()
	if len(seen) == 0 {
		return nil, nil
	}

	procAddrs, err := readProcNetAddrs(d.ProcRoot)
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().UTC().Add(-d.Grace)
	var findings []Finding
	for addr, lastSeen := range seen {
		if lastSeen.Before(cutoff) {
			continue
		}
		if procAddrs[addr] {
			continue
		}
		findings = append(findings, Finding{
			Type:     "hidden_connection",
			Severity: "high",
			RuleID:   "ROOTKIT-006",
			Action:   "network_isolate",
			Object: map[string]any{
				"remote_addr": addr,
				"last_seen":   lastSeen.Format(time.RFC3339Nano),
				"signal_set":  "bpf_seen_missing_from_proc_net_tcp",
			},
		})
	}
	return findings, nil
}

// readProcNetAddrs returns the set of remote addresses currently
// visible in /proc/net/tcp and /proc/net/tcp6.
func readProcNetAddrs(procRoot string) (map[string]bool, error) {
	out := make(map[string]bool)
	for _, name := range []string{"tcp", "tcp6"} {
		path := filepath.Join(procRoot, "net", name)
		f, err := os.Open(path)
		if err != nil {
			continue // tcp6 may not exist
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue // skip header
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			// Format: sl local_address rem_address st ...
			// local_address = hexIP:hexPort, rem_address same format
			local := fields[1]
			remote := fields[2]
			// Extract addresses (strip port after last ':')
			if idx := strings.LastIndex(local, ":"); idx > 0 {
				out[hexToIP(local[:idx])] = true
			}
			if idx := strings.LastIndex(remote, ":"); idx > 0 {
				out[hexToIP(remote[:idx])] = true
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// hexToIP converts a hex-encoded IPv4 address (from /proc/net/tcp)
// to dotted-quad notation. Returns the original string if parsing fails.
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return hex
	}
	// /proc/net/tcp stores address in little-endian hex
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return hex
		}
		b[3-i] = byte(v) // little-endian → network byte order
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// CheckSyscallIntegrity reads /proc/kallsyms and verifies that key
// syscall function addresses fall within the kernel .text segment.
// Addresses outside _text.._etext indicate syscall table hooking
// or a compromised kallsyms output.
func (d *Detector) CheckSyscallIntegrity() ([]Finding, error) {
	kallsyms, err := os.ReadFile(filepath.Join(d.ProcRoot, "kallsyms"))
	if err != nil {
		return nil, err
	}

	var textStart, textEnd uint64
	syscallAddrs := map[string]uint64{}

	lines := strings.Split(string(kallsyms), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		// Type T = text (global), t = text (local)
		if fields[1] != "T" && fields[1] != "t" {
			continue
		}
		name := fields[2]

		switch name {
		case "_text":
			textStart = addr
		case "_etext":
			textEnd = addr
		case "__x64_sys_kill", "__x64_sys_ptrace",
			"__x64_sys_init_module", "__x64_sys_delete_module",
			"__x64_sys_openat", "__x64_sys_getdents64",
			"__x64_sys_process_vm_writev", "__x64_sys_bpf":
			syscallAddrs[name] = addr
		}
	}

	var findings []Finding
	if textStart == 0 || textEnd == 0 {
		findings = append(findings, Finding{
			Type:     "syscall_table_unverifiable",
			Severity: "high",
			RuleID:   "ROOTKIT-007",
			Action:   "observe",
			Object: map[string]any{
				"reason":     "kernel .text boundaries not found in kallsyms",
				"text_start": textStart,
				"text_end":   textEnd,
			},
		})
		return findings, nil
	}

	for name, addr := range syscallAddrs {
		if addr == 0 {
			continue // syscall not found (e.g. CONFIG option disabled)
		}
		if addr < textStart || addr > textEnd {
			findings = append(findings, Finding{
				Type:     "syscall_hooked",
				Severity: "critical",
				RuleID:   "ROOTKIT-007",
				Action:   "network_isolate",
				Object: map[string]any{
					"syscall":    name,
					"address":    fmt.Sprintf("0x%x", addr),
					"text_start": fmt.Sprintf("0x%x", textStart),
					"text_end":   fmt.Sprintf("0x%x", textEnd),
				},
			})
		}
	}
	return findings, nil
}
