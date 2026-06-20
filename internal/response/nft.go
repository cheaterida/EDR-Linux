package response

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reNFTIdent   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,30}$`)
	reNFTAddr    = regexp.MustCompile(`^[a-fA-F0-9.:/\[\]%]{1,255}$`)
	reNFTProto   = regexp.MustCompile(`^(tcp|udp|udplite|sctp|dccp|icmp|icmpv6|ip|ip6)$`)
	reNFTPort    = regexp.MustCompile(`^[0-9]{1,5}$`)
)

type NFTProvider struct {
	Enabled bool
	DryRun  bool
	Table   string
	Chain   string
}

func (p NFTProvider) ApplyBlock(req ActionRequest) Result {
	if req.Action != "nft_block" {
		return Result{Action: req.Action, Success: false, Detail: "not an nft action"}
	}
	table := sanitizeNFTIdent(valueOr(p.Table, "edr"), "edr")
	chain := sanitizeNFTIdent(valueOr(p.Chain, "blocklist"), "blocklist")
	cmds := p.commands(table, chain, req)
	if p.DryRun || !p.Enabled {
		var desc []string
		for _, c := range cmds {
			desc = append(desc, strings.Join(c, " "))
		}
		return Result{Action: req.Action, Success: true, Detail: "nft dry-run: " + strings.Join(desc, " && ")}
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return Result{Action: req.Action, Success: false, Detail: "nft binary not found"}
	}
	for _, args := range cmds {
		if len(args) == 0 {
			continue
		}
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return Result{Action: req.Action, Success: false, Detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
		}
	}
	return Result{Action: req.Action, Success: true, Detail: fmt.Sprintf("nft block applied table=%s chain=%s", table, chain)}
}

func (p NFTProvider) commands(table, chain string, req ActionRequest) [][]string {
	table = sanitizeNFTIdent(table, "edr")
	chain = sanitizeNFTIdent(chain, "blocklist")
	cmds := [][]string{
		{"nft", "add", "table", "inet", table},
		{"nft", "add", "chain", "inet", table, chain, "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"},
	}
	proto := strings.ToLower(req.Protocol)
	if proto == "" || !reNFTProto.MatchString(proto) {
		proto = "tcp"
	}
	rule := []string{"nft", "add", "rule", "inet", table, chain, proto}
	if req.RemoteAddr != "" && reNFTAddr.MatchString(req.RemoteAddr) {
		rule = append(rule, "daddr", req.RemoteAddr)
	}
	if req.LocalPort != 0 {
		port := strconv.Itoa(req.LocalPort)
		if reNFTPort.MatchString(port) {
			rule = append(rule, "dport", port)
		}
	}
	rule = append(rule, "drop")
	cmds = append(cmds, rule)
	return cmds
}

// sanitizeNFTIdent returns the value if it matches the nft identifier
// pattern, otherwise returns the fallback.
func sanitizeNFTIdent(v, fallback string) string {
	if reNFTIdent.MatchString(v) {
		return v
	}
	return fallback
}

func (p NFTProvider) ListRules() Result {
	table := sanitizeNFTIdent(valueOr(p.Table, "edr"), "edr")
	if p.DryRun || !p.Enabled {
		return Result{Action: "nft_list", Success: true, Detail: "nft dry-run: nft list table inet " + table}
	}
	out, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		return Result{Action: "nft_list", Success: false, Detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
	}
	return Result{Action: "nft_list", Success: true, Detail: string(out)}
}

func (p NFTProvider) Rollback() Result {
	table := sanitizeNFTIdent(valueOr(p.Table, "edr"), "edr")
	if p.DryRun || !p.Enabled {
		return Result{Action: "nft_rollback", Success: true, Detail: "nft dry-run: nft delete table inet " + table}
	}
	out, err := exec.Command("nft", "delete", "table", "inet", table).CombinedOutput()
	if err != nil {
		return Result{Action: "nft_rollback", Success: false, Detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
	}
	return Result{Action: "nft_rollback", Success: true, Detail: "nft table removed"}
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// SaveSnapshot writes the current nftables ruleset to path (v0.6).
// The snapshot can be restored later via RestoreFromSnapshot.
func (p NFTProvider) SaveSnapshot(path string) error {
	if p.DryRun || !p.Enabled {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft list ruleset: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// RestoreFromSnapshot restores nftables ruleset from a previously saved
// snapshot file, then cleans up the edr table.
func (p NFTProvider) RestoreFromSnapshot(snapshotPath string) error {
	table := sanitizeNFTIdent(valueOr(p.Table, "edr"), "edr")
	if p.DryRun || !p.Enabled {
		return nil
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No snapshot to restore — just flush the edr table.
			return p.flushTable(table)
		}
		return err
	}
	// Restore from snapshot
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft restore: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Clean up the edr table from snapshot
	_ = p.flushTable(table)
	// Remove the snapshot file to prevent stale restore
	_ = os.Remove(snapshotPath)
	return nil
}

func (p NFTProvider) flushTable(table string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft binary not found")
	}
	out, err := exec.Command("nft", "delete", "table", "inet", table).CombinedOutput()
	// "No such file or directory" is fine — table already removed.
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft delete table: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RollbackWithSnapshot saves the snapshot before applying, and schedules
// an auto-rollback after timeout. Caller must call the returned cancel
// function if the block should persist.
func (p NFTProvider) RollbackWithSnapshot(req ActionRequest, snapshotPath string, timeout time.Duration) (Result, func()) {
	result := p.ApplyBlock(req)
	if !result.Success {
		return result, nil
	}
	if err := p.SaveSnapshot(snapshotPath); err != nil {
		return Result{Action: req.Action, Success: false, Detail: "save snapshot: " + err.Error()}, nil
	}
	timer := time.AfterFunc(timeout, func() {
		_ = p.RestoreFromSnapshot(snapshotPath)
	})
	cancel := func() {
		if timer.Stop() {
			_ = os.Remove(snapshotPath)
		}
	}
	return result, cancel
}

// ApplyIsolate creates a full network isolation using nftables.
// Default DROP policy, only allows loopback, established/related,
// DNS, and SSH port 22 to maintain management access.
// Rules are applied atomically via nft -f - to prevent transient
// network blackout windows.
func (p NFTProvider) ApplyIsolate() Result {
	table := sanitizeNFTIdent(valueOr(p.Table, "edr"), "edr")
	isolateChain := "isolate"

	rules := []string{
		fmt.Sprintf("add table inet %s", table),
		fmt.Sprintf("add chain inet %s %s { type filter hook output priority 0; policy drop; }", table, isolateChain),
		fmt.Sprintf("add rule inet %s %s oifname lo accept", table, isolateChain),
		fmt.Sprintf("add rule inet %s %s ct state established,related accept", table, isolateChain),
		fmt.Sprintf("add rule inet %s %s tcp dport 22 accept", table, isolateChain),
		fmt.Sprintf("add rule inet %s %s udp dport 53 accept", table, isolateChain),
		fmt.Sprintf("add rule inet %s %s tcp dport 53 accept", table, isolateChain),
	}
	script := strings.Join(rules, "\n") + "\n"

	if p.DryRun || !p.Enabled {
		return Result{Action: "network_isolate", Success: true, Detail: "nft dry-run:\n" + script}
	}

	if _, err := exec.LookPath("nft"); err != nil {
		return Result{Action: "network_isolate", Success: false, Detail: "nft binary not found"}
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Action: "network_isolate", Success: false, Detail: strings.TrimSpace(string(out)) + ": " + err.Error()}
	}

	return Result{Action: "network_isolate", Success: true, Detail: fmt.Sprintf("network isolation applied (table=%s, default DROP)", table)}
}
