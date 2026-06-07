package response

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
