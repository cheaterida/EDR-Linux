package control

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"edr/internal/baseline"
	"edr/internal/eventlog"
	"edr/internal/integrity"
	"edr/internal/metrics"
	"edr/internal/policy"
	"edr/internal/response"
	"edr/internal/adminauth"
	"edr/internal/transport"
)

type ServerOptions struct {
	BaselinePath           string
	PolicyPath             string
	EventPath              string
	ArtifactDir            string
	AllowedUIDs            []int
	IntegrityKey           []byte
	IngestKey              []byte
	SigningKeyPath         string
	AdminKey               []byte
	Anchor                 *eventlog.Anchor
	Shutdown               func()
	Restart                 func()
	WebhookTestFn          func() error
	MetricsWriter          func(io.Writer)
	HAStatus               func() (any, error)
	RootSessionStatus      func() (any, error)
	RootSessionChallenge   func(int) (any, error)
	RootSessionRespond     func(map[string]any) (any, error)
	RootSessionBypass      func(string, time.Duration) (any, error)
	RootSessionClearBypass func() (any, error)
}

const (
	defaultEventLimit = 50
	maxEventLimit     = 1000
)

func NewServer(agent *Agent, baselinePath string) http.Handler {
	return NewServerWithOptions(agent, ServerOptions{BaselinePath: baselinePath})
}

func NewServerWithOptions(agent *Agent, opts ServerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		writeJSON(w, map[string]any{"ok": true, "schema_version": "v0.1", "suppressor_state": agent.Suppressor.Snapshot()})
	})
	mux.HandleFunc("/v0/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		writeJSON(w, agent.Metrics())
	})
	mux.HandleFunc("/v0/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		pol := agent.CurrentPolicy()
		ring0 := "disabled"
		if h := agent.BPFHealth(); h.Attached {
			ring0 = "active"
		}
		connTracker := "active"
		connCount := countActiveConns()
		if connCount == 0 {
			connTracker = "idle"
		}
		procTreeNodes := 0
		if pt := agent.ProcTree(); pt != nil {
			procTreeNodes = pt.Size()
		}
		recentBlocks := 0
		for _, rec := range agent.ResponseHistory(200) {
			switch rec.Result.Action {
			case "kill", "kill_tree", "block", "deny", "quarantine", "isolate":
				recentBlocks++
			}
		}
		rootkitChecks := uint64(0)
		rootkitFindings := uint64(0)
		rootkitMode := "disabled"
		if agent.RootkitDetector != nil {
			rootkitMode = "monitor"
			if !agent.RootkitDetector.MonitorOnly {
				rootkitMode = "enforce"
			}
			rootkitChecks = agent.RootkitDetector.Checks()
			rootkitFindings = agent.RootkitDetector.Findings()
		}
		writeJSON(w, map[string]any{
			"policy_rules":       len(pol.Rules),
			"process_access":     pol.ProcessAccess.Mode != "",
			"collector":          "procfs",
			"ring0":              ring0,
			"response_history":   len(agent.ResponseHistory(0)),
			"proc_tree_nodes":    procTreeNodes,
			"conn_tracker":       connTracker,
			"active_connections": connCount,
			"recent_blocks":      recentBlocks,
			"rootkit_mode":       rootkitMode,
			"rootkit_checks":     rootkitChecks,
			"rootkit_findings":   rootkitFindings,
		})
	})
	mux.HandleFunc("/v0/ha/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if opts.HAStatus == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "ha status not available"})
			return
		}
		status, err := opts.HAStatus()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, status)
	})
	mux.HandleFunc("/v0/root-sessions/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if opts.RootSessionStatus == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "root session status not available"})
			return
		}
		status, err := opts.RootSessionStatus()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, status)
	})
	mux.HandleFunc("/v0/root-sessions/challenge", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.RootSessionChallenge == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "root session challenge not available"})
			return
		}
		var req struct {
			PID int `json:"pid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.PID <= 0 {
			http.Error(w, "pid must be > 0", http.StatusBadRequest)
			return
		}
		resp, err := opts.RootSessionChallenge(req.PID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/root-sessions/respond", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.RootSessionRespond == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "root session response not available"})
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := opts.RootSessionRespond(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/root-sessions/bypass", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.RootSessionBypass == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "root session bypass not available"})
			return
		}
		var req struct {
			Token  string `json:"token"`
			TTLSec int    `json:"ttl_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := opts.RootSessionBypass(req.Token, time.Duration(req.TTLSec)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/root-sessions/bypass/clear", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.RootSessionClearBypass == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "root session bypass clear not available"})
			return
		}
		resp, err := opts.RootSessionClearBypass()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/policy/reload", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := opts.PolicyPath
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(filepath.Dir(opts.PolicyPath), override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			path = safePath
		}
		if path == "" {
			http.Error(w, "policy path is required", http.StatusBadRequest)
			return
		}
		if opts.PolicyPath != "" {
			_ = BackupPolicy(opts.PolicyPath)
		}
		pol, err := policy.Load(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := VerifyPolicySig(path, opts.SigningKeyPath); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		agent.ReplacePolicy(pol)
		writeJSON(w, map[string]any{"ok": true, "policy_path": path, "policy_rules": len(pol.Rules), "process_access": pol.ProcessAccess.Mode})
	})
	mux.HandleFunc("/v0/policy/versions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		versions, err := ListPolicyVersions(opts.PolicyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"versions": versions})
	})
	mux.HandleFunc("/v0/policy/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		version := r.URL.Query().Get("version")
		path, err := RollbackPolicyFile(opts.PolicyPath, version)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pol, err := policy.Load(opts.PolicyPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := VerifyPolicySig(opts.PolicyPath, opts.SigningKeyPath); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		agent.ReplacePolicy(pol)
		writeJSON(w, map[string]any{"ok": true, "restored_from": path, "policy_rules": len(pol.Rules)})
	})
	mux.HandleFunc("/v0/policy/verify-signature", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := opts.PolicyPath
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(filepath.Dir(opts.PolicyPath), override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			path = safePath
		}
		if path == "" {
			http.Error(w, "policy path is required", http.StatusBadRequest)
			return
		}
		if opts.SigningKeyPath == "" {
			writeJSON(w, map[string]any{"ok": false, "detail": "signing key is not configured"})
			return
		}
		if err := VerifyPolicySig(path, opts.SigningKeyPath); err != nil {
			writeJSON(w, map[string]any{"ok": false, "detail": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "policy_path": path})
	})

	mux.HandleFunc("/v0/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		// Single event lookup: GET /v0/events?event_id=xxx
		if eid := r.URL.Query().Get("event_id"); eid != "" {
			result, err := queryEvents(opts.EventPath, eventQuery{EventID: eid, Limit: 1})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(result.Events) == 0 {
				http.Error(w, "event not found", http.StatusNotFound)
				return
			}
			writeJSON(w, result.Events[0])
			return
		}
		result, err := queryEvents(opts.EventPath, eventQueryFromRequest(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/v0/events/verify", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if seqStr := r.URL.Query().Get("seq"); seqStr != "" {
			seq, err := strconv.ParseUint(seqStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid seq parameter", http.StatusBadRequest)
				return
			}
			result, err := VerifyEventSeq(opts.EventPath, opts.IntegrityKey, seq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, result)
			return
		}
		result, err := eventlog.Verify(opts.EventPath, opts.IntegrityKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"verify":       result,
			"chain_state":  agent.Logger.ChainSnapshot(),
			"agent_schema": "v0.15",
		}
		if opts.Anchor != nil {
			snap := agent.Logger.ChainSnapshot()
			issues := opts.Anchor.CrossVerify(snap.ChainID, snap.LastSeq, snap.LastHash)
			if len(issues) > 0 {
				resp["anchor_issues"] = issues
			}
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/v0/responses", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		limit := intParam(r, "limit", defaultEventLimit)
		writeJSON(w, map[string]any{"responses": agent.ResponseHistory(limit)})
	})
	mux.HandleFunc("/v0/report/generate", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		report, err := GenerateReport(agent, opts.EventPath, opts.IntegrityKey, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, report)
	})
	mux.HandleFunc("/v0/network/nft/list", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if nftLister, ok := agent.Responder.(interface{ NFTList() any }); ok {
			writeJSON(w, nftLister.NFTList())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider is not available"})
	})
	mux.HandleFunc("/v0/network/nft/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if nftRollback, ok := agent.Responder.(interface{ NFTRollback() any }); ok {
			writeJSON(w, nftRollback.NFTRollback())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider is not available"})
	})
	mux.HandleFunc("/v0/forensics/export", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		outPath := ""
		if override := r.URL.Query().Get("path"); override != "" {
			safePath, err := safePathUnder(opts.ArtifactDir, override)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			outPath = safePath
		}
		eventLimit := intParam(r, "event_limit", 200)
		bundle, err := ExportForensics(agent, opts.EventPath, outPath, eventLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, bundle)
	})

	mux.HandleFunc("/v0/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Admin token bypasses all other credential checks
		if adminAuthOK(r, opts.AdminKey, "shutdown") {
			if opts.Shutdown == nil {
				http.Error(w, "shutdown handler is not configured", http.StatusServiceUnavailable)
				return
			}
			auditShutdown(agent, peerCred{}, 0, "allow", "admin-authorized shutdown")
			writeJSON(w, map[string]any{"ok": true, "shutdown": "scheduled"})
			opts.Shutdown()
			return
		}
		// Normal path: require shutdown_enabled + root loginuid
		cred, loginUID, credErr := shutdownCredential(r)
		if credErr != nil {
			auditShutdown(agent, cred, loginUID, "deny", credErr.Error())
			http.Error(w, credErr.Error(), http.StatusForbidden)
			return
		}
		pol := agent.CurrentPolicy()
		if pol == nil || !pol.SelfProtection.ShutdownEnabled {
			reason := "self_protection.shutdown_enabled is false"
			auditShutdown(agent, cred, loginUID, "deny", reason)
			http.Error(w, reason, http.StatusForbidden)
			return
		}
		cred, loginUID, err := authorizeRootLogin(r)
		if err != nil {
			auditShutdown(agent, cred, loginUID, "deny", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if opts.Shutdown == nil {
			reason := "shutdown handler is not configured"
			auditShutdown(agent, cred, loginUID, "deny", reason)
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}
		auditShutdown(agent, cred, loginUID, "allow", "root login shutdown accepted")
		writeJSON(w, map[string]any{"ok": true, "shutdown": "scheduled"})
		opts.Shutdown()
	})

	// Admin API endpoints (require admin token)
	mux.HandleFunc("/v0/admin/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireAdminAuth(w, r, opts.AdminKey, "restart") {
			return
		}
		if opts.Restart == nil {
			http.Error(w, "restart handler is not configured", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "restart": "scheduled"})
		opts.Restart()
	})

	mux.HandleFunc("/v0/admin/token", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(opts.AdminKey) < 16 {
			http.Error(w, "admin key not configured", http.StatusServiceUnavailable)
			return
		}
		token, expiresAt, err := adminauth.IssueToken(opts.AdminKey, req.Action, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{
			"ok":         true,
			"token":      token,
			"expires_at": expiresAt,
		})
	})

	// Process freeze/resume
	mux.HandleFunc("/v0/process/freeze", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PID         int    `json:"pid"`
			ProcessPath string `json:"process_path"`
			StartTicks  string `json:"start_ticks"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.PID <= 0 {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}
		res := response.Suspend(req.PID, req.ProcessPath, req.StartTicks)
		writeJSON(w, res)
	})
	mux.HandleFunc("/v0/process/resume", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			PID int `json:"pid"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.PID <= 0 {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}
		res := response.Resume(req.PID)
		writeJSON(w, res)
	})
	mux.HandleFunc("/v0/process/frozen", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		frozen := response.SuspendedPIDs()
		out := make([]map[string]any, 0, len(frozen))
		for pid, path := range frozen {
			out = append(out, map[string]any{"pid": pid, "path": path})
		}
		writeJSON(w, map[string]any{"frozen": out, "count": len(out)})
	})

	// Network isolate/restore
	mux.HandleFunc("/v0/network/isolate", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if nft, ok := NftProvider(agent); ok {
			writeJSON(w, nft.ApplyIsolate())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider not available"})
	})
	mux.HandleFunc("/v0/network/restore", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if nft, ok := NftProvider(agent); ok {
			writeJSON(w, nft.Rollback())
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "nft provider not available"})
	})

	// Process tree (v0.6)
	mux.HandleFunc("GET /v0/process/tree", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		tree := agent.ProcTree()
		if tree == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "process tree not available (requires merged collector)"})
			return
		}
		writeJSON(w, map[string]any{
			"ok":         true,
			"size":       tree.Size(),
			"updated_at": tree.UpdatedAt(),
			"nodes":      tree.FullTree(),
		})
	})
	mux.HandleFunc("GET /v0/process/{pid}/info", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		pidStr := r.PathValue("pid")
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}
		tree := agent.ProcTree()
		if tree == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "process tree not available"})
			return
		}
		node := tree.Get(pid)
		if node == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "pid not found"})
			return
		}
		writeJSON(w, map[string]any{
			"ok":          true,
			"node":        node,
			"ancestors":   tree.Ancestors(pid),
			"descendants": tree.Descendants(pid),
		})
	})

	// Notify test
	mux.HandleFunc("/v0/notify/test", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if opts.WebhookTestFn == nil {
			writeJSON(w, map[string]any{"ok": false, "detail": "webhook not configured"})
			return
		}
		if err := opts.WebhookTestFn(); err != nil {
			writeJSON(w, map[string]any{"ok": false, "detail": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// Prometheus metrics
	mux.HandleFunc("/v0/metrics/prometheus", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if opts.MetricsWriter != nil {
			opts.MetricsWriter(w)
			return
		}
		// Adapt agent to MetricsSource interface
		metrics.WritePrometheus(w, &metricsAdapter{agent: agent})
	})

	// Quarantine
	mux.HandleFunc("/v0/quarantine/list", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if qp, ok := QuarantineProvider(agent); ok {
			list, err := qp.ListQuarantined()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"quarantined": list, "count": len(list)})
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "quarantine provider not available"})
	})
	mux.HandleFunc("/v0/quarantine/restore", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		origPath := r.URL.Query().Get("path")
		if origPath == "" {
			http.Error(w, "path parameter required", http.StatusBadRequest)
			return
		}
		if qp, ok := QuarantineProvider(agent); ok {
			writeJSON(w, qp.Restore(origPath))
			return
		}
		writeJSON(w, map[string]any{"ok": false, "detail": "quarantine provider not available"})
	})

	mux.HandleFunc("/v0/baseline/run", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		t, err := baseline.Load(opts.BaselinePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, baseline.Run(t))
	})

	// POST /v0/events/ingest — receive events from peer agents (v0.6).
	// Used for multi-machine log concentration: peer agents push events
	// to a central collector via webhook, which lands here.
	// Accepts both eventlog.Event and notify-style webhook payloads.
	mux.HandleFunc("/v0/events/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 131072))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(opts.IngestKey) > 0 {
			if _, _, err := transport.NewAuthenticator(opts.IngestKey, 30*time.Second).Authorize(r, body); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		} else if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		ev, err := ingestPeerPayload(body, r.URL.Query().Get("source"))
		if err != nil {
			http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if ev == nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		if err := agent.IngestPeerEvent(*ev); err != nil {
			http.Error(w, "ingest: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/v0/events/batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(opts.IngestKey) > 0 {
			if _, _, err := transport.NewAuthenticator(opts.IngestKey, 30*time.Second).Authorize(r, body); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		} else if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		var batch transport.EventBatch
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if batch.RequestID == "" {
			http.Error(w, "missing request id", http.StatusBadRequest)
			return
		}
		if batch.RecordedAt.IsZero() {
			http.Error(w, "missing recorded_at", http.StatusBadRequest)
			return
		}
		if len(batch.Events) == 0 {
			writeJSON(w, map[string]any{"ok": true, "ingested": 0})
			return
		}
		ingested := 0
		for _, env := range batch.Events {
			ev := eventlog.Event{
				SchemaVersion: env.SensorGeneration,
				Timestamp:     env.Timestamp,
				EventID:       env.EventID,
				Host:          batch.HostID,
				Category:      env.Category,
				Severity:      env.Severity,
				Subject:       env.Subject,
				Object:        env.Object,
				Action:        env.LocalActionHint,
				Decision:      "alert",
				RuleID:        env.Subtype,
				Evidence:      env.Evidence,
				Seq:           env.ChainSeq,
				Hash:          env.ChainHash,
				HMAC:          env.Signature,
			}
			if ev.Decision == "" {
				ev.Decision = "alert"
			}
			if ev.Timestamp.IsZero() {
				ev.Timestamp = batch.RecordedAt
			}
			if ev.Host == "" {
				ev.Host = batch.HostID
			}
			if ev.Subject == nil {
				ev.Subject = map[string]any{}
			}
			if batch.InstanceID != "" {
				ev.Subject["_source_instance_id"] = batch.InstanceID
			}
			if batch.BootID != "" {
				ev.Subject["_source_boot_id"] = batch.BootID
			}
			if err := agent.IngestPeerEvent(ev); err != nil {
				http.Error(w, "ingest batch: "+err.Error(), http.StatusInternalServerError)
				return
			}
			ingested++
		}
		writeJSON(w, map[string]any{"ok": true, "ingested": ingested})
	})

	// POST /v0/agent/config — runtime configuration adjustments (v0.6).
	// Accepted fields: suppression_rate, suppression_burst.
	mux.HandleFunc("/v0/agent/config", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthorized(w, r, opts.AllowedUIDs) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SuppressionRate  *uint64 `json:"suppression_rate"`
			SuppressionBurst *uint64 `json:"suppression_burst"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		rate, burst := uint64(0), uint64(0)
		if req.SuppressionRate != nil {
			rate = *req.SuppressionRate
		}
		if req.SuppressionBurst != nil {
			burst = *req.SuppressionBurst
		}
		agent.AdjustSuppression(rate, burst)
		writeJSON(w, map[string]any{
			"ok":    true,
			"state": agent.Suppressor.Snapshot(),
		})
	})

	return mux
}

type eventQuery struct {
	Limit          int
	Offset         int
	Category       string
	Severity       string
	RuleID         string
	EventID        string
	Host           string
	Decision       string
	SubjectPID     string
	FilePath       string
	FileOp         string
	SubjectName    string
	SubjectPath    string
	SubjectCmdline string
	Since          time.Time
	Until          time.Time
	Summary        bool // return compact row-per-event instead of full JSON
}

type eventQueryResult struct {
	Events []map[string]any `json:"events"`
	Count  int              `json:"count"`
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
}

func auditShutdown(agent *Agent, cred peerCred, loginUID uint32, decision, reason string) {
	if agent == nil || agent.Logger == nil {
		return
	}
	severity := "critical"
	action := "shutdown"
	if decision != "allow" {
		action = "shutdown_denied"
	}
	_ = agent.Logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("shutdown-%s-%d", decision, time.Now().UnixNano()),
		Category: "self_protection",
		Severity: severity,
		Subject: map[string]any{
			"peer_uid":      cred.uid,
			"peer_gid":      cred.gid,
			"peer_pid":      cred.pid,
			"peer_loginuid": loginUID,
		},
		Action:   action,
		Decision: decision,
		RuleID:   "self-protect-shutdown",
		Evidence: map[string]any{"reason": reason, "boundary": "uid=0 and loginuid in {0,4294967295}"},
	})
}

func eventQueryFromRequest(r *http.Request) eventQuery {
	return eventQuery{
		Limit:          intParam(r, "limit", defaultEventLimit),
		Offset:         intParam(r, "offset", 0),
		Category:       r.URL.Query().Get("category"),
		Severity:       r.URL.Query().Get("severity"),
		RuleID:         r.URL.Query().Get("rule_id"),
		EventID:        r.URL.Query().Get("event_id"),
		Host:           r.URL.Query().Get("host"),
		Decision:       r.URL.Query().Get("decision"),
		SubjectPID:     r.URL.Query().Get("subject_pid"),
		FilePath:       r.URL.Query().Get("file_path"),
		FileOp:         r.URL.Query().Get("file_op"),
		SubjectName:    r.URL.Query().Get("subject_name"),
		SubjectPath:    r.URL.Query().Get("subject_path"),
		SubjectCmdline: r.URL.Query().Get("subject_cmdline"),
		Since:          timeParam(r, "since"),
		Until:          timeParam(r, "until"),
		Summary:        r.URL.Query().Get("format") == "summary",
	}
}

func queryEvents(path string, q eventQuery) (eventQueryResult, error) {
	if path == "" {
		return eventQueryResult{}, errors.New("event path is not configured")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return eventQueryResult{Events: []map[string]any{}, Limit: clampEventLimit(q.Limit), Offset: q.Offset}, nil
		}
		return eventQueryResult{}, err
	}
	defer f.Close()
	limit := clampEventLimit(q.Limit)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	page := make([]map[string]any, 0, minInt(limit, 128))
	total := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	ghostEvents := 0
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if q.Category != "" && event["category"] != q.Category {
			continue
		}
		if q.Severity != "" && event["severity"] != q.Severity {
			continue
		}
		if q.RuleID != "" && event["rule_id"] != q.RuleID {
			continue
		}
		if q.EventID != "" && event["event_id"] != q.EventID {
			continue
		}
		if q.Host != "" && event["host"] != q.Host {
			continue
		}
		if q.Decision != "" && event["decision"] != q.Decision {
			continue
		}
		if !eventMatchesFile(event, q.FilePath, q.FileOp) {
			continue
		}
		if !eventMatchesSubject(event, q.SubjectName, q.SubjectPath, q.SubjectCmdline) {
			continue
		}
		if q.SubjectPID != "" {
			subj, _ := event["subject"].(map[string]any)
			if subj == nil {
				continue
			}
			pidStr := fmt.Sprint(subj["pid"])
			if pidStr != q.SubjectPID {
				continue
			}
		}
		if !eventInTimeRange(event, q.Since, q.Until) {
			continue
		}
		if total >= offset && len(page) < limit {
			if q.Summary {
				page = append(page, eventSummary(event))
			} else {
				page = append(page, event)
			}
		}
		total++
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			ghostEvents++
			fmt.Fprintf(os.Stderr, "edr-agent: WARNING: event log contains lines exceeding 1 MiB buffer; "+
				"%d oversized event(s) skipped in this query\n", ghostEvents)
		} else {
			return eventQueryResult{}, err
		}
	}
	if offset > total {
		offset = total
	}
	return eventQueryResult{Events: append([]map[string]any(nil), page...), Count: len(page), Total: total, Offset: offset, Limit: limit}, nil
}

func eventMatchesSubject(event map[string]any, name, path, cmdline string) bool {
	if name == "" && path == "" && cmdline == "" {
		return true
	}
	subj, ok := event["subject"].(map[string]any)
	if !ok {
		return false
	}
	if name != "" {
		v, _ := subj["name"].(string)
		if v != name {
			return false
		}
	}
	if path != "" {
		v, _ := subj["path"].(string)
		if v != path {
			return false
		}
	}
	if cmdline != "" {
		v, _ := subj["cmdline"].(string)
		if !strings.Contains(v, cmdline) {
			return false
		}
	}
	return true
}

func eventMatchesFile(event map[string]any, filePath, fileOp string) bool {
	if filePath == "" && fileOp == "" {
		return true
	}
	obj, ok := event["object"].(map[string]any)
	if !ok {
		return false
	}
	if filePath != "" {
		v, _ := obj["path"].(string)
		if v != filePath {
			return false
		}
	}
	if fileOp != "" {
		v, _ := obj["op"].(string)
		if !strings.EqualFold(v, fileOp) {
			return false
		}
	}
	return true
}

func eventInTimeRange(event map[string]any, since, until time.Time) bool {
	if since.IsZero() && until.IsZero() {
		return true
	}
	raw, ok := event["timestamp"].(string)
	if !ok || raw == "" {
		return false
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return false
	}
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

// eventSummary returns a compact one-line representation of an event
// for CLI table display. Includes only the key fields operators need.
func eventSummary(event map[string]any) map[string]any {
	s := map[string]any{
		"timestamp": event["timestamp"],
		"host":      event["host"],
		"category":  event["category"],
		"severity":  event["severity"],
		"rule_id":   event["rule_id"],
		"decision":  event["decision"],
		"action":    event["action"],
	}
	if subj, ok := event["subject"].(map[string]any); ok {
		if name, ok := subj["name"]; ok {
			s["subject_name"] = name
		}
	}
	return s
}

// countActiveConns reads /proc/net/tcp and /proc/net/udp to count
// active network connections for the status endpoint.
func countActiveConns() int {
	count := 0
	for _, f := range []string{"/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			count++
		}
		fh.Close()
		if count > 0 {
			count-- // subtract header line
		}
	}
	return count
}

func timeParam(r *http.Request, key string) time.Time {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func intParam(r *http.Request, key string, fallback int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func clampEventLimit(n int) int {
	if n <= 0 {
		return defaultEventLimit
	}
	if n > maxEventLimit {
		return maxEventLimit
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// verifyEventSeq checks a single event by its sequence number. It scans
// the event file to reconstruct the chain state up to that seq, then
// verifies hash continuity and HMAC (when a key is provided).
// VerifyEventSeq verifies a specific event in the log chain.
func VerifyEventSeq(path string, key []byte, targetSeq uint64) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"ok": true, "seq": targetSeq, "detail": "file not found"}, nil
		}
		return nil, err
	}
	defer f.Close()

	var prevHash string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		var e eventlog.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.IntegrityVersion != eventlog.IntegrityVersion {
			continue
		}
		if e.Seq == targetSeq {
			stored := e
			ok := true
			issues := []map[string]any{}

			if e.PrevHash != prevHash && targetSeq > 1 {
				ok = false
				issues = append(issues, map[string]any{
					"kind":     "prev_hash_break",
					"expected": prevHash,
					"actual":   e.PrevHash,
				})
			}

			// Recompute hash by stripping integrity fields.
			e.Hash = ""
			e.HMAC = ""
			payload, err := json.Marshal(e)
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			h.Write([]byte(prevHash))
			h.Write(payload)
			want := hex.EncodeToString(h.Sum(nil))
			if stored.Hash != want {
				ok = false
				issues = append(issues, map[string]any{
					"kind":     "hash_mismatch",
					"expected": want,
					"actual":   stored.Hash,
				})
			}

			hasHMAC := len(key) > 0
			hmacOK := true
			if hasHMAC {
				mac := hmac.New(sha256.New, key)
				mac.Write([]byte(stored.Hash))
				wantHMAC := hex.EncodeToString(mac.Sum(nil))
				if wantHMAC != stored.HMAC {
					hmacOK = false
					ok = false
					issues = append(issues, map[string]any{
						"kind":     "hmac_mismatch",
						"expected": wantHMAC,
						"actual":   stored.HMAC,
					})
				}
			}

			return map[string]any{
				"ok":        ok,
				"seq":       targetSeq,
				"hash":      stored.Hash,
				"prev_hash": stored.PrevHash,
				"chain_id":  stored.ChainID,
				"has_hmac":  hasHMAC,
				"hmac_ok":   hmacOK,
				"issues":    issues,
			}, nil
		}
		prevHash = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": false, "seq": targetSeq, "detail": "sequence not found"}, nil
}

// PolicyVersion describes a policy backup version.
type PolicyVersion struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// BackupPolicy creates a timestamped backup of the policy file.
func BackupPolicy(path string) error {
	if path == "" {
		return nil
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	backupDir := filepath.Join(filepath.Dir(path), ".versions")
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return err
	}
	name := fmt.Sprintf("%s.%s.bak", filepath.Base(path), time.Now().UTC().Format("20060102T150405.000000000Z"))
	out, err := os.OpenFile(filepath.Join(backupDir, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ListPolicyVersions returns all available policy backup versions.
func ListPolicyVersions(policyPath string) ([]PolicyVersion, error) {
	backupDir := filepath.Join(filepath.Dir(policyPath), ".versions")
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PolicyVersion{}, nil
		}
		return nil, err
	}
	versions := make([]PolicyVersion, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bak") || strings.Contains(entry.Name(), string(filepath.Separator)) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		versions = append(versions, PolicyVersion{Name: entry.Name(), Path: filepath.Join(backupDir, entry.Name()), Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].ModTime.After(versions[j].ModTime) })
	return versions, nil
}

// RollbackPolicyFile restores a previous policy version.
func RollbackPolicyFile(policyPath, version string) (string, error) {
	versions, err := ListPolicyVersions(policyPath)
	if err != nil {
		return "", err
	}
	if len(versions) == 0 {
		return "", errors.New("no policy versions available")
	}
	selected := versions[0]
	if version != "" {
		found := false
		for _, v := range versions {
			if v.Name == version {
				selected = v
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("policy version %q not found", version)
		}
	}
	if err := BackupPolicy(policyPath); err != nil {
		return "", err
	}
	in, err := os.Open(selected.Path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(policyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return selected.Path, nil
}

// policySignatureFile returns the conventional .sig path for a policy file.
func policySignatureFile(policyPath string) string {
	return policyPath + ".sig"
}

// VerifyPolicySig checks the Ed25519 signature for a policy file when a
// signing key is configured. Returns an error when no signing key is
// configured, effectively disabling the policy reload endpoint for
// security (M8 fix: empty path must not bypass verification).
// VerifyPolicySig checks the Ed25519 signature for a policy file.
func VerifyPolicySig(policyPath, signingKeyPath string) error {
	if signingKeyPath == "" {
		return fmt.Errorf("policy signing key not configured; reload endpoint disabled for security")
	}
	sigPath := policySignatureFile(policyPath)
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("policy signature file %q not found", sigPath)
		}
		return fmt.Errorf("read signature: %w", err)
	}
	// Verify needs only the public key. The agent must NOT hold the
	// signing private key — possession of the private key would let
	// a compromised host forge合法 policies.
	pubKeyPath := signingKeyPath + ".pub"
	pub, err := integrity.LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("public key %q: %w (agent must not hold signing private key)", pubKeyPath, err)
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	ok, err := integrity.Verify(pub, raw, string(sigData))
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return fmt.Errorf("policy signature does not match")
	}
	return nil
}

// NftProvider extracts the NFTProvider from the agent's Responder via type assertion.
func NftProvider(agent *Agent) (response.NFTProvider, bool) {
	sr, ok := agent.Responder.(response.SoftResponder)
	if !ok {
		return response.NFTProvider{}, false
	}
	return sr.NFT, true
}

// QuarantineProvider extracts the QuarantineProvider from the agent's Responder via type assertion.
func QuarantineProvider(agent *Agent) (response.QuarantineProvider, bool) {
	sr, ok := agent.Responder.(response.SoftResponder)
	if !ok {
		return response.QuarantineProvider{}, false
	}
	return sr.Quarantine, true
}

// metricsAdapter bridges Agent to the metrics.MetricsSource interface.
type metricsAdapter struct {
	agent *Agent
}

func (a *metricsAdapter) Metrics() map[string]any {
	return a.agent.Metrics()
}

func (a *metricsAdapter) BPFHealth() metrics.BPFHealthStatus {
	h := a.agent.BPFHealth()
	return metrics.BPFHealthStatus{
		Attached:      h.Attached,
		EventsDrained: h.EventsDrained,
		OverloadDrops: h.OverloadDrops,
	}
}

func (a *metricsAdapter) ResponseHistory(limit int) []metrics.ResponseRecord {
	recs := a.agent.ResponseHistory(limit)
	out := make([]metrics.ResponseRecord, len(recs))
	for i, r := range recs {
		out[i] = metrics.ResponseRecord{
			Action:    r.Result.Action,
			Timestamp: r.Timestamp,
		}
	}
	return out
}

// ingestPeerPayload parses a peer event from either eventlog.Event or
// webhook-style format, and returns an eventlog.Event ready for ingestion.
func ingestPeerPayload(body []byte, sourceHost string) (*eventlog.Event, error) {
	// Try eventlog.Event format first.
	var ev eventlog.Event
	if err := json.Unmarshal(body, &ev); err == nil && ev.EventID != "" {
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now().UTC()
		}
		if sourceHost != "" {
			if ev.Subject == nil {
				ev.Subject = map[string]any{}
			}
			ev.Subject["_source_host"] = sourceHost
		}
		return &ev, nil
	}
	// Try webhook-style format.
	var wh struct {
		RuleID    string         `json:"rule_id"`
		Severity  string         `json:"severity"`
		Category  string         `json:"category"`
		Decision  string         `json:"decision"`
		Action    string         `json:"action,omitempty"`
		Subject   map[string]any `json:"subject,omitempty"`
		Object    map[string]any `json:"object,omitempty"`
		Timestamp time.Time      `json:"timestamp"`
		Host      string         `json:"host"`
	}
	if err := json.Unmarshal(body, &wh); err == nil && wh.RuleID != "" {
		if wh.Timestamp.IsZero() {
			wh.Timestamp = time.Now().UTC()
		}
		src := sourceHost
		if src == "" {
			src = wh.Host
		}
		if wh.Subject == nil {
			wh.Subject = map[string]any{}
		}
		if src != "" {
			wh.Subject["_source_host"] = src
		}
		return &eventlog.Event{
			EventID:   fmt.Sprintf("peer-%s-%d", wh.RuleID, wh.Timestamp.UnixNano()),
			Category:  wh.Category,
			Severity:  wh.Severity,
			Decision:  wh.Decision,
			Action:    wh.Action,
			Subject:   wh.Subject,
			Object:    wh.Object,
			Timestamp: wh.Timestamp,
		}, nil
	}
	return nil, fmt.Errorf("payload did not match supported peer event formats")
}
