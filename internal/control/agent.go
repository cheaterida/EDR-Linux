package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"edr/internal/bpf"
	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/policy"
	"edr/internal/procutil"
	"edr/internal/response"
)

type ResponseRecord struct {
	Timestamp time.Time              `json:"timestamp"`
	RuleID    string                 `json:"rule_id"`
	Category  string                 `json:"category"`
	Subject   map[string]any         `json:"subject,omitempty"`
	Object    map[string]any         `json:"object,omitempty"`
	Request   response.ActionRequest `json:"request"`
	Result    response.Result        `json:"result"`
}

type Agent struct {
	mu                  sync.RWMutex
	Policy              *policy.Policy
	Collector           collector.Collector
	Logger              *eventlog.Logger
	Responder           response.Responder
	History             []ResponseRecord
	MaxHistory          int
	ResponsePath        string
	SuppressorStatePath string
	StartedAt           time.Time
	RunCount            uint64
	EventCount          uint64
	ResponseCount       uint64
	SuppressedTotal     uint64
	SuppressionReasons  map[string]uint64
	RuleHits            map[string]uint64
	Suppressor          *Suppressor

	mapFiller bpf.MapFiller // optional; set via SetMapFiller for BPF map hot-reload

	// bpfHealthFn is an optional callback that returns the current
	// ring0 health snapshot. Set via SetBPFHealthProvider.
	bpfHealthFn func() collector.BPFHealth

	responseCh   chan ResponseRecord
	responseDone chan struct{}

	// deferredEvalCh receives exec events that were not matched by the
	// fast-path blacklist. A dedicated goroutine enriches them with
	// /proc data and runs EvaluateAll for full rule coverage.
	deferredEvalCh   chan deferredEval
	deferredEvalDone chan struct{}
}

// deferredEval carries a BPF exec event for second-stage evaluation.
type deferredEval struct {
	pid      uint32
	ppid     uint32
	uid      uint32
	comm     string
	filename string
	ts       time.Time
}

func (a *Agent) Init() {
	a.mu.Lock()
	if a.StartedAt.IsZero() {
		a.StartedAt = time.Now().UTC()
	}
	if a.RuleHits == nil {
		a.RuleHits = map[string]uint64{}
	}
	if a.SuppressionReasons == nil {
		a.SuppressionReasons = map[string]uint64{}
	}
	if a.responseCh == nil && a.ResponsePath != "" {
		a.responseCh = make(chan ResponseRecord, 256)
		a.responseDone = make(chan struct{})
		go a.responseWriter()
	}
	if a.deferredEvalCh == nil {
		a.deferredEvalCh = make(chan deferredEval, 256)
		a.deferredEvalDone = make(chan struct{})
		go a.handleDeferredEval()
	}
	supPath := a.SuppressorStatePath
	a.mu.Unlock()

	if supPath != "" && a.Suppressor != nil {
		_ = a.Suppressor.LoadState(supPath)
	}
}

func (a *Agent) Shutdown() {
	a.mu.RLock()
	ch := a.responseCh
	dch := a.deferredEvalCh
	a.mu.RUnlock()
	if ch != nil {
		close(ch)
		<-a.responseDone
	}
	if dch != nil {
		close(dch)
		<-a.deferredEvalDone
	}
}

func (a *Agent) responseWriter() {
	defer close(a.responseDone)
	path := a.ResponsePath
	for rec := range a.responseCh {
		appendResponseRecord(path, rec)
	}
}

func (a *Agent) Metrics() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	uptime := time.Duration(0)
	if !a.StartedAt.IsZero() {
		uptime = time.Since(a.StartedAt)
	}
	ruleHits := make(map[string]uint64, len(a.RuleHits))
	for k, v := range a.RuleHits {
		ruleHits[k] = v
	}
	reasons := make(map[string]uint64, len(a.SuppressionReasons))
	for k, v := range a.SuppressionReasons {
		reasons[k] = v
	}
	m := map[string]any{
		"started_at":          a.StartedAt,
		"uptime_sec":          int64(uptime.Seconds()),
		"run_count":           a.RunCount,
		"event_count":         a.EventCount,
		"response_count":      a.ResponseCount,
		"suppressed_total":    a.SuppressedTotal,
		"suppression_reasons": reasons,
		"response_history":    len(a.History),
		"rule_hits":           ruleHits,
	}
	if a.bpfHealthFn != nil {
		m["bpf"] = a.bpfHealthFn()
	}
	return m
}

func (a *Agent) CurrentPolicy() *policy.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Policy
}

func (a *Agent) ReplacePolicy(p *policy.Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Policy = p
	a.syncBPFMaps()
}

// SetMapFiller stores the BPF MapFiller so ReplacePolicy can keep the
// blacklist_comm BPF map in sync with the policy after a reload.
// Passing nil is safe and disables the sync path.
func (a *Agent) SetMapFiller(mf bpf.MapFiller) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mapFiller = mf
}

// SetBPFHealthProvider stores a callback that returns the current
// ring0 health snapshot. Passing nil disables the BPF health section
// in /v0/metrics.
func (a *Agent) SetBPFHealthProvider(fn func() collector.BPFHealth) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bpfHealthFn = fn
}

// BPFHealth returns the current ring0 health snapshot. If no BPF
// health provider is configured, returns a zero value with Attached=false.
func (a *Agent) BPFHealth() collector.BPFHealth {
	if a.bpfHealthFn != nil {
		return a.bpfHealthFn()
	}
	return collector.BPFHealth{}
}

// ClearAgentPID removes the current agent PID from the BPF self-protection
// map before a controlled shutdown. The BPF links are detached shortly after
// by loader.Close(); clearing the map first prevents the agent from blocking
// its own final process teardown path on kernels with aggressive signal use.
func (a *Agent) ClearAgentPID() {
	a.mu.RLock()
	mf := a.mapFiller
	a.mu.RUnlock()
	if mf == nil {
		return
	}
	if err := mf.SetAgentPID(0); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: clear agent_pid BPF map: %v\n", err)
	}
}

// syncBPFMaps clears the BPF blacklist_comm and blacklist_filename maps
// and repopulates them from the current policy. Process names <= 15 chars
// go into blacklist_comm (fast 16-byte key); longer names go into
// blacklist_filename (256-byte key, full exec path matching).
// Must be called with a.mu held.
func (a *Agent) syncBPFMaps() {
	if a.mapFiller == nil {
		return
	}
	if err := a.mapFiller.BlacklistClear(); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: blacklist_clear BPF map: %v\n", err)
		return
	}
	if err := a.mapFiller.BlacklistFilenameClear(); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: blacklist_filename_clear BPF map: %v\n", err)
	}
	for _, bl := range a.Policy.ProcessAccess.Blacklist {
		if bl.ProcessName == "" {
			continue
		}
		if len(bl.ProcessName) <= 15 {
			if err := a.mapFiller.BlacklistAdd(bl.ProcessName); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: blacklist_add(%q): %v\n", bl.ProcessName, err)
			}
		} else {
			// Name exceeds TASK_COMM_LEN; use filename map with
			// full path matching for reliable detection.
			if err := a.mapFiller.BlacklistFilenameAdd(bl.ProcessName); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: blacklist_filename_add(%q): %v\n", bl.ProcessName, err)
			}
			fmt.Fprintf(os.Stderr, "edr-agent: process name %q exceeds 15 chars, using filename blacklist\n", bl.ProcessName)
		}
	}
}

func (a *Agent) ResponseHistory(limit int) []ResponseRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if limit <= 0 || limit > len(a.History) {
		limit = len(a.History)
	}
	start := len(a.History) - limit
	out := make([]ResponseRecord, limit)
	copy(out, a.History[start:])
	return out
}

func (a *Agent) recordResponse(rec ResponseRecord) {
	a.mu.Lock()
	if a.MaxHistory <= 0 {
		a.MaxHistory = 256
	}
	rec.Timestamp = time.Now().UTC()
	a.History = append(a.History, rec)
	a.ResponseCount++
	if rec.Result.Success || rec.Result.Detail != "" {
		a.EventCount++
	}
	path := a.ResponsePath
	if len(a.History) > a.MaxHistory {
		a.History = append([]ResponseRecord(nil), a.History[len(a.History)-a.MaxHistory:]...)
	}
	a.mu.Unlock()

	if path != "" {
		select {
		case a.responseCh <- rec:
		default:
			fmt.Fprintf(os.Stderr, "edr-agent: response channel full, dropping record\n")
		}
	}
}

func (a *Agent) recordRuleHit(ruleID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.RuleHits == nil {
		a.RuleHits = map[string]uint64{}
	}
	a.RuleHits[ruleID]++
}

func (a *Agent) recordSuppressed(ruleID, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.SuppressedTotal++
	if a.SuppressionReasons == nil {
		a.SuppressionReasons = map[string]uint64{}
	}
	a.SuppressionReasons[reason]++
}

func appendResponseRecord(path string, rec ResponseRecord) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: append response: %v\n", err)
	}
}

func (a *Agent) RunOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.Init()
	a.mu.Lock()
	a.RunCount++
	a.mu.Unlock()
	snap, err := a.Collector.Snapshot()
	if err != nil {
		return err
	}
	pol := a.CurrentPolicy()
	now := time.Now()

	for _, proc := range snap.Processes {
		subj := policy.Subject{ProcessName: proc.Name, ProcessPath: proc.Path, Cmdline: proc.Cmdline, User: proc.User}
		if rule, ok := pol.EvaluateProcessAccess(subj); ok {
			if rule.Decision == "allow" {
				continue
			}
			subject := map[string]any{"pid": proc.PID, "name": proc.Name, "path": proc.Path, "cmdline": proc.Cmdline}
			key := DedupKey("process", rule.ID, strconv.Itoa(proc.PID), proc.StartTicks)
			if a.allowAndRecord("process", rule.ID, key) {
				a.handleProcessResponse(rule, proc, subject)
			}
			continue
		}
		matches := pol.EvaluateAll(now, subj, policy.Object{})
		if len(matches) == 0 {
			continue
		}
		a.applyMatchSet(now, matches, "process", map[string]any{
			"pid":     proc.PID,
			"name":    proc.Name,
			"path":    proc.Path,
			"cmdline": proc.Cmdline,
			"user":    proc.User,
		}, nil, &proc)
	}

	for _, fileEvent := range snap.FileEvents {
		object := map[string]any{
			"path":     fileEvent.Path,
			"op":       fileEvent.Op,
			"size":     fileEvent.Size,
			"mode":     fileEvent.Mode,
			"mod_time": fileEvent.ModTime,
		}
		matches := pol.EvaluateAll(now, policy.Subject{}, policy.Object{FilePath: fileEvent.Path, FileOp: fileEvent.Op})
		if len(matches) == 0 {
			a.recordRuleHit("file-watch")
			a.mu.Lock()
			a.EventCount++
			a.mu.Unlock()
			_ = a.Logger.Write(eventlog.Event{
				EventID:  fmt.Sprintf("file-%s-%d", fileEvent.Op, time.Now().UnixNano()),
				Category: "file",
				Severity: "medium",
				Object:   object,
				Action:   "observe",
				Decision: "alert",
				RuleID:   "file-watch",
			})
			continue
		}
		a.applyMatchSet(now, matches, "file", nil, object, nil)
	}

	for _, conn := range snap.Connections {
		matches := pol.EvaluateAll(now, policy.Subject{}, policy.Object{RemoteAddr: conn.RemoteAddr, LocalPort: conn.LocalPort, Protocol: conn.Protocol})
		if len(matches) == 0 {
			continue
		}
		object := map[string]any{
			"protocol":    conn.Protocol,
			"local_addr":  conn.LocalAddr,
			"local_port":  conn.LocalPort,
			"remote_addr": conn.RemoteAddr,
			"state":       conn.State,
		}
		a.applyMatchSet(now, matches, "network", nil, object, nil)
	}

	if a.SuppressorStatePath != "" && a.Suppressor != nil {
		_ = a.Suppressor.SaveState(a.SuppressorStatePath)
	}

	return nil
}

// allowAndRecord asks the Suppressor whether the event may be
// emitted. It also bumps the rule-hit counter when the rule is
// considered "seen" regardless of suppression, and increments the
// suppression metric when the Suppressor blocks the emit.
func (a *Agent) allowAndRecord(category, ruleID, key string) bool {
	a.recordRuleHit(ruleID)
	if a.Suppressor == nil {
		return true
	}
	ok, reason := a.Suppressor.Allow(category, ruleID, key)
	if !ok {
		a.recordSuppressed(ruleID, reason)
	}
	return ok
}

// applyMatchSet is the v0.15 multi-hit pipeline entrypoint. Given
// the matches from EvaluateAll plus the subject/object already
// gathered, it walks AggregatedDecision, emits one audit event per
// matching audit rule, and applies the highest-priority response
// rule (if any) — each subject to its own Suppressor gate.
func (a *Agent) applyMatchSet(now time.Time, matches []policy.Rule, category string, subject, object map[string]any, proc *collector.Process) {
	resp, audit := policy.AggregatedDecision(matches)
	for i := range audit {
		rule := audit[i]
		key := dedupKeyForRule(category, rule, subject, object, proc)
		if !a.allowAndRecord(category, rule.ID, key) {
			continue
		}
		_ = a.Logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("%s-%s-%d", category, rule.ID, now.UnixNano()),
			Category: category,
			Severity: rule.Severity,
			Subject:  copyMap(subject),
			Object:   copyMap(object),
			Action:   rule.Action,
			Decision: rule.Decision,
			RuleID:   rule.ID,
		})
	}
	if resp == nil {
		return
	}
	key := dedupKeyForRule(category, *resp, subject, object, proc)
	if !a.allowAndRecord(category, resp.ID, key) {
		return
	}
	a.applyResponse(*resp, category, subject, object, proc)
}

func (a *Agent) applyResponse(rule policy.Rule, category string, subject, object map[string]any, proc *collector.Process) {
	var req response.ActionRequest
	req.Action = rule.Action
	req.RuleID = rule.ID
	switch category {
	case "process":
		if proc == nil {
			return
		}
		req.PID = proc.PID
		req.ProcessPath = proc.Path
		req.StartTicks = proc.StartTicks
	case "file":
		if object == nil {
			return
		}
		if p, ok := object["path"].(string); ok {
			req.Path = p
		}
	case "network":
		if object == nil {
			return
		}
		if v, ok := object["remote_addr"].(string); ok {
			req.RemoteAddr = v
		}
		if v, ok := object["local_port"].(int); ok {
			req.LocalPort = v
		}
		if v, ok := object["protocol"].(string); ok {
			req.Protocol = v
		}
	}
	res := a.Responder.Apply(req)
	rec := ResponseRecord{RuleID: rule.ID, Category: category, Subject: copyMap(subject), Object: copyMap(object), Request: req, Result: res}
	a.recordResponse(rec)
	_ = a.Logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("%s-%s-resp-%d", category, rule.ID, time.Now().UnixNano()),
		Category: category,
		Severity: rule.Severity,
		Subject:  copyMap(subject),
		Object:   copyMap(object),
		Action:   rule.Action,
		Decision: rule.Decision,
		RuleID:   rule.ID,
		Evidence: map[string]any{"response": res},
	})
}

func (a *Agent) handleProcessResponse(rule policy.Rule, proc collector.Process, subject map[string]any) {
	a.applyResponse(rule, "process", subject, nil, &proc)
}

func dedupKeyForRule(category string, rule policy.Rule, subject, object map[string]any, proc *collector.Process) string {
	switch category {
	case "process":
		pid := ""
		ticks := ""
		if proc != nil {
			pid = strconv.Itoa(proc.PID)
			ticks = proc.StartTicks
		} else if subject != nil {
			if v, ok := subject["pid"].(int); ok {
				pid = strconv.Itoa(v)
			}
			if v, ok := subject["start_ticks"].(string); ok {
				ticks = v
			}
		}
		return DedupKey("process", rule.ID, pid, ticks)
	case "file":
		path := ""
		op := ""
		if object != nil {
			if v, ok := object["path"].(string); ok {
				path = v
			}
			if v, ok := object["op"].(string); ok {
				op = v
			}
		}
		return DedupKey("file", rule.ID, path, op)
	case "network":
		remote := ""
		port := ""
		proto := ""
		if object != nil {
			if v, ok := object["remote_addr"].(string); ok {
				remote = v
			}
			if v, ok := object["local_port"].(int); ok {
				port = strconv.Itoa(v)
			}
			if v, ok := object["protocol"].(string); ok {
				proto = v
			}
		}
		return DedupKey("network", rule.ID, remote, port, proto)
	}
	return DedupKey(category, rule.ID)
}

func copyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// StartFastPath begins a dedicated goroutine that consumes the BPF
// fast-path event channel for low-latency enforcement. It runs
// independently of the main 5s ticker loop.
//
// Exec events are immediately checked against process_access
// blacklist and killed within milliseconds via ring0 bpf_send_signal.
// Selfprotect events are written as critical audit events.
// This is a no-op if loader does not implement FastPathLoader.
func (a *Agent) StartFastPath(loader bpf.Loader) {
	fpl, ok := loader.(bpf.FastPathLoader)
	if !ok {
		return
	}
	fastCh := fpl.FastEvents()
	go func() {
		for ev := range fastCh {
			switch ev.Type {
			case bpf.EventExec:
				a.handleFastPathExec(ev)
			case bpf.EventSelfProtect:
				a.handleFastPathSelfProtect(ev)
			case bpf.EventPtraceEnh:
				a.handleFastPathPtraceEnh(ev)
			case bpf.EventLDPreload:
				a.handleFastPathLDPreload(ev)
			case bpf.EventInstrument:
				a.handleFastPathInstrument(ev)
			}
		}
	}()
}

func (a *Agent) handleFastPathExec(ev bpf.Event) {
	subj := policy.Subject{
		ProcessName: ev.Comm,
		ProcessPath: ev.Filename,
		User:        fmt.Sprintf("%d", ev.UID),
	}
	pol := a.CurrentPolicy()
	rule, ok := pol.EvaluateProcessAccess(subj)
	if !ok || rule.Decision == "allow" {
		// No blacklist match — send to deferred evaluation for full
		// rule coverage (CmdlineContains, EnvContains, MapsContains, etc.)
		select {
		case a.deferredEvalCh <- deferredEval{
			pid: ev.PID, ppid: ev.PPID, uid: ev.UID,
			comm: ev.Comm, filename: ev.Filename, ts: time.Now(),
		}:
		default:
			fmt.Fprintf(os.Stderr, "edr-agent: deferred eval channel full, dropping exec event pid=%d\n", ev.PID)
		}
		return
	}
	// Blacklisted: kill immediately. Bypass Suppressor — enforcement
	// is always immediate; suppression is for observability only.
	req := response.ActionRequest{
		Action:      rule.Action,
		PID:         int(ev.PID),
		ProcessPath: ev.Filename,
		RuleID:      rule.ID,
	}
	res := a.Responder.Apply(req)
	rec := ResponseRecord{
		RuleID:   rule.ID,
		Category: "process",
		Subject: map[string]any{
			"pid":  ev.PID,
			"name": ev.Comm,
			"path": ev.Filename,
		},
		Request: req,
		Result:  res,
	}
	a.recordResponse(rec)
}

// resolveProcExe reads /proc/<pid>/exe to get the actual binary path.
// Returns empty string on any error.
func resolveProcExe(pid uint32) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

// readProcCmdline reads /proc/<pid>/cmdline and returns the full command line.
// Returns empty string on any error (process exited, permission denied, etc.).
func readProcCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline is NUL-separated; join with spaces for readability.
	parts := strings.Split(string(data), "\x00")
	// Trim trailing empty string from the final NUL.
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, " ")
}

// readProcEnviron reads /proc/<pid>/environ and returns the full content.
// Returns empty string on any error.
func readProcEnviron(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	// environ is NUL-separated; replace with newlines for substring matching.
	parts := strings.Split(string(data), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "\n")
}

// readProcMaps reads /proc/<pid>/maps and returns the first 4 KiB.
// Returns empty string on any error.
func readProcMaps(pid uint32) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// isProcessAlive checks whether a PID is still alive by sending signal 0.
func isProcessAlive(pid uint32) bool {
	err := syscall.Kill(int(pid), 0)
	return err == nil
}

// handleDeferredEval is the second-stage evaluation goroutine. It reads
// exec events from deferredEvalCh, enriches the Subject with /proc data,
// and runs the full policy rule engine (EvaluateAll). This catches rules
// that depend on CmdlineContains, EnvContains, MapsContains, etc.
//
// Strict mode: events go through the Suppressor, and PID exit is logged
// as a warning plus an audit event.
func (a *Agent) handleDeferredEval() {
	defer close(a.deferredEvalDone)
	for de := range a.deferredEvalCh {
		a.processDeferredEval(de)
	}
}

func (a *Agent) processDeferredEval(de deferredEval) {
	// Check if the process is still alive before doing expensive /proc reads.
	if !isProcessAlive(de.pid) {
		a.mu.Lock()
		a.SuppressedTotal++
		a.mu.Unlock()
		fmt.Fprintf(os.Stderr, "edr-agent: deferred eval skipped — pid %d exited before enrichment\n", de.pid)
		_ = a.Logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("deferred-exit-%d-%d", de.pid, de.ts.UnixNano()),
			Category: "process",
			Severity: "low",
			Subject: map[string]any{
				"pid":  de.pid,
				"name": de.comm,
			},
			Action:   "observe",
			Decision: "skip",
			RuleID:   "deferred-eval-exit",
		})
		return
	}

	// Enrich Subject with /proc data.
	procPath := resolveProcExe(de.pid)
	if procPath == "" {
		procPath = de.filename // fallback to BPF-provided filename
	}
	subj := policy.Subject{
		ProcessName: de.comm,
		ProcessPath: procPath,
		Cmdline:     readProcCmdline(de.pid),
		User:        fmt.Sprintf("%d", de.uid),
		Environ:     readProcEnviron(de.pid),
		MapsLibs:    readProcMaps(de.pid),
	}

	pol := a.CurrentPolicy()
	now := time.Now()
	matches := pol.EvaluateAll(now, subj, policy.Object{})
	if len(matches) == 0 {
		return
	}

	// Verify PID hasn't been reused between enrichment and evaluation.
	if !isProcessAlive(de.pid) {
		fmt.Fprintf(os.Stderr, "edr-agent: deferred eval race — pid %d exited between enrichment and evaluation\n", de.pid)
		return
	}

	// Build a collector.Process for applyMatchSet (needs StartTicks).
	var proc *collector.Process
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", de.pid))
	if err == nil {
		ticks := procutil.StartTicksFromStat(string(statData))
		proc = &collector.Process{
			PID:        int(de.pid),
			Name:       de.comm,
			Path:       procPath,
			Cmdline:    subj.Cmdline,
			User:       subj.User,
			StartTicks: ticks,
		}
	}

	subject := map[string]any{
		"pid":     de.pid,
		"name":    de.comm,
		"path":    procPath,
		"cmdline": subj.Cmdline,
		"user":    subj.User,
	}
	a.applyMatchSet(now, matches, "process", subject, nil, proc)
}

// handleFastPathPtraceEnh evaluates enhanced ptrace events against policy.
// PTRACE_TRACEME (request=0) is the classic anti-debug self-check.
func (a *Agent) handleFastPathPtraceEnh(ev bpf.Event) {
	isTraceMe := ev.Reserved == 0 // PTRACE_TRACEME
	procPath := resolveProcExe(ev.PID)
	subj := policy.Subject{
		ProcessName:     ev.Comm,
		ProcessPath:     procPath,
		User:            fmt.Sprintf("%d", ev.UID),
		PtraceSelfCheck: isTraceMe,
	}
	pol := a.CurrentPolicy()
	now := time.Now()
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	if len(rules) == 0 {
		return
	}
	resp, audits := policy.AggregatedDecision(rules)
	for _, r := range audits {
		a.Logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("ptrace-enh-%d-%d", ev.PID, now.UnixNano()),
			Category: "process",
			Severity: r.Severity,
			Subject: map[string]any{
				"pid":            ev.PID,
				"name":           ev.Comm,
				"ptrace_request": ev.Reserved,
				"ptrace_label":   ev.Filename,
				"target_pid":     ev.PPID,
			},
			Action:   r.Action,
			Decision: r.Decision,
			RuleID:   r.ID,
		})
	}
	if resp != nil && resp.Action != "none" {
		req := response.ActionRequest{
			Action: resp.Action, PID: int(ev.PID),
			ProcessPath: procPath, RuleID: resp.ID,
		}
		res := a.Responder.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "ptrace_request": ev.Reserved},
			Request: req, Result: res,
		})
	}
}

// handleFastPathLDPreload evaluates LD_PRELOAD injection events.
func (a *Agent) handleFastPathLDPreload(ev bpf.Event) {
	procPath := resolveProcExe(ev.PID)
	subj := policy.Subject{
		ProcessName: ev.Comm,
		ProcessPath: procPath,
		User:        fmt.Sprintf("%d", ev.UID),
		Environ:     "LD_PRELOAD=" + ev.Filename,
	}
	pol := a.CurrentPolicy()
	now := time.Now()
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	if len(rules) == 0 {
		return
	}
	resp, audits := policy.AggregatedDecision(rules)
	for _, r := range audits {
		a.Logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("ldpreload-%d-%d", ev.PID, now.UnixNano()),
			Category: "process",
			Severity: r.Severity,
			Subject: map[string]any{
				"pid":        ev.PID,
				"name":       ev.Comm,
				"ld_preload": ev.Filename,
			},
			Action:   r.Action,
			Decision: r.Decision,
			RuleID:   r.ID,
		})
	}
	if resp != nil && resp.Action != "none" {
		req := response.ActionRequest{
			Action: resp.Action, PID: int(ev.PID),
			ProcessPath: procPath, RuleID: resp.ID,
		}
		res := a.Responder.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "ld_preload": ev.Filename},
			Request: req, Result: res,
		})
	}
}

// handleFastPathInstrument evaluates suspicious mmap events.
// The Go side resolves /proc/pid/fd to identify the mapped file.
func (a *Agent) handleFastPathInstrument(ev bpf.Event) {
	// Resolve fd to path via /proc/pid/fd
	mappedPath := ""
	if ev.Reserved > 0 {
		link := fmt.Sprintf("/proc/%d/fd/%d", ev.PID, ev.Reserved)
		if target, err := os.Readlink(link); err == nil {
			mappedPath = target
		}
	}
	procPath := resolveProcExe(ev.PID)
	subj := policy.Subject{
		ProcessName: ev.Comm,
		ProcessPath: procPath,
		User:        fmt.Sprintf("%d", ev.UID),
		MapsLibs:    mappedPath,
	}
	pol := a.CurrentPolicy()
	now := time.Now()
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	if len(rules) == 0 {
		return
	}
	resp, audits := policy.AggregatedDecision(rules)
	for _, r := range audits {
		a.Logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("instrument-%d-%d", ev.PID, now.UnixNano()),
			Category: "process",
			Severity: r.Severity,
			Subject: map[string]any{
				"pid":         ev.PID,
				"name":        ev.Comm,
				"mapped_file": mappedPath,
				"fd":          ev.Reserved,
			},
			Action:   r.Action,
			Decision: r.Decision,
			RuleID:   r.ID,
		})
	}
	if resp != nil && resp.Action != "none" {
		req := response.ActionRequest{
			Action: resp.Action, PID: int(ev.PID),
			ProcessPath: procPath, RuleID: resp.ID,
		}
		res := a.Responder.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "mapped_file": mappedPath},
			Request: req, Result: res,
		})
	}
}

func (a *Agent) handleFastPathSelfProtect(ev bpf.Event) {
	a.mu.RLock()
	logger := a.Logger
	a.mu.RUnlock()
	if logger == nil {
		return
	}
	_ = logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("selfprotect-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "self_protection",
		Severity: "critical",
		Subject: map[string]any{
			"attacker_pid":  ev.PID,
			"attacker_comm": ev.Comm,
			"target_pid":    ev.PPID,
			"syscall":       ev.Filename,
			"attacker_uid":  ev.UID,
		},
		Action:   "alert",
		Decision: "alert",
		RuleID:   "self-protect-detect",
	})
	// Enforce mode: kill the attacker process if policy says so.
	// Safety: never kill PID 1, never kill our own process.
	pol := a.CurrentPolicy()
	if pol.SelfProtection.EnforceMode != "kill" {
		return
	}
	attackerPID := int(ev.PID)
	if attackerPID <= 1 || attackerPID == os.Getpid() {
		return
	}
	// Use pidfd for TOCTOU-safe kill (S18). Falls back to
	// syscall.Kill on kernels without pidfd support.
	if err := response.PidfdKill(attackerPID); err != nil {
		// Fallback for pre-5.3 kernels.
		_ = syscall.Kill(attackerPID, syscall.SIGKILL)
	}
	_ = logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("selfprotect-enforce-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "self_protection",
		Severity: "critical",
		Subject: map[string]any{
			"attacker_pid":  ev.PID,
			"attacker_comm": ev.Comm,
			"syscall":       ev.Filename,
		},
		Action:   "kill",
		Decision: "block",
		RuleID:   "self-protect-enforce",
	})
}
