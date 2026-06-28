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
	"edr/internal/integrity"
	"edr/internal/policy"
	"edr/internal/procutil"
	"edr/internal/response"
	"edr/internal/rootkit"
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
	Source              EventSource
	Engine              DecisionEngine
	Executor            ActionExecutor
	Events              AuditSink
	StartedAt           time.Time
	RunCount            uint64
	EventCount          uint64
	ResponseCount       uint64
	SuppressedTotal     uint64
	SuppressionReasons  map[string]uint64
	RuleHits            map[string]uint64
	Suppressor          *Suppressor
	SelfProtectBlocks   uint64 // v0.6: self-protection block counter
	RootkitDetector     *rootkit.Detector

	// v0.9: integrity sentinel — detects when EDR is being dismantled.
	SelfCheck *integrity.SelfCheck

	mapFiller bpf.MapFiller // optional; set via SetMapFiller for BPF map hot-reload

	// bpfHealthFn is an optional callback that returns the current
	// ring0 health snapshot. Set via SetBPFHealthProvider.
	bpfHealthFn func() collector.BPFHealth

	// resourceFn is an optional callback that returns host-level
	// resource usage (CPU%, RSS, fanotify latency). Set via
	// SetResourceInfoProvider.
	resourceFn func() ResourceInfo

	// OnResponse is an optional callback invoked for each new response record.
	OnResponse func(ResponseRecord)

	responseCh   chan ResponseRecord
	responseDone chan struct{}

	// deferredEvalCh receives exec events that were not matched by the
	// fast-path blacklist. A dedicated goroutine enriches them with
	// /proc data and runs EvaluateAll for full rule coverage.
	deferredEvalCh   chan deferredEval
	deferredEvalDone chan struct{}

	// rootkit lifecycle
	rootkitDone chan struct{}
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

	if a.RootkitDetector != nil {
		if a.rootkitDone == nil {
			a.rootkitDone = make(chan struct{})
		}
		go a.rootkitLoop()
	}
}

func (a *Agent) Shutdown() {
	a.mu.RLock()
	ch := a.responseCh
	dch := a.deferredEvalCh
	rd := a.rootkitDone
	a.mu.RUnlock()
	if ch != nil {
		close(ch)
		<-a.responseDone
	}
	if dch != nil {
		close(dch)
		<-a.deferredEvalDone
	}
	if rd != nil {
		close(rd)
	}
}

// rootkitLoop runs periodic cross-source consistency checks. It exits
// when a.rootkitDone is closed.
func (a *Agent) rootkitLoop() {
	d := a.RootkitDetector
	if d == nil {
		return
	}
	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()

	// Run an initial check shortly after startup to establish baseline.
	time.AfterFunc(2*time.Second, func() { a.runRootkitCheck() })

	for {
		select {
		case <-ticker.C:
			a.runRootkitCheck()
		case <-a.rootkitDone:
			return
		}
	}
}

func (a *Agent) runRootkitCheck() {
	d := a.RootkitDetector
	if d == nil {
		return
	}
	findings, err := d.RunOnce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: rootkit check error: %v\n", err)
		return
	}
	for _, f := range findings {
		a.handleRootkitFinding(f)
	}
}

func (a *Agent) handleRootkitFinding(f rootkit.Finding) {
	subject := f.Subject
	object := f.Object
	if subject == nil {
		subject = map[string]any{}
	}
	if object == nil {
		object = map[string]any{}
	}

	// Emit audit event.
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("rootkit-%s-%d", f.Type, time.Now().UnixNano()),
		Category: "rootkit",
		Severity: f.Severity,
		Subject:  subject,
		Object:   object,
		Action:   f.Action,
		Decision: "alert",
		RuleID:   f.RuleID,
	})

	if a.RootkitDetector != nil && a.RootkitDetector.MonitorOnly {
		return
	}

	// Enforce mode: apply response action.
	var req response.ActionRequest
	req.Action = f.Action
	req.RuleID = f.RuleID
	switch f.Type {
	case "hidden_process":
		if pid, ok := subject["pid"].(int); ok && pid > 1 {
			req.PID = pid
		}
	case "hidden_module", "module_load", "module_unload", "bpf_op":
		req.Action = "network_isolate"
	}
	if req.Action == "" || req.Action == "none" {
		return
	}
	res := a.Responder.Apply(req)
	a.recordResponse(ResponseRecord{
		RuleID:   f.RuleID,
		Category: "rootkit",
		Subject:  subject,
		Object:   object,
		Request:  req,
		Result:   res,
	})
	_ = a.Logger.Write(eventlog.Event{
		EventID:  fmt.Sprintf("rootkit-%s-resp-%d", f.Type, time.Now().UnixNano()),
		Category: "rootkit",
		Severity: f.Severity,
		Subject:  subject,
		Object:   object,
		Action:   req.Action,
		Decision: "block",
		RuleID:   f.RuleID,
		Evidence: map[string]any{"response": res},
	})
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
		"self_protect_blocks": a.SelfProtectBlocks,
	}
	if a.RootkitDetector != nil {
		m["rootkit_checks_total"] = a.RootkitDetector.Checks()
		m["rootkit_findings_total"] = a.RootkitDetector.Findings()
	}
	if a.bpfHealthFn != nil {
		m["bpf"] = a.bpfHealthFn()
	}
	if a.resourceFn != nil {
		m["resource"] = a.resourceFn()
	}
	return m
}

func (a *Agent) currentEventSource() EventSource {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Source != nil {
		return a.Source
	}
	if a.Collector != nil {
		return CollectorSource{Collector: a.Collector}
	}
	return nil
}

func (a *Agent) currentDecisionEngine() DecisionEngine {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Engine != nil {
		return a.Engine
	}
	if a.Policy != nil {
		return PolicyEngine{Policy: a.Policy}
	}
	return nil
}

func (a *Agent) currentPolicy() *policy.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Policy
}

func (a *Agent) currentActionExecutor() ActionExecutor {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Executor != nil {
		return a.Executor
	}
	if a.Responder != nil {
		return ResponderExecutor{Responder: a.Responder}
	}
	return nil
}

func (a *Agent) writeEvent(ev eventlog.Event) error {
	sink := a.currentAuditSink()
	if sink == nil {
		return fmt.Errorf("audit sink not configured")
	}
	return sink.Write(ev)
}

func (a *Agent) logEvent(ev eventlog.Event) {
	_ = a.writeEvent(ev)
}

func (a *Agent) currentAuditSink() AuditSink {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Events != nil {
		return a.Events
	}
	if a.Logger != nil {
		return LoggerSink{Logger: a.Logger}
	}
	return nil
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
	if a.Policy != nil {
		a.syncBPFMaps()
	}
}

// ResourceInfo carries host-level resource usage for the agent process
// and key kernel subsystems.
type ResourceInfo struct {
	CPUPercent        float64 `json:"cpu_percent"`
	RSSMB             float64 `json:"rss_mb"`
	FanotifyLatencyUs int64   `json:"fanotify_latency_us"`
	FanotifyAllows    uint64  `json:"fanotify_allows"`
	FanotifyDenies    uint64  `json:"fanotify_denies"`
}

// SetResourceInfoProvider stores a callback for resource metrics.
func (a *Agent) SetResourceInfoProvider(fn func() ResourceInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resourceFn = fn
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

// CheckCriticalProcesses verifies that each named process appears in the
// latest collector snapshot. Missing processes trigger a critical alert.
func (a *Agent) CheckCriticalProcesses(names []string) {
	if len(names) == 0 {
		return
	}
	source := a.currentEventSource()
	if source == nil {
		return
	}
	snap, err := source.Snapshot(context.Background())
	if err != nil {
		return
	}
	seen := make(map[string]bool, len(snap.Processes))
	for _, p := range snap.Processes {
		seen[p.Name] = true
	}
	for _, name := range names {
		if seen[name] {
			continue
		}
		a.logEvent(eventlog.Event{
			EventID:  fmt.Sprintf("critical-missing-%s-%d", name, time.Now().Unix()),
			Category: "service",
			Severity: "critical",
			Subject: map[string]any{
				"process": name,
			},
			Action:   "critical_process_missing",
			Decision: "alert",
			RuleID:   "service-continuity",
		})
	}
}

// CheckCPULimits queries the CPULimitTracker for processes exceeding the
// given threshold and applies the specified action (kill or process_suspend).
// Whitelist entries are matched against process comm names.
func (a *Agent) CheckCPULimits(tracker *collector.CPULimitTracker, threshold float64, action string, whitelist []string) {
	if tracker == nil || threshold <= 0 {
		return
	}
	highPIDs := tracker.HighCPU(threshold, whitelist)
	if len(highPIDs) == 0 {
		return
	}
	source := a.currentEventSource()
	if source == nil {
		return
	}
	snap, err := source.Snapshot(context.Background())
	if err != nil {
		return
	}
	pidToProc := make(map[int]*collector.Process, len(snap.Processes))
	for i := range snap.Processes {
		pidToProc[snap.Processes[i].PID] = &snap.Processes[i]
	}
	whitelistSet := make(map[string]bool, len(whitelist))
	for _, w := range whitelist {
		whitelistSet[w] = true
	}
	for _, pid := range highPIDs {
		proc := pidToProc[pid]
		if proc == nil || whitelistSet[proc.Name] {
			continue
		}
		subject := map[string]any{
			"pid": pid, "name": proc.Name, "path": proc.Path,
			"cmdline": proc.Cmdline, "user": proc.User, "cpu_pct": threshold,
		}
		ruleID := "CPU-001-cpu-limit-exceeded"
		key := DedupKey("process", ruleID, strconv.Itoa(pid), proc.StartTicks)
		if !a.allowAndRecord("process", ruleID, key) {
			continue
		}
		a.logEvent(eventlog.Event{
			EventID:  fmt.Sprintf("cpu-limit-%d-%d", pid, time.Now().Unix()),
			Category: "process", Severity: "high", Subject: subject,
			Action: action, Decision: "block", RuleID: ruleID,
		})
		switch action {
		case "kill":
			a.Responder.Apply(response.ActionRequest{
				PID: pid, ProcessPath: proc.Path,
				StartTicks: proc.StartTicks, Action: "kill",
				RuleID: ruleID,
			})
		case "process_suspend":
			a.Responder.Apply(response.ActionRequest{
				PID: pid, ProcessPath: proc.Path,
				StartTicks: proc.StartTicks, Action: "process_suspend",
				RuleID: ruleID,
			})
		}
	}
}

// RecordSelfProtectBlock increments the self-protection block counter
// and publishes a sensor_tamper event. Called from the fast-path when
// LSM/kprobe self-protection intercepts an attack against the agent.
func (a *Agent) RecordSelfProtectBlock(attackerPID uint32, method string) {
	a.mu.Lock()
	a.SelfProtectBlocks++
	blocks := a.SelfProtectBlocks
	a.mu.Unlock()

	// Emit a sensor tamper event through the logger.
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("sensor-tamper-%d-%d", blocks, time.Now().UnixNano()),
		Category: "self_protection",
		Severity: "critical",
		Subject: map[string]any{
			"pid":    attackerPID,
			"method": method,
		},
		Object: map[string]any{
			"block_count": blocks,
		},
		Action:   "sensor_tamper_blocked",
		Decision: "block",
		RuleID:   "self-protect-lsm",
	})
}

// ProcTree returns the process lineage tree from the underlying collector.
func (a *Agent) ProcTree() *collector.Tree {
	if mc, ok := a.Collector.(*collector.MergedCollector); ok {
		return mc.ProcTree()
	}
	return nil
}

// IngestPeerEvent writes an event from a peer agent into the local event
// log. Used for multi-machine log concentration (v0.6).
func (a *Agent) IngestPeerEvent(ev eventlog.Event) error {
	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("peer-%d", time.Now().UnixNano())
	} else if !strings.HasPrefix(ev.EventID, "peer-") {
		ev.EventID = fmt.Sprintf("peer-%s-%d", ev.EventID, time.Now().UnixNano())
	}
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = eventlog.SchemaVersion
	}
	return a.writeEvent(ev)
}

// AdjustSuppression updates the suppressor rate and burst at runtime
// without requiring a full policy reload. Set zero to keep the current value.
func (a *Agent) AdjustSuppression(ratePerSec, burst uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Suppressor != nil {
		a.Suppressor.SetRate(ratePerSec, burst)
	}
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
	ldpreloadKill := false
	for _, rule := range a.Policy.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		if rule.ID == "ATT002-ld-preload-injection" && rule.Decision == "block" && rule.Action == "kill" {
			ldpreloadKill = true
			break
		}
	}
	if err := a.mapFiller.SetLDPreloadKill(ldpreloadKill); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: ldpreload_kill BPF map: %v\n", err)
	}
	if err := a.mapFiller.BlacklistClear(); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: blacklist_clear BPF map: %v\n", err)
		return
	}
	if err := a.mapFiller.BlacklistFilenameClear(); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: blacklist_filename_clear BPF map: %v\n", err)
	}
	for _, bl := range a.Policy.ProcessAccess.Blacklist {
		if bl.ProcessName == "" && bl.ProcessPath == "" {
			continue
		}
		if bl.ProcessName != "" {
			if len(bl.ProcessName) > 15 {
				fmt.Fprintf(os.Stderr, "edr-agent: refusing to downshift long process_name %q into filename map; use process_path instead\n", bl.ProcessName)
				continue
			}
			if err := a.mapFiller.BlacklistAdd(bl.ProcessName); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: blacklist_add(%q): %v\n", bl.ProcessName, err)
			}
		}
		if bl.ProcessPath != "" {
			if err := a.mapFiller.BlacklistFilenameAdd(bl.ProcessPath); err != nil {
				fmt.Fprintf(os.Stderr, "edr-agent: blacklist_filename_add(%q): %v\n", bl.ProcessPath, err)
			}
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
	onResp := a.OnResponse
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
	if onResp != nil {
		onResp(rec)
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

// RecordRuleHit is the exported version of recordRuleHit for
// use by external event sources (e.g. fanotify handler) that
// evaluate policy rules outside the main RunOnce loop.
func (a *Agent) RecordRuleHit(ruleID string) {
	a.recordRuleHit(ruleID)
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
	source := a.currentEventSource()
	if source == nil {
		return fmt.Errorf("event source not configured")
	}
	engine := a.currentDecisionEngine()
	if engine == nil {
		return fmt.Errorf("decision engine not configured")
	}
	snap, err := source.Snapshot(ctx)
	if err != nil {
		return err
	}
	now := time.Now()

	for _, proc := range snap.Processes {
		subj := policy.Subject{ProcessName: proc.Name, ProcessPath: proc.Path, Cmdline: proc.Cmdline, User: proc.User}
		if rule, ok := engine.EvaluateProcessAccess(subj); ok {
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
		matches := engine.EvaluateAll(now, subj, policy.Object{})
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
		matches := engine.EvaluateAll(now, policy.Subject{}, policy.Object{FilePath: fileEvent.Path, FileOp: fileEvent.Op})
		if len(matches) == 0 {
			a.recordRuleHit("file-watch")
			a.mu.Lock()
			a.EventCount++
			a.mu.Unlock()
			_ = a.writeEvent(eventlog.Event{
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
		matches := engine.EvaluateAll(now, policy.Subject{}, policy.Object{RemoteAddr: conn.RemoteAddr, LocalPort: conn.LocalPort, Protocol: conn.Protocol})
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

	// v0.9: integrity sentinel — detect BPF detachment, binary
	// tampering, install-dir deletion at every collection cycle.
	if a.SelfCheck != nil {
		a.SelfCheck.RunAll()
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
		_ = a.writeEvent(eventlog.Event{
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
	executor := a.currentActionExecutor()
	if executor == nil {
		res := response.Result{Action: req.Action, Success: false, Detail: "action executor not configured"}
		rec := ResponseRecord{RuleID: rule.ID, Category: category, Subject: copyMap(subject), Object: copyMap(object), Request: req, Result: res}
		a.recordResponse(rec)
		_ = a.writeEvent(eventlog.Event{
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
		return
	}
	res := executor.Apply(req)
	rec := ResponseRecord{RuleID: rule.ID, Category: category, Subject: copyMap(subject), Object: copyMap(object), Request: req, Result: res}
	a.recordResponse(rec)
	_ = a.writeEvent(eventlog.Event{
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
			case bpf.EventPrivesc:
				a.handleFastPathPrivesc(ev)
			case bpf.EventModuleLoad:
				a.handleFastPathModuleLoad(ev)
			case bpf.EventModuleUnload:
				a.handleFastPathModuleUnload(ev)
			case bpf.EventBPFOp:
				a.handleFastPathBPFOp(ev)
			case bpf.EventFileOp:
				a.handleFastPathFileOp(ev)
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
	pol := a.currentPolicy()
	if pol == nil {
		return
	}
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
		a.logEvent(eventlog.Event{
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
		executor := a.currentActionExecutor()
		if executor == nil {
			return
		}
		res := executor.Apply(req)
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
	startTicks := readProcStartTicks(ev.PID)
	subj := policy.Subject{
		ProcessName: ev.Comm,
		ProcessPath: procPath,
		User:        fmt.Sprintf("%d", ev.UID),
		Environ:     "LD_PRELOAD=" + ev.Filename,
	}
	pol := a.currentPolicy()
	if pol == nil {
		return
	}
	now := time.Now()
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	if len(rules) == 0 {
		return
	}
	resp, audits := policy.AggregatedDecision(rules)
	for _, r := range audits {
		a.logEvent(eventlog.Event{
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
		if resp.ID == "ATT002-ld-preload-injection" && isProcessGone(ev.PID) {
			a.recordResponse(ResponseRecord{
				RuleID: resp.ID,
				Category: "process",
				Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "ld_preload": ev.Filename},
				Request: response.ActionRequest{Action: resp.Action, PID: int(ev.PID), RuleID: resp.ID},
				Result: response.Result{Action: resp.Action, Success: true, Detail: "already terminated by ring0 fast path"},
			})
			return
		}
		req := response.ActionRequest{
			Action: resp.Action, PID: int(ev.PID),
			ProcessPath: procPath, StartTicks: startTicks, RuleID: resp.ID,
		}
		if req.StartTicks != "" {
			// exec-transition events can race /proc/PID/exe updates. Keep the
			// stable start_ticks identity and let the responder re-resolve exe.
			req.ProcessPath = ""
		}
		if req.ProcessPath == "" && req.StartTicks == "" {
			// LD_PRELOAD fires at exec time; a very short-lived process may be gone
			// from /proc before userspace can enrich it. Allow a pidfd-only kill
			// fallback for this transient fast-path case.
			req.TransientOK = true
		}
		executor := a.currentActionExecutor()
		if executor == nil {
			return
		}
		res := executor.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "ld_preload": ev.Filename},
			Request: req, Result: res,
		})
	}
}

func readProcStartTicks(pid uint32) string {
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	return procutil.StartTicksFromStat(string(statData))
}

func isProcessGone(pid uint32) bool {
	err := syscall.Kill(int(pid), 0)
	return err == syscall.ESRCH
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
	pol := a.currentPolicy()
	if pol == nil {
		return
	}
	now := time.Now()
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	if len(rules) == 0 {
		return
	}
	resp, audits := policy.AggregatedDecision(rules)
	for _, r := range audits {
		a.logEvent(eventlog.Event{
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
		executor := a.currentActionExecutor()
		if executor == nil {
			return
		}
		res := executor.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "mapped_file": mappedPath},
			Request: req, Result: res,
		})
	}
}

func (a *Agent) handleFastPathPrivesc(ev bpf.Event) {
	procPath := resolveProcExe(ev.PID)
	privType := "setuid"
	switch ev.Reserved {
	case 1:
		privType = "setuid"
	case 2:
		privType = "setgid"
	case 3:
		privType = "capset"
	}
	now := time.Now()
	// Always log privesc events — the BPF probe is the detection mechanism.
	// Policy rules can add blocking (kill) for specific patterns.
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("privesc-%s-%d-%d", privType, ev.PID, now.UnixNano()),
		Category: "privilege_escalation",
		Severity: "high",
		Subject: map[string]any{
			"pid":      ev.PID,
			"name":     ev.Comm,
			"path":     procPath,
			"old_val":  ev.PPID,
			"new_val":  ev.UID,
			"privtype": privType,
		},
		Action:   "alert",
		Decision: "alert",
		RuleID:   "privesc-bpf-probe",
	})
	// Also check policy rules for additional actions (kill, block, etc.)
	subj := policy.Subject{
		ProcessName: ev.Comm,
		ProcessPath: procPath,
		User:        fmt.Sprintf("%d", ev.UID),
	}
	pol := a.currentPolicy()
	if pol == nil {
		return
	}
	rules := pol.EvaluateAll(now, subj, policy.Object{})
	resp, _ := policy.AggregatedDecision(rules)
	if resp != nil && resp.Action != "none" {
		req := response.ActionRequest{
			Action: resp.Action, PID: int(ev.PID),
			ProcessPath: procPath, RuleID: resp.ID,
		}
		executor := a.currentActionExecutor()
		if executor == nil {
			return
		}
		res := executor.Apply(req)
		a.recordResponse(ResponseRecord{
			RuleID: resp.ID, Category: "process",
			Subject: map[string]any{"pid": ev.PID, "name": ev.Comm, "privtype": privType, "old_val": ev.PPID, "new_val": ev.UID},
			Request: req, Result: res,
		})
	}
}

func (a *Agent) handleFastPathModuleLoad(ev bpf.Event) {
	subj := map[string]any{
		"pid":  ev.PID,
		"name": ev.Comm,
		"path": ev.Filename,
	}
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("rootkit-module-load-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "rootkit",
		Severity: "critical",
		Subject:  subj,
		Action:   "network_isolate",
		Decision: "alert",
		RuleID:   "ROOTKIT-001",
	})
	if a.RootkitDetector != nil && a.RootkitDetector.MonitorOnly {
		return
	}
	executor := a.currentActionExecutor()
	if executor == nil {
		return
	}
	res := executor.Apply(response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-001"})
	a.recordResponse(ResponseRecord{
		RuleID: "ROOTKIT-001", Category: "rootkit",
		Subject: subj, Request: response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-001"},
		Result: res,
	})
}

func (a *Agent) handleFastPathModuleUnload(ev bpf.Event) {
	subj := map[string]any{
		"pid":  ev.PID,
		"name": ev.Comm,
		"path": ev.Filename,
	}
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("rootkit-module-unload-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "rootkit",
		Severity: "critical",
		Subject:  subj,
		Action:   "network_isolate",
		Decision: "alert",
		RuleID:   "ROOTKIT-003",
	})
	if a.RootkitDetector != nil && a.RootkitDetector.MonitorOnly {
		return
	}
	executor := a.currentActionExecutor()
	if executor == nil {
		return
	}
	res := executor.Apply(response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-003"})
	a.recordResponse(ResponseRecord{
		RuleID: "ROOTKIT-003", Category: "rootkit",
		Subject: subj, Request: response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-003"},
		Result: res,
	})
}

func (a *Agent) handleFastPathBPFOp(ev bpf.Event) {
	subj := map[string]any{
		"pid":     ev.PID,
		"name":    ev.Comm,
		"bpf_cmd": ev.Reserved,
		"detail":  ev.Filename,
	}
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("rootkit-bpf-op-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "rootkit",
		Severity: "critical",
		Subject:  subj,
		Action:   "network_isolate",
		Decision: "alert",
		RuleID:   "ROOTKIT-005",
	})
	if a.RootkitDetector != nil && a.RootkitDetector.MonitorOnly {
		return
	}
	executor := a.currentActionExecutor()
	if executor == nil {
		return
	}
	res := executor.Apply(response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-005"})
	a.recordResponse(ResponseRecord{
		RuleID: "ROOTKIT-005", Category: "rootkit",
		Subject: subj, Request: response.ActionRequest{Action: "network_isolate", RuleID: "ROOTKIT-005"},
		Result: res,
	})
}

// handleFastPathFileOp processes file operation events (unlink,
// unlinkat, renameat) from the file_mon BPF probe. Events are
// logged and evaluated by the policy engine against file rules.
// v0.9.1: file operation monitoring.
func (a *Agent) handleFastPathFileOp(ev bpf.Event) {
	if a.currentAuditSink() == nil {
		return
	}
	opNames := map[uint32]string{1: "unlinkat", 2: "unlink", 3: "renameat"}
	opName := opNames[ev.Reserved]
	if opName == "" {
		opName = "unknown"
	}

	subj := map[string]any{
		"pid":      ev.PID,
		"comm":     ev.Comm,
		"filename": ev.Filename,
		"file_op":  opName,
		"uid":      ev.UID,
	}
	a.logEvent(eventlog.Event{
		EventID:  fmt.Sprintf("file-op-%d-%d", ev.PID, time.Now().UnixNano()),
		Category: "file",
		Severity: "medium",
		Subject:  subj,
		Action:   "observe",
		Decision: "alert",
		RuleID:   "FILEOP-001",
	})
}

func (a *Agent) handleFastPathSelfProtect(ev bpf.Event) {
	if a.currentAuditSink() == nil {
		return
	}
	a.logEvent(eventlog.Event{
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
	pol := a.currentPolicy()
	if pol == nil {
		return
	}
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
	a.logEvent(eventlog.Event{
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
