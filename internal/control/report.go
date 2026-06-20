package control

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"edr/internal/eventlog"
)

// ReportRequest is the input for /v0/report/generate.
type ReportRequest struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// ReportPeriod describes the time window covered by the report.
type ReportPeriod struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

// ReportSummary provides top-level counts.
type ReportSummary struct {
	TotalEvents          int `json:"total_events"`
	TotalAlerts          int `json:"total_alerts"`
	TotalBlocks          int `json:"total_blocks"`
	RulesFired           int `json:"rules_fired"`
	HostsMonitored       int `json:"hosts_monitored"`
	FalsePositivesEst    int `json:"false_positives_estimated"`
}

// HostReport groups statistics per monitored host.
type HostReport struct {
	Host      string          `json:"host"`
	Alerts    int             `json:"alerts"`
	Blocks    int             `json:"blocks"`
	TopRules  []RuleHitCount  `json:"top_rules"`
}

// RuleHitCount tracks how many times a rule fired.
type RuleHitCount struct {
	RuleID   string `json:"rule_id"`
	Hits     int    `json:"hits"`
	Severity string `json:"severity"`
}

// RuleReport groups statistics per rule.
type RuleReport struct {
	RuleID   string   `json:"rule_id"`
	Hits     int      `json:"hits"`
	Severity string   `json:"severity"`
	Hosts    []string `json:"hosts"`
}

// TimelineEntry is a single alert event in chronological order.
type TimelineEntry struct {
	Time     string `json:"time"`
	Host     string `json:"host"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	PID      any    `json:"pid,omitempty"`
	Action   string `json:"action,omitempty"`
	Decision string `json:"decision"`
}

// AttackChain links related events by PID / process ancestry.
type AttackChain struct {
	RootPID int      `json:"root_pid"`
	Stages  []string `json:"stages"`
	Hosts   []string `json:"hosts"`
}

// Report is the full exercise post-mortem output.
type Report struct {
	Period       ReportPeriod     `json:"period"`
	Summary      ReportSummary    `json:"summary"`
	ByHost       []HostReport     `json:"by_host"`
	ByRule       []RuleReport     `json:"by_rule"`
	Timeline     []TimelineEntry  `json:"timeline"`
	AttackChains []AttackChain    `json:"attack_chains"`
	Responses    []ResponseRecord `json:"responses"`
	Integrity    json.RawMessage  `json:"integrity"`
}

// GenerateReport scans the event log and produces a structured report.
func GenerateReport(agent *Agent, eventPath string, hmacKey []byte, req ReportRequest) (Report, error) {
	// Scan events within the time range (reuse queryEvents).
	q := eventQuery{
		Limit:  100000, // scan all events, not paginated
		Offset: 0,
		Since:  req.Since,
		Until:  req.Until,
	}
	result, err := queryEvents(eventPath, q)
	if err != nil {
		return Report{}, fmt.Errorf("scan events: %w", err)
	}

	r := Report{
		Period: ReportPeriod{Since: req.Since, Until: req.Until},
	}
	r.buildSummary(result.Events)
	r.buildByHost(result.Events)
	r.buildByRule(result.Events)
	r.buildTimeline(result.Events)
	r.buildAttackChains(agent)

	// Response history
	recs := agent.ResponseHistory(10000)
	r.Responses = make([]ResponseRecord, len(recs))
	copy(r.Responses, recs)

	// Integrity
	if hmacKey != nil && eventPath != "" {
		_, err := os.Stat(eventPath)
		if err == nil {
			vRes, vErr := eventlog.Verify(eventPath, hmacKey)
			if vErr == nil {
				data, _ := json.Marshal(map[string]any{
					"ok":       vRes.OK,
					"chain_id": vRes.ChainID,
					"issues":   vRes.Issues,
				})
				r.Integrity = data
			}
		}
	}

	return r, nil
}

func (r *Report) buildSummary(events []map[string]any) {
	r.Summary.TotalEvents = len(events)
	hosts := map[string]bool{}
	rulesFired := map[string]bool{}
	perPIDRule := map[string]int{} // "pid:rule_id" -> count

	for _, e := range events {
		decision, _ := e["decision"].(string)
		if decision == "block" || decision == "deny" {
			r.Summary.TotalBlocks++
		}
		if decision != "" && decision != "allow" {
			r.Summary.TotalAlerts++
		}
		if ruleID, ok := e["rule_id"].(string); ok && ruleID != "" {
			rulesFired[ruleID] = true
		}
		if host, ok := e["host"].(string); ok && host != "" {
			hosts[host] = true
		}
		// Estimate false positives: same rule firing on same PID > 5 times
		pid := fmt.Sprint(e["pid"])
		rid, _ := e["rule_id"].(string)
		key := pid + ":" + rid
		perPIDRule[key]++
	}
	r.Summary.RulesFired = len(rulesFired)
	r.Summary.HostsMonitored = len(hosts)
	for _, v := range perPIDRule {
		if v > 5 {
			r.Summary.FalsePositivesEst++
		}
	}
}

func (r *Report) buildByHost(events []map[string]any) {
	hostMap := map[string]*HostReport{}
	for _, e := range events {
		host, _ := e["host"].(string)
		if host == "" {
			continue
		}
		hr, ok := hostMap[host]
		if !ok {
			hr = &HostReport{Host: host}
			hostMap[host] = hr
		}
		decision, _ := e["decision"].(string)
		if decision == "block" || decision == "deny" {
			hr.Blocks++
		}
		if decision != "" && decision != "allow" {
			hr.Alerts++
		}
	}
	for _, hr := range hostMap {
		r.ByHost = append(r.ByHost, *hr)
	}
	sort.Slice(r.ByHost, func(i, j int) bool { return r.ByHost[i].Alerts > r.ByHost[j].Alerts })
}

func (r *Report) buildByRule(events []map[string]any) {
	ruleMap := map[string]*RuleReport{}
	for _, e := range events {
		rid, _ := e["rule_id"].(string)
		if rid == "" {
			continue
		}
		rr, ok := ruleMap[rid]
		if !ok {
			rr = &RuleReport{RuleID: rid, Severity: stringField(e, "severity")}
			ruleMap[rid] = rr
		}
		rr.Hits++
		host, _ := e["host"].(string)
		if host != "" && !containsStr(rr.Hosts, host) {
			rr.Hosts = append(rr.Hosts, host)
		}
	}
	for _, rr := range ruleMap {
		r.ByRule = append(r.ByRule, *rr)
	}
	sort.Slice(r.ByRule, func(i, j int) bool { return r.ByRule[i].Hits > r.ByRule[j].Hits })
}

func (r *Report) buildTimeline(events []map[string]any) {
	// Only include non-allow events in timeline.
	for _, e := range events {
		decision, _ := e["decision"].(string)
		if decision == "allow" || decision == "" {
			continue
		}
		ts, _ := e["timestamp"].(string)
		r.Timeline = append(r.Timeline, TimelineEntry{
			Time:     ts,
			Host:     stringField(e, "host"),
			RuleID:   stringField(e, "rule_id"),
			Severity: stringField(e, "severity"),
			Category: stringField(e, "category"),
			PID:      e["pid"],
			Action:   stringField(e, "action"),
			Decision: decision,
		})
	}
	sort.Slice(r.Timeline, func(i, j int) bool { return r.Timeline[i].Time < r.Timeline[j].Time })
}

func (r *Report) buildAttackChains(agent *Agent) {
	if agent == nil || agent.ProcTree() == nil {
		return
	}
	// Walk the process tree to find PIDs with descendant alerts.
	// collectAlertPIDs returns the set of PIDs that triggered non-allow events.
	// Since we don't have easy access to events here, we return a placeholder.
	// The caller can enrich with event data.
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
