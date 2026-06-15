package metrics

import (
	"fmt"
	"io"
	"time"
)

// MetricsSource provides the data needed for Prometheus exposition.
type MetricsSource interface {
	Metrics() map[string]any
	BPFHealth() BPFHealthStatus
	ResponseHistory(limit int) []ResponseRecord
}

// BPFHealthStatus holds BPF subsystem health info.
type BPFHealthStatus struct {
	Attached       bool
	EventsDrained  uint64
	OverloadDrops  uint64
}

// ResponseRecord represents a response action for metrics.
type ResponseRecord struct {
	Action    string
	Timestamp time.Time
}

// WritePrometheus writes metrics in Prometheus text exposition format.
// Zero external dependencies — hand-rolled per the Prometheus spec.
func WritePrometheus(w io.Writer, src MetricsSource) {
	m := src.Metrics()

	// Counters
	writeCounter(w, "edr_events_total", "Total events processed", toUint64(m["event_count"]))
	writeCounter(w, "edr_responses_total", "Total response actions taken", toUint64(m["response_count"]))
	writeCounter(w, "edr_suppressed_total", "Total events suppressed", toUint64(m["suppressed_total"]))
	writeCounter(w, "edr_runs_total", "Total agent run cycles", toUint64(m["run_count"]))

	// Per-rule hit counters
	if ruleHits, ok := m["rule_hits"].(map[string]uint64); ok {
		for ruleID, count := range ruleHits {
			writeCounterWithLabel(w, "edr_rule_hits_total", "Total rule hits", "rule", ruleID, count)
		}
	}

	// Gauges
	if uptime, ok := m["uptime_sec"].(float64); ok {
		writeGauge(w, "edr_uptime_seconds", "Agent uptime in seconds", uptime)
	}
	if started, ok := m["started_at"].(time.Time); ok {
		writeGauge(w, "edr_started_at_timestamp", "Agent start time as Unix timestamp", float64(started.Unix()))
	}

	// BPF health
	bpf := src.BPFHealth()
	writeGaugeBool(w, "edr_bpf_attached", "Whether BPF probes are attached", bpf.Attached)
	writeCounter(w, "edr_bpf_events_drained_total", "Total BPF events drained from ring buffer", bpf.EventsDrained)
	writeCounter(w, "edr_bpf_overload_drops_total", "Total BPF events dropped due to ring buffer overload", bpf.OverloadDrops)

	// Response history size
	history := src.ResponseHistory(0)
	writeGauge(w, "edr_response_history_size", "Number of responses in history", float64(len(history)))
}

func writeCounter(w io.Writer, name, help string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, value)
}

func writeCounterWithLabel(w io.Writer, name, help, label, labelValue string, value uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", name, label, labelValue, value)
}

func writeGauge(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %g\n", name, value)
}

func writeGaugeBool(w io.Writer, name, help string, value bool) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	if value {
		fmt.Fprintf(w, "%s 1\n", name)
	} else {
		fmt.Fprintf(w, "%s 0\n", name)
	}
}

func toUint64(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	case int:
		return uint64(n)
	case float64:
		return uint64(n)
	default:
		return 0
	}
}
