package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"edr/internal/collector"
)

type ForensicsBundle struct {
	SchemaVersion string             `json:"schema_version"`
	ExportedAt    time.Time          `json:"exported_at"`
	Metrics       map[string]any     `json:"metrics"`
	Policy        any                `json:"policy"`
	Responses     []ResponseRecord   `json:"responses"`
	Snapshot      collector.Snapshot `json:"snapshot"`
	Events        []map[string]any   `json:"events"`
	EventSummary  map[string]any     `json:"event_summary"`
	ProcessTree   any                `json:"process_tree,omitempty"`
	RuleHitCounts map[string]uint64  `json:"rule_hit_counts,omitempty"`
}

func ExportForensics(agent *Agent, eventPath, outPath string, eventLimit int) (ForensicsBundle, error) {
	if eventLimit <= 0 {
		eventLimit = 200
	}
	snap, err := agent.Collector.Snapshot()
	if err != nil {
		return ForensicsBundle{}, err
	}
	events, err := queryEvents(eventPath, eventQuery{Limit: eventLimit})
	if err != nil {
		return ForensicsBundle{}, err
	}
	metrics := agent.Metrics()
	ruleHits, _ := metrics["rule_hits"].(map[string]uint64)
	bundle := ForensicsBundle{
		SchemaVersion: "v0.1",
		ExportedAt:    time.Now().UTC(),
		Metrics:       metrics,
		Policy:        agent.CurrentPolicy(),
		Responses:     agent.ResponseHistory(0),
		Snapshot:      snap,
		Events:        events.Events,
		EventSummary: map[string]any{
			"count":  events.Count,
			"total":  events.Total,
			"limit":  events.Limit,
			"offset": events.Offset,
		},
		RuleHitCounts: ruleHits,
	}
	if outPath != "" {
		if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
			return ForensicsBundle{}, err
		}
		raw, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return ForensicsBundle{}, err
		}
		if err := os.WriteFile(outPath, append(raw, '\n'), 0o640); err != nil {
			return ForensicsBundle{}, err
		}
	}
	return bundle, nil
}
