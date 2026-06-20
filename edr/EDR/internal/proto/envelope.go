package proto

import (
	"fmt"
	"time"

	"edr/internal/eventlog"
)

// EventEnvelope is the normalized event shape for the future
// sensor/orchestrator transport. Phase 1 keeps it as an internal bridge
// type so the single-process agent can converge on a stable schema
// before the data/control plane split.
type EventEnvelope struct {
	EventID          string         `json:"event_id"`
	InstanceID       string         `json:"instance_id,omitempty"`
	HostID           string         `json:"host_id,omitempty"`
	BootID           string         `json:"boot_id,omitempty"`
	SensorGeneration string         `json:"sensor_generation,omitempty"`
	Category         string         `json:"category"`
	Subtype          string         `json:"subtype,omitempty"`
	Severity         string         `json:"severity"`
	Timestamp        time.Time      `json:"timestamp"`
	Subject          map[string]any `json:"subject,omitempty"`
	Object           map[string]any `json:"object,omitempty"`
	Evidence         map[string]any `json:"evidence,omitempty"`
	LocalActionHint  string         `json:"local_action_hint,omitempty"`
	ChainSeq         uint64         `json:"chain_seq,omitempty"`
	ChainHash        string         `json:"chain_hash,omitempty"`
	Signature        string         `json:"signature,omitempty"`
}

// FromEventlog normalizes the current audit event model into the future
// transport envelope without changing the on-disk event format.
func FromEventlog(ev eventlog.Event, instanceID, hostID, bootID string) EventEnvelope {
	subtype := ev.RuleID
	if subtype == "" {
		subtype = ev.Decision
	}
	return EventEnvelope{
		EventID:          ev.EventID,
		InstanceID:       instanceID,
		HostID:           hostID,
		BootID:           bootID,
		SensorGeneration: ev.SchemaVersion,
		Category:         ev.Category,
		Subtype:          subtype,
		Severity:         ev.Severity,
		Timestamp:        ev.Timestamp,
		Subject:          ev.Subject,
		Object:           ev.Object,
		Evidence:         ev.Evidence,
		LocalActionHint:  ev.Action,
		ChainSeq:         ev.Seq,
		ChainHash:        ev.Hash,
		Signature:        ev.HMAC,
	}
}

func (e EventEnvelope) Validate() error {
	if e.EventID == "" {
		return fmt.Errorf("event_id is required")
	}
	if e.Category == "" {
		return fmt.Errorf("category is required")
	}
	if e.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	return nil
}
