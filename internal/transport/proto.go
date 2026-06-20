package transport

import (
	"time"

	"edr/internal/collector"
	"edr/internal/proto"
	"edr/internal/response"
)

type SensorSnapshot struct {
	InstanceID string             `json:"instance_id"`
	HostID     string             `json:"host_id"`
	BootID     string             `json:"boot_id"`
	Timestamp  time.Time          `json:"timestamp"`
	Snapshot   collector.Snapshot `json:"snapshot"`
}

type EventBatch struct {
	RequestID  string                `json:"request_id"`
	InstanceID string                `json:"instance_id"`
	HostID     string                `json:"host_id"`
	BootID     string                `json:"boot_id"`
	RecordedAt time.Time             `json:"recorded_at"`
	Events     []proto.EventEnvelope `json:"events"`
}

func (b EventBatch) RequestAuthMeta() (string, time.Time, bool) {
	return b.RequestID, b.RecordedAt, true
}

type ActionEnvelope struct {
	RequestID   string                 `json:"request_id"`
	InstanceID  string                 `json:"instance_id"`
	Generation  uint64                 `json:"generation"`
	Request     response.ActionRequest `json:"request"`
	RequestedAt time.Time              `json:"requested_at"`
}

func (a ActionEnvelope) RequestAuthMeta() (string, time.Time, bool) {
	return a.RequestID, a.RequestedAt, true
}

type ActionResultEnvelope struct {
	RequestID   string          `json:"request_id"`
	InstanceID  string          `json:"instance_id"`
	Generation  uint64          `json:"generation"`
	Result      response.Result `json:"result"`
	CompletedAt time.Time       `json:"completed_at"`
}
