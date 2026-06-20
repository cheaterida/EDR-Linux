package liveness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Heartbeat struct {
	InstanceID        string    `json:"instance_id"`
	BootID            string    `json:"boot_id"`
	PID               int       `json:"pid"`
	StartTime         time.Time `json:"start_time"`
	Seq               uint64    `json:"seq"`
	State             string    `json:"state"`
	Components        map[string]string `json:"components,omitempty"`
	LeaseID           string    `json:"lease_id,omitempty"`
	RestartGeneration uint64    `json:"restart_generation"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func Path(runDir, instanceID string) string {
	return filepath.Join(runDir, fmt.Sprintf("%s.heartbeat", instanceID))
}

func Write(runDir string, hb Heartbeat) error {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	hb.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(hb)
	if err != nil {
		return err
	}
	tmp := Path(runDir, hb.InstanceID) + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, Path(runDir, hb.InstanceID))
}

func Read(runDir, instanceID string) (Heartbeat, error) {
	var hb Heartbeat
	raw, err := os.ReadFile(Path(runDir, instanceID))
	if err != nil {
		return hb, err
	}
	if err := json.Unmarshal(raw, &hb); err != nil {
		return hb, err
	}
	return hb, nil
}

func State(now time.Time, hb Heartbeat, suspectAfter, downAfter int, every time.Duration) string {
	switch hb.State {
	case "down", "suspect", "starting":
		return hb.State
	}
	if hb.UpdatedAt.IsZero() {
		return "unknown"
	}
	miss := int(now.Sub(hb.UpdatedAt) / every)
	switch {
	case miss >= downAfter:
		return "down"
	case miss >= suspectAfter:
		return "suspect"
	default:
		return "healthy"
	}
}
