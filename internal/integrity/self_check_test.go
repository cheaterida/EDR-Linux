package integrity

import (
	"errors"
	"testing"
)

type mockBPFReader struct {
	heartbeat uint64
	agentPID  uint32
	err       error
}

func (m *mockBPFReader) ReadHeartbeat() (uint64, error) { return m.heartbeat, m.err }
func (m *mockBPFReader) ReadAgentPID() (uint32, error)   { return m.agentPID, m.err }

func TestSelfCheckBPFMaps(t *testing.T) {
	tests := []struct {
		name     string
		agentPID uint32
		err      error
		wantPass bool
		detail   string
	}{
		{
			name:     "valid PID",
			agentPID: 1234,
			err:      nil,
			wantPass: true,
		},
		{
			name:     "zero PID — tampered",
			agentPID: 0,
			err:      nil,
			wantPass: false,
			detail:   "agent_pid map contains zero",
		},
		{
			name:     "read error",
			agentPID: 0,
			err:      errors.New("map not found"),
			wantPass: false,
			detail:   "agent_pid map read error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockBPFReader{agentPID: tt.agentPID, err: tt.err}
			sc := &SelfCheck{heartbeat: reader}
			result := sc.checkBPFMaps()
			if result.Passed != tt.wantPass {
				t.Errorf("checkBPFMaps() = %v, want %v (detail: %s)", result.Passed, tt.wantPass, result.Detail)
			}
		})
	}
}

func TestSelfCheckBPFHeartbeatStale(t *testing.T) {
	reader := &mockBPFReader{heartbeat: 1000}
	sc := &SelfCheck{heartbeat: reader}

	// First check — baseline
	r := sc.checkBPFHeartbeat()
	if !r.Passed {
		t.Fatalf("baseline heartbeat should pass: %s", r.Detail)
	}
	if sc.lastBeat != 1000 {
		t.Fatalf("lastBeat should be 1000, got %d", sc.lastBeat)
	}

	// Same heartbeat — should detect stale
	r = sc.checkBPFHeartbeat()
	if r.Passed {
		t.Error("stale heartbeat should be detected")
	}
}

func TestSelfCheckBPFHeartbeatUpdated(t *testing.T) {
	reader := &mockBPFReader{heartbeat: 1000}
	sc := &SelfCheck{heartbeat: reader}

	sc.checkBPFHeartbeat() // baseline at 1000

	// New heartbeat value
	reader.heartbeat = 2000
	sc.beatStale = true // reset stale flag

	r := sc.checkBPFHeartbeat()
	if !r.Passed {
		t.Errorf("updated heartbeat should pass: %s", r.Detail)
	}
	if sc.lastBeat != 2000 {
		t.Errorf("lastBeat should be 2000, got %d", sc.lastBeat)
	}
}

func TestSelfCheckNoReader(t *testing.T) {
	sc := &SelfCheck{heartbeat: nil}

	r := sc.checkBPFHeartbeat()
	if !r.Passed {
		t.Error("nil reader should pass (gracefully skip)")
	}

	r = sc.checkBPFMaps()
	if !r.Passed {
		t.Error("nil reader for maps should pass (gracefully skip)")
	}
}
