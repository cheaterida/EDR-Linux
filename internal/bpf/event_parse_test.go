package bpf

import (
	"encoding/binary"
	"testing"
	"time"
)

// putU32LE / putU16LE / putU64LE are tiny test helpers — they
// keep the table-style test cases readable.
func putU32(b []byte, off uint32, v uint32) {
	binary.LittleEndian.PutUint32(b[off:], v)
}

func putU16(b []byte, off uint32, v uint16) {
	binary.LittleEndian.PutUint16(b[off:], v)
}

func putU64(b []byte, off uint32, v uint64) {
	binary.LittleEndian.PutUint64(b[off:], v)
}

func putCString(b []byte, off uint32, s string) {
	copy(b[off:], s)
	// remaining bytes are already zero
}

func TestParseEvent_ShortBufferIsRejected(t *testing.T) {
	if _, err := ParseEvent(make([]byte, eventTotalSize-1)); err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestParseEvent_UnknownTypeIsRejected(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 99
	if _, err := ParseEvent(raw); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestParseEvent_ExecEvent(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 1 // EDR_EVENT_EXEC
	putU64(raw, eventOffTimestamp, 1234567890)
	putU32(raw, eventOffPID, 42)
	putU32(raw, eventOffPPID, 1)
	putU32(raw, eventOffTGID, 42)
	putU32(raw, eventOffUID, 1000)
	putCString(raw, eventOffComm, "ls")
	putCString(raw, eventOffFilename, "/bin/ls")

	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Type != EventExec {
		t.Errorf("Type: want exec, got %v", ev.Type)
	}
	if ev.PID != 42 || ev.PPID != 1 || ev.TGID != 42 || ev.UID != 1000 {
		t.Errorf("identity: pid=%d ppid=%d tgid=%d uid=%d", ev.PID, ev.PPID, ev.TGID, ev.UID)
	}
	if ev.Comm != "ls" {
		t.Errorf("Comm: want %q, got %q", "ls", ev.Comm)
	}
	if ev.Filename != "/bin/ls" {
		t.Errorf("Filename: want %q, got %q", "/bin/ls", ev.Filename)
	}
	if ev.Timestamp.UnixNano() != 1234567890 {
		t.Errorf("Timestamp: want 1234567890, got %d", ev.Timestamp.UnixNano())
	}
}

func TestParseEvent_ConnectEventV4(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 4 // EDR_EVENT_CONNECT
	putU32(raw, eventOffPID, 7)
	putCString(raw, eventOffComm, "curl")
	raw[eventOffFamily] = 2 // AF_INET
	putU16(raw, eventOffDPort, 443)
	// 1.2.3.4 in raw bytes (network order in the tracepoint)
	raw[eventOffDAddrV4+0] = 1
	raw[eventOffDAddrV4+1] = 2
	raw[eventOffDAddrV4+2] = 3
	raw[eventOffDAddrV4+3] = 4

	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Type != EventConnect {
		t.Errorf("Type: want connect, got %v", ev.Type)
	}
	if ev.DAddr != "1.2.3.4" {
		t.Errorf("DAddr: want 1.2.3.4, got %q", ev.DAddr)
	}
	if ev.DPort != 443 {
		t.Errorf("DPort: want 443, got %d", ev.DPort)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm: want curl, got %q", ev.Comm)
	}
}

func TestParseEvent_ConnectEventV6(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 4
	putU32(raw, eventOffPID, 8)
	putCString(raw, eventOffComm, "curl6")
	raw[eventOffFamily] = 10 // AF_INET6
	putU16(raw, eventOffDPort, 80)
	// ::1 in v6 raw bytes
	v6 := raw[eventOffDAddrV6 : eventOffDAddrV6+eventDAddrV6Size]
	for i := 0; i < 15; i++ {
		v6[i] = 0
	}
	v6[15] = 1

	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.DAddr != "::1" {
		t.Errorf("DAddr: want ::1, got %q", ev.DAddr)
	}
}

func TestParseEvent_ConnectEventUnknownFamilyLeavesDAddrEmpty(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 4
	putU32(raw, eventOffPID, 9)
	raw[eventOffFamily] = 1 // AF_UNIX — not handled
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.DAddr != "" {
		t.Errorf("DAddr: want empty for family 1, got %q", ev.DAddr)
	}
}

func TestParseEvent_ForkAndExitCarryNoPayload(t *testing.T) {
	for _, typ := range []uint8{2, 3} { // FORK, EXIT
		raw := make([]byte, eventTotalSize)
		raw[eventOffType] = typ
		putU32(raw, eventOffPID, 100)
		putCString(raw, eventOffComm, "x")
		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		if ev.Filename != "" {
			t.Errorf("type %d: Filename should be empty, got %q", typ, ev.Filename)
		}
		if ev.DAddr != "" {
			t.Errorf("type %d: DAddr should be empty, got %q", typ, ev.DAddr)
		}
	}
}

func TestParseEvent_ExtraBytesAreIgnored(t *testing.T) {
	// The ring buffer can in theory deliver a payload longer
	// than our struct (e.g. a future C struct with extra
	// trailing fields). ParseEvent must truncate, not crash.
	raw := make([]byte, eventTotalSize+64)
	raw[eventOffType] = 1
	putU32(raw, eventOffPID, 1)
	putCString(raw, eventOffComm, "a")
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Type != EventExec || ev.PID != 1 {
		t.Errorf("oversize parse: %+v", ev)
	}
}

func TestParseEvent_CommAndFilenameNULTermination(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 1
	putCString(raw, eventOffComm, "ls")
	putCString(raw, eventOffFilename, "/bin/ls")
	// Pad with garbage AFTER the NUL — the parser must stop at NUL.
	for i := eventOffComm + 3; i < eventOffComm+eventCommSize; i++ {
		raw[i] = 'X'
	}
	for i := eventOffFilename + 8; i < eventOffFilename+eventFilenameSize; i++ {
		raw[i] = 'Y'
	}
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Comm != "ls" {
		t.Errorf("Comm NUL-trim: got %q", ev.Comm)
	}
	if ev.Filename != "/bin/ls" {
		t.Errorf("Filename NUL-trim: got %q", ev.Filename)
	}
}

func TestParseEvent_TimestampIsUTC(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 1
	putU64(raw, eventOffTimestamp, 999)
	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp location: want UTC, got %v", ev.Timestamp.Location())
	}
	if ev.Timestamp.UnixNano() != 999 {
		t.Errorf("Timestamp: got %d", ev.Timestamp.UnixNano())
	}
}

func TestCStringN_NoNULReturnsFullString(t *testing.T) {
	if got := cStringN([]byte("abc")); got != "abc" {
		t.Errorf("no-NUL: got %q", got)
	}
}

func TestCStringN_NULInMiddleStopsAtNUL(t *testing.T) {
	if got := cStringN([]byte{'a', 0, 'b'}); got != "a" {
		t.Errorf("mid-NUL: got %q", got)
	}
}

func TestParseEvent_ModuleAndBPFOp(t *testing.T) {
	cases := []struct {
		typ      uint8
		wantType EventType
		filename string
		reserved uint32
	}{
		{11, EventModuleLoad, "evil.ko", 1},
		{12, EventModuleUnload, "evil", 3},
		{13, EventBPFOp, "BPF_PROG_LOAD", 5},
	}
	for _, c := range cases {
		raw := make([]byte, eventTotalSize)
		raw[eventOffType] = c.typ
		putU32(raw, eventOffPID, 1234)
		putU32(raw, eventOffReserved, c.reserved)
		putCString(raw, eventOffComm, "insmod")
		putCString(raw, eventOffFilename, c.filename)

		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatalf("type %d: %v", c.typ, err)
		}
		if ev.Type != c.wantType {
			t.Errorf("type %d: want %v, got %v", c.typ, c.wantType, ev.Type)
		}
		if ev.Filename != c.filename {
			t.Errorf("type %d: filename want %q, got %q", c.typ, c.filename, ev.Filename)
		}
		if ev.Reserved != c.reserved {
			t.Errorf("type %d: reserved want %d, got %d", c.typ, c.reserved, ev.Reserved)
		}
	}
}

func TestParseEvent_SelfProtect(t *testing.T) {
	raw := make([]byte, eventTotalSize)
	raw[eventOffType] = 5 // EDR_EVENT_SELFPROTECT
	putU64(raw, eventOffTimestamp, 9876543210)
	putU32(raw, eventOffPID, 12345) // attacker PID
	putU32(raw, eventOffPPID, 1)    // agent PID (target)
	putU32(raw, eventOffTGID, 12345)
	putU32(raw, eventOffUID, 1000)
	putCString(raw, eventOffComm, "bash")
	putCString(raw, eventOffFilename, "sys_kill")

	ev, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.Type != EventSelfProtect {
		t.Errorf("Type: want selfprotect, got %v", ev.Type)
	}
	if ev.PID != 12345 || ev.PPID != 1 {
		t.Errorf("PID=%d PPID=%d, want 12345, 1", ev.PID, ev.PPID)
	}
	if ev.Comm != "bash" {
		t.Errorf("Comm: want bash, got %q", ev.Comm)
	}
	if ev.Filename != "sys_kill" {
		t.Errorf("Filename: want sys_kill, got %q", ev.Filename)
	}
	if ev.Timestamp.UnixNano() != 9876543210 {
		t.Errorf("Timestamp: want 9876543210, got %d", ev.Timestamp.UnixNano())
	}
}
