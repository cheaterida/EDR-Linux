package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Event binary layout — the C side is internal/bpf/probes/common.bpf.h.
// These offsets MUST stay in lockstep with the C struct. Any change
// there is a schema break (R-L3) and must bump SchemaVersion.
//
// Total size: 330 bytes.
//
//	off  0  type            u8
//	off  1  _pad0[3]
//	off  4  _reserved       u32
//	off  8  timestamp_ns    u64
//	off 16  pid             u32
//	off 20  ppid            u32
//	off 24  tgid            u32
//	off 28  uid             u32
//	off 32  comm[16]        char[16]
//	off 48  filename[256]   char[256]
//	off 304 family          u8
//	off 305 _pad1[3]
//	off 308 dport           u16
//	off 310 daddr_v4[4]     u8[4]
//	off 314 daddr_v6[16]    u8[16]
const (
	eventOffType      = 0
	eventOffReserved  = 4  // _reserved: ptrace_enh uses for ptrace request
	eventOffTimestamp = 8
	eventOffPID       = 16
	eventOffPPID      = 20
	eventOffTGID      = 24
	eventOffUID       = 28
	eventOffComm      = 32
	eventCommSize     = 16
	eventOffFilename  = 48
	eventFilenameSize = 256
	eventOffFamily    = 304
	eventOffDPort     = 308
	eventOffDAddrV4   = 310
	eventDAddrV4Size  = 4
	eventOffDAddrV6   = 314
	eventDAddrV6Size  = 16
	eventTotalSize    = 330
)

// ParseEvent decodes one ring buffer payload into a Go Event.
// It is the pure-Go counterpart to the cgo callback in
// loader_libbpf.go and exists so the binary contract is
// unit-testable without a kernel or libbpf in the loop.
//
// raw must be exactly eventTotalSize bytes. Anything shorter is
// rejected as malformed; anything longer is truncated to the
// contract size. timestamp_ns is interpreted as kernel
// monotonic nanoseconds since boot, then wrapped in time.Time
// using time.Unix(0, ns). The wall-clock value is therefore
// off by the boot duration — agents that need a true
// wall-clock should subtract the boot offset (R-K4 backlog).
func ParseEvent(raw []byte) (Event, error) {
	if len(raw) < eventTotalSize {
		return Event{}, fmt.Errorf("bpf event: short buffer %d < %d", len(raw), eventTotalSize)
	}
	if len(raw) > eventTotalSize {
		raw = raw[:eventTotalSize]
	}
	typ := EventType(raw[eventOffType])
	switch typ {
	case EventExec, EventFork, EventExit, EventConnect, EventSelfProtect,
		EventPtraceEnh, EventLDPreload, EventInstrument, EventPrivesc,
		EventModuleLoad, EventModuleUnload, EventBPFOp:
	default:
		return Event{}, fmt.Errorf("bpf event: unknown type %d", typ)
	}
	ev := Event{
		Type:   typ,
		PID:    binary.LittleEndian.Uint32(raw[eventOffPID:]),
		PPID:   binary.LittleEndian.Uint32(raw[eventOffPPID:]),
		TGID:   binary.LittleEndian.Uint32(raw[eventOffTGID:]),
		UID:    binary.LittleEndian.Uint32(raw[eventOffUID:]),
		Comm:   cStringN(raw[eventOffComm : eventOffComm+eventCommSize]),
		Family: raw[eventOffFamily],
		DPort:  binary.LittleEndian.Uint16(raw[eventOffDPort:]),
	}
	ts := int64(binary.LittleEndian.Uint64(raw[eventOffTimestamp:]))
	ev.Timestamp = time.Unix(0, ts).UTC()

	if typ == EventExec || typ == EventSelfProtect || typ == EventPtraceEnh ||
		typ == EventLDPreload || typ == EventInstrument ||
		typ == EventModuleLoad || typ == EventModuleUnload || typ == EventBPFOp {
		ev.Filename = cStringN(raw[eventOffFilename : eventOffFilename+eventFilenameSize])
	}
	// ptrace_enh stores the ptrace request in _reserved; privesc stores the subtype;
	// module load/unload stores subtype/flags/fd; bpf_op stores the bpf cmd.
	if typ == EventPtraceEnh || typ == EventPrivesc ||
		typ == EventModuleLoad || typ == EventModuleUnload || typ == EventBPFOp {
		ev.Reserved = binary.LittleEndian.Uint32(raw[eventOffReserved:])
	}
	if typ == EventConnect {
		v4 := raw[eventOffDAddrV4 : eventOffDAddrV4+eventDAddrV4Size]
		v6 := raw[eventOffDAddrV6 : eventOffDAddrV6+eventDAddrV6Size]
		switch ev.Family {
		case 2: // AF_INET
			ev.DAddr = net.IPv4(v4[0], v4[1], v4[2], v4[3]).String()
		case 10: // AF_INET6
			ip := make(net.IP, net.IPv6len)
			copy(ip, v6)
			ev.DAddr = ip.String()
		}
	}
	return ev, nil
}

func cStringN(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}
