package collector

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"edr/internal/procutil"
)

type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	User       string `json:"user,omitempty"`
	StartTicks string `json:"start_ticks,omitempty"`

	// v0.5 enrichment fields
	PPID        int    `json:"ppid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	EUID        string `json:"euid,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

type Connection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state"`
}

type FileEvent struct {
	Path    string    `json:"path"`
	Op      string    `json:"op"`
	Size    int64     `json:"size,omitempty"`
	Mode    string    `json:"mode,omitempty"`
	ModTime time.Time `json:"mod_time,omitempty"`
}

type Snapshot struct {
	Processes   []Process    `json:"processes"`
	Connections []Connection `json:"connections"`
	FileEvents  []FileEvent  `json:"file_events,omitempty"`
}

type Collector interface {
	Snapshot() (Snapshot, error)
}

type ProcfsCollector struct {
	ProcRoot      string
	WatchPaths    []string
	WatchMode     string
	lastFileState map[string]fileState

	mu         sync.Mutex
	inotifyFD  int
	watchMap   map[int]string
	inotifyErr error
}

type fileState struct {
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
}

func (c *ProcfsCollector) Snapshot() (Snapshot, error) {
	root := c.ProcRoot
	if root == "" {
		root = "/proc"
	}
	procs := readProcesses(root)
	conns := readNet(root)
	fileEvents := c.scanFileChanges()
	return Snapshot{Processes: procs, Connections: conns, FileEvents: fileEvents}, nil
}

type UnsupportedKernelCollector struct{}

func (UnsupportedKernelCollector) Snapshot() (Snapshot, error) {
	return Snapshot{}, fmt.Errorf("kernel collectors are reserved for v0.2 and unsupported in v0.1")
}

func readProcesses(root string) []Process {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]Process, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		nameBytes, _ := os.ReadFile(filepath.Join(dir, "comm"))
		cmdBytes, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		statBytes, _ := os.ReadFile(filepath.Join(dir, "stat"))
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))

		ppid := readPPIDFromStat(string(statBytes))
		parentName := readProcComm(root, ppid)
		euid := readProcEUID(dir)
		containerID := readProcCgroup(dir)

		out = append(out, Process{
			PID:         pid,
			Name:        strings.TrimSpace(string(nameBytes)),
			Path:        exe,
			Cmdline:     strings.ReplaceAll(strings.TrimRight(string(cmdBytes), "\x00"), "\x00", " "),
			User:        procutil.UserFromPID(pid),
			StartTicks:  procutil.StartTicksFromStat(string(statBytes)),
			PPID:        ppid,
			ParentName:  parentName,
			EUID:        euid,
			ContainerID: containerID,
		})
	}
	return out
}

// readPPIDFromStat extracts PPID (field 4) from /proc/pid/stat content.
func readPPIDFromStat(stat string) int {
	// stat format: pid (comm) state ppid ...
	// comm can contain spaces and parens, so find the last ')'
	closeParen := strings.LastIndex(stat, ")")
	if closeParen < 0 || closeParen+2 >= len(stat) {
		return 0
	}
	fields := strings.Fields(stat[closeParen+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// readProcComm reads the comm name for a given PID from /proc.
func readProcComm(root string, pid int) string {
	if pid <= 0 {
		return ""
	}
	comm, _ := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "comm"))
	return strings.TrimSpace(string(comm))
}

// readProcEUID reads the effective UID from /proc/pid/status.
func readProcEUID(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1] // second field is effective UID
			}
		}
	}
	return ""
}

// readProcCgroup extracts a container ID from /proc/pid/cgroup.
// Looks for docker or containerd cgroup entries and returns the
// last path component (the container ID).
func readProcCgroup(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
			parts := strings.Split(strings.TrimSpace(line), "/")
			if len(parts) > 0 {
				id := parts[len(parts)-1]
				if len(id) >= 12 { // container IDs are at least 12 hex chars
					return id
				}
			}
		}
	}
	return ""
}

func readNet(root string) []Connection {
	var out []Connection
	for _, item := range []struct {
		file  string
		proto string
	}{
		{"/net/tcp", "tcp"},
		{"/net/udp", "udp"},
	} {
		path := filepath.Join(root, item.file)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			localAddr, localPort := parseProcNetAddr(fields[1])
			remoteAddr, remotePort := parseProcNetAddr(fields[2])
			out = append(out, Connection{
				Protocol:   item.proto,
				LocalAddr:  localAddr,
				LocalPort:  localPort,
				RemoteAddr: remoteAddr,
				RemotePort: remotePort,
				State:      fields[3],
			})
		}
		_ = f.Close()
	}
	return out
}

func parseProcNetAddr(raw string) (string, int) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return raw, 0
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	if len(parts[0]) != 8 {
		return parts[0], int(port64)
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, _ := strconv.ParseUint(parts[0][i*2:i*2+2], 16, 8)
		b[3-i] = byte(v)
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String(), int(port64)
}

func (c *ProcfsCollector) scanFileChanges() []FileEvent {
	if len(c.WatchPaths) == 0 {
		return nil
	}
	if strings.EqualFold(c.WatchMode, "poll") {
		return c.scanFileChangesPoll()
	}
	if events := c.scanFileChangesInotify(); events != nil {
		return events
	}
	return c.scanFileChangesPoll()
}

func (c *ProcfsCollector) scanFileChangesPoll() []FileEvent {
	if c.lastFileState == nil {
		c.lastFileState = map[string]fileState{}
	}
	next := map[string]fileState{}
	var events []FileEvent
	for _, root := range c.WatchPaths {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			state := fileState{Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()}
			next[path] = state
			prev, ok := c.lastFileState[path]
			if !ok {
				events = append(events, newFileEvent(path, "create", info))
				return nil
			}
			if prev.Size != state.Size || prev.Mode != state.Mode || !prev.ModTime.Equal(state.ModTime) {
				events = append(events, newFileEvent(path, "write", info))
			}
			return nil
		})
	}
	for path, prev := range c.lastFileState {
		if _, ok := next[path]; !ok {
			events = append(events, FileEvent{Path: path, Op: "delete", Size: prev.Size, Mode: prev.Mode.Perm().String(), ModTime: prev.ModTime})
		}
	}
	c.lastFileState = next
	return events
}

func (c *ProcfsCollector) scanFileChangesInotify() []FileEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureInotify(); err != nil {
		c.inotifyErr = err
		return nil
	}
	buf := make([]byte, 8192)
	n, err := syscall.Read(c.inotifyFD, buf)
	if err != nil {
		if err == syscall.EAGAIN {
			return nil
		}
		c.inotifyErr = err
		return nil
	}
	var events []FileEvent
	for offset := 0; offset < n; {
		raw := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameStart := offset + syscall.SizeofInotifyEvent
		nameEnd := nameStart + int(raw.Len)
		nameBytes := buf[nameStart:nameEnd]
		name := strings.TrimRight(string(nameBytes), "\x00")
		base := c.watchMap[int(raw.Wd)]
		path := filepath.Join(base, name)
		if name == "" {
			path = base
		}
		if raw.Mask&syscall.IN_CREATE != 0 || raw.Mask&syscall.IN_MOVED_TO != 0 {
			events = append(events, statBackedFileEvent(path, "create"))
		}
		if raw.Mask&syscall.IN_MODIFY != 0 || raw.Mask&syscall.IN_CLOSE_WRITE != 0 {
			events = append(events, statBackedFileEvent(path, "write"))
		}
		if raw.Mask&syscall.IN_DELETE != 0 || raw.Mask&syscall.IN_MOVED_FROM != 0 {
			events = append(events, FileEvent{Path: path, Op: "delete"})
		}
		if raw.Mask&syscall.IN_ISDIR != 0 && (raw.Mask&syscall.IN_CREATE != 0 || raw.Mask&syscall.IN_MOVED_TO != 0) {
			// R-O1: a recursive watch failure (e.g. EACCES on a subdir) must not be
			// silently swallowed — record it so the operator can see blind spots.
			if err := c.addWatchRecursive(path); err != nil {
				c.inotifyErr = fmt.Errorf("add watch for new dir %q: %w", path, err)
			}
		}
		offset += syscall.SizeofInotifyEvent + int(raw.Len)
	}
	return compactFileEvents(events)
}

// Close releases the inotify file descriptor. It is safe to call
// multiple times or on a collector that never opened inotify.
func (c *ProcfsCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inotifyFD > 0 {
		syscall.Close(c.inotifyFD)
		c.inotifyFD = 0
	}
}

func (c *ProcfsCollector) ensureInotify() error {
	if c.inotifyFD > 0 {
		return nil
	}
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK)
	if err != nil {
		return err
	}
	c.inotifyFD = fd
	c.watchMap = map[int]string{}
	for _, root := range c.WatchPaths {
		if err := c.addWatchRecursive(root); err != nil {
			return err
		}
	}
	return nil
}

func (c *ProcfsCollector) addWatchRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.IsDir() {
			return nil
		}
		wd, err := syscall.InotifyAddWatch(c.inotifyFD, path, syscall.IN_CREATE|syscall.IN_MODIFY|syscall.IN_DELETE|syscall.IN_MOVED_FROM|syscall.IN_MOVED_TO|syscall.IN_CLOSE_WRITE)
		if err == nil {
			c.watchMap[wd] = path
		}
		return nil
	})
}

func compactFileEvents(events []FileEvent) []FileEvent {
	if len(events) == 0 {
		return nil
	}
	seen := map[string]FileEvent{}
	order := make([]string, 0, len(events))
	for _, event := range events {
		key := event.Op + ":" + event.Path
		if _, ok := seen[key]; !ok {
			order = append(order, key)
		}
		seen[key] = event
	}
	out := make([]FileEvent, 0, len(order))
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}

func statBackedFileEvent(path, op string) FileEvent {
	info, err := os.Stat(path)
	if err != nil {
		return FileEvent{Path: path, Op: op}
	}
	return newFileEvent(path, op, info)
}

func newFileEvent(path, op string, info os.FileInfo) FileEvent {
	return FileEvent{Path: path, Op: op, Size: info.Size(), Mode: info.Mode().Perm().String(), ModTime: info.ModTime()}
}
