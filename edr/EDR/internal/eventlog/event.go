package eventlog

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const SchemaVersion = "v0.15"

type Event struct {
	SchemaVersion    string         `json:"schema_version"`
	IntegrityVersion string         `json:"integrity_version,omitempty"`
	ChainID          string         `json:"chain_id,omitempty"`
	Seq              uint64         `json:"seq,omitempty"`
	PrevHash         string         `json:"prev_hash,omitempty"`
	Hash             string         `json:"hash,omitempty"`
	HMAC             string         `json:"hmac,omitempty"`
	Timestamp        time.Time      `json:"timestamp"`
	EventID          string         `json:"event_id"`
	Host             string         `json:"host"`
	Category         string         `json:"category"`
	Severity         string         `json:"severity"`
	Subject          map[string]any `json:"subject,omitempty"`
	Object           map[string]any `json:"object,omitempty"`
	Action           string         `json:"action"`
	Decision         string         `json:"decision"`
	RuleID           string         `json:"rule_id,omitempty"`
	Evidence         map[string]any `json:"evidence,omitempty"`
}

type Options struct {
	EnableSyslog bool
	MaxBytes     int64
	MaxBackups   int
	Integrity    IntegrityOptions
	RemoteSyslog RemoteSyslogConfig
}

// RemoteSyslogConfig configures a remote syslog target (RFC 5424).
type RemoteSyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "udp" or "tcp", default "udp"
	Facility int    `json:"facility"` // syslog facility code, default LOG_DAEMON (3)
	AppName  string `json:"app_name"` // default "edr-agent"
}

type Logger struct {
	mu         sync.Mutex
	path       string
	host       string
	syslog     *syslog.Writer
	maxBytes   int64
	maxBackups int
	chain      *chainWriter
	remote     net.Conn
	remoteCfg  RemoteSyslogConfig
}

func New(path string, enableSyslog bool) (*Logger, error) {
	return NewWithOptions(path, Options{EnableSyslog: enableSyslog})
}

func NewWithOptions(path string, opts Options) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	l := &Logger{path: path, host: host, maxBytes: opts.MaxBytes, maxBackups: opts.MaxBackups, chain: newChainWriter(path, opts.Integrity)}
	if opts.EnableSyslog {
		w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "edr-agent")
		if err == nil {
			l.syslog = w
		}
	}
	if opts.RemoteSyslog.Enabled && opts.RemoteSyslog.Host != "" {
		cfg := opts.RemoteSyslog
		proto := cfg.Protocol
		if proto != "tcp" {
			proto = "udp"
		}
		port := cfg.Port
		if port <= 0 {
			port = 514
		}
		addr := fmt.Sprintf("%s:%d", cfg.Host, port)
		conn, err := net.Dial(proto, addr)
		if err == nil {
			l.remote = conn
			l.remoteCfg = cfg
		}
		// Silently skip if connection fails — remote syslog is best-effort
	}
	return l, nil
}

func (l *Logger) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.SchemaVersion == "" {
		e.SchemaVersion = SchemaVersion
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Host == "" {
		if l.host != "" {
			e.Host = l.host
		} else if host, err := os.Hostname(); err == nil {
			e.Host = host
		}
	}
	var raw []byte
	if l.chain != nil && l.chain.Enabled() {
		sealed, err := l.chain.Seal(&e)
		if err != nil {
			return err
		}
		raw = sealed
	} else {
		marshaled, err := json.Marshal(e)
		if err != nil {
			return err
		}
		raw = append(marshaled, '\n')
	}
	if err := l.rotateIfNeeded(int64(len(raw))); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if l.syslog != nil {
		stripHash(&e)
		if plain, err := json.Marshal(e); err == nil {
			_ = l.syslog.Info(string(plain))
		}
	}
	if l.remote != nil {
		stripHash(&e)
		if plain, err := json.Marshal(e); err == nil {
			_ = l.writeRemote(plain)
		}
	}
	return nil
}

func stripHash(e *Event) {
	e.HMAC = ""
	e.Hash = ""
}

// writeRemote sends a log line to the remote syslog in RFC 5424 format.
func (l *Logger) writeRemote(msg []byte) error {
	severity := int(syslog.LOG_INFO)
	facility := l.remoteCfg.Facility << 3
	if facility == 0 {
		facility = 3 << 3 // LOG_DAEMON
	}
	priority := facility | severity
	appName := l.remoteCfg.AppName
	if appName == "" {
		appName = "edr-agent"
	}
	// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	ts := time.Now().UTC().Format(time.RFC3339)
	hostname := l.host
	if hostname == "" {
		hostname = "-"
	}
	line := fmt.Sprintf("<%d>1 %s %s %s - - - %s\n", priority, ts, hostname, appName, string(msg))
	_, err := l.remote.Write([]byte(line))
	return err
}
func (l *Logger) ChainSnapshot() ChainState {
	if l == nil || l.chain == nil {
		return ChainState{}
	}
	return l.chain.Snapshot()
}

// Path returns the on-disk path of the event log. It is intended for
// the startup verify step, which needs to call Verify(path, key).
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close releases resources held by the logger (remote connection, syslog writer).
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.remote != nil {
		l.remote.Close()
		l.remote = nil
	}
	if l.syslog != nil {
		err := l.syslog.Close()
		l.syslog = nil
		return err
	}
	return nil
}

func (l *Logger) rotateIfNeeded(incoming int64) error {
	if l.maxBytes <= 0 {
		return nil
	}
	st, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size()+incoming <= l.maxBytes {
		return nil
	}
	if l.maxBackups <= 0 {
		l.maxBackups = 1
	}
	oldest := l.path + "." + strconv.Itoa(l.maxBackups)
	_ = os.Remove(oldest)
	for i := l.maxBackups - 1; i >= 1; i-- {
		src := l.path + "." + strconv.Itoa(i)
		dst := l.path + "." + strconv.Itoa(i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	if _, err := os.Stat(l.path); err == nil {
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return err
		}
	}
	return nil
}
