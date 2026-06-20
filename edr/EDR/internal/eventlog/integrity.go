package eventlog

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// IntegrityVersion is stamped on every event that participates in the
// v0.15 hash chain. Older (v0.1) events lack this field and are
// recognised as legacy segments on verify.
const IntegrityVersion = "v0.15"

// IntegrityOptions configures hash-chain and HMAC signing on the
// Logger. When EnableChain is false the logger behaves exactly as in
// v0.1 and ignores every other field.
type IntegrityOptions struct {
	EnableChain bool
	Algorithm   string
	Key         []byte
	StatePath   string
	OnError     func(err error)
}

func (o IntegrityOptions) algorithm() string {
	if o.Algorithm == "" {
		return "sha256"
	}
	return o.Algorithm
}

func (o IntegrityOptions) statePathFor(eventPath string) string {
	if o.StatePath != "" {
		return o.StatePath
	}
	return eventPath + ".state"
}

// ChainState is the on-disk bookkeeping the writer maintains between
// runs. It is the only source of truth for the chain head; the event
// file itself is reconstructable from it.
type ChainState struct {
	ChainID    string `json:"chain_id"`
	LastSeq    uint64 `json:"last_seq"`
	LastHash   string `json:"last_hash"`
	LastHMAC   string `json:"last_hmac,omitempty"`
	Algorithm  string `json:"algorithm"`
	LegacyAck  bool   `json:"legacy_acked"`
	HasHMACKey bool   `json:"has_hmac_key,omitempty"`
}

func loadState(path string) (ChainState, error) {
	var s ChainState
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("parse chain state: %w", err)
	}
	return s, nil
}

func saveState(path string, s ChainState) error {
	if err := os.MkdirAll(parentDir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// IntegrityIssue describes one anomaly found by Verify.
type IntegrityIssue struct {
	Line     int    `json:"line"`
	Seq      uint64 `json:"seq,omitempty"`
	Kind     string `json:"kind"` // "hash_mismatch", "prev_hash_break", "hmac_mismatch", "malformed"
	Detail   string `json:"detail,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// LegacySegment records a contiguous run of v0.1 lines that precede
// the v0.15 chain. They are retained for forensics but cannot be
// hash-verified.
type LegacySegment struct {
	FromLine int `json:"from_line"`
	ToLine   int `json:"to_line"`
	Count    int `json:"count"`
}

// VerifyResult is returned by Verify and is the body of the
// /v0/events/verify control-plane endpoint.
type VerifyResult struct {
	OK            bool             `json:"ok"`
	ChainID       string           `json:"chain_id,omitempty"`
	LastSeq       uint64           `json:"last_seq"`
	LastHash      string           `json:"last_hash,omitempty"`
	Algorithm     string           `json:"algorithm,omitempty"`
	HasHMACKey    bool             `json:"has_hmac_key"`
	LinesScanned  int              `json:"lines_scanned"`
	ChainLines    int              `json:"chain_lines"`
	LegacyLines   int              `json:"legacy_lines"`
	LegacySegment []LegacySegment  `json:"legacy_segments,omitempty"`
	Issues        []IntegrityIssue `json:"issues,omitempty"`
}

// stripIntegrity zeroes the fields that are computed during write so
// the same canonical bytes can be reproduced on verify. We mutate a
// shallow copy because the caller still wants the populated event for
// downstream use.
func stripIntegrity(e *Event) {
	e.Hash = ""
	e.HMAC = ""
}

func chainEventBytes(e Event) ([]byte, error) {
	stripIntegrity(&e)
	return json.Marshal(e)
}

func newHasher(algo string) (hash.Hash, error) {
	switch algo {
	case "", "sha256":
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported integrity algorithm %q", algo)
	}
}

func newChainID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "edr-chain-fallback"
	}
	return fmt.Sprintf("edr-%s", hex.EncodeToString(b[:]))
}

// sealChain computes the hash and optional HMAC for an event and
// updates the caller's state to reflect the new head. It returns the
// canonical bytes that must be written to disk so the file and the
// state never disagree.
func sealChain(state ChainState, e *Event, key []byte, algo string) (raw []byte, next ChainState, err error) {
	hasher, err := newHasher(algo)
	if err != nil {
		return nil, state, err
	}
	if state.ChainID == "" {
		state.ChainID = newChainID()
	}
	if state.Algorithm == "" {
		state.Algorithm = algo
	}
	state.LastSeq++
	e.IntegrityVersion = IntegrityVersion
	e.ChainID = state.ChainID
	e.Seq = state.LastSeq
	e.PrevHash = state.LastHash
	payload, err := chainEventBytes(*e)
	if err != nil {
		return nil, state, err
	}
	hasher.Reset()
	if _, err := hasher.Write([]byte(state.LastHash)); err != nil {
		return nil, state, err
	}
	if _, err := hasher.Write(payload); err != nil {
		return nil, state, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	e.Hash = digest
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(digest))
		e.HMAC = hex.EncodeToString(mac.Sum(nil))
		state.LastHMAC = e.HMAC
		state.HasHMACKey = true
	}
	out, err := json.Marshal(e)
	if err != nil {
		return nil, state, err
	}
	state.LastHash = digest
	return append(out, '\n'), state, nil
}

// Verify walks the event log, replays the chain, and reports any
// anomaly. It scans rotated files (.1, .2, ...) in chronological
// order so the chain is verified across rotation boundaries.
//
// It is safe to call while the Logger is still writing new events:
// the worst case is a spurious "prev_hash_break" on the last
// in-flight line, which the next verify will reconcile.
//
// The function is read-only with respect to the event file; it
// touches no state on disk. To roll a fresh chain after tampering,
// delete the state file before the next write.
func Verify(path string, key []byte) (VerifyResult, error) {
	res := VerifyResult{HasHMACKey: len(key) > 0}
	files, err := rotatedFiles(path)
	if err != nil {
		return res, err
	}
	if len(files) == 0 {
		res.OK = true
		return res, nil
	}

	var (
		prevHash   string
		currentSeq uint64
		chainOpen  bool
		legacyOpen *LegacySegment
		line       int
	)
	for _, fpath := range files {
		prevHash, currentSeq, chainOpen, legacyOpen, line = verifyOneFile(
			fpath, key, &res, prevHash, currentSeq, chainOpen, legacyOpen, line,
		)
	}
	if legacyOpen != nil {
		res.LegacySegment = append(res.LegacySegment, *legacyOpen)
	}
	res.ChainID = ""
	res.LastHash = prevHash
	res.LastSeq = currentSeq
	res.OK = len(res.Issues) == 0
	return res, nil
}

// rotatedFiles returns the list of log files to verify, in
// chronological order (oldest rotated file first, current file last).
// E.g. for path "events.jsonl" it may return
// ["events.jsonl.2", "events.jsonl.1", "events.jsonl"].
func rotatedFiles(path string) ([]string, error) {
	dir := parentDir(path)
	base := path
	if dir != "." {
		base = path[len(dir)+1:]
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var nums []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base+".") || name == base {
			continue
		}
		suffix := name[len(base)+1:]
		n, err := strconv.Atoi(suffix)
		if err == nil && n > 0 {
			nums = append(nums, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums))) // descending: .3, .2, .1 (oldest first)

	var files []string
	for _, n := range nums {
		files = append(files, fmt.Sprintf("%s.%d", path, n))
	}
	// Append the current (non-rotated) file last
	if _, err := os.Stat(path); err == nil {
		files = append(files, path)
	}
	return files, nil
}

// verifyOneFile scans a single log file and updates the VerifyResult.
// Returns updated chain state so the caller can chain across files.
func verifyOneFile(fpath string, key []byte, res *VerifyResult,
	prevHash string, currentSeq uint64, chainOpen bool,
	legacyOpen *LegacySegment, line int,
) (string, uint64, bool, *LegacySegment, int) {
	f, err := os.Open(fpath)
	if err != nil {
		res.Issues = append(res.Issues, IntegrityIssue{Line: line + 1, Kind: "malformed", Detail: fmt.Sprintf("open %s: %v", fpath, err)})
		return prevHash, currentSeq, chainOpen, legacyOpen, line
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			res.Issues = append(res.Issues, IntegrityIssue{Line: line + 1, Kind: "malformed", Detail: err.Error()})
			break
		}
		line++
		res.LinesScanned++

		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Issues = append(res.Issues, IntegrityIssue{Line: line, Kind: "malformed", Detail: err.Error()})
			if legacyOpen != nil {
				legacyOpen.ToLine = line
				legacyOpen.Count++
			} else {
				legacyOpen = &LegacySegment{FromLine: line, ToLine: line, Count: 1}
			}
			continue
		}
		if e.IntegrityVersion != IntegrityVersion {
			res.LegacyLines++
			if legacyOpen != nil {
				legacyOpen.ToLine = line
				legacyOpen.Count++
			} else {
				legacyOpen = &LegacySegment{FromLine: line, ToLine: line, Count: 1}
			}
			if chainOpen {
				chainOpen = false
			}
			continue
		}
		if legacyOpen != nil {
			res.LegacySegment = append(res.LegacySegment, *legacyOpen)
			legacyOpen = nil
		}
		if !chainOpen {
			chainOpen = true
		}
		res.ChainLines++
		if e.PrevHash != prevHash {
			res.Issues = append(res.Issues, IntegrityIssue{Line: line, Seq: e.Seq, Kind: "prev_hash_break", Expected: prevHash, Actual: e.PrevHash, Detail: "prev_hash does not match predecessor"})
		}
		expected, err := recomputeHash(e, prevHash)
		if err != nil {
			res.Issues = append(res.Issues, IntegrityIssue{Line: line, Seq: e.Seq, Kind: "malformed", Detail: err.Error()})
		} else if expected != e.Hash {
			res.Issues = append(res.Issues, IntegrityIssue{Line: line, Seq: e.Seq, Kind: "hash_mismatch", Expected: expected, Actual: e.Hash})
		}
		if len(key) > 0 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(e.Hash))
			want := hex.EncodeToString(mac.Sum(nil))
			if want != e.HMAC {
				res.Issues = append(res.Issues, IntegrityIssue{Line: line, Seq: e.Seq, Kind: "hmac_mismatch", Expected: want, Actual: e.HMAC})
			}
		}
		prevHash = e.Hash
		currentSeq = e.Seq
		res.Algorithm = e.IntegrityVersion
	}
	return prevHash, currentSeq, chainOpen, legacyOpen, line
}

func recomputeHash(e Event, prevHash string) (string, error) {
	hasher, err := newHasher("")
	if err != nil {
		return "", err
	}
	payload, err := chainEventBytes(e)
	if err != nil {
		return "", err
	}
	hasher.Reset()
	if _, err := hasher.Write([]byte(prevHash)); err != nil {
		return "", err
	}
	if _, err := hasher.Write(payload); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyOne validates the hash and optional HMAC on a single event line
// without scanning the full file. It returns the overall ok status, the
// event sequence number, and individual match results for hash and HMAC.
// Legacy events (no IntegrityVersion) pass trivially since they carry
// no integrity fields to verify.
func VerifyOne(line []byte, key []byte) (ok bool, seq uint64, hashMatch bool, hmacMatch bool) {
	if len(line) == 0 {
		return true, 0, true, true
	}
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return false, 0, false, false
	}
	if e.IntegrityVersion != IntegrityVersion {
		return true, e.Seq, true, true
	}
	seq = e.Seq
	expected, err := recomputeHash(e, e.PrevHash)
	if err != nil {
		return false, seq, false, false
	}
	hashMatch = expected == e.Hash
	hmacMatch = true
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(e.Hash))
		want := hex.EncodeToString(mac.Sum(nil))
		hmacMatch = want == e.HMAC
	}
	ok = hashMatch && hmacMatch
	return
}

// chainWriter is the in-memory companion the Logger uses to advance
// ChainState under its existing mutex. It is intentionally minimal —
// the on-disk file and state are the only authoritative records.
type chainWriter struct {
	mu       sync.Mutex
	enabled  bool
	key      []byte
	algo     string
	state    ChainState
	stateLk  sync.Mutex
	statePth string
	onError  func(error)
}

func newChainWriter(path string, opts IntegrityOptions) *chainWriter {
	if !opts.EnableChain {
		return &chainWriter{enabled: false}
	}
	cw := &chainWriter{
		enabled:  true,
		key:      opts.Key,
		algo:     opts.algorithm(),
		statePth: opts.statePathFor(path),
		onError:  opts.OnError,
	}
	s, err := loadState(cw.statePth)
	if err != nil {
		if cw.onError != nil {
			cw.onError(fmt.Errorf("load chain state: %w", err))
		}
		s = ChainState{}
	}
	// S13+S16: if state is empty (missing or corrupted), attempt
	// recovery by scanning the log file for the last chain event.
	if s.ChainID == "" || s.LastHash == "" {
		if recovered, ok := cw.recoverFromLog(path); ok {
			s = recovered
		}
	}
	cw.state = s
	return cw
}

func (c *chainWriter) Enabled() bool {
	return c != nil && c.enabled
}

// recoverFromLog scans the log file for the last chain event and
// recovers the chain state from it. This handles the case where
// the .state file was deleted or corrupted (S13+S16).
// Returns the recovered state and true on success, or zero state
// and false if recovery is not possible.
func (c *chainWriter) recoverFromLog(logPath string) (ChainState, bool) {
	// Also check rotated files (oldest first) to find any chain event.
	files := []string{logPath}
	if rotated, err := rotatedFiles(logPath); err == nil {
		files = append(rotated, logPath)
	}

	var lastState ChainState
	found := false
	for _, fpath := range files {
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for scanner.Scan() {
			var ev Event
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				continue
			}
			if ev.IntegrityVersion != IntegrityVersion {
				continue
			}
			if ev.Hash == "" || ev.ChainID == "" {
				continue
			}
			// Found a chain event. Update recovery state.
			lastState = ChainState{
				ChainID:    ev.ChainID,
				LastSeq:    ev.Seq,
				LastHash:   ev.Hash,
				LastHMAC:   ev.HMAC,
				Algorithm:  c.algo,
				HasHMACKey: len(c.key) > 0,
			}
			found = true
		}
		f.Close()
	}
	if found && c.onError != nil {
		c.onError(fmt.Errorf("chain state recovered from log file (state file was missing or corrupted)"))
	}
	return lastState, found
}

func (c *chainWriter) Seal(e *Event) ([]byte, error) {
	if !c.Enabled() {
		return nil, errChainDisabled
	}
	c.stateLk.Lock()
	raw, next, err := sealChain(c.state, e, c.key, c.algo)
	if err != nil {
		c.stateLk.Unlock()
		return nil, err
	}
	c.state = next
	c.stateLk.Unlock()
	if err := saveState(c.statePth, next); err != nil {
		if c.onError != nil {
			c.onError(err)
		}
	}
	return raw, nil
}

func (c *chainWriter) Snapshot() ChainState {
	if c == nil {
		return ChainState{}
	}
	c.stateLk.Lock()
	defer c.stateLk.Unlock()
	return c.state
}

var errChainDisabled = errors.New("eventlog: chain writer disabled")
