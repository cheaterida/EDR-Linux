package eventlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AnchorRecord is the payload pushed to the remote anchor on each tick.
type AnchorRecord struct {
	ChainID   string    `json:"chain_id"`
	Seq       uint64    `json:"seq"`
	Hash      string    `json:"hash"`
	HMAC      string    `json:"hmac,omitempty"`
	PushedAt  time.Time `json:"pushed_at"`
	Hostname  string    `json:"hostname"`
	BootID    string    `json:"boot_id"`
}

// Anchor periodically pushes the latest chain head to an external
// endpoint (HTTP or file mirror) so that log truncation by a root
// attacker can be detected during verify.
type Anchor struct {
	mu       sync.Mutex
	url      string
	filePath string
	hostname string
	bootID   string
	client   *http.Client
	lastSeq  uint64
}

// AnchorOptions configures an Anchor.
type AnchorOptions struct {
	URL      string        // HTTP endpoint (optional)
	FilePath string        // file mirror path (optional)
	Interval time.Duration // push interval; 0 defaults to 60s
	Hostname string
	BootID   string
}

// NewAnchor returns an Anchor that pushes to at least one of URL or
// FilePath. If both are empty the anchor is a no-op.
func NewAnchor(opts AnchorOptions) *Anchor {
	if opts.URL == "" && opts.FilePath == "" {
		return nil
	}
	if opts.Interval <= 0 {
		opts.Interval = 60 * time.Second
	}
	return &Anchor{
		url:      opts.URL,
		filePath: opts.FilePath,
		hostname: opts.Hostname,
		bootID:   opts.BootID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Push sends the current chain head to all configured backends.
// Seq=0 is silently ignored (no events have been written yet).
func (a *Anchor) Push(chainID string, seq uint64, hash, hmac string) error {
	if a == nil || seq == 0 {
		return nil
	}
	a.mu.Lock()
	if seq <= a.lastSeq {
		a.mu.Unlock()
		return nil
	}
	a.lastSeq = seq
	a.mu.Unlock()

	rec := AnchorRecord{
		ChainID:  chainID,
		Seq:      seq,
		Hash:     hash,
		HMAC:     hmac,
		PushedAt: time.Now().UTC(),
		Hostname: a.hostname,
		BootID:   a.bootID,
	}

	var firstErr error
	if a.url != "" {
		if err := a.pushHTTP(rec); err != nil {
			firstErr = err
		}
	}
	if a.filePath != "" {
		if err := a.pushFile(rec); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Fetch retrieves the last known anchor record from the primary backend
// (HTTP first, then file mirror). Returns nil if no anchor is available.
func (a *Anchor) Fetch() (*AnchorRecord, error) {
	if a == nil {
		return nil, nil
	}
	if a.url != "" {
		return a.fetchHTTP()
	}
	if a.filePath != "" {
		return a.fetchFile()
	}
	return nil, nil
}

// Start begins a background goroutine that calls PushFn at each
// interval. PushFn is a callback that returns the current chain head.
// Returns a stop function that shuts down the goroutine.
func (a *Anchor) Start(pushFn func() (chainID string, seq uint64, hash, hmac string)) (stop func()) {
	if a == nil || pushFn == nil {
		return func() {}
	}
	ticker := time.NewTicker(60 * time.Second)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cid, seq, hash, hmac := pushFn()
				_ = a.Push(cid, seq, hash, hmac)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

func (a *Anchor) pushHTTP(rec AnchorRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	resp, err := a.client.Post(a.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("anchor push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("anchor push: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *Anchor) fetchHTTP() (*AnchorRecord, error) {
	resp, err := a.client.Get(a.url)
	if err != nil {
		return nil, fmt.Errorf("anchor fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("anchor fetch: HTTP %d", resp.StatusCode)
	}
	var rec AnchorRecord
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&rec); err != nil {
		return nil, fmt.Errorf("anchor fetch: %w", err)
	}
	return &rec, nil
}

func (a *Anchor) pushFile(rec AnchorRecord) error {
	if err := os.MkdirAll(filepath.Dir(a.filePath), 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(a.filePath, raw, 0o640)
}

func (a *Anchor) fetchFile() (*AnchorRecord, error) {
	raw, err := os.ReadFile(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec AnchorRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// CrossVerify compares the local chain state against the remote anchor.
// Returns issues when the anchor has a higher seq than local (truncation)
// or when hashes don't match for the same seq (tampering).
func (a *Anchor) CrossVerify(localChainID string, localSeq uint64, localHash string) []map[string]any {
	if a == nil {
		return nil
	}
	rec, err := a.Fetch()
	if err != nil || rec == nil {
		return nil
	}
	var issues []map[string]any
	if rec.ChainID != localChainID {
		issues = append(issues, map[string]any{
			"kind":         "anchor_chain_mismatch",
			"local_chain":  localChainID,
			"anchor_chain": rec.ChainID,
		})
	}
	if rec.Seq > localSeq {
		issues = append(issues, map[string]any{
			"kind":        "anchor_truncation",
			"anchor_seq":  rec.Seq,
			"local_seq":   localSeq,
			"detail":      "remote anchor has more events than local log — possible deletion",
		})
	}
	if rec.Seq == localSeq && rec.Hash != "" && localHash != "" && rec.Hash != localHash {
		issues = append(issues, map[string]any{
			"kind":         "anchor_hash_mismatch",
			"anchor_hash":  rec.Hash,
			"local_hash":   localHash,
			"seq":          rec.Seq,
		})
	}
	return issues
}
