package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Suppressor cuts down event volume by enforcing three independent
// gates per (category, rule, dedup-key) tuple:
//
//  1. Cooldown: at most one emit per process/file/network Cooldown
//     window for the same dedup key.
//  2. Rate limit: a per-rule token bucket caps the number of emits
//     per second across all keys for the rule.
//  3. Default effect: when Allow is consulted with a category the
//     Suppressor does not recognise, the call is allowed (the
//     unknown category is treated as a passthrough).
//
// State is in-memory only: a restart resets all dedup timers. This
// is deliberate for v0.15 — the alternative (persisted dedup
// state) has a non-trivial cost in startup time and crash-recovery
// semantics, and is better folded into the v0.16 anchor work.
type Suppressor struct {
	mu              sync.Mutex
	processCooldown time.Duration
	fileCooldown    time.Duration
	networkCooldown time.Duration
	ratePerSec      float64
	burst           float64
	lastSeen        map[string]time.Time
	buckets         map[string]*tokenBucket
	evictCounter    int // calls since last eviction sweep
}

type tokenBucket struct {
	Tokens float64   `json:"tokens"`
	Last   time.Time `json:"last"`
}

// SuppressorOptions configures a Suppressor. Zero values fall back to
// the documented defaults so callers can leave the struct empty
// during tests.
type SuppressorOptions struct {
	ProcessCooldown time.Duration
	FileCooldown    time.Duration
	NetworkCooldown time.Duration
	RatePerSec      uint64
	Burst           uint64
	Now             func() time.Time
}

const (
	defaultProcessCooldown = 30 * time.Second
	defaultFileCooldown    = 60 * time.Second
	defaultNetworkCooldown = 30 * time.Second
	defaultRatePerSec      = 10
)

// NewSuppressor returns a Suppressor initialised with sane defaults
// for any zero-valued cooldown. RatePerSec is left untouched so a
// caller can pass 0 to disable rate limiting entirely (the field
// must be set explicitly).
func NewSuppressor(opts SuppressorOptions) *Suppressor {
	if opts.ProcessCooldown <= 0 {
		opts.ProcessCooldown = defaultProcessCooldown
	}
	if opts.FileCooldown <= 0 {
		opts.FileCooldown = defaultFileCooldown
	}
	if opts.NetworkCooldown <= 0 {
		opts.NetworkCooldown = defaultNetworkCooldown
	}
	rate := float64(opts.RatePerSec)
	burst := float64(opts.Burst)
	if burst == 0 && rate > 0 {
		burst = rate
	}
	return &Suppressor{
		processCooldown: opts.ProcessCooldown,
		fileCooldown:    opts.FileCooldown,
		networkCooldown: opts.NetworkCooldown,
		ratePerSec:      rate,
		burst:           burst,
		lastSeen:        map[string]time.Time{},
		buckets:         map[string]*tokenBucket{},
	}
}

// Reason values returned by Allow. Exposed as constants so the
// agent can record them in metrics without re-typing the strings.
const (
	ReasonCooldown  = "cooldown"
	ReasonRateLimit = "rate_limit"
)

// Allow reports whether the event is allowed to be emitted. The
// reason is "" when allowed, otherwise one of the Reason* constants.
//
// The key is the per-event dedup key, typically built with
// DedupKey. The ruleID is the policy rule that matched — it owns
// the rate-limit bucket.
func (s *Suppressor) Allow(category, ruleID, key string) (bool, string) {
	if s == nil {
		return true, ""
	}
	cooldown := s.cooldownFor(category)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cooldown > 0 {
		if last, ok := s.lastSeen[key]; ok && now.Sub(last) < cooldown {
			return false, ReasonCooldown
		}
	}
	if s.ratePerSec > 0 && ruleID != "" {
		if !s.consumeToken(ruleID, now) {
			return false, ReasonRateLimit
		}
	}
	s.lastSeen[key] = now
	s.evictCounter++
	if s.evictCounter >= 1000 {
		s.evictCounter = 0
		s.evictStale(now)
	}
	return true, ""
}

// Stats returns a snapshot of the suppressor's bookkeeping, useful
// for diagnostics and metrics.
func (s *Suppressor) Stats() (tracked int, rules int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lastSeen), len(s.buckets)
}

// evictStale removes lastSeen entries older than 2x the longest
// cooldown. Must be called with s.mu held.
func (s *Suppressor) evictStale(now time.Time) {
	maxCooldown := s.fileCooldown
	if s.processCooldown > maxCooldown {
		maxCooldown = s.processCooldown
	}
	if s.networkCooldown > maxCooldown {
		maxCooldown = s.networkCooldown
	}
	threshold := maxCooldown * 2
	if threshold == 0 {
		threshold = 2 * time.Minute
	}
	for key, last := range s.lastSeen {
		if now.Sub(last) > threshold {
			delete(s.lastSeen, key)
		}
	}
}

// Snapshot returns a summary of suppressor state for the health endpoint.
func (s *Suppressor) Snapshot() map[string]any {
	if s == nil {
		return map[string]any{"active": false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"active":         true,
		"tracked_events": len(s.lastSeen),
		"active_rules":   len(s.buckets),
	}
}

type suppressorPersist struct {
	LastSeen     map[string]time.Time    `json:"last_seen"`
	BucketTokens map[string]*tokenBucket `json:"bucket_tokens"`
}

// SaveState serialises the suppressor's in-memory dedup and
// rate-limit state to a JSON file so it survives restarts.
func (s *Suppressor) SaveState(path string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	ls := make(map[string]time.Time, len(s.lastSeen))
	for k, v := range s.lastSeen {
		ls[k] = v
	}
	bt := make(map[string]*tokenBucket, len(s.buckets))
	for k, v := range s.buckets {
		bt[k] = v
	}
	s.mu.Unlock()

	state := suppressorPersist{LastSeen: ls, BucketTokens: bt}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// LoadState restores the suppressor state previously written by
// SaveState. Missing files are silently ignored (they mean a fresh
// start). Corrupt files return an error but the suppressor remains
// usable with empty state.
func (s *Suppressor) LoadState(path string) error {
	if s == nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var state suppressorPersist
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.LastSeen != nil {
		s.lastSeen = state.LastSeen
	}
	if state.BucketTokens != nil {
		s.buckets = state.BucketTokens
	}
	return nil
}

func (s *Suppressor) cooldownFor(category string) time.Duration {
	switch category {
	case "process":
		return s.processCooldown
	case "file":
		return s.fileCooldown
	case "network":
		return s.networkCooldown
	default:
		return 0
	}
}

func (s *Suppressor) consumeToken(ruleID string, now time.Time) bool {
	bucket, ok := s.buckets[ruleID]
	if !ok {
		bucket = &tokenBucket{Tokens: s.burst, Last: now}
		s.buckets[ruleID] = bucket
	}
	elapsed := now.Sub(bucket.Last).Seconds()
	bucket.Tokens += elapsed * s.ratePerSec
	if bucket.Tokens > s.burst {
		bucket.Tokens = s.burst
	}
	bucket.Last = now
	if bucket.Tokens < 1 {
		return false
	}
	bucket.Tokens--
	return true
}

// DedupKey builds the per-event suppression key. The format mirrors
// the four-axis design the user agreed on (rule, identity, op).
func DedupKey(category, ruleID string, parts ...string) string {
	out := category + ":" + ruleID
	for _, p := range parts {
		if p == "" {
			continue
		}
		out += ":" + p
	}
	return out
}
