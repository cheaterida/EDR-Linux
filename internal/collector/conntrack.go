package collector

import (
	"sync"
	"time"
)

// ConnTracker tracks connection frequency per remote address using a
// sliding window. It detects potential C2 beacon patterns by checking
// if connections fall within a configurable interval range.
type ConnTracker struct {
	mu      sync.Mutex
	window  time.Duration
	buckets map[string]*connBucket
}

type connBucket struct {
	timestamps []time.Time
}

// ConnStats holds connection statistics for a remote address.
type ConnStats struct {
	Addr        string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	IsBeacon    bool
	AvgInterval time.Duration
}

// NewConnTracker creates a tracker with the given sliding window duration.
func NewConnTracker(window time.Duration) *ConnTracker {
	return &ConnTracker{
		window:  window,
		buckets: make(map[string]*connBucket),
	}
}

// Record logs a connection to the given remote address at the given time.
func (ct *ConnTracker) Record(addr string, now time.Time) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	b, ok := ct.buckets[addr]
	if !ok {
		b = &connBucket{}
		ct.buckets[addr] = b
	}
	b.timestamps = append(b.timestamps, now)
	ct.pruneLocked(b, now)
}

// Stats returns connection stats for a specific address.
func (ct *ConnTracker) Stats(addr string) ConnStats {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	b, ok := ct.buckets[addr]
	if !ok {
		return ConnStats{Addr: addr}
	}
	now := time.Now()
	ct.pruneLocked(b, now)
	return ct.buildStats(addr, b)
}

// AllStats returns connection stats for all tracked addresses.
func (ct *ConnTracker) AllStats() []ConnStats {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	now := time.Now()
	out := make([]ConnStats, 0, len(ct.buckets))
	for addr, b := range ct.buckets {
		ct.pruneLocked(b, now)
		if len(b.timestamps) > 0 {
			out = append(out, ct.buildStats(addr, b))
		}
	}
	return out
}

// CheckBeacon checks if the given address exhibits beacon-like behavior
// (connections within the specified interval range, at least minCount times).
func (ct *ConnTracker) CheckBeacon(addr string, minCount int, minInterval, maxInterval time.Duration) bool {
	stats := ct.Stats(addr)
	if stats.Count < minCount {
		return false
	}
	if minInterval <= 0 || maxInterval <= 0 {
		return false
	}
	if stats.AvgInterval < minInterval || stats.AvgInterval > maxInterval {
		return false
	}
	return true
}

// Cleanup removes stale entries (addresses with no recent connections).
func (ct *ConnTracker) Cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	now := time.Now()
	for addr, b := range ct.buckets {
		ct.pruneLocked(b, now)
		if len(b.timestamps) == 0 {
			delete(ct.buckets, addr)
		}
	}
}

func (ct *ConnTracker) pruneLocked(b *connBucket, now time.Time) {
	cutoff := now.Add(-ct.window)
	i := 0
	for i < len(b.timestamps) && b.timestamps[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		b.timestamps = b.timestamps[i:]
	}
}

func (ct *ConnTracker) buildStats(addr string, b *connBucket) ConnStats {
	s := ConnStats{
		Addr:      addr,
		Count:     len(b.timestamps),
		FirstSeen: b.timestamps[0],
		LastSeen:  b.timestamps[len(b.timestamps)-1],
	}
	if len(b.timestamps) >= 2 {
		var total time.Duration
		for i := 1; i < len(b.timestamps); i++ {
			total += b.timestamps[i].Sub(b.timestamps[i-1])
		}
		s.AvgInterval = total / time.Duration(len(b.timestamps)-1)
	}
	return s
}
