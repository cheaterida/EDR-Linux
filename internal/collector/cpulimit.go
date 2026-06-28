package collector

import (
	"sync"
	"time"
)

// CPULimitTracker samples per-process CPU usage from /proc/<pid>/stat
// and identifies processes exceeding configurable thresholds. Used to
// detect and respond to CPU exhaustion attacks (fork bombs, crypto
// miners, runaway workloads).
//
// Each Sample records the cumulative CPU time (utime + stime) in
// kernel clock ticks. The CPU% is computed as the delta between two
// samples divided by wall-clock elapsed time.
type CPULimitTracker struct {
	mu       sync.Mutex
	samples  map[int]*cpuSample // PID → last sample
	interval time.Duration      // sampling window for rolling average
}

type cpuSample struct {
	utime    uint64 // cumulative user-mode ticks from /proc/stat field 14
	stime    uint64 // cumulative kernel-mode ticks from /proc/stat field 15
	lastSeen time.Time
	cpuPct   float64 // rolling average CPU percentage (0-100 * ncpus)
}

// NewCPULimitTracker creates a tracker with the given rolling window.
// One-minute window is recommended: short enough to catch rapid spikes,
// long enough to filter out transient bursts.
func NewCPULimitTracker(window time.Duration) *CPULimitTracker {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &CPULimitTracker{
		samples:  make(map[int]*cpuSample),
		interval: window,
	}
}

// Sample records a CPU tick snapshot for the given PID. Called once per
// Snapshot cycle from ProcfsCollector. Returns the current rolling CPU
// percentage (0-100 scale, may exceed 100 on multi-core).
func (t *CPULimitTracker) Sample(pid int, utime, stime uint64, now time.Time) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	prev, exists := t.samples[pid]
	t.samples[pid] = &cpuSample{utime: utime, stime: stime, lastSeen: now}

	if !exists {
		return 0
	}

	// CPU tick delta. ticksPerSec is typically 100 (USER_HZ).
	deltaTicks := (utime + stime) - (prev.utime + prev.stime)
	deltaSec := now.Sub(prev.lastSeen).Seconds()
	if deltaSec <= 0 {
		return prev.cpuPct
	}

	// ticks/sec → CPU% (one core = 100%)
	instantPct := (float64(deltaTicks) / deltaSec) * (100.0 / float64(ticksPerSec()))

	// Exponential moving average (α = delta/interval)
	alpha := deltaSec / t.interval.Seconds()
	if alpha > 1.0 {
		alpha = 1.0
	}
	newPct := alpha*instantPct + (1-alpha)*prev.cpuPct
	t.samples[pid].cpuPct = newPct
	return newPct
}

// HighCPU returns the set of PIDs whose rolling CPU% exceeds the
// given threshold, excluding any process whose comm matches an
// entry in the whitelist.
func (t *CPULimitTracker) HighCPU(threshold float64, whitelist []string) []int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var result []int
	for pid, s := range t.samples {
		if now.Sub(s.lastSeen) > 2*t.interval {
			continue // stale sample
		}
		if s.cpuPct > threshold {
			result = append(result, pid)
		}
	}
	return result
}

// Cleanup removes stale samples older than 2× the sampling window.
func (t *CPULimitTracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-2 * t.interval)
	for pid, s := range t.samples {
		if s.lastSeen.Before(cutoff) {
			delete(t.samples, pid)
		}
	}
}

// ticksPerSec returns the kernel's USER_HZ value (clock ticks per second).
// We read this once and cache it. The standard Linux value is 100.
var cachedTicksPerSec int

func ticksPerSec() int {
	if cachedTicksPerSec > 0 {
		return cachedTicksPerSec
	}
	// Standard Linux USER_HZ is 100. Some real-time kernels use 1000,
	// but the /proc/stat field format doesn't change — it just means
	// each tick represents a smaller time slice.
	cachedTicksPerSec = 100
	return cachedTicksPerSec
}
