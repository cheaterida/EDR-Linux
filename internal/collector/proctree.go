package collector

import (
	"sort"
	"sync"
	"time"
)

// ProcNode is a single entry in the process lineage tree.
// Updated on every Snapshot from /proc data (authoritative) and
// enriched by BPF events for freshness.
type ProcNode struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	Name      string    `json:"name"`
	Path      string    `json:"path,omitempty"`
	Cmdline   string    `json:"cmdline,omitempty"`
	User      string    `json:"user,omitempty"`
	EUID      string    `json:"euid,omitempty"`
	CapEff    string    `json:"cap_eff,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	ExitTime  time.Time `json:"exit_time,omitempty"`
	StartTicks string   `json:"start_ticks,omitempty"`
	Children  []int     `json:"children"`
}

// Tree is a concurrency-safe in-memory process lineage index.
// It is rebuilt from /proc on every Snapshot and enriched by BPF
// fork/exec/exit events. The zero value is ready to use.
type Tree struct {
	mu        sync.RWMutex
	nodes     map[int]*ProcNode
	updatedAt time.Time
}

// Update replaces the tree from a Snapshot's process list. Called
// after drainBPF so ring0-enriched data is included.
func (t *Tree) Update(snap *Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.nodes == nil {
		t.nodes = make(map[int]*ProcNode, len(snap.Processes))
	}
	// Clear children slices — rebuilt below.
	for _, n := range t.nodes {
		n.Children = n.Children[:0]
	}
	seen := make(map[int]bool, len(snap.Processes))

	for _, p := range snap.Processes {
		n, ok := t.nodes[p.PID]
		if !ok {
			n = &ProcNode{}
			t.nodes[p.PID] = n
		}
		n.PID = p.PID
		n.PPID = p.PPID
		n.Name = p.Name
		n.Path = p.Path
		n.Cmdline = p.Cmdline
		n.User = p.User
		n.EUID = p.EUID
		n.CapEff = p.CapEff
		n.StartTicks = p.StartTicks
		n.ExitTime = time.Time{}
		seen[p.PID] = true
	}

	// Remove dead PIDs (exited between snapshots).
	for pid := range t.nodes {
		if !seen[pid] {
			if n := t.nodes[pid]; n.ExitTime.IsZero() {
				n.ExitTime = time.Now().UTC()
			}
		}
	}

	// Rebuild children lists.
	for pid, n := range t.nodes {
		if n.PPID > 0 {
			if parent, ok := t.nodes[n.PPID]; ok {
				parent.Children = append(parent.Children, pid)
			}
		}
	}

	// Sort children for deterministic output.
	for _, n := range t.nodes {
		sort.Ints(n.Children)
	}

	t.updatedAt = time.Now().UTC()
}

// Get returns the node for pid, or nil if not found.
func (t *Tree) Get(pid int) *ProcNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.nodes == nil {
		return nil
	}
	n := t.nodes[pid]
	if n == nil {
		return nil
	}
	cp := *n
	cp.Children = append([]int(nil), n.Children...)
	return &cp
}

// Ancestors returns the chain from pid up to PID 1 (inclusive).
func (t *Tree) Ancestors(pid int) []ProcNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.nodes == nil {
		return nil
	}
	var chain []ProcNode
	for pid > 0 {
		n, ok := t.nodes[pid]
		if !ok {
			break
		}
		chain = append(chain, *n)
		if n.PPID == pid {
			break
		}
		pid = n.PPID
	}
	return chain
}

// Descendants returns all PIDs in the subtree rooted at pid (BFS).
func (t *Tree) Descendants(pid int) []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.nodes == nil {
		return nil
	}
	var out []int
	queue := []int{pid}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		n, ok := t.nodes[cur]
		if !ok {
			continue
		}
		for _, c := range n.Children {
			out = append(out, c)
			queue = append(queue, c)
		}
	}
	return out
}

// Subtree returns the node at pid with all descendants nested.
func (t *Tree) Subtree(pid int) *ProcNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.nodes == nil {
		return nil
	}
	n, ok := t.nodes[pid]
	if !ok {
		return nil
	}
	return t.subtreeLocked(n)
}

func (t *Tree) subtreeLocked(n *ProcNode) *ProcNode {
	cp := *n
	cp.Children = append([]int(nil), n.Children...)
	// Not recursing into nested children for the flat JSON form —
	// the caller can use Children PIDs with Get for details.
	return &cp
}

// FullTree returns all nodes for serialization.
func (t *Tree) FullTree() map[int]*ProcNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int]*ProcNode, len(t.nodes))
	for pid, n := range t.nodes {
		cp := *n
		cp.Children = append([]int(nil), n.Children...)
		out[pid] = &cp
	}
	return out
}

// UpdatedAt returns the last rebuild timestamp.
func (t *Tree) UpdatedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.updatedAt
}

// Size returns the number of nodes.
func (t *Tree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.nodes)
}
