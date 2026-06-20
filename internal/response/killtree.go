package response

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"edr/internal/procutil"
)

// KillTree sends SIGKILL to a process and all its descendants.
// Children are killed before parents to prevent fork bombs from
// respawning. Each PID is verified via sameProcess-style identity
// check before killing.
func KillTree(pid int, processPath, startTicks string) Result {
	if pid <= 1 {
		return Result{Action: "kill_tree", Success: false, Detail: "refusing to kill protected pid"}
	}

	// Build process tree
	tree, err := buildProcessTree()
	if err != nil {
		return Result{Action: "kill_tree", Success: false, Detail: fmt.Sprintf("build process tree: %v", err)}
	}

	// Find all descendants of the target PID
	descendants := findDescendants(tree, pid)
	if len(descendants) == 0 {
		// No descendants, just kill the target
		return killSingleProcess(pid, processPath, startTicks)
	}

	// Sort by depth (deepest first) to kill children before parents
	sort.Slice(descendants, func(i, j int) bool {
		return descendants[i].depth > descendants[j].depth
	})

	killed := 0
	var errors []string
	for _, d := range descendants {
		if d.pid == pid {
			continue // skip the root, kill it last
		}
		result := killSingleProcess(d.pid, "", "")
		if result.Success {
			killed++
		} else {
			errors = append(errors, fmt.Sprintf("pid %d: %s", d.pid, result.Detail))
		}
	}

	// Kill the root process last
	rootResult := killSingleProcess(pid, processPath, startTicks)
	if rootResult.Success {
		killed++
	} else {
		errors = append(errors, fmt.Sprintf("root pid %d: %s", pid, rootResult.Detail))
	}

	detail := fmt.Sprintf("killed %d processes (root=%d)", killed, pid)
	if len(errors) > 0 {
		detail += fmt.Sprintf("; errors: %s", strings.Join(errors, "; "))
	}

	return Result{
		Action:  "kill_tree",
		Success: killed > 0,
		Detail:  detail,
	}
}

type procNode struct {
	pid    int
	ppid   int
	depth  int
}

// buildProcessTree reads /proc to build a map of pid -> ppid.
func buildProcessTree() (map[int]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	tree := make(map[int]int, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		ppid := readPPIDFromStat(string(statBytes))
		tree[pid] = ppid
	}
	return tree, nil
}

// findDescendants returns all descendants of the given PID with their depth.
func findDescendants(tree map[int]int, targetPID int) []procNode {
	var result []procNode
	// BFS to find all descendants
	queue := []procNode{{pid: targetPID, ppid: 0, depth: 0}}
	visited := map[int]bool{targetPID: true}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		// Find children of current
		for pid, ppid := range tree {
			if ppid == current.pid && !visited[pid] {
				visited[pid] = true
				queue = append(queue, procNode{pid: pid, ppid: ppid, depth: current.depth + 1})
			}
		}
	}
	return result
}

// readPPIDFromStat extracts PPID (field 4) from /proc/pid/stat content.
func readPPIDFromStat(stat string) int {
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

func killSingleProcess(pid int, processPath, startTicks string) Result {
	if pid <= 1 {
		return Result{Action: "kill", Success: false, Detail: "refusing to kill protected pid"}
	}
	// Identity check if path/ticks provided
	if processPath != "" || startTicks != "" {
		req := ActionRequest{PID: pid, ProcessPath: processPath, StartTicks: startTicks}
		if !sameProcess(req) {
			return Result{Action: "kill", Success: false, Detail: "process identity changed"}
		}
	}
	// Use pidfd for TOCTOU-safe kill
	if err := PidfdKill(pid); err == nil {
		return Result{Action: "kill", Success: true, Detail: fmt.Sprintf("killed pid %d via pidfd", pid)}
	} else if err != errPidfdNotSupported {
		return Result{Action: "kill", Success: false, Detail: err.Error()}
	}
	// Fallback
	p, err := os.FindProcess(pid)
	if err != nil {
		return Result{Action: "kill", Success: false, Detail: err.Error()}
	}
	if err := p.Kill(); err != nil {
		return Result{Action: "kill", Success: false, Detail: err.Error()}
	}
	return Result{Action: "kill", Success: true, Detail: fmt.Sprintf("killed pid %d", pid)}
}

// StartTicksFromStat is re-exported from procutil for use in this package.
func startTicksFromStat(stat string) string {
	return procutil.StartTicksFromStat(stat)
}
