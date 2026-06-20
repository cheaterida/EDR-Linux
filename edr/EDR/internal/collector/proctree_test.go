package collector

import (
	"testing"
)

func TestTreeUpdate(t *testing.T) {
	var tree Tree
	snap := &Snapshot{
		Processes: []Process{
			{PID: 1, PPID: 0, Name: "init"},
			{PID: 100, PPID: 1, Name: "sshd"},
			{PID: 200, PPID: 100, Name: "bash"},
			{PID: 300, PPID: 200, Name: "nc"},
		},
	}
	tree.Update(snap)

	if tree.Size() != 4 {
		t.Fatalf("expected 4 nodes, got %d", tree.Size())
	}

	// Check children
	n1 := tree.Get(1)
	if n1 == nil {
		t.Fatal("pid 1 not found")
	}
	if len(n1.Children) != 1 || n1.Children[0] != 100 {
		t.Fatalf("pid 1 children: %v", n1.Children)
	}

	// Ancestors of nc (pid 300)
	anc := tree.Ancestors(300)
	if len(anc) != 4 {
		t.Fatalf("expected 4 ancestors for pid 300, got %d", len(anc))
	}
	if anc[0].PID != 300 || anc[1].PID != 200 || anc[2].PID != 100 || anc[3].PID != 1 {
		t.Fatalf("wrong ancestor chain: %v", anc)
	}

	// Descendants of sshd (pid 100)
	desc := tree.Descendants(100)
	if len(desc) != 2 {
		t.Fatalf("expected 2 descendants for pid 100, got %d", len(desc))
	}

	// Update with process exit
	snap2 := &Snapshot{
		Processes: []Process{
			{PID: 1, PPID: 0, Name: "init"},
			{PID: 100, PPID: 1, Name: "sshd"},
			{PID: 200, PPID: 100, Name: "bash"},
		},
	}
	tree.Update(snap2)
	if tree.Size() != 4 { // still has 4 nodes, nc marked as exited
		t.Fatalf("expected 4 nodes (nc retained with exit time), got %d", tree.Size())
	}
	ncNode := tree.Get(300)
	if ncNode == nil {
		t.Fatal("nc node should be retained after exit")
	}
	if ncNode.ExitTime.IsZero() {
		t.Fatal("nc should have exit time set")
	}
}

func TestTreeEmpty(t *testing.T) {
	var tree Tree
	if tree.Get(1) != nil {
		t.Fatal("empty tree should return nil")
	}
	if tree.Ancestors(1) != nil {
		t.Fatal("empty tree ancestors should be nil")
	}
	if tree.Descendants(1) != nil {
		t.Fatal("empty tree descendants should be nil")
	}
}
