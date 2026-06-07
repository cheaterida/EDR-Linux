package response

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixPermissionsRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	res := SoftResponder{}.Apply(ActionRequest{Action: "fix_permissions", Path: link})
	if res.Success || res.Detail == "" {
		t.Fatalf("expected symlink refusal, got %#v", res)
	}
}

func TestFixPermissionsAppliesToRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := SoftResponder{}.Apply(ActionRequest{Action: "fix_permissions", Path: target})
	if !res.Success {
		t.Fatalf("expected chmod success, got %#v", res)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestKillRejectsChangedProcessIdentity(t *testing.T) {
	res := SoftResponder{}.Apply(ActionRequest{Action: "kill", PID: os.Getpid(), ProcessPath: "/definitely/not/self", StartTicks: "0"})
	if res.Success || res.Detail == "" {
		t.Fatalf("expected process identity rejection, got %#v", res)
	}
}
