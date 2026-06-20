package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunFileModeCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := Run(Template{SchemaVersion: SchemaVersion, Checks: []FileCheck{{ID: "b1", Path: path, MustExist: true, MaxMode: "0600"}}})
	if len(findings) != 1 || findings[0].Passed {
		t.Fatalf("expected mode finding, got %#v", findings)
	}
}
