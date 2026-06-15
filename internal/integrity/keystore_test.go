package integrity

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateGenerates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "log.key")
	key, src, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != keySize {
		t.Fatalf("key length = %d, want %d", len(key), keySize)
	}
	if src != SourceGenFile {
		t.Fatalf("source = %q, want %q", src, SourceGenFile)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected key file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != filePerm {
		t.Fatalf("key file perm = %o, want %o", perm, filePerm)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	want := bytes32(0xAB)
	if err := os.WriteFile(path, want, filePerm); err != nil {
		t.Fatal(err)
	}
	got, src, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("loaded key mismatch")
	}
	if src != SourceFile {
		t.Fatalf("source = %q, want %q", src, SourceFile)
	}
}

func TestLoadFromEnvHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	want := bytes32(0xCD)
	t.Setenv(envKey, prefixHex+hex.EncodeToString(want))
	got, src, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("env-hex key mismatch")
	}
	if src != SourceEnv {
		t.Fatalf("source = %q, want %q", src, SourceEnv)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("env key path should not be created, got err=%v", err)
	}
}

func TestLoadFromEnvBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	want := bytes32(0xEF)
	t.Setenv(envKey, prefixB64+base64.StdEncoding.EncodeToString(want))
	got, src, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("env-b64 key mismatch")
	}
	if src != SourceEnv {
		t.Fatalf("source = %q, want %q", src, SourceEnv)
	}
}

func TestLoadFromEnvRaw(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	want := bytes32(0x42)
	t.Setenv(envKey, string(want))
	got, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("env-raw key mismatch")
	}
}

func TestLoadFromEnvRejectsBadLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	t.Setenv(envKey, "hex:deadbeef")
	if _, _, err := LoadOrCreate(path); err == nil || !strings.Contains(err.Error(), "hex is") {
		t.Fatalf("expected length error, got %v", err)
	}
}

func TestLoadFromFileWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	if err := os.WriteFile(path, []byte{1, 2, 3}, filePerm); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil || !strings.Contains(err.Error(), "expected 32") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestEncodeKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.key")
	key, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKey, EncodeKey(key))
	got, _, err := LoadOrCreate(filepath.Join(dir, "log.key.alt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatalf("encoded key round-trip mismatch")
	}
}

func bytes32(seed byte) []byte {
	b := make([]byte, keySize)
	for i := range b {
		b[i] = seed
	}
	return b
}
