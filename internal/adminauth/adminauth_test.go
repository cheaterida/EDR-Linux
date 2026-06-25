package adminauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeyByteLen {
		t.Fatalf("key length %d != %d", len(key), KeyByteLen)
	}
}

func TestGenerateEncodedKey(t *testing.T) {
	encoded, err := GenerateEncodedKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != KeyByteLen*2 {
		t.Fatalf("encoded length %d != %d", len(encoded), KeyByteLen*2)
	}
}

func TestIssueAndVerifyToken(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Now()

	token, expiresAt, err := IssueToken(key, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt <= now.Unix() {
		t.Fatal("expiresAt not in the future")
	}

	err = VerifyToken(key, token, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Now()

	token, _, err := IssueToken(key, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}

	future := now.Add(TokenValidSec*time.Second + MaxClockSkew*time.Second + time.Second)
	err = VerifyToken(key, token, "shutdown", future)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyWrongAction(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Now()

	token, _, err := IssueToken(key, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyToken(key, token, "restart", now)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	now := time.Now()

	token, _, err := IssueToken(key1, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyToken(key2, token, "shutdown", now)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyTamperedToken(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Now()

	token, _, err := IssueToken(key, "shutdown", now)
	if err != nil {
		t.Fatal(err)
	}

	tampered := token + "x"
	err = VerifyToken(key, tampered, "shutdown", now)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestInvalidAction(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Now()

	_, _, err := IssueToken(key, "nonexistent-action", now)
	if err == nil {
		t.Fatal("expected error for unsupported action")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.key")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeyByteLen {
		t.Fatalf("key length %d != %d", len(key), KeyByteLen)
	}

	key2, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != string(key2) {
		t.Fatal("key not persisted correctly")
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.key")

	encoded, _ := GenerateEncodedKey()
	os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600)

	key, err := LoadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeyByteLen {
		t.Fatalf("key length %d != %d", len(key), KeyByteLen)
	}
}
