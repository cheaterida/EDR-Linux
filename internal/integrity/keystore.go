// Package integrity provides tamper-detection primitives for the EDR
// event log: HMAC key management and hash chain bookkeeping.
package integrity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	envKey    = "EDR_LOG_KEY"
	keySize   = 32
	dirPerm   = 0o700
	filePerm  = 0o600
	prefixHex = "hex:"
	prefixB64 = "b64:"
)

// KeySource identifies where a signing key came from. The value is
// suitable for surfacing in the verify event and metrics so operators
// can tell at a glance whether the agent is using a transient
// environment key, a persistent file key, or a freshly generated
// one.
type KeySource string

const (
	SourceEnv     KeySource = "env:EDR_LOG_KEY"
	SourceFile    KeySource = "file"
	SourceGenFile KeySource = "generated_file"
)

// LoadOrCreate returns the HMAC key for log signing, in this order:
//
//  1. The EDR_LOG_KEY environment variable, if set. Supports "hex:<...>"
//     and "b64:<...>" encodings (raw 32 bytes are also accepted).
//  2. The contents of path, if the file exists and is exactly 32 bytes.
//  3. A freshly generated random key, which is then persisted to path
//     with 0600 permissions.
//
// The directory containing path is created with 0700 if missing. An
// existing key file is never silently truncated: LoadOrCreate will only
// overwrite when the file is missing, unreadable, or has the wrong size
// (in which case the new key replaces the old one — this is a deliberate
// "self-heal" so a corrupted keyfile does not strand the agent).
//
// The returned KeySource tells the caller which of the three branches
// was taken; this lets the agent surface a precise provenance in
// startup events and metrics.
func LoadOrCreate(path string) ([]byte, KeySource, error) {
	if path == "" {
		return nil, "", errors.New("integrity: empty key path")
	}
	if k, err := loadFromEnv(); err == nil {
		fmt.Fprintf(os.Stderr, "integrity: WARNING: HMAC key loaded from %s environment variable; "+
			"same-UID processes can read this key — consider using a key file instead\n", envKey)
		return k, SourceEnv, nil
	} else if !errors.Is(err, errNoEnv) {
		return nil, "", err
	}
	if b, err := os.ReadFile(path); err == nil {
		if len(b) == keySize {
			return b, SourceFile, nil
		}
		return nil, "", fmt.Errorf("integrity: key file %q has %d bytes, expected %d", path, len(b), keySize)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("integrity: read key file: %w", err)
	}
	k, err := generateAndPersist(path)
	if err != nil {
		return nil, "", err
	}
	return k, SourceGenFile, nil
}

var errNoEnv = errors.New("integrity: no env key")

func loadFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return nil, errNoEnv
	}
	switch {
	case strings.HasPrefix(raw, prefixHex):
		b, err := hex.DecodeString(strings.TrimPrefix(raw, prefixHex))
		if err != nil {
			return nil, fmt.Errorf("integrity: %s hex decode: %w", envKey, err)
		}
		if len(b) != keySize {
			return nil, fmt.Errorf("integrity: %s hex is %d bytes, expected %d", envKey, len(b), keySize)
		}
		return b, nil
	case strings.HasPrefix(raw, prefixB64):
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, prefixB64))
		if err != nil {
			return nil, fmt.Errorf("integrity: %s base64 decode: %w", envKey, err)
		}
		if len(b) != keySize {
			return nil, fmt.Errorf("integrity: %s base64 is %d bytes, expected %d", envKey, len(b), keySize)
		}
		return b, nil
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("integrity: %s raw is %d bytes, expected %d (use %shex: or %sb64: prefix)", envKey, len(raw), keySize, prefixHex, prefixB64)
	}
	return []byte(raw), nil
}

func generateAndPersist(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("integrity: mkdir key dir: %w", err)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("integrity: read random: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, filePerm); err != nil {
		return nil, fmt.Errorf("integrity: write key tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("integrity: rename key: %w", err)
	}
	_ = os.Chmod(path, filePerm)
	return key, nil
}

// EncodeKey returns a hex-prefixed string suitable for the EDR_LOG_KEY
// environment variable. It is the inverse of the hex branch of
// LoadOrCreate and is intended for operator onboarding.
func EncodeKey(key []byte) string {
	return prefixHex + hex.EncodeToString(key)
}
