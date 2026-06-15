package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SigningKey is an Ed25519 key used to sign and verify policy files.
type SigningKey struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateSigningKey creates a new Ed25519 key pair.
func GenerateSigningKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &SigningKey{Private: priv, Public: pub}, nil
}

// LoadSigningKey reads an Ed25519 private key from a hex-encoded file.
// Accepts two formats:
//   - 64 hex chars (32-byte seed, as written by SaveSigningKey)
//   - 128 hex chars (64-byte full private key)
//
// The file must be 0600.
func LoadSigningKey(path string) (*SigningKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(trimString(string(raw)))
	var seed []byte
	switch len(raw) {
	case 64: // 32-byte seed
		seed = make([]byte, 32)
		if _, err := hex.Decode(seed, raw); err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
	case 128: // 64-byte full private key
		full := make([]byte, 64)
		if _, err := hex.Decode(full, raw); err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		seed = full[:32]
	default:
		return nil, fmt.Errorf("signing key: expected 64 or 128 hex chars, got %d", len(raw))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &SigningKey{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// SaveSigningKey writes the private key seed as hex to path with mode 0600.
func SaveSigningKey(key *SigningKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// ed25519.PrivateKey is 64 bytes: seed (32) + public (32).
	// We store the seed (first 32 bytes) as hex.
	seedHex := hex.EncodeToString(key.Private.Seed())
	return os.WriteFile(path, []byte(seedHex+"\n"), 0o600)
}

// Sign produces a hex-encoded Ed25519 signature over data.
func Sign(key *SigningKey, data []byte) (string, error) {
	if key == nil || len(key.Private) == 0 {
		return "", errors.New("signing key is nil")
	}
	sig := ed25519.Sign(key.Private, data)
	return hex.EncodeToString(sig), nil
}

// Verify checks an Ed25519 signature. sigHex is the hex-encoded
// signature; data is the original payload.
func Verify(pub ed25519.PublicKey, data []byte, sigHex string) (bool, error) {
	sig, err := hex.DecodeString(trimString(sigHex))
	if err != nil {
		return false, fmt.Errorf("signature hex decode: %w", err)
	}
	return ed25519.Verify(pub, data, sig), nil
}

// SignatureFile returns the conventional signature path for a policy
// file: <policy_path>.sig.
func SignatureFile(policyPath string) string {
	return policyPath + ".sig"
}

// LoadOrCreateSigningKey reads the key from path; if it doesn't exist,
// generates a new one and saves it.
func LoadOrCreateSigningKey(path string) (*SigningKey, string, error) {
	if path == "" {
		return nil, "", errors.New("signing key path is empty")
	}
	key, err := LoadSigningKey(path)
	if err == nil {
		return key, "loaded", nil
	}
	if !os.IsNotExist(err) {
		return nil, "", err
	}
	key, err = GenerateSigningKey()
	if err != nil {
		return nil, "", err
	}
	if err := SaveSigningKey(key, path); err != nil {
		return nil, "", err
	}
	return key, "generated", nil
}

// LoadPublicKey reads just the public key from a hex-encoded public key
// file (32 bytes = 64 hex chars). The file is typically deployed
// alongside the agent binary for signature verification.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(trimString(string(raw)))
	if len(raw) != 64 {
		return nil, fmt.Errorf("public key: expected 64 hex chars, got %d", len(raw))
	}
	pub := make([]byte, 32)
	if _, err := hex.Decode(pub, raw); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return ed25519.PublicKey(pub), nil
}

// SavePublicKey writes a hex-encoded public key to path.
func SavePublicKey(pub ed25519.PublicKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

func trimString(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
