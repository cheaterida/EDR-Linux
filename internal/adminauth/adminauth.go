package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrInvalidToken   = errors.New("invalid admin token")
	ErrTokenExpired   = errors.New("admin token has expired")
	ErrKeyNotSet      = errors.New("admin key is not configured")
	ErrKeyTooShort    = errors.New("admin key too short (min 32 hex / 16 bytes)")
)

const (
	KeyByteLen     = 32
	TokenValidSec  = 300
	MaxClockSkew   = 30
)

var validActions = map[string]bool{
	"shutdown":        true,
	"restart":         true,
	"config-reload":   true,
	"policy-override": true,
	"rootkit-bypass":  true,
	"enforce-toggle":  true,
	"self-protect":    true,
}

func validAction(action string) bool {
	return validActions[action]
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyByteLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateEncodedKey() (string, error) {
	key, err := GenerateKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func LoadOrCreateKey(keyPath string) ([]byte, error) {
	if keyPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(keyPath)
	if err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err == nil && len(key) >= 16 {
			if len(key) < KeyByteLen {
				padded := make([]byte, KeyByteLen)
				copy(padded, key)
				return padded, nil
			}
			return key[:KeyByteLen], nil
		}
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func LoadKey(keyPath string) ([]byte, error) {
	if keyPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("invalid admin key format: %w", err)
	}
	if len(key) < 16 {
		return nil, ErrKeyTooShort
	}
	if len(key) < KeyByteLen {
		padded := make([]byte, KeyByteLen)
		copy(padded, key)
		return padded, nil
	}
	return key[:KeyByteLen], nil
}

func computeToken(key []byte, action string, timestamp int64, nonce string) string {
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%s:%d:%s", action, timestamp, nonce)
	return hex.EncodeToString(h.Sum(nil))
}

func IssueToken(key []byte, action string, now time.Time) (token string, expiresAt int64, err error) {
	if len(key) < 16 {
		return "", 0, ErrKeyTooShort
	}
	if !validAction(action) {
		return "", 0, fmt.Errorf("unsupported admin action: %s", action)
	}
	nonce := hex.EncodeToString(randomBytes(16))
	ts := now.Unix()
	token = fmt.Sprintf("%s:%d:%s:%s", action, ts, nonce, computeToken(key, action, ts, nonce))
	expiresAt = now.Add(TokenValidSec * time.Second).Unix()
	return token, expiresAt, nil
}

func VerifyToken(key []byte, token string, action string, now time.Time) error {
	if len(key) < 16 {
		return ErrKeyNotSet
	}
	parts := strings.SplitN(token, ":", 4)
	if len(parts) != 4 {
		return ErrInvalidToken
	}
	tokenAction := parts[0]
	var timestamp int64
	if _, err := fmt.Sscanf(parts[1], "%d", &timestamp); err != nil {
		return ErrInvalidToken
	}
	nonce := parts[2]
	signature := parts[3]

	if tokenAction != action {
		return ErrInvalidToken
	}

	ts := time.Unix(timestamp, 0)
	age := now.Sub(ts)
	if age > TokenValidSec*time.Second+MaxClockSkew*time.Second {
		return ErrTokenExpired
	}
	if age < -MaxClockSkew*time.Second {
		return ErrTokenExpired
	}

	expected := computeToken(key, action, timestamp, nonce)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrInvalidToken
	}
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("adminauth: crypto/rand failed: %v", err))
	}
	return b
}
