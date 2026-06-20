package requestauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	HeaderIngestSignature = "X-EDR-Ingest-Signature"
	HeaderRequestID       = "X-EDR-Request-ID"
	HeaderTimestamp       = "X-EDR-Timestamp"
)

type Authenticator struct {
	secret       []byte
	replayWindow time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

func New(secret []byte, replayWindow time.Duration) *Authenticator {
	if replayWindow <= 0 {
		replayWindow = 30 * time.Second
	}
	return &Authenticator{
		secret:       append([]byte(nil), secret...),
		replayWindow: replayWindow,
		seen:         make(map[string]time.Time),
	}
}

func (a *Authenticator) Enabled() bool {
	return a != nil && len(a.secret) > 0
}

func (a *Authenticator) Sign(req *http.Request, body []byte, requestID string, ts time.Time) {
	if !a.Enabled() {
		return
	}
	if requestID == "" {
		requestID = NewRequestID(strings.ToLower(req.Method))
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, ts.UTC().Format(time.RFC3339Nano))
	req.Header.Set(HeaderIngestSignature, "sha256="+signRequest(req.Method, req.URL.Path, body, requestID, ts, a.secret))
}

func (a *Authenticator) Authorize(req *http.Request, body []byte) (string, time.Time, error) {
	if !a.Enabled() {
		return "", time.Time{}, nil
	}
	requestID := strings.TrimSpace(req.Header.Get(HeaderRequestID))
	if requestID == "" {
		return "", time.Time{}, errors.New("missing request id")
	}
	ts, err := ParseHeaderTime(req.Header.Get(HeaderTimestamp))
	if err != nil {
		return "", time.Time{}, err
	}
	if !Recent(ts, a.replayWindow) {
		return "", time.Time{}, errors.New("stale request")
	}
	signature := strings.TrimPrefix(strings.TrimSpace(req.Header.Get(HeaderIngestSignature)), "sha256=")
	if signature == "" {
		return "", time.Time{}, errors.New("missing request signature")
	}
	expected := signRequest(req.Method, req.URL.Path, body, requestID, ts, a.secret)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", time.Time{}, errors.New("invalid request signature")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(time.Now().UTC())
	if seenAt, ok := a.seen[requestID]; ok && Recent(seenAt, a.replayWindow) {
		return "", time.Time{}, errors.New("replayed request")
	}
	a.seen[requestID] = ts
	return requestID, ts, nil
}

func NewRequestID(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.ReplaceAll(prefix, " ", "-")
	if prefix == "" {
		prefix = "req"
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
}

func ParseHeaderTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("missing request timestamp")
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid request timestamp: %w", err)
	}
	return ts, nil
}

func Recent(ts time.Time, d time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	delta := time.Since(ts)
	if delta < 0 {
		delta = -delta
	}
	return delta <= d
}

func signRequest(method, path string, body []byte, requestID string, ts time.Time, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(method))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(path))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(ts.UTC().Format(time.RFC3339Nano)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(requestID))
	mac.Write([]byte{'\n'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) pruneLocked(now time.Time) {
	for requestID, ts := range a.seen {
		if now.Sub(ts) > a.replayWindow {
			delete(a.seen, requestID)
		}
	}
}
