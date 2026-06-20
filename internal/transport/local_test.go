package transport

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"edr/internal/response"
)

func TestAuthenticatorAuthorizesAndRejectsReplay(t *testing.T) {
	auth := NewAuthenticator([]byte("secret"), 30*time.Second)
	body := []byte(`{"ok":true}`)
	req, err := http.NewRequest(http.MethodPost, "http://unix/v0/test", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC()
	auth.Sign(req, body, "req-1", ts)

	requestID, requestTime, err := auth.Authorize(req, body)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if requestID != "req-1" {
		t.Fatalf("requestID = %q, want req-1", requestID)
	}
	if !requestTime.Equal(ts) {
		t.Fatalf("requestTime = %v, want %v", requestTime, ts)
	}
	if _, _, err := auth.Authorize(req, body); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("second Authorize() error = %v, want replay rejection", err)
	}
}

func TestPostJSONUsesActionEnvelopeAuthMeta(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.Header.Get(HeaderRequestID); got != "action-1" {
				t.Fatalf("request id header = %q, want action-1", got)
			}
			if got := r.Header.Get(HeaderTimestamp); got != "2026-06-18T00:00:00Z" {
				t.Fatalf("timestamp header = %q", got)
			}
			if got := r.Header.Get(HeaderIngestSignature); !strings.HasPrefix(got, "sha256=") {
				t.Fatalf("signature header = %q, want sha256 prefix", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}
	_, err := PostJSON(client, "http://unix/v0/enforcer/apply", ActionEnvelope{
		RequestID:   "action-1",
		InstanceID:  "edr-a",
		Generation:  2,
		Request:     response.ActionRequest{Action: "kill", RuleID: "rule-1"},
		RequestedAt: time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC),
	}, []byte("secret"))
	if err != nil {
		t.Fatalf("PostJSON() error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
