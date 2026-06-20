package supervisor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"edr/internal/liveness"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPushHeartbeatSendsPayloadAndParsesIntent(t *testing.T) {
	var gotSig string
	client := Client{
		BaseURL: "http://supervisor.test",
		Secret:  []byte("secret"),
		HTTP: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v0/supervisor/heartbeat" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), `"instance_id":"edr-a"`) {
					t.Fatalf("unexpected body %s", string(body))
				}
				gotSig = r.Header.Get("X-EDR-Signature")
				if r.Header.Get("X-EDR-Request-ID") == "" {
					t.Fatal("missing request id header")
				}
				if r.Header.Get("X-EDR-Timestamp") == "" {
					t.Fatal("missing timestamp header")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"ok":true,"decision_id":"d1","restart_intent":{"request_id":"r1","target":"edr-b","generation":3,"reason":"peer_down"}}`)),
				}, nil
			}),
		},
	}
	resp, err := client.PushHeartbeat(context.Background(), HeartbeatRequest{
		InstanceID:     "edr-a",
		PeerInstanceID: "edr-b",
		Hostname:       "host-1",
		SentAt:         time.Now().UTC(),
		Local: liveness.Heartbeat{
			InstanceID:        "edr-a",
			RestartGeneration: 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("missing signature header: %q", gotSig)
	}
	if resp.RestartIntent.Target != "edr-b" || resp.RestartIntent.Generation != 3 {
		t.Fatalf("unexpected response %+v", resp)
	}
}
