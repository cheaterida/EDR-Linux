package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"edr/internal/requestauth"
)

const (
	HeaderIngestSignature = requestauth.HeaderIngestSignature
	HeaderRequestID       = requestauth.HeaderRequestID
	HeaderTimestamp       = requestauth.HeaderTimestamp
)

type Authenticator = requestauth.Authenticator

type requestAuthMetaProvider interface {
	RequestAuthMeta() (string, time.Time, bool)
}

func NewAuthenticator(secret []byte, replayWindow time.Duration) *Authenticator {
	return requestauth.New(secret, replayWindow)
}

func ListenUnix(socketPath string, handler http.Handler, connContext func(context.Context, net.Conn) context.Context) (*http.Server, net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, nil, err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, err
	}
	_ = os.Chmod(socketPath, 0o600)
	srv := &http.Server{
		Handler:     handler,
		ConnContext: connContext,
	}
	return srv, ln, nil
}

func NewUnixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
	}
}

func PostJSON(client *http.Client, url string, body any, secret []byte) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(secret) > 0 {
		requestID := NewRequestID("post")
		requestTime := time.Now().UTC()
		if meta, ok := body.(requestAuthMetaProvider); ok {
			if id, ts, use := meta.RequestAuthMeta(); use {
				if id != "" {
					requestID = id
				}
				if !ts.IsZero() {
					requestTime = ts
				}
			}
		}
		NewAuthenticator(secret, 30*time.Second).Sign(req, raw, requestID, requestTime)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("http %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func Get(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("http %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

func NewRequestID(prefix string) string {
	return requestauth.NewRequestID(prefix)
}
