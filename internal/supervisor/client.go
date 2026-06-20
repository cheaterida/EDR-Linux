package supervisor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"edr/internal/eventlog"
	"edr/internal/lease"
	"edr/internal/liveness"
)

type RestartIntent struct {
	RequestID  string `json:"request_id"`
	Target     string `json:"target"`
	Generation uint64 `json:"generation"`
	Reason     string `json:"reason"`
}

type HeartbeatRequest struct {
	RequestID         string              `json:"request_id"`
	InstanceID        string              `json:"instance_id"`
	PeerInstanceID    string              `json:"peer_instance_id"`
	BootID            string              `json:"boot_id"`
	Hostname          string              `json:"hostname"`
	Priority          int                 `json:"priority"`
	HeartbeatEverySec int                 `json:"heartbeat_every_sec"`
	SentAt            time.Time           `json:"sent_at"`
	Local             liveness.Heartbeat  `json:"local"`
	Peer              *liveness.Heartbeat `json:"peer,omitempty"`
	PeerState         string              `json:"peer_state,omitempty"`
	Lease             *lease.Lease        `json:"lease,omitempty"`
	Chain             eventlog.ChainState `json:"chain"`
}

type HeartbeatResponse struct {
	OK            bool          `json:"ok"`
	DecisionID    string        `json:"decision_id,omitempty"`
	RestartIntent RestartIntent `json:"restart_intent,omitempty"`
}

type EvidenceRecord struct {
	RequestID  string         `json:"request_id,omitempty"`
	DecisionID string         `json:"decision_id,omitempty"`
	Host       string         `json:"host"`
	InstanceID string         `json:"instance_id"`
	Category   string         `json:"category"`
	Action     string         `json:"action"`
	RuleID     string         `json:"rule_id"`
	RecordedAt time.Time      `json:"recorded_at"`
	Subject    map[string]any `json:"subject,omitempty"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

type Client struct {
	BaseURL string
	Secret  []byte
	HTTP    *http.Client
}

type TLSOptions struct {
	CertPath   string
	KeyPath    string
	CAPath     string
	ServerName string
}

func NewHTTPClientWithTLS(timeout time.Duration, tlsOpts TLSOptions) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if tlsOpts.ServerName != "" {
		tlsConfig.ServerName = tlsOpts.ServerName
	}
	if tlsOpts.CAPath != "" {
		raw, err := os.ReadFile(tlsOpts.CAPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("append supervisor ca: no certificates loaded")
		}
		tlsConfig.RootCAs = pool
	}
	if tlsOpts.CertPath != "" || tlsOpts.KeyPath != "" {
		if tlsOpts.CertPath == "" || tlsOpts.KeyPath == "" {
			return nil, fmt.Errorf("supervisor client tls requires both cert and key")
		}
		cert, err := tls.LoadX509KeyPair(tlsOpts.CertPath, tlsOpts.KeyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func (c Client) PushHeartbeat(ctx context.Context, req HeartbeatRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	if c.BaseURL == "" {
		return out, fmt.Errorf("supervisor url is empty")
	}
	if req.RequestID == "" {
		req.RequestID = uniqueRequestID("heartbeat", req.InstanceID)
	}
	if req.SentAt.IsZero() {
		req.SentAt = time.Now().UTC()
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	path := "/v0/supervisor/heartbeat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if len(c.Secret) > 0 {
		signRequestHeaders(httpReq, http.MethodPost, path, raw, req.RequestID, req.SentAt, c.Secret)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("supervisor heartbeat http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if len(body) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c Client) PushEvidence(ctx context.Context, rec EvidenceRecord) error {
	if c.BaseURL == "" {
		return fmt.Errorf("supervisor url is empty")
	}
	if rec.RequestID == "" {
		rec.RequestID = uniqueRequestID("evidence", rec.InstanceID)
	}
	if rec.RecordedAt.IsZero() {
		rec.RecordedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := "/v0/supervisor/evidence"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if len(c.Secret) > 0 {
		signRequestHeaders(httpReq, http.MethodPost, path, raw, rec.RequestID, rec.RecordedAt, c.Secret)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("supervisor evidence http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func WriteEvidenceFile(dir string, rec EvidenceRecord) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	name := rec.RecordedAt.UTC().Format("20060102T150405.000000000") + "-" + sanitize(rec.InstanceID) + "-" + sanitize(rec.Action) + ".json"
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o640)
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if s == "" {
		return "unknown"
	}
	return s
}

func sign(body []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
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

func signRequestHeaders(req *http.Request, method, path string, body []byte, requestID string, ts time.Time, secret []byte) {
	req.Header.Set("X-EDR-Request-ID", requestID)
	req.Header.Set("X-EDR-Timestamp", ts.UTC().Format(time.RFC3339Nano))
	req.Header.Set("X-EDR-Signature", "sha256="+signRequest(method, path, body, requestID, ts, secret))
}

func uniqueRequestID(prefix, instanceID string) string {
	instanceID = sanitize(instanceID)
	return fmt.Sprintf("%s-%s-%d", prefix, instanceID, time.Now().UTC().UnixNano())
}
