package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"edr/internal/collector"
	"edr/internal/response"
)

type RemoteCollector struct {
	Client  *http.Client
	BaseURL string
	Auth    *Authenticator
}

func (r RemoteCollector) Snapshot() (collector.Snapshot, error) {
	return r.SnapshotContext(context.Background())
}

func (r RemoteCollector) SnapshotContext(ctx context.Context) (collector.Snapshot, error) {
	var out struct {
		OK       bool               `json:"ok"`
		Snapshot collector.Snapshot `json:"snapshot"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/v0/sensor/snapshot", nil)
	if err != nil {
		return collector.Snapshot{}, err
	}
	if r.Auth != nil {
		r.Auth.Sign(req, nil, NewRequestID("sensor-snapshot"), time.Now().UTC())
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return collector.Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return collector.Snapshot{}, fmt.Errorf("sensor snapshot http %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return collector.Snapshot{}, err
	}
	return out.Snapshot, nil
}

type RemoteResponder struct {
	Client     *http.Client
	BaseURL    string
	InstanceID string
	Generation uint64
	Secret     []byte
}

func (r RemoteResponder) Apply(req response.ActionRequest) response.Result {
	body := ActionEnvelope{
		RequestID:   fmt.Sprintf("%s-%d", r.InstanceID, time.Now().UnixNano()),
		InstanceID:  r.InstanceID,
		Generation:  r.Generation,
		Request:     req,
		RequestedAt: time.Now().UTC(),
	}
	raw, err := PostJSON(r.Client, r.BaseURL+"/v0/enforcer/apply", body, r.Secret)
	if err != nil {
		return response.Result{Action: req.Action, Success: false, Detail: err.Error()}
	}
	var out ActionResultEnvelope
	if err := json.Unmarshal(raw, &out); err != nil {
		return response.Result{Action: req.Action, Success: false, Detail: err.Error()}
	}
	return out.Result
}
