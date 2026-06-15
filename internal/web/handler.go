package web

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

//go:embed static/index.html
var indexHTML string

// AgentView provides the data needed for the dashboard.
type AgentView interface {
	Metrics() map[string]any
	ResponseHistory(limit int) []ResponseEvent
	Status() map[string]any
}

// ResponseEvent is a simplified response record for the dashboard.
type ResponseEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	RuleID    string         `json:"rule_id"`
	Category  string         `json:"category"`
	Subject   map[string]any `json:"subject,omitempty"`
	Result    map[string]any `json:"result,omitempty"`
}

// DashboardConfig configures the web dashboard.
type DashboardConfig struct {
	Listen string `json:"listen"` // e.g. ":8080"
}

// Dashboard serves a single-page web dashboard with SSE real-time updates.
type Dashboard struct {
	agent   AgentView
	clients map[chan []byte]struct{}
	mu      sync.Mutex
}

// NewDashboard creates a dashboard handler.
func NewDashboard(agent AgentView) *Dashboard {
	return &Dashboard{
		agent:   agent,
		clients: make(map[chan []byte]struct{}),
	}
}

// Handler returns an http.Handler for the dashboard.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.serveIndex)
	mux.HandleFunc("/api/metrics", d.apiMetrics)
	mux.HandleFunc("/api/status", d.apiStatus)
	mux.HandleFunc("/api/responses", d.apiResponses)
	mux.HandleFunc("/events", d.serveSSE)
	return mux
}

// Publish sends an event to all connected SSE clients.
func (d *Dashboard) Publish(event any) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "data: %s\n\n", data)
	d.mu.Lock()
	defer d.mu.Unlock()
	for ch := range d.clients {
		select {
		case ch <- buf.Bytes():
		default:
			// Client too slow, drop event
		}
	}
}

func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

func (d *Dashboard) apiMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.agent.Metrics())
}

func (d *Dashboard) apiStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.agent.Status())
}

func (d *Dashboard) apiResponses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.agent.ResponseHistory(50))
}

func (d *Dashboard) serveSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 16)
	d.mu.Lock()
	d.clients[ch] = struct{}{}
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.clients, ch)
		d.mu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			w.Write(msg)
			flusher.Flush()
		}
	}
}
