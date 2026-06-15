package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// WebhookConfig defines a single webhook endpoint.
type WebhookConfig struct {
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	TimeoutSec  int               `json:"timeout_sec,omitempty"`
	Format      string            `json:"format"`                  // "generic", "dingtalk", "wechat_work", "feishu"
	MinSeverity string            `json:"min_severity,omitempty"`  // only notify for this severity and above
}

// WebhookEvent is the event payload sent to webhooks.
type WebhookEvent struct {
	RuleID    string         `json:"rule_id"`
	Severity  string         `json:"severity"`
	Category  string         `json:"category"`
	Decision  string         `json:"decision"`
	Action    string         `json:"action,omitempty"`
	Subject   map[string]any `json:"subject,omitempty"`
	Object    map[string]any `json:"object,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	Host      string         `json:"host"`
}

// WebhookDispatcher sends events to configured webhook endpoints.
type WebhookDispatcher struct {
	mu      sync.Mutex
	clients []*webhookClient
	queue   chan WebhookEvent
	done    chan struct{}
	wg      sync.WaitGroup
}

type webhookClient struct {
	cfg        WebhookConfig
	httpClient *http.Client
}

// NewWebhookDispatcher creates a dispatcher with the given configs.
// Events are dispatched asynchronously via a buffered channel.
func NewWebhookDispatcher(cfgs []WebhookConfig) *WebhookDispatcher {
	d := &WebhookDispatcher{
		queue: make(chan WebhookEvent, 256),
		done:  make(chan struct{}),
	}
	for _, cfg := range cfgs {
		if cfg.URL == "" {
			continue
		}
		timeout := cfg.TimeoutSec
		if timeout <= 0 {
			timeout = 10
		}
		d.clients = append(d.clients, &webhookClient{
			cfg: cfg,
			httpClient: &http.Client{
				Timeout: time.Duration(timeout) * time.Second,
			},
		})
	}
	if len(d.clients) > 0 {
		d.wg.Add(1)
		go d.dispatchLoop()
	}
	return d
}

// Dispatch sends an event to all configured webhooks (non-blocking).
func (d *WebhookDispatcher) Dispatch(ev WebhookEvent) {
	select {
	case d.queue <- ev:
	default:
		// Queue full, drop event
	}
}

// Stop shuts down the dispatcher, waiting for pending events.
func (d *WebhookDispatcher) Stop() {
	close(d.done)
	d.wg.Wait()
}

func (d *WebhookDispatcher) dispatchLoop() {
	defer d.wg.Done()
	for {
		select {
		case ev := <-d.queue:
			d.sendToAll(ev)
		case <-d.done:
			// Drain remaining events
			for {
				select {
				case ev := <-d.queue:
					d.sendToAll(ev)
				default:
					return
				}
			}
		}
	}
}

func (d *WebhookDispatcher) sendToAll(ev WebhookEvent) {
	for _, c := range d.clients {
		if !shouldNotify(ev.Severity, c.cfg.MinSeverity) {
			continue
		}
		go d.sendOne(c, ev)
	}
}

func (d *WebhookDispatcher) sendOne(c *webhookClient, ev WebhookEvent) {
	body := formatPayload(c.cfg.Format, ev)
	req, err := http.NewRequest("POST", c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: new request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook: post %s: %v\n", redactURL(c.cfg.URL), err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "webhook: post %s: status %d\n", redactURL(c.cfg.URL), resp.StatusCode)
	}
}

func formatPayload(format string, ev WebhookEvent) []byte {
	switch format {
	case "dingtalk":
		return formatDingTalk(ev)
	case "wechat_work":
		return formatWeChatWork(ev)
	case "feishu":
		return formatFeishu(ev)
	default:
		data, _ := json.Marshal(ev)
		return data
	}
}

func formatDingTalk(ev WebhookEvent) []byte {
	severity := severityEmoji(ev.Severity)
	msg := fmt.Sprintf("%s **EDR Alert** [%s]\n\n- **Rule**: %s\n- **Severity**: %s\n- **Category**: %s\n- **Decision**: %s\n- **Host**: %s\n- **Time**: %s",
		severity, ev.RuleID, ev.RuleID, ev.Severity, ev.Category, ev.Decision, ev.Host, ev.Timestamp.Format(time.RFC3339))
	if ev.Subject != nil {
		if name, ok := ev.Subject["process_name"]; ok {
			msg += fmt.Sprintf("\n- **Process**: %v", name)
		}
	}
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": fmt.Sprintf("EDR [%s] %s", ev.Severity, ev.RuleID),
			"text":  msg,
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

func formatWeChatWork(ev WebhookEvent) []byte {
	severity := severityEmoji(ev.Severity)
	msg := fmt.Sprintf("%s EDR Alert [%s]\n> Rule: %s\n> Severity: %s\n> Category: %s\n> Decision: %s\n> Host: %s\n> Time: %s",
		severity, ev.RuleID, ev.RuleID, ev.Severity, ev.Category, ev.Decision, ev.Host, ev.Timestamp.Format(time.RFC3339))
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": msg,
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

func formatFeishu(ev WebhookEvent) []byte {
	severity := severityEmoji(ev.Severity)
	title := fmt.Sprintf("%s EDR Alert [%s]", severity, ev.Severity)
	content := fmt.Sprintf("**Rule**: %s\n**Category**: %s\n**Decision**: %s\n**Host**: %s\n**Time**: %s",
		ev.RuleID, ev.Category, ev.Decision, ev.Host, ev.Timestamp.Format(time.RFC3339))
	payload := map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"header": map[string]any{
				"title": map[string]string{
					"tag":     "plain_text",
					"content": title,
				},
			},
			"elements": []any{
				map[string]any{
					"tag":     "markdown",
					"content": content,
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

var severityOrder = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func shouldNotify(eventSeverity, minSeverity string) bool {
	if minSeverity == "" {
		return true
	}
	return severityOrder[eventSeverity] >= severityOrder[minSeverity]
}

func redactURL(url string) string {
	if idx := strings.Index(url, "access_token="); idx >= 0 {
		return url[:idx+13] + "***"
	}
	if idx := strings.Index(url, "key="); idx >= 0 {
		return url[:idx+4] + "***"
	}
	return url
}
