package notify

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"os"
	"strings"
)

// EmailConfig configures email alert delivery.
type EmailConfig struct {
	Enabled     bool     `json:"enabled"`
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	UseTLS      bool     `json:"use_tls"`
	MinSeverity string   `json:"min_severity"`
}

// EmailDispatcher sends alert emails via SMTP.
type EmailDispatcher struct {
	cfg  EmailConfig
	tmpl *template.Template
}

// NewEmailDispatcher creates an email dispatcher from config.
func NewEmailDispatcher(cfg EmailConfig) *EmailDispatcher {
	return &EmailDispatcher{
		cfg:  cfg,
		tmpl: template.Must(template.New("email").Parse(emailHTML)),
	}
}

// Dispatch sends an alert email if the event meets the severity threshold.
func (d *EmailDispatcher) Dispatch(ev WebhookEvent) error {
	if !d.cfg.Enabled {
		return nil
	}
	if !shouldNotify(ev.Severity, d.cfg.MinSeverity) {
		return nil
	}
	var body bytes.Buffer
	if err := d.tmpl.Execute(&body, ev); err != nil {
		return fmt.Errorf("template: %v", err)
	}
	return d.send(body.String(), ev)
}

func (d *EmailDispatcher) send(htmlBody string, ev WebhookEvent) error {
	port := d.cfg.SMTPPort
	if port <= 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", d.cfg.SMTPHost, port)

	subject := fmt.Sprintf("[EDR %s] %s — %s", strings.ToUpper(ev.Severity), ev.RuleID, ev.Host)

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", d.cfg.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(d.cfg.To, ",")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	var auth smtp.Auth
	if d.cfg.Username != "" {
		host, _, _ := net.SplitHostPort(addr)
		auth = smtp.PlainAuth("", d.cfg.Username, d.cfg.Password, host)
	}

	err := smtp.SendMail(addr, auth, d.cfg.From, d.cfg.To, []byte(msg.String()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "email: send to %s: %v\n", strings.Join(d.cfg.To, ","), err)
	}
	return err
}

var emailHTML = `<!DOCTYPE html>
<html><head><style>
body{font-family:sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px}
.alert{background:#16213e;border-left:4px solid #e94560;padding:16px;border-radius:4px;max-width:600px}
.severity{font-size:14px;font-weight:bold;padding:2px 8px;border-radius:3px;display:inline-block}
.severity-critical{background:#e94560;color:#fff}
.severity-high{background:#f5803e;color:#fff}
.severity-medium{background:#f5c542;color:#000}
.severity-low{background:#4ecca3;color:#fff}
table{width:100%;border-collapse:collapse;margin-top:12px}
td{padding:6px 8px;border-bottom:1px solid #2a2a4a;font-size:13px}
td:first-child{font-weight:bold;width:100px;color:#888}
.footer{margin-top:16px;font-size:11px;color:#666}
</style></head><body>
<div class="alert">
<h2 style="margin:0 0 8px 0">EDR Alert</h2>
<span class="severity severity-{{.Severity}}">{{.Severity}}</span>
<table>
<tr><td>Rule</td><td>{{.RuleID}}</td></tr>
<tr><td>Category</td><td>{{.Category}}</td></tr>
<tr><td>Decision</td><td>{{.Decision}}</td></tr>
<tr><td>Host</td><td>{{.Host}}</td></tr>
<tr><td>Time</td><td>{{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</td></tr>
{{if .Action}}<tr><td>Action</td><td>{{.Action}}</td></tr>{{end}}
</table>
<div class="footer">Sent by EDR Agent at {{.Timestamp.Format "15:04:05"}}</div>
</div></body></html>`
