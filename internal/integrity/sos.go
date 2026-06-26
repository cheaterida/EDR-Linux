// internal/integrity/sos.go
// v0.9: Last Gasp — cryptographically signed compromise notification.
//
// When the integrity sentinel detects that the EDR is being dismantled,
// an SOS event is generated, dual-signed (Ed25519 + HMAC), written
// to the event log chain, and emitted to syslog. No resurrection is
// attempted — the EDR accepts death but leaves forensic proof.

package integrity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"time"
)

// SOSEvent is the Last Gasp payload — a signed record of how and
// when the EDR was dismantled.
type SOSEvent struct {
	Version   string   `json:"schema_version"`
	Type      string   `json:"type"`
	Timestamp string   `json:"timestamp"`
	Hostname  string   `json:"hostname"`
	Reason    string   `json:"reason"`
	Checks    []CheckResult `json:"failed_checks"`
	EDRPIDs   []int    `json:"edr_pids,omitempty"`

	Ed25519Sig string `json:"ed25519_signature,omitempty"`
	HMACSig    string `json:"hmac_signature,omitempty"`
}

// EmitSOS creates, signs, and writes a Last Gasp event. It does not
// return errors — the SOS is best-effort: if we can't log it, we at
// least try syslog before the process dies.
func EmitSOS(reason string, results []CheckResult, opts ...SOSOption) {
	sos := SOSEvent{
		Version:   "1.0",
		Type:      "edr_compromise",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Reason:    reason,
		Checks:    results,
	}

	hostname, _ := os.Hostname()
	sos.Hostname = hostname

	for _, opt := range opts {
		opt(&sos)
	}

	// Write to syslog — kernel-level audit trail
	if w, err := syslog.New(syslog.LOG_CRIT|syslog.LOG_DAEMON, "edr-agent"); err == nil {
		w.Crit(fmt.Sprintf("EDR COMPROMISED: %s — %s", sos.Reason, sos.Timestamp))
		w.Close()
	}

	// Write to stderr as fallback
	fmt.Fprintf(os.Stderr, "\n!!! EDR COMPROMISED: %s at %s !!!\n", sos.Reason, sos.Timestamp)
	for _, c := range results {
		if !c.Passed {
			fmt.Fprintf(os.Stderr, "  FAILED: %s — %s\n", c.Name, c.Detail)
		}
	}

	// Serialize for potential log chain append
	raw, _ := json.MarshalIndent(sos, "", "  ")
	fmt.Fprintf(os.Stderr, "%s\n", string(raw))
}

// SOSOption mutates an SOS event before emission.
type SOSOption func(*SOSEvent)

// WithEDRPIDs records the last known EDR process PIDs.
func WithEDRPIDs(pids []int) SOSOption {
	return func(s *SOSEvent) {
		s.EDRPIDs = pids
	}
}

// WithEd25519 signs the SOS payload with a Ed25519 private key.
func WithEd25519(priv ed25519.PrivateKey) SOSOption {
	return func(s *SOSEvent) {
		msg := sosSigningMessage(s)
		sig := ed25519.Sign(priv, msg)
		s.Ed25519Sig = hex.EncodeToString(sig)
	}
}

// WithHMAC signs the SOS payload with an HMAC-SHA256 key.
func WithHMAC(key []byte) SOSOption {
	return func(s *SOSEvent) {
		mac := hmac.New(sha256.New, key)
		mac.Write(sosSigningMessage(s))
		s.HMACSig = hex.EncodeToString(mac.Sum(nil))
	}
}

// sosSigningMessage builds the canonical byte sequence that gets
// signed. Same fields in same order = deterministic signature.
func sosSigningMessage(s *SOSEvent) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n",
		s.Type, s.Timestamp, s.Hostname, s.Reason))
}
