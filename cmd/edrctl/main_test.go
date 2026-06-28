package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPrintHAStatus(t *testing.T) {
	raw := []byte(`{
  "instance_id":"edr-a",
  "peer_instance_id":"edr-b",
  "run_dir":"/run/edr",
  "supervisor_enabled":true,
  "local_state":"healthy",
  "peer_state":"suspect",
  "supervisor_sync":{
    "status":"failed",
    "action":"heartbeat_error",
    "attempted_at":"2026-06-18T07:10:00Z",
    "last_success_at":"0001-01-01T00:00:00Z",
    "decision_id":"decision-1",
    "error":"dial tcp 127.0.0.1:9099: connect: connection refused"
  },
  "ha_activity":{
    "recorded_at":"2026-06-18T07:12:00Z",
    "action":"restart_peer_failed",
    "rule_id":"peer-down-failed",
    "peer":"edr-b",
    "source":"local-peer-down",
    "lease_id":"lease-1",
    "error":"systemctl restart failed"
  }
}`)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printHAStatus(raw)
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"instance:",
		"edr-a",
		"peer state:",
		"suspect",
		"last sync status:",
		"failed",
		"last error:",
		"connection refused",
		"last ha action:",
		"restart_peer_failed",
		"last ha lease:",
		"lease-1",
		"last ha error:",
		"systemctl restart failed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0001-01-01T00:00:00Z") {
		t.Fatalf("zero time should be suppressed:\n%s", out)
	}
}

func TestUnixGetWaitsForSocketReady(t *testing.T) {
	prevDial := unixDial
	t.Cleanup(func() { unixDial = prevDial })

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var mu sync.Mutex
	attempts := 0
	unixDial = func(network, address string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return nil, syscall.ECONNREFUSED
		}
		return clientConn, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		req := string(buf[:n])
		if !strings.Contains(req, "GET /v0/ha/status HTTP/1.1") {
			t.Errorf("unexpected request: %s", req)
			return
		}
		_, _ = serverConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"))
		_ = serverConn.Close()
	}()

	started := time.Now()
	body, err := unixGet("/tmp/fake.sock", "/v0/ha/status")
	if err != nil {
		t.Fatalf("unixGet failed before socket became ready: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
	if attempts != 3 {
		t.Fatalf("expected 3 dial attempts, got %d", attempts)
	}
	if time.Since(started) < 2*unixRequestRetryInterval {
		t.Fatalf("unixGet returned too early; retry window did not apply")
	}
	<-done
}

func TestPrintRootSessionStatus(t *testing.T) {
	raw := []byte(`{
  "enabled":true,
  "mode":"audit",
  "bypass_until":"2026-06-18T10:10:00Z",
  "sessions":[
    {"pid":101,"class":"class-admin","state":"challenged","tty":"/dev/pts/0"},
    {"pid":202,"class":"class-tooling","state":"valid","tty":"-"}
  ]
}`)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printRootSessionStatus(raw)
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"enabled:",
		"true",
		"mode:",
		"audit",
		"bypass until:",
		"2026-06-18T10:10:00Z",
		"pid=101",
		"class-admin",
		"challenged",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}
