package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"edr/internal/baseline"
	"edr/internal/integrity"
	"edr/internal/policy"
	"edr/internal/rootsession"
)

const (
	unixRequestReadyTimeout  = 3 * time.Second
	unixRequestRetryInterval = 100 * time.Millisecond
)

var unixDial = func(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func main() {
	socket := flag.String("socket", "var/run/edr-agent.sock", "agent unix socket")
	jsonFlag := flag.Bool("json", false, "output raw JSON instead of formatted text")
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
	}
	cmd := flag.Arg(0)
	switch cmd {
	case "policy":
		if flag.NArg() == 3 && flag.Arg(1) == "validate" {
			p, err := policy.Load(flag.Arg(2))
			die(err)
			fmt.Printf("ok: %d rules, process_access=%s\n", len(p.Rules), p.ProcessAccess.Mode)
			return
		}
		if flag.NArg() == 2 && flag.Arg(1) == "versions" {
			body, err := unixGet(*socket, "/v0/policy/versions")
			die(err)
			fmt.Println(string(body))
			return
		}
		if flag.NArg() >= 2 && flag.Arg(1) == "rollback" {
			path := ""
			if flag.NArg() == 3 {
				path = "?version=" + flag.Arg(2)
			}
			body, err := unixPost(*socket, "/v0/policy/rollback"+path)
			die(err)
			fmt.Println(string(body))
			return
		}
		if flag.NArg() == 4 && flag.Arg(1) == "sign" {
			policyPath := flag.Arg(2)
			keyPath := flag.Arg(3)
			key, err := integrity.LoadSigningKey(keyPath)
			die(err)
			raw, err := os.ReadFile(policyPath)
			die(err)
			sig, err := integrity.Sign(key, raw)
			die(err)
			sigPath := integrity.SignatureFile(policyPath)
			die(os.WriteFile(sigPath, []byte(sig+"\n"), 0o640))
			fmt.Printf("ok: signed %s -> %s\n", policyPath, sigPath)
			return
		}
		if flag.NArg() >= 3 && flag.Arg(1) == "verify-signature" {
			policyPath := flag.Arg(2)
			keyPath := flag.Arg(3)
			// Verification uses only the public key. The agent and
			// CLI verify path must not hold the signing private key.
			pub, err := integrity.LoadPublicKey(keyPath)
			die(err)
			raw, err := os.ReadFile(policyPath)
			die(err)
			sigRaw, err := os.ReadFile(integrity.SignatureFile(policyPath))
			die(err)
			ok, err := integrity.Verify(pub, raw, string(sigRaw))
			die(err)
			if !ok {
				fmt.Println("invalid signature")
				os.Exit(1)
			}
			fmt.Printf("ok: valid signature for %s\n", policyPath)
			return
		}
		if flag.NArg() == 2 && flag.Arg(1) == "verify-signature" {
			body, err := unixPost(*socket, "/v0/policy/verify-signature")
			die(err)
			fmt.Println(string(body))
			return
		}
		if flag.NArg() >= 2 && flag.Arg(1) == "reload" {
			path := ""
			if flag.NArg() == 3 {
				path = "?version=" + flag.Arg(2)
			}
			body, err := unixPost(*socket, "/v0/policy/reload"+path)
			die(err)
			fmt.Println(string(body))
			return
		}
	case "baseline":
		if flag.NArg() == 3 && flag.Arg(1) == "run" {
			t, err := baseline.Load(flag.Arg(2))
			die(err)
			printJSON(baseline.Run(t))
			return
		}
		usage()
	case "status":
		body, err := unixGet(*socket, "/v0/status")
		die(err)
		if *jsonFlag {
			fmt.Println(string(body))
			return
		}
		printStatus(body)
	case "ha":
		if flag.NArg() != 2 || flag.Arg(1) != "status" {
			usage()
		}
		body, err := unixGet(*socket, "/v0/ha/status")
		die(err)
		if *jsonFlag {
			fmt.Println(string(body))
			return
		}
		printHAStatus(body)
	case "rootsession":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "status":
			body, err := unixGet(*socket, "/v0/root-sessions/status")
			die(err)
			if *jsonFlag {
				fmt.Println(string(body))
				return
			}
			printRootSessionStatus(body)
		case "challenge":
			if flag.NArg() != 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl rootsession challenge PID")
				os.Exit(2)
			}
			pid, err := strconv.Atoi(flag.Arg(2))
			die(err)
			body, err := unixPostJSON(*socket, "/v0/root-sessions/challenge", fmt.Sprintf(`{"pid":%d}`, pid))
			die(err)
			fmt.Println(string(body))
		case "ack":
			if flag.NArg() != 4 {
				fmt.Fprintln(os.Stderr, "usage: edrctl rootsession ack PID SECRET")
				os.Exit(2)
			}
			pid, err := strconv.Atoi(flag.Arg(2))
			die(err)
			body, err := ackRootSession(*socket, pid, flag.Arg(3))
			die(err)
			fmt.Println(string(body))
		case "bypass":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl rootsession bypass TOKEN [ttl=SECONDS]")
				os.Exit(2)
			}
			ttl := 0
			var err error
			for _, arg := range flag.Args()[3:] {
				if strings.HasPrefix(arg, "ttl=") {
					ttl, err = strconv.Atoi(strings.TrimPrefix(arg, "ttl="))
					die(err)
				}
			}
			body, err := unixPostJSON(*socket, "/v0/root-sessions/bypass", fmt.Sprintf(`{"token":%q,"ttl_sec":%d}`, flag.Arg(2), ttl))
			die(err)
			fmt.Println(string(body))
		case "bypass-clear":
			body, err := unixPost(*socket, "/v0/root-sessions/bypass/clear")
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "metrics":
		if flag.NArg() >= 2 && flag.Arg(1) == "prometheus" {
			body, err := unixGet(*socket, "/v0/metrics/prometheus")
			die(err)
			fmt.Println(string(body))
			return
		}
		body, err := unixGet(*socket, "/v0/metrics")
		die(err)
		fmt.Println(string(body))
	case "health":
		body, err := unixGet(*socket, "/v0/health")
		die(err)
		fmt.Println(string(body))
	case "shutdown":
		if flag.NArg() != 1 {
			usage()
		}
		body, err := unixPost(*socket, "/v0/shutdown")
		die(err)
		fmt.Println(string(body))
	case "events":
		if flag.NArg() >= 2 && flag.Arg(1) == "verify" {
			body, err := unixGet(*socket, "/v0/events/verify")
			die(err)
			fmt.Println(string(body))
			return
		}
		if flag.NArg() >= 2 && flag.Arg(1) == "tail" {
			body, err := unixGet(*socket, "/v0/events"+queryString(flag.Args()[2:]))
			die(err)
			if *jsonFlag {
				fmt.Println(string(body))
			} else {
				printEventTable(body)
			}
			return
		}
		if flag.NArg() >= 2 && flag.Arg(1) == "query" {
			body, err := unixGet(*socket, "/v0/events"+queryString(flag.Args()[2:]))
			die(err)
			if *jsonFlag {
				fmt.Println(string(body))
			} else {
				printEventTable(body)
			}
			return
		}
		usage()
	case "responses":
		if flag.NArg() != 2 || flag.Arg(1) != "list" {
			usage()
		}
		body, err := unixGet(*socket, "/v0/responses")
		die(err)
		fmt.Println(string(body))
	case "forensics":
		if flag.NArg() >= 2 && flag.Arg(1) == "export" {
			body, err := unixPost(*socket, "/v0/forensics/export"+queryString(flag.Args()[2:]))
			die(err)
			fmt.Println(string(body))
			return
		}
		usage()
	case "nft":
		if flag.NArg() != 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "list":
			body, err := unixGet(*socket, "/v0/network/nft/list")
			die(err)
			fmt.Println(string(body))
		case "rollback":
			body, err := unixPost(*socket, "/v0/network/nft/rollback")
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "process":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "freeze":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl process freeze PID [path=PATH] [ticks=TICKS]")
				os.Exit(2)
			}
			pid := flag.Arg(2)
			body := fmt.Sprintf(`{"pid":%s`, pid)
			for _, arg := range flag.Args()[3:] {
				if strings.HasPrefix(arg, "path=") {
					body += fmt.Sprintf(`,"process_path":"%s"`, strings.TrimPrefix(arg, "path="))
				} else if strings.HasPrefix(arg, "ticks=") {
					body += fmt.Sprintf(`,"start_ticks":"%s"`, strings.TrimPrefix(arg, "ticks="))
				}
			}
			body += "}"
			resp, err := unixPostJSON(*socket, "/v0/process/freeze", body)
			die(err)
			fmt.Println(string(resp))
		case "resume":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl process resume PID")
				os.Exit(2)
			}
			body := fmt.Sprintf(`{"pid":%s}`, flag.Arg(2))
			resp, err := unixPostJSON(*socket, "/v0/process/resume", body)
			die(err)
			fmt.Println(string(resp))
		case "frozen":
			body, err := unixGet(*socket, "/v0/process/frozen")
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "network":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "isolate":
			body, err := unixPost(*socket, "/v0/network/isolate")
			die(err)
			fmt.Println(string(body))
		case "restore":
			body, err := unixPost(*socket, "/v0/network/restore")
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "notify":
		if flag.NArg() < 2 || flag.Arg(1) != "test" {
			usage()
		}
		body, err := unixPost(*socket, "/v0/notify/test")
		die(err)
		fmt.Println(string(body))
	case "quarantine":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "list":
			body, err := unixGet(*socket, "/v0/quarantine/list")
			die(err)
			fmt.Println(string(body))
		case "restore":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl quarantine restore ORIGINAL_PATH")
				os.Exit(2)
			}
			body, err := unixPost(*socket, "/v0/quarantine/restore?path="+flag.Arg(2))
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "report":
		if flag.NArg() < 2 || flag.Arg(1) != "generate" {
			usage()
		}
		reportReq := map[string]string{}
		for _, arg := range flag.Args()[2:] {
			kv := strings.SplitN(arg, "=", 2)
			if len(kv) == 2 {
				reportReq[kv[0]] = kv[1]
			}
		}
		body := `{}`
		if _, ok := reportReq["from"]; ok || reportReq["since"] != "" {
			since := reportReq["from"]
			if since == "" {
				since = reportReq["since"]
			}
			until := reportReq["to"]
			if until == "" {
				until = reportReq["until"]
			}
			body = fmt.Sprintf(`{"since":"%s","until":"%s"}`, since, until)
		}
		resp, err := unixPostJSON(*socket, "/v0/report/generate", body)
		die(err)
		outputPath := reportReq["output"]
		if outputPath != "" {
			die(os.WriteFile(outputPath, resp, 0o640))
			fmt.Printf("report written to %s (%d bytes)\n", outputPath, len(resp))
		} else {
			fmt.Println(string(resp))
		}
	default:
		usage()
	}
}

func queryString(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.Contains(arg, "=") {
			parts = append(parts, arg)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func unixGet(socket, path string) ([]byte, error) {
	return unixRequest(socket, http.MethodGet, path, "")
}

func unixPost(socket, path string) ([]byte, error) {
	return unixPostJSON(socket, path, "")
}

func unixPostJSON(socket, path, jsonBody string) ([]byte, error) {
	return unixRequest(socket, http.MethodPost, path, jsonBody)
}

func unixRequest(socket, method, path, jsonBody string) ([]byte, error) {
	deadline := time.Now().Add(unixRequestReadyTimeout)
	var lastErr error
	for {
		client := unixClient(socket)
		var body io.Reader
		if jsonBody != "" {
			body = strings.NewReader(jsonBody)
		}
		req, err := http.NewRequest(method, "http://unix"+path, body)
		if err != nil {
			return nil, err
		}
		if jsonBody != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				respBody, _ := io.ReadAll(resp.Body)
				if method == http.MethodGet {
					if len(respBody) == 0 {
						return nil, errors.New(resp.Status)
					}
					return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(respBody)))
				}
				return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(respBody)))
			}
			return io.ReadAll(resp.Body)
		}
		lastErr = err
		if !shouldRetryUnixRequest(err) || time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(unixRequestRetryInterval)
	}
}

func shouldRetryUnixRequest(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ECONNREFUSED)
}

func unixClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return unixDial("unix", socket) }}}
}

func printJSON(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }
func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: edrctl [--socket path] [--json] COMMAND")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  status                        Show agent status")
	fmt.Fprintln(os.Stderr, "  ha status                     Show HA/supervisor status")
	fmt.Fprintln(os.Stderr, "  rootsession status            Show root session liveness state")
	fmt.Fprintln(os.Stderr, "  rootsession challenge PID     Issue a root session challenge")
	fmt.Fprintln(os.Stderr, "  rootsession ack PID SECRET    Answer a root session challenge")
	fmt.Fprintln(os.Stderr, "  rootsession bypass TOKEN [ttl=SECONDS]")
	fmt.Fprintln(os.Stderr, "  rootsession bypass-clear      Clear an active break-glass window")
	fmt.Fprintln(os.Stderr, "  metrics                       Show agent metrics (JSON)")
	fmt.Fprintln(os.Stderr, "  metrics prometheus             Show Prometheus metrics")
	fmt.Fprintln(os.Stderr, "  health                        Health check")
	fmt.Fprintln(os.Stderr, "  shutdown                      Shutdown agent")
	fmt.Fprintln(os.Stderr, "  policy validate FILE          Validate policy file")
	fmt.Fprintln(os.Stderr, "  policy sign FILE KEY          Sign policy file")
	fmt.Fprintln(os.Stderr, "  policy verify-signature [F K] Verify policy signature")
	fmt.Fprintln(os.Stderr, "  policy reload [FILE]          Reload policy")
	fmt.Fprintln(os.Stderr, "  policy versions               List policy versions")
	fmt.Fprintln(os.Stderr, "  policy rollback [VERSION]     Rollback policy")
	fmt.Fprintln(os.Stderr, "  baseline run FILE             Run baseline check")
	fmt.Fprintln(os.Stderr, "  events tail [k=v...]          Tail events")
	fmt.Fprintln(os.Stderr, "  events query [k=v...]         Query events")
	fmt.Fprintln(os.Stderr, "  events verify                 Verify event chain")
	fmt.Fprintln(os.Stderr, "  responses list                List response history")
	fmt.Fprintln(os.Stderr, "  forensics export [k=v...]     Export forensics")
	fmt.Fprintln(os.Stderr, "  nft list                      List nft rules")
	fmt.Fprintln(os.Stderr, "  nft rollback                  Rollback nft rules")
	fmt.Fprintln(os.Stderr, "  process freeze PID [k=v...]   Freeze process (SIGSTOP)")
	fmt.Fprintln(os.Stderr, "  process resume PID            Resume process (SIGCONT)")
	fmt.Fprintln(os.Stderr, "  process frozen                List frozen processes")
	fmt.Fprintln(os.Stderr, "  network isolate               Apply network isolation")
	fmt.Fprintln(os.Stderr, "  network restore               Restore network")
	fmt.Fprintln(os.Stderr, "  notify test                   Test webhook notification")
	fmt.Fprintln(os.Stderr, "  quarantine list               List quarantined files")
	fmt.Fprintln(os.Stderr, "  quarantine restore PATH       Restore quarantined file")
	fmt.Fprintln(os.Stderr, "  report generate [from=T] [to=T] [output=FILE]")
	fmt.Fprintln(os.Stderr, "                                Generate post-exercise report")
	os.Exit(2)
}

func printStatus(raw []byte) {
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Println(string(raw))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range []string{"ring0", "collector", "policy_rules", "process_access", "response_history", "proc_tree_nodes", "conn_tracker", "active_connections", "recent_blocks"} {
		v, ok := s[k]
		if !ok {
			continue
		}
		switch k {
		case "ring0":
			fmt.Fprintf(w, "ring0:\t%s\n", v)
		case "collector":
			fmt.Fprintf(w, "collector:\t%s\n", v)
		case "policy_rules":
			fmt.Fprintf(w, "policy rules:\t%.0f\n", v)
		case "process_access":
			if b, ok := v.(bool); ok && b {
				fmt.Fprintf(w, "process access:\tenabled\n")
			} else {
				fmt.Fprintf(w, "process access:\tdisabled\n")
			}
		case "response_history":
			fmt.Fprintf(w, "responses:\t%.0f\n", v)
		case "proc_tree_nodes":
			fmt.Fprintf(w, "proc tree nodes:\t%.0f\n", v)
		case "conn_tracker":
			fmt.Fprintf(w, "conn tracker:\t%s\n", v)
		case "active_connections":
			fmt.Fprintf(w, "active conns:\t%.0f\n", v)
		case "recent_blocks":
			fmt.Fprintf(w, "recent blocks:\t%.0f\n", v)
		}
	}
	w.Flush()
}

func printHAStatus(raw []byte) {
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Println(string(raw))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "instance:\t%s\n", strField(s, "instance_id"))
	fmt.Fprintf(w, "peer:\t%s\n", strField(s, "peer_instance_id"))
	fmt.Fprintf(w, "run dir:\t%s\n", strField(s, "run_dir"))
	fmt.Fprintf(w, "supervisor:\t%v\n", s["supervisor_enabled"])
	fmt.Fprintf(w, "local state:\t%s\n", strField(s, "local_state"))
	fmt.Fprintf(w, "peer state:\t%s\n", strField(s, "peer_state"))
	if sync, ok := s["supervisor_sync"].(map[string]any); ok {
		fmt.Fprintf(w, "last sync status:\t%s\n", strField(sync, "status"))
		fmt.Fprintf(w, "last sync action:\t%s\n", strField(sync, "action"))
		if v := strField(sync, "attempted_at"); v != "-" && !isZeroTime(v) {
			fmt.Fprintf(w, "last attempted:\t%s\n", v)
		}
		if v := strField(sync, "last_success_at"); v != "-" && !isZeroTime(v) {
			fmt.Fprintf(w, "last success:\t%s\n", v)
		}
		if v := strField(sync, "decision_id"); v != "-" {
			fmt.Fprintf(w, "decision id:\t%s\n", v)
		}
		if v := strField(sync, "error"); v != "-" {
			fmt.Fprintf(w, "last error:\t%s\n", v)
		}
	}
	if activity, ok := s["ha_activity"].(map[string]any); ok {
		fmt.Fprintf(w, "last ha action:\t%s\n", strField(activity, "action"))
		if v := strField(activity, "recorded_at"); v != "-" && !isZeroTime(v) {
			fmt.Fprintf(w, "last ha at:\t%s\n", v)
		}
		if v := strField(activity, "rule_id"); v != "-" {
			fmt.Fprintf(w, "last ha rule:\t%s\n", v)
		}
		if v := strField(activity, "peer"); v != "-" {
			fmt.Fprintf(w, "last ha peer:\t%s\n", v)
		}
		if v := strField(activity, "source"); v != "-" {
			fmt.Fprintf(w, "last ha source:\t%s\n", v)
		}
		if v := strField(activity, "lease_id"); v != "-" {
			fmt.Fprintf(w, "last ha lease:\t%s\n", v)
		}
		if v := strField(activity, "detail"); v != "-" {
			fmt.Fprintf(w, "last ha detail:\t%s\n", v)
		}
		if v := strField(activity, "error"); v != "-" {
			fmt.Fprintf(w, "last ha error:\t%s\n", v)
		}
	}
	w.Flush()
}

func printRootSessionStatus(raw []byte) {
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Println(string(raw))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "enabled:\t%v\n", s["enabled"])
	fmt.Fprintf(w, "mode:\t%s\n", strField(s, "mode"))
	if v := strField(s, "bypass_until"); v != "-" && !isZeroTime(v) {
		fmt.Fprintf(w, "bypass until:\t%s\n", v)
	}
	if sessions, ok := s["sessions"].([]any); ok {
		fmt.Fprintf(w, "sessions:\t%d\n", len(sessions))
		for _, item := range sessions {
			session, ok := item.(map[string]any)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "session:\tpid=%v class=%s state=%s tty=%s\n",
				session["pid"], strField(session, "class"), strField(session, "state"), strField(session, "tty"))
		}
	}
	w.Flush()
}

func ackRootSession(socket string, pid int, secret string) ([]byte, error) {
	chRaw, err := unixPostJSON(socket, "/v0/root-sessions/challenge", fmt.Sprintf(`{"pid":%d}`, pid))
	if err != nil {
		return nil, err
	}
	var ch struct {
		SessionID string    `json:"session_id"`
		PID       int       `json:"pid"`
		TTY       string    `json:"tty"`
		Nonce     string    `json:"nonce"`
		Deadline  time.Time `json:"deadline"`
	}
	if err := json.Unmarshal(chRaw, &ch); err != nil {
		return nil, err
	}
	resp := rootsession.ComputeResponse([]byte(secret), ch.SessionID, ch.TTY, ch.PID, ch.Deadline, ch.Nonce)
	body := fmt.Sprintf(`{"pid":%d,"session_id":%q,"tty":%q,"nonce":%q,"deadline":%q,"response":%q}`,
		ch.PID, ch.SessionID, ch.TTY, ch.Nonce, ch.Deadline.UTC().Format(time.RFC3339Nano), resp)
	return unixPostJSON(socket, "/v0/root-sessions/respond", body)
}

func printEventTable(raw []byte) {
	var result struct {
		Events []map[string]any `json:"events"`
		Count  int              `json:"count"`
		Total  int              `json:"total"`
		Offset int              `json:"offset"`
		Limit  int              `json:"limit"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Println(string(raw))
		return
	}
	if len(result.Events) == 0 {
		fmt.Println("(no events)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tHOST\tRULE\tSEVERITY\tCATEGORY\tDECISION\tACTION")
	for _, e := range result.Events {
		ts := shortTime(strField(e, "timestamp"))
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			ts,
			strField(e, "host"),
			strField(e, "rule_id"),
			strField(e, "severity"),
			strField(e, "category"),
			strField(e, "decision"),
			strField(e, "action"),
		)
	}
	w.Flush()
	fmt.Printf("\n%d of %d events (offset=%d, limit=%d)\n", result.Count, result.Total, result.Offset, result.Limit)
}

func strField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	if v == "" {
		return "-"
	}
	return v
}

func isZeroTime(v string) bool {
	return v == "0001-01-01T00:00:00Z" || v == "0001-01-01T00:00:00Z00:00"
}

func shortTime(ts string) string {
	if len(ts) >= 19 {
		return ts[11:19] // HH:MM:SS from RFC3339
	}
	return ts
}

var _ = strings.Builder{}
