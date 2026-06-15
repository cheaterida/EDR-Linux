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
	"strings"

	"edr/internal/baseline"
	"edr/internal/integrity"
	"edr/internal/policy"
)

func main() {
	socket := flag.String("socket", "var/run/edr-agent.sock", "agent unix socket")
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
		fmt.Println(string(body))
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
			fmt.Println(string(body))
			return
		}
		if flag.NArg() >= 2 && flag.Arg(1) == "query" {
			body, err := unixGet(*socket, "/v0/events"+queryString(flag.Args()[2:]))
			die(err)
			fmt.Println(string(body))
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
	client := unixClient(socket)
	resp, err := client.Get("http://unix" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func unixPost(socket, path string) ([]byte, error) {
	return unixPostJSON(socket, path, "")
}

func unixPostJSON(socket, path, jsonBody string) ([]byte, error) {
	client := unixClient(socket)
	var body io.Reader
	if jsonBody != "" {
		body = strings.NewReader(jsonBody)
	}
	req, err := http.NewRequest("POST", "http://unix"+path, body)
	if err != nil {
		return nil, err
	}
	if jsonBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return io.ReadAll(resp.Body)
}

func unixClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return net.Dial("unix", socket) }}}
}

func printJSON(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }
func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: edrctl [--socket path] COMMAND")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  status                        Show agent status")
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
	os.Exit(2)
}

var _ = strings.Builder{}
