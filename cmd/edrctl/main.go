package main

import (
	"context"
		"crypto/rand"
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
	case "admin":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "gen-key":
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				die(err)
			}
			fmt.Printf("%x\n", key)
		case "token":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl admin token ACTION (e.g. shutdown, restart, config-reload)")
				os.Exit(2)
			}
			action := flag.Arg(2)
			body, err := unixPostJSON(*socket, "/v0/admin/token", fmt.Sprintf(`{"action":%q}`, action))
			die(err)
			fmt.Println(string(body))
		case "shutdown":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl admin shutdown TOKEN")
				os.Exit(2)
			}
			token := flag.Arg(2)
			body, err := unixPostRawAuth(*socket, "/v0/shutdown", token)
			die(err)
			fmt.Println(string(body))
		case "restart":
			if flag.NArg() < 3 {
				fmt.Fprintln(os.Stderr, "usage: edrctl admin restart TOKEN")
				os.Exit(2)
			}
			token := flag.Arg(2)
			body, err := unixPostRawAuth(*socket, "/v0/admin/restart", token)
			die(err)
			fmt.Println(string(body))
		default:
			usage()
		}
	case "audit":
		if flag.NArg() < 2 {
			usage()
		}
		switch flag.Arg(1) {
		case "export":
			from := ""
			to := ""
			format := "jsonl"
			for _, arg := range flag.Args()[2:] {
				if strings.HasPrefix(arg, "from=") {
					from = strings.TrimPrefix(arg, "from=")
				} else if strings.HasPrefix(arg, "to=") {
					to = strings.TrimPrefix(arg, "to=")
				} else if strings.HasPrefix(arg, "format=") {
					format = strings.TrimPrefix(arg, "format=")
				}
			}
			params := fmt.Sprintf("since=%s&until=%s&limit=100000", from, to)
			body, err := unixGet(*socket, "/v0/events?"+params)
			die(err)
			var result struct {
				Events []map[string]any `json:"events"`
				Count  int              `json:"count"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				die(err)
			}
			switch format {
			case "cef":
				printCEF(result.Events)
			case "leef":
				printLEEF(result.Events)
			default:
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(result.Events)
			}
		case "integrity":
			body, err := unixGet(*socket, "/v0/events/verify")
			die(err)
			if *jsonFlag {
				fmt.Println(string(body))
			} else {
				printIntegrityReport(body)
			}
		case "timeline":
			from := ""
			to := ""
			for _, arg := range flag.Args()[2:] {
				if strings.HasPrefix(arg, "from=") {
					from = strings.TrimPrefix(arg, "from=")
				} else if strings.HasPrefix(arg, "to=") {
					to = strings.TrimPrefix(arg, "to=")
				}
			}
			body, err := unixPostJSON(*socket, "/v0/report/generate", fmt.Sprintf(`{"since":%q,"until":%q}`, from, to))
			die(err)
			var report struct {
				Events []map[string]any `json:"events"`
				Count  int              `json:"event_count"`
			}
			if err := json.Unmarshal(body, &report); err != nil {
				fmt.Println(string(body))
				return
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIME\tSEVERITY\tCATEGORY\tRULE\tDECISION\tACTION\tHOST")
			for _, e := range report.Events {
				ts := shortTime(strField(e, "timestamp"))
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					ts,
					strField(e, "severity"),
					strField(e, "category"),
					strField(e, "rule_id"),
					strField(e, "decision"),
					strField(e, "action"),
					strField(e, "host"),
				)
			}
			w.Flush()
		default:
			usage()
		}
	case "investigate":
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "usage: edrctl investigate EVENT_ID")
			os.Exit(2)
		}
		eventID := flag.Arg(1)
		investigateEvent(*socket, eventID)
	case "pstree":
		detail := false
		filter := ""
		for _, arg := range flag.Args()[1:] {
			if arg == "--detail" {
				detail = true
			} else if strings.HasPrefix(arg, "--filter=") {
				filter = strings.TrimPrefix(arg, "--filter=")
			}
		}
		body, err := unixGet(*socket, "/v0/process/tree")
		die(err)
		printProcTree(body, detail, filter)
	default:
		usage()
	}
}

func printCEF(events []map[string]any) {
	for _, e := range events {
		ts := strField(e, "timestamp")
		host := strField(e, "host")
		rule := strField(e, "rule_id")
		sev := strField(e, "severity")
		cat := strField(e, "category")
		decision := strField(e, "decision")
		action := strField(e, "action")
		desc := strField(e, "description")
		fmt.Printf("CEF:0|EDR|edr-agent|1.0|%s|%s|%s|", rule, desc, sevMap(sev))
		if host != "-" {
			fmt.Printf("dhost=%s ", host)
		}
		fmt.Printf("cat=%s act=%s decision=%s rt=%s\n", cat, action, decision, ts)
	}
}

func printLEEF(events []map[string]any) {
	for _, e := range events {
		ts := strField(e, "timestamp")
		rule := strField(e, "rule_id")
		sev := strField(e, "severity")
		cat := strField(e, "category")
		decision := strField(e, "decision")
		action := strField(e, "action")
		desc := strField(e, "description")
		fmt.Printf("LEEF:2.0|EDR|edr-agent|1.0|%s|", rule)
		fmt.Printf("devTime=%s\tsev=%s\tcat=%s\tdesc=%s\tdecision=%s\taction=%s\n",
			ts, sevMap(sev), cat, desc, decision, action)
	}
}

func sevMap(severity string) string {
	switch severity {
	case "critical":
		return "10"
	case "high":
		return "8"
	case "medium":
		return "5"
	case "low":
		return "3"
	case "info":
		return "1"
	default:
		return "5"
	}
}

func printProcTree(raw []byte, detail bool, filter string) {
	var result struct {
		OK        bool           `json:"ok"`
		Size      int            `json:"size"`
		UpdatedAt string         `json:"updated_at"`
		Nodes     map[int]any    `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || !result.OK {
		fmt.Println(string(raw))
		return
	}

	// Build lookup
	type node struct {
		PID      int
		PPID     int
		Name     string
		Path     string
		Cmdline  string
		User     string
		EUID     string
		Children []int
	}
	nodes := make(map[int]*node)
	for pidStr, v := range result.Nodes {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		pid := int(toFloat(m["pid"]))
		ppid := int(toFloat(m["ppid"]))
		n := &node{
			PID:  pid,
			PPID: ppid,
			Name: strField(m, "name"),
			Path: strField(m, "path"),
		}
		if ch, ok := m["children"].([]any); ok {
			for _, c := range ch {
				n.Children = append(n.Children, int(toFloat(c)))
			}
		}
		if detail {
			n.Cmdline = strField(m, "cmdline")
			n.User = strField(m, "user")
			n.EUID = strField(m, "euid")
		}
		nodes[pid] = n
	}

	// Find roots (PPID not in nodes, or PPID=0)
	var roots []int
	for pid, n := range nodes {
		if _, ok := nodes[n.PPID]; !ok || n.PPID == 0 {
			roots = append(roots, pid)
		}
	}
	sortInts(roots)

	// Filter
	if filter != "" {
		filtered := make(map[int]*node)
		filterLower := strings.ToLower(filter)
		var collect func(int)
		collect = func(pid int) {
			n, ok := nodes[pid]
			if !ok {
				return
			}
			if strings.Contains(strings.ToLower(n.Name), filterLower) ||
				strings.Contains(strings.ToLower(n.Path), filterLower) {
				filtered[pid] = n
				// Walk up to root
				cur := n.PPID
				for cur > 0 {
					if p, ok := nodes[cur]; ok {
						filtered[cur] = p
						cur = p.PPID
					} else {
						break
					}
				}
				// Walk down children
				for _, c := range n.Children {
					collect(c)
				}
			} else {
				for _, c := range n.Children {
					collect(c)
				}
			}
		}
		for _, r := range roots {
			collect(r)
		}
		nodes = filtered
		// Recompute roots from filtered set
		roots = nil
		for pid, n := range nodes {
			if _, ok := nodes[n.PPID]; !ok {
				roots = append(roots, pid)
			}
		}
		sortInts(roots)
	}

	fmt.Printf("\n进程树 (%d 进程, 更新时间: %s)\n", len(nodes), result.UpdatedAt)
	fmt.Println(strings.Repeat("─", 60))

	var render func(pid, depth int, prefix string)
	render = func(pid, depth int, prefix string) {
		n, ok := nodes[pid]
		if !ok {
			return
		}
		connector := "├─"
		childPrefix := "│  "
		if depth == 0 {
			connector = ""
			childPrefix = "   "
		}
		if depth == 0 {
			fmt.Printf("%s%d %s", prefix, pid, n.Name)
		} else {
			fmt.Printf("%s%s %d %s", prefix, connector, pid, n.Name)
		}
		if n.Path != "" && n.Path != "-" {
			fmt.Printf(" [%s]", n.Path)
		}
		if detail {
			fmt.Printf(" user=%s euid=%s cmdline=%s", n.User, n.EUID, n.Cmdline)
		}
		fmt.Println()

		sortInts(n.Children)
		for i, c := range n.Children {
			last := i == len(n.Children)-1
			p := prefix + childPrefix
			if last && depth > 0 {
				// Find if any ancestors have more siblings
				render(c, depth+1, prefix+childPrefix)
			} else {
				render(c, depth+1, prefix+childPrefix)
			}
		}
	}

	for _, r := range roots {
		render(r, 0, "")
	}
}

func toFloat(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case json.Number:
		f, _ := val.Float64()
		return f
	}
	return 0
}

func sortInts(a []int) {
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[i] > a[j] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}

func printIntegrityReport(raw []byte) {
	var result struct {
		Verify      map[string]any `json:"verify"`
		ChainState  map[string]any `json:"chain_state"`
		AgentSchema string         `json:"agent_schema"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Println(string(raw))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if result.Verify != nil {
		fmt.Fprintf(w, "valid:\t%v\n", result.Verify["valid"])
		fmt.Fprintf(w, "events:\t%v\n", result.Verify["events"])
		fmt.Fprintf(w, "errors:\t%v\n", result.Verify["errors"])
	}
	if result.ChainState != nil {
		fmt.Fprintf(w, "chain id:\t%s\n", strField(result.ChainState, "chain_id"))
		fmt.Fprintf(w, "last seq:\t%v\n", result.ChainState["last_seq"])
		fmt.Fprintf(w, "last hash:\t%s\n", strField(result.ChainState, "last_hash"))
	}
	fmt.Fprintf(w, "schema:\t%s\n", result.AgentSchema)
	w.Flush()
}

func unixPostRawAuth(socket, path, token string) ([]byte, error) {
	conn, err := unixDial("unix", socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	req, err := http.NewRequest(http.MethodPost, "http://unix"+path+"?token="+token, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-EDR-Admin-Token", token)
	cli := &http.Client{Transport: &http.Transport{Dial: func(_, _ string) (net.Conn, error) { return conn, nil }}}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
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
	fmt.Fprintln(os.Stderr, "  admin gen-key                 Generate a hex-encoded admin key")
	fmt.Fprintln(os.Stderr, "  admin token ACTION            Request an admin token for ACTION")
	fmt.Fprintln(os.Stderr, "  admin shutdown TOKEN          Admin-authorized shutdown")
	fmt.Fprintln(os.Stderr, "  admin restart TOKEN           Admin-authorized restart")
	fmt.Fprintln(os.Stderr, "  audit export [from=T] [to=T] [format=jsonl|cef|leef]")
	fmt.Fprintln(os.Stderr, "                                Export events in SIEM format")
	fmt.Fprintln(os.Stderr, "  audit integrity               Verify event log chain integrity")
	fmt.Fprintln(os.Stderr, "  audit timeline [from=T] [to=T]")
	fmt.Fprintln(os.Stderr, "                                Show forensic event timeline")
	fmt.Fprintln(os.Stderr, "  investigate EVENT_ID          Full event investigation (rule match, behavior,")
	fmt.Fprintln(os.Stderr, "                                EDR response, network, file operations)")
	fmt.Fprintln(os.Stderr, "  pstree [--detail] [--filter=S]")
	fmt.Fprintln(os.Stderr, "                                Process tree visualization")
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

func investigateEvent(socket, eventID string) {
	// 1. Fetch the event
	ev, err := fetchEvent(socket, eventID)
	die(err)

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  EDR 事件研判: %s\n", eventID)
	fmt.Println("══════════════════════════════════════════════════════════════")

	// Panel 1: Rule Match Details
	printRuleMatch(ev)

	// Panel 2: Process Behavior Timeline
	pid := subjectPID(ev)
	if pid != "" {
		printBehaviorTimeline(socket, pid)
	}

	// Panel 3: EDR Response Records
	printResponseRecords(socket, pid)

	// Panel 4: Network Connections
	printNetworkConnections(socket, pid)

	// Panel 5: File Operations
	printFileOperations(socket, pid)

	fmt.Println("══════════════════════════════════════════════════════════════")
}

func fetchEvent(socket, eventID string) (map[string]any, error) {
	body, err := unixGet(socket, "/v0/events?event_id="+eventID+"&limit=1")
	if err != nil {
		return nil, err
	}
	// unixGet on the /v0/events endpoint with event_id returns a single event
	// or a result object. Try both.
	var ev map[string]any
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	// If it's a result wrapper, extract the first event
	if _, hasEvents := ev["events"]; hasEvents {
		if events, ok := ev["events"].([]any); ok && len(events) > 0 {
			if e, ok := events[0].(map[string]any); ok {
				return e, nil
			}
		}
		return nil, fmt.Errorf("event %s not found", eventID)
	}
	return ev, nil
}

func subjectPID(ev map[string]any) string {
	subj, _ := ev["subject"].(map[string]any)
	if subj == nil {
		return ""
	}
	return fmt.Sprint(subj["pid"])
}

func printRuleMatch(ev map[string]any) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\n▌ 规则命中详情")
	fmt.Fprintf(w, "  规则 ID:\t%s\n", strField(ev, "rule_id"))
	fmt.Fprintf(w, "  分类:\t%s\n", strField(ev, "category"))
	fmt.Fprintf(w, "  严重级别:\t%s\n", strField(ev, "severity"))
	fmt.Fprintf(w, "  决策:\t%s\n", strField(ev, "decision"))
	fmt.Fprintf(w, "  动作:\t%s\n", strField(ev, "action"))
	fmt.Fprintf(w, "  主机:\t%s\n", strField(ev, "host"))
	fmt.Fprintf(w, "  时间:\t%s\n", strField(ev, "timestamp"))

	// Show evidence (rule match details)
	if evidence, ok := ev["evidence"].(map[string]any); ok {
		fmt.Fprintf(w, "  匹配证据:\n")
		for k, v := range evidence {
			fmt.Fprintf(w, "    %s:\t%v\n", k, v)
		}
	}

	// Show subject (process info)
	if subj, ok := ev["subject"].(map[string]any); ok {
		fmt.Fprintf(w, "  进程信息:\n")
		keys := []string{"pid", "ppid", "name", "exe", "cmdline", "user", "euid"}
		for _, k := range keys {
			if v := subj[k]; v != nil && fmt.Sprint(v) != "" && fmt.Sprint(v) != "0" {
				fmt.Fprintf(w, "    %s:\t%v\n", k, v)
			}
		}
	}

	// Show object (file/network info)
	if obj, ok := ev["object"].(map[string]any); ok {
		fmt.Fprintf(w, "  操作对象:\n")
		for k, v := range obj {
			if s := fmt.Sprint(v); s != "" && s != "0" && s != "<nil>" {
				fmt.Fprintf(w, "    %s:\t%s\n", k, s)
			}
		}
	}
	w.Flush()
}

func printBehaviorTimeline(socket, pid string) {
	body, err := unixGet(socket, "/v0/events?subject_pid="+pid+"&limit=200")
	if err != nil {
		return
	}
	var result struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Events) == 0 {
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n▌ 进程行为时间线 (PID=%s, %d 条事件)\n", pid, len(result.Events))
	fmt.Fprintln(w, "  时间\t类型\t规则\t决策\t动作")
	for _, e := range result.Events {
		ts := shortTime(strField(e, "timestamp"))
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
			ts,
			strField(e, "category"),
			strField(e, "rule_id"),
			strField(e, "decision"),
			strField(e, "action"),
		)
	}
	w.Flush()
}

func printResponseRecords(socket, pid string) {
	body, err := unixGet(socket, "/v0/responses?limit=500")
	if err != nil {
		return
	}
	var result struct {
		Responses []map[string]any `json:"responses"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Responses) == 0 {
		return
	}

	var matched []map[string]any
	for _, r := range result.Responses {
		rPID := fmt.Sprint(r["pid"])
		subj, _ := r["subject"].(map[string]any)
		if subj != nil && fmt.Sprint(subj["pid"]) == pid {
			matched = append(matched, r)
			continue
		}
		if rPID == pid {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n▌ EDR 响应记录 (%d 条)\n", len(matched))
	fmt.Fprintln(w, "  时间\t动作\t结果\t详情")
	for _, r := range matched {
		ts := shortTime(strField(r, "timestamp"))
		action := strField(r, "action")
		reasons := "-"
		if info, ok := r["result"].(map[string]any); ok {
			if msg, ok := info["message"].(string); ok {
				reasons = msg
			}
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", ts, action, strField(r, "success"), reasons)
	}
	w.Flush()
}

func printNetworkConnections(socket, pid string) {
	body, err := unixGet(socket, "/v0/events?subject_pid="+pid+"&category=network&limit=100")
	if err != nil {
		return
	}
	var result struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Events) == 0 {
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n▌ 网络连接 (%d 条)\n", len(result.Events))
	fmt.Fprintln(w, "  时间\t协议\t本地端口\t远程地址\t远程端口\t状态")
	for _, e := range result.Events {
		ts := shortTime(strField(e, "timestamp"))
		obj, _ := e["object"].(map[string]any)
		proto := "-"
		localPort := "-"
		remoteAddr := "-"
		remotePort := "-"
		if obj != nil {
			proto = strField(obj, "protocol")
			localPort = fmt.Sprint(obj["local_port"])
			remoteAddr = strField(obj, "remote_addr")
			remotePort = fmt.Sprint(obj["remote_port"])
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			ts, proto, localPort, remoteAddr, remotePort, strField(e, "action"))
	}
	w.Flush()
}

func printFileOperations(socket, pid string) {
	body, err := unixGet(socket, "/v0/events?subject_pid="+pid+"&category=file&limit=100")
	if err != nil {
		return
	}
	var result struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Events) == 0 {
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n▌ 文件操作 (%d 条)\n", len(result.Events))
	fmt.Fprintln(w, "  时间\t操作\t文件路径\t规则")
	for _, e := range result.Events {
		ts := shortTime(strField(e, "timestamp"))
		obj, _ := e["object"].(map[string]any)
		filePath := "-"
		fileOp := "-"
		if obj != nil {
			filePath = strField(obj, "path")
			fileOp = strField(obj, "op")
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			ts, fileOp, filePath, strField(e, "rule_id"))
	}
	w.Flush()
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
