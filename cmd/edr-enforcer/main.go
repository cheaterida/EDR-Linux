package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"edr/internal/app"
	"edr/internal/eventlog"
	"edr/internal/response"
	iruntime "edr/internal/runtime"
	"edr/internal/transport"
)

func main() {
	app.CacheRuntimeVars()

	cfgPath := flag.String("config", "configs/enforcer.json", "config path")
	flag.Parse()

	cfg, err := iruntime.LoadConfig(*cfgPath)
	if err != nil {
		app.Fatal(err)
	}
	if err := app.ValidateConfigPaths(cfg); err != nil {
		app.Fatal(err)
	}

	logger, err := eventlog.NewWithOptions(cfg.EventPath, eventlog.Options{
		EnableSyslog: cfg.Syslog,
		MaxBytes:     cfg.Retention.MaxBytes,
		MaxBackups:   cfg.Retention.MaxBackups,
	})
	if err != nil {
		app.Fatal(err)
	}
	responder := response.SoftResponder{
		DryRun: cfg.DryRun,
		NFT:    response.NFTProvider{Enabled: cfg.NFT.Enabled, DryRun: cfg.NFT.DryRun, Table: cfg.NFT.Table, Chain: cfg.NFT.Chain},
	}
	localAuth := transport.NewAuthenticator(iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret), 30*time.Second)

	socketPath := iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.EnforcerSocket)
	if err := app.PrepareSocketPath(socketPath); err != nil {
		app.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := localAuth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "component": "enforcer", "instance_id": cfg.HA.InstanceID})
	})
	mux.HandleFunc("/v0/enforcer/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req transport.ActionEnvelope
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := authorizeAction(localAuth, r, body, req); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		result := responder.Apply(req.Request)
		_ = logger.Write(eventlog.Event{
			EventID:  "enforcer-" + req.RequestID,
			Category: "enforcer",
			Severity: "high",
			Action:   req.Request.Action,
			Decision: "alert",
			RuleID:   req.Request.RuleID,
			Subject:  map[string]any{"instance_id": cfg.HA.InstanceID, "request_id": req.RequestID},
			Evidence: map[string]any{"result": result},
		})
		_ = json.NewEncoder(w).Encode(transport.ActionResultEnvelope{
			RequestID:   req.RequestID,
			InstanceID:  cfg.HA.InstanceID,
			Generation:  req.Generation,
			Result:      result,
			CompletedAt: time.Now().UTC(),
		})
	})

	srv, ln, err := transport.ListenUnix(socketPath, mux, nil)
	if err != nil {
		app.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(ln) }()

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	defer signal.Stop(sigCh)
	<-sigCh
	_ = srv.Shutdown(context.Background())
}

func authorizeAction(auth *transport.Authenticator, r *http.Request, body []byte, req transport.ActionEnvelope) error {
	if req.RequestID == "" {
		return fmt.Errorf("missing request id")
	}
	if req.RequestedAt.IsZero() {
		return fmt.Errorf("missing request time")
	}
	headerID, headerTS, err := auth.Authorize(r, body)
	if err != nil {
		return err
	}
	if auth.Enabled() && headerID != req.RequestID {
		return fmt.Errorf("request id mismatch")
	}
	if auth.Enabled() && !headerTS.Equal(req.RequestedAt) {
		return fmt.Errorf("request time mismatch")
	}
	return nil
}
