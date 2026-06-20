package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"edr/internal/app"
	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/proto"
	iruntime "edr/internal/runtime"
	"edr/internal/transport"
)

func main() {
	app.CacheRuntimeVars()

	cfgPath := flag.String("config", "configs/sensor.json", "config path")
	flag.Parse()

	cfg, err := iruntime.LoadConfig(*cfgPath)
	if err != nil {
		app.Fatal(err)
	}
	if err := app.ValidateConfigPaths(cfg); err != nil {
		app.Fatal(err)
	}

	procfs := &collector.ProcfsCollector{WatchPaths: cfg.FileWatch.Paths, WatchMode: cfg.FileWatch.Mode}
	col := collector.NewMergedCollector(procfs, nil)
	logger, err := eventlog.NewWithOptions(cfg.EventPath, eventlog.Options{
		EnableSyslog: cfg.Syslog,
		MaxBytes:     cfg.Retention.MaxBytes,
		MaxBackups:   cfg.Retention.MaxBackups,
	})
	if err != nil {
		app.Fatal(err)
	}

	socketPath := iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.SensorSocket)
	if err := app.PrepareSocketPath(socketPath); err != nil {
		app.Fatal(err)
	}
	localAuth := transport.NewAuthenticator(iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret), 30*time.Second)
	orchestratorClient := transport.NewUnixHTTPClient(iruntime.ResolveFromConfigPath(*cfgPath, cfg.Transport.OrchestratorSocket))

	mux := http.NewServeMux()
	mux.HandleFunc("/v0/health", func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := localAuth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"component":   "sensor",
			"instance_id": cfg.HA.InstanceID,
			"boot_id":     app.CachedBootID,
		})
	})
	mux.HandleFunc("/v0/sensor/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := localAuth.Authorize(r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		snap, err := col.Snapshot()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = logger.Write(eventlog.Event{
			EventID:  fmt.Sprintf("sensor-snapshot-%d", time.Now().UnixNano()),
			Category: "sensor",
			Severity: "info",
			Action:   "snapshot",
			Decision: "alert",
			RuleID:   "sensor-snapshot",
			Subject:  map[string]any{"instance_id": cfg.HA.InstanceID},
			Object:   map[string]any{"processes": len(snap.Processes), "connections": len(snap.Connections), "files": len(snap.FileEvents)},
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"instance_id": cfg.HA.InstanceID,
			"host_id":     app.CachedHostname,
			"boot_id":     app.CachedBootID,
			"snapshot":    snap,
		})
	})

	srv, ln, err := transport.ListenUnix(socketPath, mux, nil)
	if err != nil {
		app.Fatal(err)
	}
	defer ln.Close()

	go func() {
		_ = srv.Serve(ln)
	}()
	go eventPushLoop(cfg, col, logger, orchestratorClient)

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	defer signal.Stop(sigCh)
	<-sigCh
	_ = srv.Shutdown(context.Background())
}

func eventPushLoop(cfg iruntime.Config, col collector.Collector, logger *eventlog.Logger, client *http.Client) {
	interval := time.Duration(cfg.Transport.EventPushEverySec) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	seenProc := make(map[string]struct{})
	for range t.C {
		snap, err := col.Snapshot()
		if err != nil {
			continue
		}
		events := buildDeltaEvents(cfg, snap, seenProc, time.Now().UTC())
		if len(events) == 0 {
			continue
		}
		batch := transport.EventBatch{
			RequestID:  transport.NewRequestID("sensor-batch"),
			InstanceID: cfg.HA.InstanceID,
			HostID:     app.CachedHostname,
			BootID:     app.CachedBootID,
			RecordedAt: time.Now().UTC(),
			Events:     events,
		}
		if _, err := transport.PostJSON(client, "http://unix/v0/events/batch", batch, iruntime.ParseHexOrRawSecret(cfg.Transport.SharedSecret)); err != nil {
			if logger != nil {
				_ = logger.Write(eventlog.Event{
					EventID:  fmt.Sprintf("sensor-batch-push-%d", time.Now().UTC().UnixNano()),
					Category: "sensor",
					Severity: "medium",
					Action:   "push_batch_failed",
					Decision: "alert",
					RuleID:   "sensor-batch-push",
					Evidence: map[string]any{"error": err.Error()},
				})
			}
		}
	}
}

func buildDeltaEvents(cfg iruntime.Config, snap collector.Snapshot, seenProc map[string]struct{}, now time.Time) []proto.EventEnvelope {
	events := make([]proto.EventEnvelope, 0, len(snap.Processes)+len(snap.FileEvents))
	current := make(map[string]struct{}, len(snap.Processes))
	for _, proc := range snap.Processes {
		key := fmt.Sprintf("%d:%s", proc.PID, proc.StartTicks)
		current[key] = struct{}{}
		if _, ok := seenProc[key]; ok {
			continue
		}
		seenProc[key] = struct{}{}
		events = append(events, proto.EventEnvelope{
			EventID:          transport.NewRequestID("proc"),
			InstanceID:       cfg.HA.InstanceID,
			HostID:           app.CachedHostname,
			BootID:           app.CachedBootID,
			SensorGeneration: eventlog.SchemaVersion,
			Category:         "process",
			Subtype:          "sensor-process-observed",
			Severity:         "info",
			Timestamp:        now,
			Subject: map[string]any{
				"pid":      proc.PID,
				"name":     proc.Name,
				"path":     proc.Path,
				"cmdline":  proc.Cmdline,
				"user":     proc.User,
				"ppid":     proc.PPID,
				"cap_eff":  proc.CapEff,
				"euid":     proc.EUID,
				"instance": cfg.HA.InstanceID,
			},
			LocalActionHint: "observe",
		})
	}
	for key := range seenProc {
		if _, ok := current[key]; !ok {
			delete(seenProc, key)
		}
	}
	for _, fe := range snap.FileEvents {
		events = append(events, proto.EventEnvelope{
			EventID:          transport.NewRequestID("file"),
			InstanceID:       cfg.HA.InstanceID,
			HostID:           app.CachedHostname,
			BootID:           app.CachedBootID,
			SensorGeneration: eventlog.SchemaVersion,
			Category:         "file",
			Subtype:          "sensor-file-observed",
			Severity:         "info",
			Timestamp:        now,
			Object: map[string]any{
				"path":     fe.Path,
				"op":       fe.Op,
				"size":     fe.Size,
				"mode":     fe.Mode,
				"mod_time": fe.ModTime,
			},
			LocalActionHint: "observe",
		})
	}
	return events
}
