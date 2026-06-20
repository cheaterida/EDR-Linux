package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"edr/internal/app"
	"edr/internal/eventlog"
	iruntime "edr/internal/runtime"
	"edr/internal/supervisor"
)

func main() {
	app.CacheRuntimeVars()

	cfgPath := flag.String("config", "configs/supervisor.json", "config path")
	listenAddr := flag.String("listen", "127.0.0.1:9099", "listen address")
	flag.Parse()

	cfg, err := iruntime.LoadConfig(*cfgPath)
	if err != nil {
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
	srv := supervisor.NewServerWithOptions(supervisor.Options{
		Secret:         iruntime.ParseHexOrRawSecret(cfg.Supervisor.SharedSecret),
		Logger:         logger,
		StatePath:      iruntime.ResolveFromConfigPath(*cfgPath, cfg.Supervisor.StatePath),
		EvidenceDir:    iruntime.ResolveFromConfigPath(*cfgPath, cfg.Supervisor.EvidenceDir),
		DecisionTTL:    time.Duration(cfg.Supervisor.DecisionCooldownSec) * time.Second,
		HostStaleAfter: time.Duration(cfg.Supervisor.HostStaleAfterSec) * time.Second,
		MaxHistory:     cfg.Supervisor.MaxDecisionHistory,
	})
	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if cfg.Supervisor.TLSCertPath != "" || cfg.Supervisor.TLSKeyPath != "" {
		tlsConfig, err := buildSupervisorTLSConfig(cfg)
		if err != nil {
			app.Fatal(err)
		}
		httpSrv.TLSConfig = tlsConfig
		if err := httpSrv.ListenAndServeTLS(cfg.Supervisor.TLSCertPath, cfg.Supervisor.TLSKeyPath); err != nil && err != http.ErrServerClosed {
			app.Fatal(err)
		}
		return
	}
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		app.Fatal(err)
	}
}

func buildSupervisorTLSConfig(cfg iruntime.Config) (*tls.Config, error) {
	if cfg.Supervisor.TLSCertPath == "" || cfg.Supervisor.TLSKeyPath == "" {
		return nil, fmt.Errorf("supervisor tls requires both cert and key")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.Supervisor.RequireClientCert {
		if cfg.Supervisor.TLSCAPath == "" {
			return nil, fmt.Errorf("supervisor mTLS requires tls_ca_path")
		}
		raw, err := os.ReadFile(cfg.Supervisor.TLSCAPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("append supervisor client ca: no certificates loaded")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = pool
	}
	return tlsConfig, nil
}
