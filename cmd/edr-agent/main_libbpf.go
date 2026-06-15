//go:build bpf

package main

// Real libbpf-backed startBPFLoader. Compiled only with
// -tags bpf so the default build stays CGO-free.
//
// Wiring: cfg.ObjDir is the directory containing the
// combined probes.bpf.o / all.bpf.o (produced by `bpftool
// gen object`). The loader opens it via libbpf, attaches the
// tracepoint programs, and starts a consumer goroutine that
// pumps events onto a Go channel. R-C1: any failure here
// surfaces as fatal() — the agent must not silently fall
// back to procfs-only when the operator asked for ring0.

import (
	"fmt"

	"edr/internal/bpf"
)

func startBPFLoader(cfg bpfConfig) (bpf.Loader, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.ObjDir == "" {
		return nil, fmt.Errorf("bpf.enabled is true but obj_dir is empty")
	}
	l, err := bpf.NewLibBPFLoader(cfg.ObjDir)
	if err != nil {
		return nil, fmt.Errorf("bpf: %w", err)
	}
	if err := l.Load(); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("bpf load: %w", err)
	}
	return l, nil
}
