//go:build !bpf

package main

// Default (non-bpf) startBPFLoader: stub that returns a clear
// "not yet wired" error when bpf.enabled is true. R-C1: never
// silently fall back to procfs-only when the operator asked
// for ring0. The real loader lives in main_libbpf.go
// (//go:build bpf) and is selected at build time via
// `-tags bpf`.

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
	return nil, fmt.Errorf("bpf loader is not yet wired (obj_dir=%q); rebuild with `-tags bpf` to enable the libbpf loader (DEV_IRON_RULES R-P2)", cfg.ObjDir)
}
