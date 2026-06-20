package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type peerCredKey struct{}

type peerCred struct {
	uid uint32
	gid uint32
	pid int32
}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred peerCred
	_ = raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			cred = peerCred{uid: ucred.Uid, gid: ucred.Gid, pid: ucred.Pid}
		}
	})
	if cred.uid == 0 && cred.gid == 0 && cred.pid == 0 {
		return ctx
	}
	return context.WithValue(ctx, peerCredKey{}, cred)
}

const auditLoginUIDUnset = uint32(4294967295)

var readPeerLoginUID = readProcLoginUID

func readProcLoginUID(pid int32) (uint32, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid peer pid %d", pid)
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "loginuid"))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func shutdownCredential(r *http.Request) (peerCred, uint32, error) {
	cred, ok := r.Context().Value(peerCredKey{}).(peerCred)
	if !ok {
		return peerCred{}, 0, fmt.Errorf("missing peer credentials")
	}
	loginUID, err := readPeerLoginUID(cred.pid)
	if err != nil {
		return cred, 0, fmt.Errorf("read peer loginuid: %w", err)
	}
	return cred, loginUID, nil
}

func authorizeRootLogin(r *http.Request) (peerCred, uint32, error) {
	cred, loginUID, err := shutdownCredential(r)
	if err != nil {
		return cred, loginUID, err
	}
	if cred.uid != 0 {
		return cred, loginUID, fmt.Errorf("uid %d is not authorized for shutdown", cred.uid)
	}
	if loginUID != 0 && loginUID != auditLoginUIDUnset {
		return cred, loginUID, fmt.Errorf("peer loginuid %d is not authorized for shutdown", loginUID)
	}
	return cred, loginUID, nil
}

func authorize(r *http.Request, allowedUIDs []int) error {
	if len(allowedUIDs) == 0 {
		return fmt.Errorf("no authorized uids configured")
	}
	cred, ok := r.Context().Value(peerCredKey{}).(peerCred)
	if !ok {
		return fmt.Errorf("missing peer credentials")
	}
	for _, uid := range allowedUIDs {
		if cred.uid == uint32(uid) {
			return nil
		}
	}
	return fmt.Errorf("uid %d is not authorized", cred.uid)
}

func safePathUnder(baseDir, candidate string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		return "", fmt.Errorf("base directory is not configured")
	}
	if strings.TrimSpace(candidate) == "" {
		return "", fmt.Errorf("path is required")
	}
	// Resolve the candidate fully (including symlinks) so the
	// returned path is ready for I/O.
	candAbs, err := resolvePathAllowMissing(candidate)
	if err != nil {
		return "", err
	}
	// SECURITY: the base directory must NOT be a symlink at any
	// point — not just at startup. ValidateBaseNotSymlink() checks
	// at startup, but an attacker could replace the directory after
	// startup. Reject symlink bases at request time.
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	baseAbs = filepath.Clean(baseAbs)
	baseInfo, err := os.Lstat(baseAbs)
	if err == nil && baseInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("base directory %q is a symlink — refusing path containment check", baseDir)
	}
	rel, err := filepath.Rel(baseAbs, candAbs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes base directory %q", candidate, baseAbs)
	}
	return candAbs, nil
}

// ValidateBaseNotSymlink checks that a config directory path and all
// its parent components are not symlinks. If any component does not
// exist, it is created as a real directory (via os.Mkdir) so an
// attacker cannot race-create a symlink at that path before the
// agent's first I/O. Call this at startup for artifact_dir,
// event_path parent, etc. to prevent symlink-based containment escapes.
func ValidateBaseNotSymlink(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// Walk every component from root to the target, checking each
	// with Lstat (no symlink resolution). If any component is a
	// symlink, reject. If a component doesn't exist, create it as
	// a real directory.
	parts := strings.Split(abs, string(filepath.Separator))
	// parts[0] is "" for an absolute path (leading /), skip it.
	cur := string(filepath.Separator)
	for i := 1; i < len(parts); i++ {
		cur = filepath.Join(cur, parts[i])
		info, err := os.Lstat(cur)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("lstat %q: %w", cur, err)
			}
			// Component does not exist — create it and all
			// remaining components as real directories.
			if err := os.MkdirAll(filepath.Clean(abs), 0o750); err != nil {
				return fmt.Errorf("create config dir %q: %w", path, err)
			}
			// TOCTOU re-check: walk the full path again to
			// verify no component became a symlink between our
			// Lstat and MkdirAll.
			return recheckNoSymlink(abs, path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config path component %q is a symlink (full path: %q)", cur, path)
		}
	}
	return nil
}

// recheckNoSymlink walks abs from root and rejects if any component
// is a symlink. Used as a TOCTOU guard after MkdirAll.
func recheckNoSymlink(abs, origPath string) error {
	parts := strings.Split(abs, string(filepath.Separator))
	cur := string(filepath.Separator)
	for i := 1; i < len(parts); i++ {
		cur = filepath.Join(cur, parts[i])
		info, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("recheck lstat %q: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config path component %q became a symlink after creation (full path: %q)", cur, origPath)
		}
	}
	return nil
}

func resolvePathAllowMissing(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var suffix []string
	cur := abs
	for {
		info, err := os.Lstat(cur)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				resolved, err := filepath.EvalSymlinks(cur)
				if err != nil {
					return "", err
				}
				cur = resolved
			}
			break
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = parent
	}
	resolved, err := filepath.EvalSymlinks(cur)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		resolved = cur
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, suffix[i])
	}
	return filepath.Clean(resolved), nil
}

func requireAuthorized(w http.ResponseWriter, r *http.Request, allowedUIDs []int) bool {
	if err := authorize(r, allowedUIDs); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return false
	}
	return true
}
