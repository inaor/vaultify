package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
)

func pathsEqual(a, b string) bool {
	na, ea := filepath.Abs(filepath.Clean(a))
	nb, eb := filepath.Abs(filepath.Clean(b))
	if ea != nil || eb != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

// isSubpath reports whether target is base or a directory/file inside base.
func isSubpath(base, target string) bool {
	baseAbs, err := filepath.Abs(filepath.Clean(base))
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (srv *Server) applyLocationAllowed(sessionID, matchSHA, fullPath string, lineNum int) bool {
	if fullPath == "" || matchSHA == "" {
		return false
	}
	try := func(f scanner.Finding) bool {
		if f.MatchSHA256 != matchSHA || f.FullPath == "" {
			return false
		}
		if f.LineNumber != lineNum {
			return false
		}
		return pathsEqual(f.FullPath, fullPath)
	}

	if sessionID == "" {
		srv.state.mu.Lock()
		defer srv.state.mu.Unlock()
		for _, f := range srv.state.Findings {
			if try(f) {
				return true
			}
		}
		return false
	}

	if !session.IsValidID(sessionID) {
		return false
	}

	srv.state.mu.Lock()
	cur := srv.state.SessionID
	srv.state.mu.Unlock()
	if sessionID == cur {
		srv.state.mu.Lock()
		for _, f := range srv.state.Findings {
			if try(f) {
				srv.state.mu.Unlock()
				return true
			}
		}
		srv.state.mu.Unlock()
	}

	s, err := srv.sessions.Get(sessionID)
	if err != nil {
		return false
	}
	for _, f := range s.Findings {
		if try(f) {
			return true
		}
	}
	return false
}

func (srv *Server) replaceBrowseRootsFromScanRoots(scanRoots []string) {
	home, _ := os.UserHomeDir()
	var paths []string
	if home != "" {
		paths = append(paths, home)
	}
	for _, r := range scanRoots {
		if r != "" {
			paths = append(paths, r)
		}
	}
	srv.replaceBrowseRoots(paths)
}

func (srv *Server) replaceBrowseRoots(paths []string) {
	seen := make(map[string]bool)
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		a, err := filepath.Abs(filepath.Clean(p))
		if err != nil {
			continue
		}
		a = filepath.Clean(a)
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	srv.browseRootsMu.Lock()
	srv.browseRoots = out
	srv.browseRootsMu.Unlock()
}

func (srv *Server) pathAllowedForBrowse(target string) bool {
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return false
	}
	srv.browseRootsMu.Lock()
	roots := append([]string(nil), srv.browseRoots...)
	srv.browseRootsMu.Unlock()
	for _, root := range roots {
		if isSubpath(root, abs) {
			return true
		}
	}
	return false
}
