package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vaultify/vaultify/internal/exclusions"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
)

// ------------------------------------------------------------------
// Request / response types
// ------------------------------------------------------------------

type scanStartRequest struct {
	Roots []string `json:"roots"`
}

type scanStartResponse struct {
	SessionID string `json:"sessionId"`
}

type applyRequest struct {
	SessionID string      `json:"session_id"`
	VaultName string      `json:"vault_name"`
	Items     []applyItem `json:"items"`
}

type applyItem struct {
	MatchSHA256 string         `json:"match_sha256"`
	Action      string         `json:"action"`
	PatternID   string         `json:"pattern_id"`
	Locations   []applyItemLoc `json:"locations"`
	ItemName    string         `json:"item_name"`
	ApiURL      string         `json:"api_url"`
}

type applyItemLoc struct {
	FullPath     string `json:"full_path"`
	RelativePath string `json:"relative_path"`
	LineNumber   int    `json:"line_number"`
	MatchSHA256  string `json:"match_sha256"`
}

type applyResult struct {
	MatchSHA256 string `json:"match_sha256"`
	Action      string `json:"action"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

type applyResponse struct {
	Results []applyResult `json:"results"`
}

type vaultInfo struct {
	Name       string `json:"name"`
	CLI        string `json:"cli"`
	Installed  bool   `json:"installed"`
	InstallCmd string `json:"install_cmd,omitempty"`
	DocsURL    string `json:"docs_url,omitempty"`
}

type vaultCreateRequest struct {
	Name string `json:"name"`
}

type decisionsSaveRequest struct {
	SessionID string     `json:"sessionId"`
	Decisions []applyItem `json:"decisions"`
}

// ------------------------------------------------------------------
// Scan state tracked by the server
// ------------------------------------------------------------------

type scanState struct {
	mu        sync.Mutex
	Running   bool             `json:"running"`
	SessionID string           `json:"sessionId"`
	Progress  int              `json:"progress"`
	Total     int              `json:"total"`
	Findings  []scanner.Finding `json:"findings"`
	ScanType  string           `json:"scan_type"`
	cancel    context.CancelFunc
}

func (s *scanState) snapshot() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	safe := make([]scanner.Finding, len(s.Findings))
	for i, f := range s.Findings {
		safe[i] = f
		safe[i].Value = ""
	}
	return struct {
		Running   bool              `json:"running"`
		SessionID string            `json:"sessionId"`
		Progress  int               `json:"progress"`
		Total     int               `json:"total"`
		Findings  []scanner.Finding `json:"findings"`
	}{
		Running:   s.Running,
		SessionID: s.SessionID,
		Progress:  s.Progress,
		Total:     s.Total,
		Findings:  safe,
	}
}

// ------------------------------------------------------------------
// Handler implementations
// ------------------------------------------------------------------

func (srv *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	var req scanStartRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if len(req.Roots) == 0 {
		home, _ := os.UserHomeDir()
		if home != "" {
			req.Roots = []string{home}
		} else {
			httpError(w, http.StatusBadRequest, "roots array is required")
			return
		}
	}

	srv.state.mu.Lock()
	if srv.state.Running {
		srv.state.mu.Unlock()
		httpError(w, http.StatusConflict, "scan already running")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	sid := session.NewID()
	scanType := "entire_machine"
	if len(req.Roots) > 0 {
		home, _ := os.UserHomeDir()
		if len(req.Roots) != 1 || req.Roots[0] != home {
			scanType = "specific_folder"
		}
	}
	srv.state.Running = true
	srv.state.SessionID = sid
	srv.state.Progress = 0
	srv.state.Total = 0
	srv.state.Findings = nil
	srv.state.ScanType = scanType
	srv.state.cancel = cancel
	srv.state.mu.Unlock()

	srv.replaceBrowseRootsFromScanRoots(req.Roots)
	go srv.runScan(ctx, sid, req.Roots)
	srv.addSessionAudit("scan_started", fmt.Sprintf("type=%s roots=%v", scanType, req.Roots), sid)

	writeJSON(w, http.StatusAccepted, map[string]string{"sessionId": sid, "scan_type": scanType})
}

func (srv *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	srv.state.mu.Lock()
	if !srv.state.Running {
		srv.state.mu.Unlock()
		httpError(w, http.StatusConflict, "no scan running")
		return
	}
	if srv.state.cancel != nil {
		srv.state.cancel()
	}
	srv.state.Running = false
	sid := srv.state.SessionID
	findings := make([]scanner.Finding, len(srv.state.Findings))
	copy(findings, srv.state.Findings)
	srv.state.mu.Unlock()

	if sid != "" {
		if err := srv.sessions.Save(sid, findings, time.Now()); err != nil {
			log.Printf("save stopped session: %v", err)
		}
	}
	srv.addSessionAudit("scan_stopped", fmt.Sprintf("findings=%d", len(findings)), sid)
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (srv *Server) handleScanState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, srv.state.snapshot())
}

func (srv *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.SessionID != "" && !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	patterns := scanner.LoadPatterns()
	results := make([]applyResult, 0, len(req.Items))

	hasVaultItems := false
	for _, item := range req.Items {
		if item.Action == "vault" { hasVaultItems = true; break }
	}
	if hasVaultItems && req.VaultName != "" {
		ensureVaultExists(req.VaultName)
	}

	for _, item := range req.Items {
		res := applyResult{MatchSHA256: item.MatchSHA256, Action: item.Action, OK: true}
		switch item.Action {
		case "remove":
			var pat *scanner.CompiledPattern
			for i := range patterns {
				if patterns[i].ID == item.PatternID {
					pat = &patterns[i]
					break
				}
			}
			if pat == nil {
				res.OK = false
				res.Error = "pattern not found: " + item.PatternID
			} else {
				redacted := 0
				for _, loc := range item.Locations {
					if loc.FullPath == "" {
						continue
					}
					if !srv.applyLocationAllowed(req.SessionID, item.MatchSHA256, loc.FullPath, loc.LineNumber) {
						res.OK = false
						res.Error = "path is not part of this scan session"
						break
					}
					ok, err := redactFile(loc.FullPath, loc.LineNumber, pat.Regex, item.MatchSHA256)
					if err != nil {
						res.OK = false
						res.Error = err.Error()
					} else if ok {
						redacted++
					}
				}
				res.Detail = fmt.Sprintf("%d file(s) redacted", redacted)
			}
		case "vault":
			if req.VaultName == "" {
				res.OK = false
				res.Error = "no vault name specified"
			} else {
				var pat *scanner.CompiledPattern
				for i := range patterns {
					if patterns[i].ID == item.PatternID {
						pat = &patterns[i]
						break
					}
				}
				if pat == nil {
					res.OK = false
					res.Error = "pattern not found: " + item.PatternID
					break
				}
				plaintext := srv.findPlaintext(req.SessionID, item.MatchSHA256)
				if plaintext == "" {
					res.OK = false
					res.Error = "plaintext not found for this secret"
				} else {
					title := item.ItemName
					if title == "" {
						title = item.PatternID
					}
					itemID, err := createOpItem(req.VaultName, title, plaintext, item.ApiURL)
					if err != nil {
						res.OK = false
						res.Error = err.Error()
					} else {
						ref := fmt.Sprintf("op://%s/%s/credential", req.VaultName, itemID)
						for _, loc := range item.Locations {
							if loc.FullPath == "" {
								continue
							}
							if !srv.applyLocationAllowed(req.SessionID, item.MatchSHA256, loc.FullPath, loc.LineNumber) {
								res.OK = false
								res.Error = "path is not part of this scan session"
								break
							}
							_, err := replaceSecretInFile(loc.FullPath, loc.LineNumber, pat.Regex, item.MatchSHA256, ref)
							if err != nil {
								res.OK = false
								res.Error = err.Error()
								break
							}
						}
						if res.OK {
							res.Detail = ref
						}
					}
				}
			}
		case "dismiss", "graveyard":
			res.Detail = "dismissed"
		default:
			res.OK = false
			res.Error = fmt.Sprintf("unknown action %q", item.Action)
		}
		results = append(results, res)
	}

	// Reports remediation counts only successful vault/remove (see remediation_applied.json).
	var appliedHashes []string
	for _, res := range results {
		if !res.OK {
			continue
		}
		if res.Action == "vault" || res.Action == "remove" {
			appliedHashes = append(appliedHashes, res.MatchSHA256)
		}
	}
	if req.SessionID != "" && len(appliedHashes) > 0 {
		if err := srv.sessions.MergeRemediationApplied(req.SessionID, appliedHashes); err != nil {
			log.Printf("merge remediation applied: %v", err)
		}
	}

	// Audit log the apply action
	vaulted, removed, dismissed, errors := 0, 0, 0, 0
	for _, r := range results {
		if !r.OK {
			errors++
		} else {
			switch r.Action {
			case "vault":
				vaulted++
			case "remove":
				removed++
			case "dismiss", "graveyard":
				dismissed++
			}
		}
	}
	srv.addSessionAudit("decisions_applied",
		fmt.Sprintf("vault=%d remove=%d dismiss=%d errors=%d vault_name=%s", vaulted, removed, dismissed, errors, req.VaultName),
		req.SessionID)

	writeJSON(w, http.StatusOK, applyResponse{Results: results})
}

func opInstallCmd() string {
	if runtime.GOOS == "darwin" {
		return "brew install --cask 1password-cli"
	}
	return "winget install -e --id AgileBits.1Password.CLI"
}

func (srv *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	vaults := []vaultInfo{
		{Name: "1Password", CLI: "op", InstallCmd: opInstallCmd(), DocsURL: "https://developer.1password.com/docs/cli/"},
		{Name: "AWS Secrets Manager", CLI: "aws", DocsURL: "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"},
		{Name: "HashiCorp Vault", CLI: "vault", DocsURL: "https://developer.hashicorp.com/vault/install"},
		{Name: "Doppler", CLI: "doppler", DocsURL: "https://docs.doppler.com/docs/install-cli"},
	}
	for i := range vaults {
		_, err := exec.LookPath(vaults[i].CLI)
		vaults[i].Installed = err == nil
	}
	writeJSON(w, http.StatusOK, vaults)
}

func (srv *Server) handleInstallOp(w http.ResponseWriter, r *http.Request) {
	_, err := exec.LookPath("op")
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"installed": true})
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("brew", "install", "--cask", "1password-cli")
	} else {
		cmd = exec.Command("winget", "install", "-e", "--id", "AgileBits.1Password.CLI", "--accept-source-agreements", "--accept-package-agreements")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("op install: %v\n%s", err, out)
	}

	_, checkErr := exec.LookPath("op")
	installed := checkErr == nil
	srv.addAuditEntry("op_cli_install", fmt.Sprintf("installed=%v", installed))
	writeJSON(w, http.StatusOK, map[string]bool{"installed": installed})
}

func (srv *Server) handleVaultCreate(w http.ResponseWriter, r *http.Request) {
	var req vaultCreateRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Name == "" {
		httpError(w, http.StatusBadRequest, "name is required")
		return
	}

	cmd := exec.Command("op", "vault", "create", req.Name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("op vault create %q: %v\n%s", req.Name, err, out)
		httpError(w, http.StatusInternalServerError, "vault creation failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (srv *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sessions, err := srv.sessions.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list sessions: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (srv *Server) handleSessionsArchivedList(w http.ResponseWriter, r *http.Request) {
	sessions, err := srv.sessions.ListArchived()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list archived: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (srv *Server) handleSessionArchive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpError(w, http.StatusBadRequest, "session id required")
		return
	}
	if !session.IsValidID(id) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	if err := srv.sessions.Archive(id); err != nil {
		httpError(w, http.StatusInternalServerError, "archive: %v", err)
		return
	}
	srv.addSessionAudit("session_archived", id, id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "archived"})
}

func (srv *Server) handleSessionUnarchive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpError(w, http.StatusBadRequest, "session id required")
		return
	}
	if !session.IsValidID(id) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	if err := srv.sessions.Unarchive(id); err != nil {
		httpError(w, http.StatusInternalServerError, "unarchive: %v", err)
		return
	}
	srv.addSessionAudit("session_unarchived", id, id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "unarchived"})
}

func (srv *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpError(w, http.StatusBadRequest, "session id required")
		return
	}
	if !session.IsValidID(id) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	s, err := srv.sessions.Get(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "session not found")
		return
	}
	for i := range s.Findings {
		s.Findings[i].Value = ""
	}
	writeJSON(w, http.StatusOK, s)
}

func (srv *Server) handleDecisionsSave(w http.ResponseWriter, r *http.Request) {
	var req decisionsSaveRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.SessionID == "" {
		httpError(w, http.StatusBadRequest, "sessionId is required")
		return
	}
	if !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	dir := srv.sessions.Dir(req.SessionID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		httpError(w, http.StatusInternalServerError, "failed to save decisions")
		return
	}

	data, _ := json.MarshalIndent(req.Decisions, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "decisions.json"), data, 0o600); err != nil {
		httpError(w, http.StatusInternalServerError, "failed to save decisions")
		return
	}

	srv.addSessionAudit("decisions_saved", fmt.Sprintf("count=%d", len(req.Decisions)), req.SessionID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (srv *Server) handleExclusionsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = srv.exclusions.Load()
	writeJSON(w, http.StatusOK, map[string]any{"entries": srv.exclusions.List()})
}

type exclusionsAddRequest struct {
	Entries []struct {
		MatchSHA256 string `json:"match_sha256"`
		PatternID   string `json:"pattern_id"`
		Source      string `json:"source"`
	} `json:"entries"`
}

func (srv *Server) handleExclusionsAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req exclusionsAddRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	var add []exclusions.Entry
	for _, e := range req.Entries {
		if e.MatchSHA256 == "" {
			continue
		}
		add = append(add, exclusions.Entry{
			MatchSHA256: e.MatchSHA256,
			PatternID:   e.PatternID,
			Source:      e.Source,
		})
	}
	if err := srv.exclusions.Add(add...); err != nil {
		httpError(w, http.StatusInternalServerError, "save exclusions: %v", err)
		return
	}
	srv.addAuditEntry("exclusions_updated", fmt.Sprintf("added=%d", len(add)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(add)})
}

type exclusionsRemoveRequest struct {
	MatchSHA256 string `json:"match_sha256"`
}

func (srv *Server) handleExclusionsRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req exclusionsRemoveRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.MatchSHA256 == "" {
		httpError(w, http.StatusBadRequest, "match_sha256 required")
		return
	}
	if err := srv.exclusions.Remove(req.MatchSHA256); err != nil {
		httpError(w, http.StatusInternalServerError, "remove: %v", err)
		return
	}
	detail := req.MatchSHA256
	if len(detail) > 20 {
		detail = detail[:20] + "..."
	}
	srv.addAuditEntry("exclusion_removed", detail)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ------------------------------------------------------------------
// Background scan runner
// ------------------------------------------------------------------

func (srv *Server) runScan(ctx context.Context, sessionID string, roots []string) {
	_ = srv.exclusions.Load()
	defer func() {
		srv.state.mu.Lock()
		srv.state.Running = false
		srv.state.mu.Unlock()
		srv.state.mu.Lock()
		st := srv.state.ScanType
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":      "scan_complete",
			"sessionId": sessionID,
			"scan_type": st,
		})
	}()

	onProgress := func(progress, total int, currentPath string) {
		srv.state.mu.Lock()
		srv.state.Progress = progress
		srv.state.Total = total
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":         "scan_progress",
			"progress":     progress,
			"total":        total,
			"current_path": currentPath,
		})
	}

	onFinding := func(f scanner.Finding) {
		if srv.exclusions.Contains(f.MatchSHA256) {
			return
		}
		srv.state.mu.Lock()
		srv.state.Findings = append(srv.state.Findings, f)
		srv.state.mu.Unlock()
		safe := f
		if safe.LineSnippet != "" && safe.Value != "" {
			safe.LineSnippet = strings.Replace(safe.LineSnippet, safe.Value, "REDACTED_BY_VAULTIFY", 1)
		}
		safe.Value = ""
		srv.hub.Broadcast(map[string]any{
			"type":    "scan_finding",
			"finding": safe,
		})
	}

	if err := srv.scanner.Scan(ctx, roots, onProgress, onFinding); err != nil && ctx.Err() == nil {
		log.Printf("scan error: %v", err)
		srv.logger.Error("scan_error", fmt.Sprintf("session=%s err=%v", sessionID, err))
	}

	srv.state.mu.Lock()
	findingsCount := len(srv.state.Findings)
	srv.state.mu.Unlock()

	if err := srv.sessions.Save(sessionID, srv.state.Findings, time.Now()); err != nil {
		log.Printf("save session: %v", err)
		srv.logger.Error("session_save_error", fmt.Sprintf("session=%s err=%v", sessionID, err))
	}

	srv.addSessionAudit("scan_complete", fmt.Sprintf("findings=%d", findingsCount), sessionID)
}

// ------------------------------------------------------------------
// Vault auth and list endpoints
// ------------------------------------------------------------------

func (srv *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries := srv.logger.Entries()
	writeJSON(w, http.StatusOK, entries)
}

func (srv *Server) addAuditEntry(action, detail string) {
	srv.logger.Audit(action, detail, "")
}

func (srv *Server) addSessionAudit(action, detail, sessionID string) {
	srv.logger.Audit(action, detail, sessionID)
}

// opAuthCheckMu serializes op subprocess calls. Concurrent checks (UI polling + API)
// can interfere with 1Password desktop integration on Windows and yield flaky auth results.
var opAuthCheckMu sync.Mutex

const (
	opWhoamiTimeout    = 8 * time.Second
	opVaultListTimeout = 15 * time.Second
	// Caching avoids invoking op on every HTTP poll — repeated subprocesses trigger 1Password prompts.
	opSessionCachePosTTL = 60 * time.Second
	// Keep this short: a “not signed in” result must not stick while the user unlocks 1Password / enables CLI integration.
	opSessionCacheNegTTL = 4 * time.Second
)

var (
	opSessionCachedAt   time.Time
	opSessionCachedVal  bool
	opSessionCacheMu    sync.Mutex
)

// opVaultListJSON runs op vault list with a timeout so the HTTP handler cannot hang if op waits on the desktop app.
func opVaultListJSON(opPath string) ([]byte, error) {
	opAuthCheckMu.Lock()
	defer opAuthCheckMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), opVaultListTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, opPath, "vault", "list", "--format=json")
	return cmd.Output()
}

// opDetectSessionOnce checks the 1Password CLI session. Try `op vault list` first — it is the same
// capability Apply uses and matches “vault is usable” better than whoami alone on some Windows setups.
func opDetectSessionOnce(opPath string) bool {
	opAuthCheckMu.Lock()
	defer opAuthCheckMu.Unlock()

	ctxList, cancelList := context.WithTimeout(context.Background(), opVaultListTimeout)
	defer cancelList()
	cmdList := exec.CommandContext(ctxList, opPath, "vault", "list", "--format=json")
	outList, errList := cmdList.CombinedOutput()
	if errList == nil {
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), opWhoamiTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, opPath, "whoami", "--format=json")
	out, err := cmd.CombinedOutput()
	if err == nil && len(bytes.TrimSpace(out)) > 0 {
		return true
	}
	// Failed probes are normal until 1Password is unlocked and CLI integration responds; avoid alarming console noise.
	if os.Getenv("VAULTIFY_VERBOSE_OP") == "1" {
		log.Printf("op session check failed: vault list err=%v out=%s; whoami err=%v out=%s", errList, strings.TrimSpace(string(outList)), err, strings.TrimSpace(string(out)))
	}
	return false
}

// isOpSignedIn runs a subprocess only when cache is stale or force is true. Use force for Open Vault / Apply gates.
func isOpSignedIn(force bool) bool {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return false
	}
	opSessionCacheMu.Lock()
	defer opSessionCacheMu.Unlock()
	if !force {
		ttl := opSessionCachePosTTL
		if !opSessionCachedVal {
			ttl = opSessionCacheNegTTL
		}
		if !opSessionCachedAt.IsZero() && time.Since(opSessionCachedAt) < ttl {
			return opSessionCachedVal
		}
	}
	opSessionCachedVal = opDetectSessionOnce(opPath)
	opSessionCachedAt = time.Now()
	return opSessionCachedVal
}

func (srv *Server) handleVaultAuthStatus(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	writeJSON(w, http.StatusOK, map[string]bool{"onepassword_signed_in": isOpSignedIn(force)})
}

// tryOpenOnePasswordDesktop brings 1Password to the foreground so the user can unlock and
// use CLI integration. Best-effort; ignored if the app or URL handler is missing.
func tryOpenOnePasswordDesktop() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", "onepassword://")
		if err := cmd.Start(); err != nil {
			log.Printf("open 1Password (windows): %v", err)
		}
	case "darwin":
		if err := exec.Command("open", "-a", "1Password").Start(); err != nil {
			_ = exec.Command("open", "onepassword://").Start()
		}
	default:
		_ = exec.Command("xdg-open", "onepassword://").Start()
	}
}

// waitForOpSessionAfterUnlock polls isOpSignedIn: unlocking the desktop app + CLI integration
// routinely takes 15–45s (master password, Touch ID, app focus).
func waitForOpSessionAfterUnlock() bool {
	const maxAttempts = 48
	const between = 1100 * time.Millisecond
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(between)
		}
		if isOpSignedIn(true) {
			return true
		}
	}
	return false
}

func (srv *Server) handleVaultSignIn(w http.ResponseWriter, r *http.Request) {
	tryOpenOnePasswordDesktop()
	// Give the desktop app time to appear before the first op call; avoid racing the user to the password field.
	time.Sleep(3 * time.Second)
	signedIn := waitForOpSessionAfterUnlock()
	if !signedIn {
		writeJSON(w, http.StatusOK, map[string]any{
			"signed_in": false,
			"hint":      "Unlock 1Password (password or Touch ID), keep \u201cIntegrate with 1Password CLI\u201d on in Settings \u203a Developer, then click Retry. The first connection can take a full minute.",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_in": true})
}

func (srv *Server) handleVaultList1P(w http.ResponseWriter, r *http.Request) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	out, err := opVaultListJSON(opPath)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	var vaults []struct {
		Name  string `json:"name"`
		Items int    `json:"items"`
	}
	if json.Unmarshal(out, &vaults) != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, vaults)
}

// ------------------------------------------------------------------
// Action helpers
// ------------------------------------------------------------------

func (srv *Server) findPlaintext(sessionID, wantSHA256 string) string {
	srv.state.mu.Lock()
	for _, f := range srv.state.Findings {
		if f.MatchSHA256 == wantSHA256 && f.Value != "" {
			srv.state.mu.Unlock()
			return f.Value
		}
	}
	srv.state.mu.Unlock()

	if sessionID == "" {
		return ""
	}
	s, err := srv.sessions.Get(sessionID)
	if err != nil {
		return ""
	}
	for _, f := range s.Findings {
		if f.MatchSHA256 != wantSHA256 || f.FullPath == "" {
			continue
		}
		if v := scanner.RecoverPlaintext(f); v != "" {
			return v
		}
	}
	return ""
}

func redactFile(filePath string, lineNum int, rx *regexp.Regexp, wantSHA256 string) (bool, error) {
	return replaceSecretInFile(filePath, lineNum, rx, wantSHA256, "REDACTED_BY_VAULTIFY")
}

// replaceSecretInFile replaces the regex match on line lineNum whose SHA256 equals wantSHA256
// with replacement (e.g. REDACTED_BY_VAULTIFY or an op:// field reference).
func replaceSecretInFile(filePath string, lineNum int, rx *regexp.Regexp, wantSHA256, replacement string) (bool, error) {
	if rx == nil {
		return false, fmt.Errorf("no regex for pattern")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(data), "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return false, fmt.Errorf("line %d out of range (file has %d lines)", lineNum, len(lines))
	}
	line := lines[lineNum-1]
	if strings.Contains(line, "REDACTED_BY_VAULTIFY") {
		return false, nil
	}
	if strings.Contains(line, replacement) {
		return false, nil
	}
	locs := rx.FindAllStringIndex(line, -1)
	for _, loc := range locs {
		val := line[loc[0]:loc[1]]
		h := sha256Hex(val)
		if h == wantSHA256 {
			lines[lineNum-1] = line[:loc[0]] + replacement + line[loc[1]:]
			return true, os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return false, nil
}

func ensureVaultExists(name string) {
	opPath, err := exec.LookPath("op")
	if err != nil { return }
	checkCmd := exec.Command(opPath, "vault", "get", name, "--format=json")
	if out, err := checkCmd.Output(); err == nil && len(out) > 2 {
		return
	}
	createCmd := exec.Command(opPath, "vault", "create", name)
	out, err := createCmd.CombinedOutput()
	if err != nil {
		log.Printf("vault create %q: %s", name, strings.TrimSpace(string(out)))
	} else {
		log.Printf("vault %q created", name)
	}
}

func createOpItem(vault, title, secret, apiURL string) (string, error) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return "", fmt.Errorf("op CLI not found")
	}
	args := []string{"item", "create",
		"--vault", vault,
		"--category", "API Credential",
		"--title", title,
		"--format", "json",
		"credential=" + secret,
	}
	if apiURL != "" {
		args = append(args, "--url", apiURL)
	}
	cmd := exec.Command(opPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("op item create: %s", strings.TrimSpace(string(out)))
		return "", fmt.Errorf("failed to create 1Password item")
	}
	var item struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(out, &item) != nil {
		return "", fmt.Errorf("could not parse item ID from op output")
	}
	return item.ID, nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// ------------------------------------------------------------------
// Directory browser for folder-scoped scans
// ------------------------------------------------------------------

type browseEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type browseResponse struct {
	Parent  string        `json:"parent"`
	Current string        `json:"current"`
	Dirs    []browseEntry `json:"dirs"`
	Quick   []browseEntry `json:"quick,omitempty"`
}

func (srv *Server) handleBrowseDirs(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("path")

	if target == "" {
		home, _ := os.UserHomeDir()
		resp := browseResponse{Current: home, Dirs: listSubdirs(home)}
		resp.Quick = quickPickDirs(home)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		httpError(w, http.StatusBadRequest, "not a valid directory")
		return
	}
	if !srv.pathAllowedForBrowse(target) {
		httpError(w, http.StatusBadRequest, "path not allowed for browsing")
		return
	}

	parent := filepath.Dir(target)
	if parent == target {
		parent = ""
	}
	writeJSON(w, http.StatusOK, browseResponse{
		Parent:  parent,
		Current: target,
		Dirs:    listSubdirs(target),
	})
}

func listSubdirs(dir string) []browseEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var result []browseEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "$") {
			continue
		}
		result = append(result, browseEntry{Name: name, Path: filepath.Join(dir, name)})
	}
	return result
}

func quickPickDirs(home string) []browseEntry {
	candidates := []struct{ label, rel string }{
		{"Desktop", "Desktop"},
		{"Documents", "Documents"},
		{"Downloads", "Downloads"},
		{"dev", "dev"},
		{"src", "src"},
		{"projects", "projects"},
		{"repos", "repos"},
		{"code", "code"},
	}
	var picks []browseEntry
	for _, c := range candidates {
		p := filepath.Join(home, c.rel)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			picks = append(picks, browseEntry{Name: c.label, Path: p})
		}
	}
	return picks
}

// ------------------------------------------------------------------
// HTTP helpers
// ------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

func httpError(w http.ResponseWriter, status int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("HTTP %d: %s", status, msg)
	writeJSON(w, status, map[string]string{"error": msg})
}
