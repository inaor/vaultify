package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

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
	Name      string `json:"name"`
	CLI       string `json:"cli"`
	Installed bool   `json:"installed"`
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
	cancel    context.CancelFunc
}

func (s *scanState) snapshot() any {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		Findings:  s.Findings,
	}
}

// ------------------------------------------------------------------
// Handler implementations
// ------------------------------------------------------------------

func (srv *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	var req scanStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	srv.state.Running = true
	srv.state.SessionID = sid
	srv.state.Progress = 0
	srv.state.Total = 0
	srv.state.Findings = nil
	srv.state.cancel = cancel
	srv.state.mu.Unlock()

	go srv.runScan(ctx, sid, req.Roots)

	writeJSON(w, http.StatusAccepted, scanStartResponse{SessionID: sid})
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (srv *Server) handleScanState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, srv.state.snapshot())
}

func (srv *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
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
					if loc.FullPath == "" { continue }
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
				plaintext := srv.findPlaintext(req.SessionID, item.MatchSHA256)
				if plaintext == "" {
					res.OK = false
					res.Error = "plaintext not found for this secret"
				} else {
					itemID, err := createOpItem(req.VaultName, item.PatternID, plaintext)
					if err != nil {
						res.OK = false
						res.Error = err.Error()
					} else {
						ref := fmt.Sprintf("op://%s/%s/credential", req.VaultName, itemID)
						res.Detail = ref
					}
				}
			}
		case "dismiss":
			res.Detail = "dismissed"
		default:
			res.OK = false
			res.Error = fmt.Sprintf("unknown action %q", item.Action)
		}
		results = append(results, res)
	}

	writeJSON(w, http.StatusOK, applyResponse{Results: results})
}

func (srv *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	vaults := []vaultInfo{
		{Name: "1Password", CLI: "op"},
		{Name: "AWS Secrets Manager", CLI: "aws"},
		{Name: "HashiCorp Vault", CLI: "vault"},
		{Name: "Doppler", CLI: "doppler"},
	}
	for i := range vaults {
		_, err := exec.LookPath(vaults[i].CLI)
		vaults[i].Installed = err == nil
	}
	writeJSON(w, http.StatusOK, vaults)
}

func (srv *Server) handleVaultCreate(w http.ResponseWriter, r *http.Request) {
	var req vaultCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		httpError(w, http.StatusInternalServerError, "op vault create failed: %v\n%s", err, out)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"status": "created",
		"output": strings.TrimSpace(string(out)),
	})
}

func (srv *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	sessions, err := srv.sessions.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list sessions: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (srv *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		httpError(w, http.StatusBadRequest, "session id required")
		return
	}
	s, err := srv.sessions.Get(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "session %s: %v", id, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (srv *Server) handleDecisionsSave(w http.ResponseWriter, r *http.Request) {
	var req decisionsSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.SessionID == "" {
		httpError(w, http.StatusBadRequest, "sessionId is required")
		return
	}

	dir := srv.sessions.Dir(req.SessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		httpError(w, http.StatusInternalServerError, "create session dir: %v", err)
		return
	}

	data, _ := json.MarshalIndent(req.Decisions, "", "  ")
	path := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		httpError(w, http.StatusInternalServerError, "write decisions: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

// ------------------------------------------------------------------
// Background scan runner
// ------------------------------------------------------------------

func (srv *Server) runScan(ctx context.Context, sessionID string, roots []string) {
	defer func() {
		srv.state.mu.Lock()
		srv.state.Running = false
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":      "scan_complete",
			"sessionId": sessionID,
		})
	}()

	onProgress := func(progress, total int) {
		srv.state.mu.Lock()
		srv.state.Progress = progress
		srv.state.Total = total
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":     "scan_progress",
			"progress": progress,
			"total":    total,
		})
	}

	onFinding := func(f scanner.Finding) {
		srv.state.mu.Lock()
		srv.state.Findings = append(srv.state.Findings, f)
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":    "scan_finding",
			"finding": f,
		})
	}

	if err := srv.scanner.Scan(ctx, roots, onProgress, onFinding); err != nil && ctx.Err() == nil {
		log.Printf("scan error: %v", err)
	}

	if err := srv.sessions.Save(sessionID, srv.state.Findings, time.Now()); err != nil {
		log.Printf("save session: %v", err)
	}
}

// ------------------------------------------------------------------
// Vault auth and list endpoints
// ------------------------------------------------------------------

func isOpSignedIn() bool {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return false
	}
	cmd := exec.Command(opPath, "vault", "list", "--format=json")
	out, err := cmd.Output()
	return err == nil && len(out) > 2
}

func (srv *Server) handleVaultAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"onepassword_signed_in": isOpSignedIn()})
}

func (srv *Server) handleVaultSignIn(w http.ResponseWriter, r *http.Request) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"signed_in": false})
		return
	}
	cmd := exec.Command(opPath, "signin")
	_ = cmd.Run()
	checkCmd := exec.Command(opPath, "vault", "list", "--format=json")
	out, err := checkCmd.Output()
	signedIn := err == nil && len(out) > 2
	writeJSON(w, http.StatusOK, map[string]bool{"signed_in": signedIn})
}

func (srv *Server) handleVaultList1P(w http.ResponseWriter, r *http.Request) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	cmd := exec.Command(opPath, "vault", "list", "--format=json")
	out, err := cmd.Output()
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

func (srv *Server) findPlaintext(sessionID, sha256 string) string {
	srv.state.mu.Lock()
	for _, f := range srv.state.Findings {
		if f.MatchSHA256 == sha256 && f.Value != "" {
			srv.state.mu.Unlock()
			return f.Value
		}
	}
	srv.state.mu.Unlock()
	if sessionID != "" {
		pt := srv.sessions.LoadPlaintext(sessionID)
		if v, ok := pt[sha256]; ok {
			return v
		}
	}
	return ""
}

func redactFile(filePath string, lineNum int, rx *regexp.Regexp, wantSHA256 string) (bool, error) {
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
	locs := rx.FindAllStringIndex(line, -1)
	for _, loc := range locs {
		val := line[loc[0]:loc[1]]
		h := sha256Hex(val)
		if h == wantSHA256 {
			bakPath := filePath + ".bak"
			if _, err := os.Stat(bakPath); os.IsNotExist(err) {
				_ = os.WriteFile(bakPath, data, 0o644)
			}
			lines[lineNum-1] = line[:loc[0]] + "REDACTED_BY_VAULTIFY" + line[loc[1]:]
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

func createOpItem(vault, title, secret string) (string, error) {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return "", fmt.Errorf("op CLI not found")
	}
	cmd := exec.Command(opPath, "item", "create",
		"--vault", vault,
		"--category", "API Credential",
		"--title", title,
		"--format", "json",
		"credential="+secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("op item create failed: %s", strings.TrimSpace(string(out)))
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
