package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vaultify/vaultify/internal/archive"
	"github.com/vaultify/vaultify/internal/buildinfo"
	"github.com/vaultify/vaultify/internal/db"
	"github.com/vaultify/vaultify/internal/exclusions"
	"github.com/vaultify/vaultify/internal/inventory"
	"github.com/vaultify/vaultify/internal/paths"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/validation"
	"github.com/vaultify/vaultify/internal/vault"
)

// ------------------------------------------------------------------
// Request / response types
// ------------------------------------------------------------------

type scanStartRequest struct {
	Roots []string `json:"roots"`
}

type archiveScanRequest struct {
	ArchivePath string `json:"archive_path"`
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
	MatchSHA256  string         `json:"match_sha256"`
	Action       string         `json:"action"`
	PatternID    string         `json:"pattern_id"`
	Locations    []applyItemLoc `json:"locations"`
	ItemName     string         `json:"item_name"`
	ApiURL       string         `json:"api_url"`
	GoodPractice bool           `json:"good_practice,omitempty"`
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
	SessionID string      `json:"sessionId"`
	Decisions []applyItem `json:"decisions"`
}

// ------------------------------------------------------------------
// Scan state tracked by the server
// ------------------------------------------------------------------

type scanState struct {
	mu             sync.Mutex
	Running        bool              `json:"running"`
	SessionID      string            `json:"sessionId"`
	Progress       int               `json:"progress"`
	Total          int               `json:"total"`
	Findings       []scanner.Finding `json:"findings"`
	DevInventory   []inventory.Item  `json:"dev_inventory"`
	ScanType       string            `json:"scan_type"`
	LastScanCapped bool              `json:"-"`
	cancel         context.CancelFunc
}

func (s *scanState) snapshot() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	safe := make([]scanner.Finding, len(s.Findings))
	for i, f := range s.Findings {
		safe[i] = f
		safe[i].Value = ""
	}
	cap := buildinfo.FileCapForAPI()
	inv := make([]inventory.Item, len(s.DevInventory))
	copy(inv, s.DevInventory)
	return struct {
		Running         bool              `json:"running"`
		SessionID       string            `json:"sessionId"`
		Progress        int               `json:"progress"`
		Total           int               `json:"total"`
		Findings        []scanner.Finding `json:"findings"`
		DevInventory    []inventory.Item  `json:"dev_inventory,omitempty"`
		DevInventoryCnt int               `json:"dev_inventory_count"`
		ScanType        string            `json:"scan_type,omitempty"`
		Edition         string            `json:"edition"`
		FileCap         int               `json:"file_cap"`
		ScanCapped      bool              `json:"scan_capped"`
	}{
		Running:         s.Running,
		SessionID:       s.SessionID,
		Progress:        s.Progress,
		Total:           s.Total,
		Findings:        safe,
		DevInventory:    inv,
		DevInventoryCnt: len(inv),
		ScanType:        s.ScanType,
		Edition:         buildinfo.Edition(),
		FileCap:         cap,
		ScanCapped:      s.LastScanCapped,
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
	srv.state.DevInventory = nil
	srv.state.ScanType = scanType
	srv.state.LastScanCapped = false
	srv.state.cancel = cancel
	srv.state.mu.Unlock()

	srv.replaceBrowseRootsFromScanRoots(req.Roots)
	go srv.runScan(ctx, sid, req.Roots)
	srv.addSessionAudit("scan_started", fmt.Sprintf("type=%s roots=%v", scanType, req.Roots), sid)

	writeJSON(w, http.StatusAccepted, map[string]string{"sessionId": sid, "scan_type": scanType})
}

func (srv *Server) handleScanArchive(w http.ResponseWriter, r *http.Request) {
	var req archiveScanRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	archivePath := strings.TrimSpace(req.ArchivePath)
	if archivePath == "" {
		httpError(w, http.StatusBadRequest, "archive_path is required")
		return
	}
	info, err := os.Stat(archivePath)
	if err != nil || info.IsDir() {
		httpError(w, http.StatusBadRequest, "archive file not found or not readable")
		return
	}
	if !archive.IsSupported(archivePath) {
		httpError(w, http.StatusBadRequest, "unsupported archive format (use .zip)")
		return
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
	srv.state.DevInventory = nil
	srv.state.ScanType = "archive"
	srv.state.LastScanCapped = false
	srv.state.cancel = cancel
	srv.state.mu.Unlock()

	go srv.runArchiveScan(ctx, sid, archivePath)
	srv.addSessionAudit("scan_started", fmt.Sprintf("type=archive path=%s", archivePath), sid)

	writeJSON(w, http.StatusAccepted, map[string]string{"sessionId": sid, "scan_type": "archive"})
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

	// scanner.PatternByID uses a sync.Once-cached registry; no
	// per-request JSON parse or regex compile.
	results := make([]applyResult, 0, len(req.Items))

	hasVaultItems := false
	for _, item := range req.Items {
		if item.Action == "vault" {
			hasVaultItems = true
			break
		}
	}
	back := srv.activeBackend()
	if hasVaultItems {
		if !back.SupportsSecretApply() {
			httpError(w, http.StatusBadRequest, "moving secrets into a vault requires 1Password as the active vault in the sidebar (Choose a Vault). Select 1Password, connect the CLI, then try Apply again.")
			return
		}
		if req.VaultName != "" {
			back.EnsureVaultExists(req.VaultName)
		}
	}

	for _, item := range req.Items {
		res := applyResult{MatchSHA256: item.MatchSHA256, Action: item.Action, OK: true}
		switch item.Action {
		case "remove":
			pat := scanner.PatternByID(item.PatternID)
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
				var ok bool
				var err error
				if pat != nil {
					ok, err = redactFile(loc.FullPath, loc.LineNumber, pat.Regex, item.MatchSHA256)
				} else {
					ok, err = redactFileByPatternID(loc.FullPath, loc.LineNumber, item.PatternID, item.MatchSHA256)
				}
				if err != nil {
					res.OK = false
					res.Error = err.Error()
				} else if ok {
					redacted++
				}
			}
			res.Detail = fmt.Sprintf("%d file(s) redacted", redacted)
		case "vault":
			if req.VaultName == "" {
				res.OK = false
				res.Error = "no vault name specified"
			} else {
				pat := scanner.PatternByID(item.PatternID)
				plaintext := srv.findPlaintext(req.SessionID, item.MatchSHA256)
				if plaintext == "" {
					res.OK = false
					res.Error = "plaintext not found for this secret"
					break
				}
				title := item.ItemName
				if title == "" {
					title = item.PatternID
				}
				itemID, err := back.CreateCredentialItem(req.VaultName, title, plaintext, item.ApiURL)
				if err != nil {
					res.OK = false
					res.Error = err.Error()
					break
				}
				ref := back.CredentialReference(req.VaultName, itemID)
				for _, loc := range item.Locations {
					if loc.FullPath == "" {
						continue
					}
					if !srv.applyLocationAllowed(req.SessionID, item.MatchSHA256, loc.FullPath, loc.LineNumber) {
						res.OK = false
						res.Error = "path is not part of this scan session"
						break
					}
					var rerr error
					if pat != nil {
						_, rerr = replaceSecretInFile(loc.FullPath, loc.LineNumber, pat.Regex, item.MatchSHA256, ref)
					} else {
						_, rerr = replaceSecretInFileByPatternID(loc.FullPath, loc.LineNumber, item.PatternID, item.MatchSHA256, ref)
					}
					if rerr != nil {
						res.OK = false
						res.Error = rerr.Error()
						break
					}
				}
				if res.OK {
					res.Detail = ref
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

	// Reports remediation counts successful vault / remove + any
	// good_practice graveyards (those represent "the user reviewed this
	// and confirmed the value is already in the vault elsewhere"). The
	// scanner already auto-credits unambiguous op:// vault_refs at scan
	// time; this branch covers the heuristic patterns (jwt,
	// aws_temp_access_key_id, etc.) only when the user said so.
	var appliedHashes []string
	gpHashSet := make(map[string]bool, len(req.Items))
	for _, item := range req.Items {
		if item.GoodPractice {
			gpHashSet[item.MatchSHA256] = true
		}
	}
	for _, res := range results {
		if !res.OK {
			continue
		}
		switch res.Action {
		case "vault", "remove":
			appliedHashes = append(appliedHashes, res.MatchSHA256)
		case "graveyard", "dismiss":
			if gpHashSet[res.MatchSHA256] {
				appliedHashes = append(appliedHashes, res.MatchSHA256)
			}
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
		if vaults[i].CLI == "op" {
			vaults[i].Installed = vault.OpInstalled()
		} else {
			_, err := exec.LookPath(vaults[i].CLI)
			vaults[i].Installed = err == nil
		}
	}
	writeJSON(w, http.StatusOK, vaults)
}

func (srv *Server) handleInstallOp(w http.ResponseWriter, r *http.Request) {
	if vault.OpInstalled() {
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

	vault.ResetOpPathCache()
	installed := vault.OpInstalled()
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

	if err := srv.activeBackend().CreateEmptyVault(req.Name); err != nil {
		log.Printf("vault create %q: %v", req.Name, err)
		httpError(w, http.StatusInternalServerError, "%v", err)
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

	// Enrich the response with cached validation status + Vee
	// recommendation per finding so the Review table can render the
	// status chip and the recommendation hint without N round-trips.
	type enrichedFinding struct {
		scanner.Finding
		Validation        *validationCacheView           `json:"validation,omitempty"`
		VeeRecommendation *validation.VeeRecommendation `json:"vee_recommendation,omitempty"`
	}
	cache := map[string]db.ValidationRecord{}
	if srv.sqliteDB != nil && len(s.Findings) > 0 {
		hashes := make([]string, 0, len(s.Findings))
		seen := map[string]bool{}
		for _, f := range s.Findings {
			if seen[f.MatchSHA256] {
				continue
			}
			seen[f.MatchSHA256] = true
			hashes = append(hashes, f.MatchSHA256)
		}
		cache, _ = db.GetValidationsForHashes(r.Context(), srv.sqliteDB, hashes)
	}

	enriched := make([]enrichedFinding, len(s.Findings))
	for i, f := range s.Findings {
		ef := enrichedFinding{Finding: f}
		vstatus := validation.StatusUnknown
		if rec, ok := cache[f.MatchSHA256]; ok {
			ef.Validation = &validationCacheView{
				Status:     rec.Status,
				Reason:     rec.Reason,
				CheckedAt:  rec.CheckedAt,
				HTTPStatus: rec.HTTPStatus,
			}
			vstatus = validation.Status(rec.Status)
		} else if f.ValidatorID == "" {
			vstatus = validation.StatusUnsupported
		}
		rec := validation.Recommend(f, vstatus)
		ef.VeeRecommendation = &rec
		enriched[i] = ef
	}
	devInv, _ := session.LoadDevInventory(srv.sessions.Dir(id))
	out := struct {
		ID                    string            `json:"id"`
		Status                string            `json:"status"`
		ScannedAt             string            `json:"scanned_at"`
		FindingsCount         int               `json:"findings_count"`
		OriginalFindingsCount int               `json:"original_findings_count"`
		Findings              []enrichedFinding `json:"findings"`
		DevInventory          []inventory.Item  `json:"dev_inventory,omitempty"`
		DevInventoryCount     int               `json:"dev_inventory_count"`
	}{
		ID:                    s.ID,
		Status:                s.Status,
		ScannedAt:             s.ScannedAt,
		FindingsCount:         s.FindingsCount,
		OriginalFindingsCount: s.OriginalFindingsCount,
		Findings:              enriched,
		DevInventory:          devInv,
		DevInventoryCount:     len(devInv),
	}
	writeJSON(w, http.StatusOK, out)
}

// validationCacheView is the per-finding subset surfaced in the
// session detail response. The full ValidationRecord includes
// audit-y fields (source, expires_at) the Review UI doesn't need.
type validationCacheView struct {
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	CheckedAt  string `json:"checked_at"`
	HTTPStatus int    `json:"http_status,omitempty"`
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

func (srv *Server) runArchiveScan(ctx context.Context, sessionID, archivePath string) {
	workRoot := filepath.Join(paths.WorkDir(), "archive-"+sessionID)
	_ = os.RemoveAll(workRoot)

	fail := func(msg string) {
		log.Printf("archive scan: %s", msg)
		srv.logger.Error("archive_scan_error", fmt.Sprintf("session=%s err=%s", sessionID, msg))
		srv.state.mu.Lock()
		srv.state.Running = false
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":      "scan_complete",
			"sessionId": sessionID,
			"scan_type": "archive",
			"error":     msg,
		})
	}

	manifest, err := archive.ExtractZip(archivePath, workRoot, archive.DefaultLimits())
	if err != nil {
		fail(err.Error())
		_ = os.RemoveAll(workRoot)
		return
	}
	srv.addSessionAudit("archive_extracted",
		fmt.Sprintf("files=%d bytes=%d archive=%s", manifest.FilesExtracted, manifest.BytesExtracted, archivePath),
		sessionID)

	srv.runScan(ctx, sessionID, []string{workRoot})
	_ = os.RemoveAll(workRoot)
}

func (srv *Server) runScan(ctx context.Context, sessionID string, roots []string) {
	_ = srv.exclusions.Load()
	scanCapped := false
	defer func() {
		srv.state.mu.Lock()
		srv.state.Running = false
		srv.state.mu.Unlock()
		srv.state.mu.Lock()
		st := srv.state.ScanType
		srv.state.mu.Unlock()
		srv.state.mu.Lock()
		invCnt := len(srv.state.DevInventory)
		srv.state.mu.Unlock()
		srv.hub.Broadcast(map[string]any{
			"type":                  "scan_complete",
			"sessionId":             sessionID,
			"scan_type":             st,
			"scan_capped":           scanCapped,
			"file_cap":              buildinfo.FileCapForAPI(),
			"edition":               buildinfo.Edition(),
			"dev_inventory_count":   invCnt,
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
		// Tag the finding with its heuristic status + validator id
		// before it leaves this scope. validation.Classify reads f.Value
		// for fake/placeholder detection, which is only available here
		// (Save and the WS broadcast both redact the value out).
		f.HeuristicStatus, f.ValidatorID = validation.Classify(f)

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

	maxFiles := buildinfo.MaxScanFiles()
	filesScanned, capped, scanErr := srv.scanner.Scan(ctx, roots, maxFiles, onProgress, onFinding)
	scanCapped = capped
	if scanErr != nil && ctx.Err() == nil {
		log.Printf("scan error: %v", scanErr)
		srv.logger.Error("scan_error", fmt.Sprintf("session=%s err=%v", sessionID, scanErr))
	}

	srv.state.mu.Lock()
	srv.state.LastScanCapped = capped
	findingsCount := len(srv.state.Findings)
	srv.state.mu.Unlock()

	if capped && maxFiles > 0 {
		srv.addSessionAudit("scan_capped", fmt.Sprintf("files_scanned=%d cap=%d findings=%d", filesScanned, maxFiles, findingsCount), sessionID)
	}

	// Copy-on-save: the previous code handed srv.state.Findings to
	// sessions.Save without holding the mutex, which was racy with any
	// late onFinding callback arriving from a slow worker. Take a
	// snapshot under the lock, then release before the disk write.
	srv.state.mu.Lock()
	savedFindings := make([]scanner.Finding, len(srv.state.Findings))
	copy(savedFindings, srv.state.Findings)
	srv.state.mu.Unlock()
	if err := srv.sessions.Save(sessionID, savedFindings, time.Now()); err != nil {
		log.Printf("save session: %v", err)
		srv.logger.Error("session_save_error", fmt.Sprintf("session=%s err=%v", sessionID, err))
	}

	devItems, invErr := inventory.Collect(ctx, roots)
	if invErr != nil && ctx.Err() == nil {
		log.Printf("dev inventory: %v", invErr)
		srv.logger.Error("dev_inventory_error", fmt.Sprintf("session=%s err=%v", sessionID, invErr))
	}
	srv.state.mu.Lock()
	srv.state.DevInventory = devItems
	srv.state.mu.Unlock()
	if err := session.SaveDevInventory(srv.sessions.Dir(sessionID), devItems); err != nil {
		log.Printf("save dev inventory: %v", err)
		srv.logger.Error("dev_inventory_save_error", fmt.Sprintf("session=%s err=%v", sessionID, err))
	}

	// Auto-credit "good practice" findings as remediated. op:// inject
	// references (DetectionLayer="vault_ref") are objectively already
	// in the vault — counting them in the Reports remediation column
	// matches user intent. Heuristic good-practice patterns (jwt,
	// aws_temp_access_key_id) require a user decision to be counted; we
	// only auto-credit the unambiguous vault_ref class here.
	var autoRemediated []string
	for _, f := range savedFindings {
		if f.DetectionLayer == "vault_ref" {
			autoRemediated = append(autoRemediated, f.MatchSHA256)
		}
	}
	if len(autoRemediated) > 0 {
		if err := srv.sessions.MergeRemediationApplied(sessionID, autoRemediated); err != nil {
			log.Printf("auto-credit vault_ref remediations: %v", err)
		} else {
			srv.addSessionAudit("remediation.auto_credited", fmt.Sprintf("good_practice_vault_refs=%d", len(autoRemediated)), sessionID)
		}
	}

	// Phase 6c: fold this scan into the rolling Posture view. Bounded
	// to the actual scan roots so a folder-scoped scan can never wrongly
	// mark untouched directories as "deleted". A nil store (DB
	// unavailable) silently skips — Posture is a derived projection.
	if srv.posture != nil {
		mctx, mcancel := context.WithTimeout(context.Background(), 30*time.Second)
		rep, err := srv.posture.MergeScan(mctx, sessionID, time.Now(), roots, savedFindings)
		mcancel()
		logger := srv.slogger().With(slog.String("subsystem", "posture"), slog.String("session_id", sessionID))
		if err != nil {
			logger.Error("posture.merge_failed", slog.String("err", err.Error()))
		} else {
			logger.Info("posture.merge_done",
				slog.Int("upserted", rep.Upserted),
				slog.Int("marked_deleted", rep.MarkedDeleted),
				slog.Int("pruned", rep.Pruned),
				slog.Int("scan_findings", len(savedFindings)),
				slog.Int("roots", len(roots)),
			)
			srv.addSessionAudit("posture.merge",
				fmt.Sprintf("upserted=%d deleted=%d pruned=%d", rep.Upserted, rep.MarkedDeleted, rep.Pruned),
				sessionID)
		}
	}

	srv.addSessionAudit("scan_complete", fmt.Sprintf("findings=%d capped=%v", findingsCount, capped), sessionID)
}

// ------------------------------------------------------------------
// Vault auth and list endpoints
// ------------------------------------------------------------------

func (srv *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries := srv.logger.Entries()
	writeJSON(w, http.StatusOK, entries)
}

// handlePosture returns the rolling 30-day fingerprint view (SQLite).
func (srv *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	if srv.posture == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"summary":  map[string]any{"window_days": 30},
			"findings": []any{},
			"note":     "Posture store unavailable on this server.",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	now := time.Now()

	summary, err := srv.posture.Summary(ctx, now)
	if err != nil {
		srv.slogger().Error("posture.summary_failed", slog.String("err", err.Error()))
		httpError(w, http.StatusInternalServerError, "posture summary failed")
		return
	}
	findings, err := srv.posture.Recent(ctx, now)
	if err != nil {
		srv.slogger().Error("posture.recent_failed", slog.String("err", err.Error()))
		httpError(w, http.StatusInternalServerError, "posture findings failed")
		return
	}
	if findings == nil {
		// Force [] instead of null so JS callers can `array.length`
		// without a type-guard. Matches the rest of the API contract.
		findings = []db.PostureFinding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":  summary,
		"findings": findings,
	})
}

// addAuditEntry records a non-session audit event into the persistent
// audit ledger AND mirrors it as a slog `audit.<action>` info-level
// record so it streams into the live Logs tab. The Logs tab can then
// filter by category=audit; the persistent audit.log stays the
// source-of-truth for governance / export.
func (srv *Server) addAuditEntry(action, detail string) {
	srv.logger.Audit(action, detail, "")
	srv.slogger().Info("audit."+action, slog.String("category", "audit"), slog.String("detail", detail))
}

func (srv *Server) addSessionAudit(action, detail, sessionID string) {
	srv.logger.Audit(action, detail, sessionID)
	srv.slogger().Info("audit."+action, slog.String("category", "audit"), slog.String("detail", detail), slog.String("session_id", sessionID))
}

// handleVaultAuthStatus returns the controller's current state. When
// refresh=1 is present we kick off a background probe and return
// immediately; the WS `vault_auth` event will fire when the probe
// completes so the client updates without polling. Stub backends
// continue to use the legacy AuthSignedIn shape.
func (srv *Server) handleVaultAuthStatus(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	b := srv.activeBackend()

	if b.CLIName() == "op" {
		if !b.Installed() {
			writeJSON(w, http.StatusOK, map[string]any{
				"vault_cli":             "op",
				"vault_connected":       false,
				"onepassword_signed_in": false,
				"state":                 "cli_missing",
				"signin_active":         false,
			})
			return
		}
		ctrl := vault.OpController()
		if force {
			ctx, cancel := context.WithTimeout(r.Context(), vault.OpVaultListProbeTimeout()+3*time.Second)
			defer cancel()
			_ = ctrl.Probe(ctx, true)
		} else if ctrl.State() == vault.OpStateUnknown {
			ctrl.ProbeAsync(false)
		}
		connected := ctrl.SignedIn()
		writeJSON(w, http.StatusOK, map[string]any{
			"vault_cli":             "op",
			"vault_connected":       connected,
			"onepassword_signed_in": connected,
			"state":                 string(ctrl.State()),
			"signin_active":         ctrl.SigninActive(),
			"hint":                  ctrl.LastProbeHint(),
			"issue":                 string(ctrl.LastProbeIssue()),
			"op_settings_url":       vault.OnePasswordDeveloperSettingsURL(),
			"macos_app_bundle":      paths.RunningFromMacOSAppBundle(),
		})
		return
	}

	connected := b.Installed() && b.AuthSignedIn(force)
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_cli":             b.CLIName(),
		"vault_connected":       connected,
		"onepassword_signed_in": false,
		"state": func() string {
			if connected {
				return "signed_in"
			}
			return "signed_out"
		}(),
		"signin_active": false,
	})
}

func (srv *Server) handleOpenOpDeveloperSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	vault.OpenOnePasswordDeveloperSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"opened": true,
		"url":    vault.OnePasswordDeveloperSettingsURL(),
	})
}

// handleVaultSignIn is now non-blocking: it kicks off the controller
// signin loop in the background and returns 202 immediately. The
// client listens on the scan WS for `vault_auth` transitions to know
// when unlock succeeded. Stub backends keep their synchronous shape
// since they just return a hint message.
func (srv *Server) handleVaultSignIn(w http.ResponseWriter, r *http.Request) {
	b := srv.activeBackend()
	if b.CLIName() == "op" {
		if !b.Installed() {
			writeJSON(w, http.StatusOK, map[string]any{
				"signed_in": false,
				"accepted":  false,
				"state":     "cli_missing",
				"hint":      "Install the 1Password CLI to continue.",
			})
			return
		}
		ctrl := vault.OpController()
		ctrl.BeginSignIn()
		// Deliberately do NOT read ctrl.State() here. State() takes
		// stateMu under the same lock the goroutine uses to publish
		// its result; under congested-Desktop conditions that read
		// can serialise behind queued probes and hang this handler
		// for tens of seconds. The browser listens on /api/scan/ws
		// for the real `vault_auth` transition — that's the source
		// of truth, not whatever state happened to be cached at the
		// moment the request landed.
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted": true,
			"state":    "opening",
		})
		return
	}

	ok, hint := b.OpenSignInAndWait()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"signed_in": false, "hint": hint})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed_in": true})
}

func (srv *Server) handleVaultList1P(w http.ResponseWriter, r *http.Request) {
	b := srv.activeBackend()
	if !b.Installed() {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	vaults, err := b.ListVaults()
	if err != nil || len(vaults) == 0 {
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

func redactFileByPatternID(filePath string, lineNum int, patternID, wantSHA256 string) (bool, error) {
	return replaceSecretInFileByPatternID(filePath, lineNum, patternID, wantSHA256, "REDACTED_BY_VAULTIFY")
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
	lineOrig := lines[lineNum-1]
	lineNorm := strings.TrimSuffix(lineOrig, "\r")
	suffix := lineOrig[len(lineNorm):]
	if strings.Contains(lineNorm, "REDACTED_BY_VAULTIFY") {
		return false, nil
	}
	if strings.Contains(lineNorm, replacement) {
		return false, nil
	}
	locs := rx.FindAllStringIndex(lineNorm, -1)
	for _, loc := range locs {
		val := lineNorm[loc[0]:loc[1]]
		h := sha256Hex(val)
		if h == wantSHA256 {
			lines[lineNum-1] = lineNorm[:loc[0]] + replacement + lineNorm[loc[1]:] + suffix
			return true, os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return false, nil
}

// replaceSecretInFileByPatternID handles context-only findings (pattern_id is a variable name like
// SHODAN_API_KEY, not a row in patterns.json) by locating the value via scanner.SubmatchSpanForHash.
func replaceSecretInFileByPatternID(filePath string, lineNum int, patternID, wantSHA256, replacement string) (bool, error) {
	if patternID == "" {
		return false, fmt.Errorf("missing pattern_id")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(data), "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return false, fmt.Errorf("line %d out of range (file has %d lines)", lineNum, len(lines))
	}
	lineOrig := lines[lineNum-1]
	lineNorm := strings.TrimSuffix(lineOrig, "\r")
	suffix := lineOrig[len(lineNorm):]
	if strings.Contains(lineNorm, "REDACTED_BY_VAULTIFY") {
		return false, nil
	}
	if replacement != "REDACTED_BY_VAULTIFY" && strings.Contains(lineNorm, replacement) {
		return false, nil
	}
	start, end, ok := scanner.SubmatchSpanForHash(lineNorm, patternID, wantSHA256)
	if !ok {
		return false, nil
	}
	lines[lineNum-1] = lineNorm[:start] + replacement + lineNorm[end:] + suffix
	return true, os.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0o644)
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
