package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vaultify/vaultify/internal/db"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/validation"
)

// validateRequest is the body of POST /api/validate (single).
type validateRequest struct {
	SessionID    string `json:"session_id"`
	MatchSHA256  string `json:"match_sha256"`
	Force        bool   `json:"force"`
}

// validateResponse is the success body. UI uses status + reason to
// flip the chip; cached lets the row hint "from cache" when desired.
type validateResponse struct {
	MatchSHA256 string `json:"match_sha256"`
	ValidatorID string `json:"validator_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	CheckedAt   string `json:"checked_at"`
	Cached      bool   `json:"cached"`
}

// handleValidate runs an active validation for a single finding.
func (srv *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if err := readRequestJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.SessionID == "" || !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "session_id is required and must be a valid id")
		return
	}
	if req.MatchSHA256 == "" {
		httpError(w, http.StatusBadRequest, "match_sha256 is required")
		return
	}

	finding, err := srv.findInSession(req.SessionID, req.MatchSHA256)
	if err != nil {
		httpError(w, http.StatusNotFound, "%v", err)
		return
	}
	if finding.ValidatorID == "" {
		writeJSON(w, http.StatusOK, validateResponse{
			MatchSHA256: req.MatchSHA256,
			Status:      string(validation.StatusUnsupported),
			Reason:      "no validator registered for pattern " + finding.PatternID,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Cache hit shortcut: return a fresh row from SQLite when TTL allows.
	if !req.Force && srv.sqliteDB != nil {
		if rec, ok, err := db.GetValidation(r.Context(), srv.sqliteDB, req.MatchSHA256); err == nil && ok && rec.IsFresh(time.Now()) {
			writeJSON(w, http.StatusOK, validateResponse{
				MatchSHA256: rec.MatchSHA256,
				ValidatorID: rec.ValidatorID,
				Status:      rec.Status,
				Reason:      rec.Reason,
				HTTPStatus:  rec.HTTPStatus,
				CheckedAt:   rec.CheckedAt,
				Cached:      true,
			})
			return
		}
	}

	res, audErr := srv.runValidator(r.Context(), finding, "user")
	if audErr != nil {
		// runValidator already logged. Surface as 503 so the UI shows
		// the muted "ERROR" chip without breaking.
		httpError(w, http.StatusServiceUnavailable, "validation failed: %v", audErr)
		return
	}

	resp := validateResponse{
		MatchSHA256: req.MatchSHA256,
		ValidatorID: finding.ValidatorID,
		Status:      string(res.Status),
		Reason:      res.Reason,
		HTTPStatus:  res.HTTPStatus,
		CheckedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// runValidator does the actual provider call + cache write + audit
// log. Used by handleValidate, handleValidateBulk, and handlePlaybook.
// source: "user" | "playbook" | "scheduled" — recorded for forensics.
func (srv *Server) runValidator(ctx context.Context, f scanner.Finding, source string) (validation.Result, error) {
	v, ok := validation.ValidatorByID(f.ValidatorID)
	if !ok {
		return validation.Result{Status: validation.StatusUnsupported, Reason: "unknown validator " + f.ValidatorID}, nil
	}

	value := scanner.RecoverPlaintext(f)
	if value == "" {
		return validation.Result{Status: validation.StatusError, Reason: f.ValidatorID + ".value_unrecoverable"}, nil
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := v.Validate(cctx, value)
	if err != nil {
		return validation.Result{}, err
	}

	// Cache + audit even on Error/Invalid — the row should reflect the
	// last attempt no matter how it landed.
	now := time.Now()
	if srv.sqliteDB != nil {
		expires := ""
		if res.Status == validation.StatusActive || res.Status == validation.StatusInvalid {
			expires = now.Add(v.TTL()).UTC().Format(time.RFC3339)
		}
		_ = db.SaveValidation(ctx, srv.sqliteDB, db.ValidationRecord{
			MatchSHA256: f.MatchSHA256,
			ValidatorID: f.ValidatorID,
			Status:      string(res.Status),
			Reason:      res.Reason,
			HTTPStatus:  res.HTTPStatus,
			CheckedAt:   now.UTC().Format(time.RFC3339),
			ExpiresAt:   expires,
			Source:      source,
		})
	}
	srv.slogger().Info("validation.run",
		slog.String("subsystem", "validation"),
		slog.String("validator", f.ValidatorID),
		slog.String("status", string(res.Status)),
		slog.String("reason", res.Reason),
		slog.String("source", source),
		slog.String("hash", short(f.MatchSHA256)),
	)
	srv.addAuditEntry("validation."+string(res.Status), fmt.Sprintf("validator=%s reason=%s source=%s", f.ValidatorID, res.Reason, source))
	return res, nil
}

// findInSession looks up a finding by its match_sha256 in the named
// session. Returns the FIRST match (multiple Findings can share a
// hash because it's content-derived; their location differs).
func (srv *Server) findInSession(sessionID, hash string) (scanner.Finding, error) {
	s, err := srv.sessions.Get(sessionID)
	if err != nil {
		return scanner.Finding{}, fmt.Errorf("session not found: %w", err)
	}
	for _, f := range s.Findings {
		if f.MatchSHA256 == hash {
			return f, nil
		}
	}
	return scanner.Finding{}, fmt.Errorf("finding not found in session")
}

// ----- bulk validation (optional build) --------------------------------

type validateBulkRequest struct {
	SessionID    string   `json:"session_id"`
	MatchSHA256s []string `json:"match_sha256s"`
}

type validateBulkResultRow struct {
	MatchSHA256 string `json:"match_sha256"`
	ValidatorID string `json:"validator_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Cached      bool   `json:"cached"`
}

type validateBulkResponse struct {
	Results []validateBulkResultRow `json:"results"`
}

func (srv *Server) handleValidateBulk(w http.ResponseWriter, r *http.Request) {
	var req validateBulkRequest
	if err := readRequestJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "session_id required")
		return
	}
	s, err := srv.sessions.Get(req.SessionID)
	if err != nil {
		httpError(w, http.StatusNotFound, "session not found")
		return
	}
	wanted := make(map[string]struct{}, len(req.MatchSHA256s))
	for _, h := range req.MatchSHA256s {
		wanted[h] = struct{}{}
	}
	cache := map[string]db.ValidationRecord{}
	if srv.sqliteDB != nil && len(req.MatchSHA256s) > 0 {
		cache, _ = db.GetValidationsForHashes(r.Context(), srv.sqliteDB, req.MatchSHA256s)
	}

	// Bounded concurrency: 4 in-flight provider calls keeps us well
	// inside any reasonable per-vendor rate limit while still finishing
	// quickly on a 100-row run.
	const concurrency = 4
	type job struct {
		f scanner.Finding
	}
	jobs := make(chan job)
	out := make(chan validateBulkResultRow, len(s.Findings))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			row := validateBulkResultRow{MatchSHA256: j.f.MatchSHA256, ValidatorID: j.f.ValidatorID}
			if rec, ok := cache[j.f.MatchSHA256]; ok && rec.IsFresh(time.Now()) {
				row.Status = rec.Status
				row.Reason = rec.Reason
				row.Cached = true
				out <- row
				continue
			}
			res, err := srv.runValidator(r.Context(), j.f, "bulk")
			if err != nil {
				row.Status = string(validation.StatusError)
				row.Reason = err.Error()
			} else {
				row.Status = string(res.Status)
				row.Reason = res.Reason
			}
			out <- row
		}
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	seenHash := map[string]bool{}
	for _, f := range s.Findings {
		if _, ok := wanted[f.MatchSHA256]; len(wanted) > 0 && !ok {
			continue
		}
		if f.ValidatorID == "" {
			continue
		}
		if seenHash[f.MatchSHA256] {
			continue
		}
		seenHash[f.MatchSHA256] = true
		jobs <- job{f: f}
	}
	close(jobs)
	wg.Wait()
	close(out)

	results := make([]validateBulkResultRow, 0, len(out))
	for r := range out {
		results = append(results, r)
	}
	writeJSON(w, http.StatusOK, validateBulkResponse{Results: results})
}

// ----- Playbook request/response types ---------------------------------

type playbookRequest struct {
	SessionID    string   `json:"session_id"`
	MatchSHA256s []string `json:"match_sha256s"`
	VaultName    string   `json:"vault_name"`
}

type playbookRow struct {
	MatchSHA256 string `json:"match_sha256"`
	Validation  string `json:"validation_status"`
	Action      string `json:"action_taken"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
}

type playbookResponse struct {
	Rows []playbookRow `json:"rows"`
}

func (srv *Server) handlePlaybook(w http.ResponseWriter, r *http.Request) {
	var req playbookRequest
	if err := readRequestJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "session_id required")
		return
	}
	s, err := srv.sessions.Get(req.SessionID)
	if err != nil {
		httpError(w, http.StatusNotFound, "session not found")
		return
	}
	wanted := make(map[string]struct{}, len(req.MatchSHA256s))
	for _, h := range req.MatchSHA256s {
		wanted[h] = struct{}{}
	}

	rows := make([]playbookRow, 0)
	seen := map[string]bool{}
	for _, f := range s.Findings {
		if seen[f.MatchSHA256] {
			continue
		}
		if _, ok := wanted[f.MatchSHA256]; len(wanted) > 0 && !ok {
			continue
		}
		seen[f.MatchSHA256] = true

		row := playbookRow{MatchSHA256: f.MatchSHA256}

		// Step 1 — validate (cache or live).
		vstatus := validation.StatusUnsupported
		if f.ValidatorID != "" {
			if srv.sqliteDB != nil {
				if rec, ok, _ := db.GetValidation(r.Context(), srv.sqliteDB, f.MatchSHA256); ok && rec.IsFresh(time.Now()) {
					vstatus = validation.Status(rec.Status)
				}
			}
			if vstatus == validation.StatusUnsupported || vstatus == validation.StatusUnknown {
				if res, err := srv.runValidator(r.Context(), f, "playbook"); err == nil {
					vstatus = res.Status
				}
			}
		}
		row.Validation = string(vstatus)

		// Step 2 — translate to a decision via the same Vee rules the UI uses.
		rec := validation.Recommend(f, vstatus)
		row.Action = rec.Recommended
		row.OK = true // placeholder; real Apply is plumbed via decisions.json + handleApply pipeline below

		rows = append(rows, row)
	}

	// Persist the recommended decisions into the session's decisions
	// blob so the existing Apply pipeline can finish the work atomically
	// using the user's selected vault. The user still confirms via the
	// existing Apply Decisions modal — Playbook stages, doesn't bypass.
	if err := srv.persistPlaybookDecisions(req.SessionID, rows, s.Findings, req.VaultName); err != nil {
		srv.slogger().Warn("playbook.persist_failed", slog.String("err", err.Error()))
	}

	srv.addAuditEntry("playbook.staged", fmt.Sprintf("session=%s rows=%d", req.SessionID, len(rows)))
	writeJSON(w, http.StatusOK, playbookResponse{Rows: rows})
}

// persistPlaybookDecisions stages the Playbook output into the same
// per-session decisions.json the UI writes via handleDecisionsSave so
// the user can review + Apply through the normal flow.
func (srv *Server) persistPlaybookDecisions(sid string, rows []playbookRow, findings []scanner.Finding, vault string) error {
	byHash := map[string]scanner.Finding{}
	for _, f := range findings {
		byHash[f.MatchSHA256] = f
	}

	type decisionItem struct {
		Action       string                   `json:"action"`
		PatternID    string                   `json:"pattern_id"`
		VaultName    string                   `json:"vault_name,omitempty"`
		Locations    []map[string]interface{} `json:"locations"`
	}
	out := struct {
		Decisions  map[string]decisionItem `json:"decisions"`
		Source     string                  `json:"source"`
		StagedAt   string                  `json:"staged_at"`
	}{
		Decisions: map[string]decisionItem{},
		Source:    "playbook",
		StagedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	for _, r := range rows {
		f, ok := byHash[r.MatchSHA256]
		if !ok {
			continue
		}
		di := decisionItem{
			Action:    r.Action,
			PatternID: f.PatternID,
			VaultName: vault,
			Locations: []map[string]interface{}{{
				"full_path":     f.FullPath,
				"relative_path": f.RelativePath,
				"line_number":   f.LineNumber,
				"match_sha256":  f.MatchSHA256,
			}},
		}
		out.Decisions[r.MatchSHA256] = di
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	dir := srv.sessions.Dir(sid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "decisions.json"), data, 0o600)
}

// ----- helpers ------------------------------------------------------

func short(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8]
}
