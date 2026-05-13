package server

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/validation"
)

// StartScheduledValidation kicks off a background goroutine that
// re-validates Posture rows whose validation cache has aged out.
// One pass per 24h, bounded concurrency. Bails out cleanly if Posture
// or the SQLite handle isn't wired (--no-db, etc).
//
// The goroutine has no shutdown channel: the process exits when main
// returns, which collapses every outstanding network call. That's the
// right behaviour for a CLI agent — we never want re-validation to
// block process shutdown.
func (srv *Server) StartScheduledValidation() {
	if srv.sqliteDB == nil || srv.posture == nil {
		return
	}
	go func() {
		// Small initial delay so the scheduled run does not fight
		// startup work (DB migrations, importer, posture backfill).
		time.Sleep(60 * time.Second)
		srv.runScheduledValidationOnce(context.Background())

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			srv.runScheduledValidationOnce(context.Background())
		}
	}()
}

// runScheduledValidationOnce walks Posture for `present` rows whose
// validation entry is missing or older than the validator's TTL, then
// re-checks each via the existing runValidator pipeline (which writes
// to the cache, audit log, and Posture column on the next merge).
func (srv *Server) runScheduledValidationOnce(ctx context.Context) {
	logger := srv.slogger().With(slog.String("subsystem", "validation"), slog.String("source", "scheduled"))
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	rows, err := srv.sqliteDB.QueryContext(ctx, `
		SELECT match_sha256, last_session_id
		FROM posture_findings
		WHERE status = 'present'
		  AND COALESCE(validation_checked_at, '') < ?
		LIMIT 200
	`, cutoff)
	if err != nil {
		logger.Warn("scheduled.query_failed", slog.String("err", err.Error()))
		return
	}
	defer rows.Close()

	type job struct {
		hash      string
		sessionID string
	}
	var work []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.hash, &j.sessionID); err != nil {
			continue
		}
		if j.hash == "" || j.sessionID == "" {
			continue
		}
		work = append(work, j)
	}
	if err := rows.Err(); err != nil {
		logger.Warn("scheduled.scan_failed", slog.String("err", err.Error()))
		return
	}
	logger.Info("scheduled.start", slog.Int("candidates", len(work)))
	if len(work) == 0 {
		return
	}

	// Cache findings per session so we don't re-load the same session
	// 50 times when many fingerprints share a last_session_id.
	type sessFind struct {
		findings map[string]scanner.Finding
		err      error
	}
	sessions := map[string]sessFind{}
	getFinding := func(sessionID, hash string) (scanner.Finding, bool) {
		sf, ok := sessions[sessionID]
		if !ok {
			s, err := srv.sessions.Get(sessionID)
			sf = sessFind{findings: map[string]scanner.Finding{}}
			if err != nil {
				sf.err = err
			} else {
				for _, f := range s.Findings {
					if _, dup := sf.findings[f.MatchSHA256]; !dup {
						sf.findings[f.MatchSHA256] = f
					}
				}
			}
			sessions[sessionID] = sf
		}
		if sf.err != nil {
			return scanner.Finding{}, false
		}
		f, ok := sf.findings[hash]
		return f, ok
	}

	type result struct{ status string }
	jobsCh := make(chan job)
	resCh := make(chan result, len(work))

	const concurrency = 3
	for w := 0; w < concurrency; w++ {
		go func() {
			for j := range jobsCh {
				f, ok := getFinding(j.sessionID, j.hash)
				if !ok || f.ValidatorID == "" {
					resCh <- result{status: string(validation.StatusUnsupported)}
					continue
				}
				res, err := srv.runValidator(ctx, f, "scheduled")
				if err != nil {
					resCh <- result{status: string(validation.StatusError)}
					continue
				}
				resCh <- result{status: string(res.Status)}
			}
		}()
	}
	for _, j := range work {
		jobsCh <- j
	}
	close(jobsCh)

	counts := map[string]int{}
	for i := 0; i < len(work); i++ {
		r := <-resCh
		counts[r.status]++
	}
	logger.Info("scheduled.done",
		slog.Int("active", counts[string(validation.StatusActive)]),
		slog.Int("invalid", counts[string(validation.StatusInvalid)]),
		slog.Int("error", counts[string(validation.StatusError)]),
		slog.Int("unsupported", counts[string(validation.StatusUnsupported)]),
	)
}

// shut up unused-import warning when Go vet runs on Free builds where
// the function body short-circuits before touching sql.
var _ = sql.ErrNoRows
