package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ValidationRecord is the wire/cache shape of a validation outcome.
// Crucially, the plaintext value is NEVER part of this record; the
// match_sha256 is the only identity that ever leaves the scanner.
type ValidationRecord struct {
	MatchSHA256 string `json:"match_sha256"`
	ValidatorID string `json:"validator_id"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	CheckedAt   string `json:"checked_at"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Source      string `json:"source"`
}

// SaveValidation upserts a validation outcome. Caller computes
// expires_at; nil/empty keeps the cache row but disables freshness
// checks. Idempotent: re-validating the same hash overwrites in place.
func SaveValidation(ctx context.Context, d *sql.DB, v ValidationRecord) error {
	if d == nil {
		return fmt.Errorf("nil db")
	}
	if v.MatchSHA256 == "" || v.ValidatorID == "" || v.Status == "" {
		return fmt.Errorf("validation missing required fields")
	}
	if v.CheckedAt == "" {
		v.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if v.Source == "" {
		v.Source = "user"
	}
	_, err := d.ExecContext(ctx, `
		INSERT INTO validations (match_sha256, validator_id, status, reason, http_status, checked_at, expires_at, source)
		VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)
		ON CONFLICT(match_sha256) DO UPDATE SET
			validator_id = excluded.validator_id,
			status       = excluded.status,
			reason       = excluded.reason,
			http_status  = excluded.http_status,
			checked_at   = excluded.checked_at,
			expires_at   = excluded.expires_at,
			source       = excluded.source
	`, v.MatchSHA256, v.ValidatorID, v.Status, v.Reason, v.HTTPStatus, v.CheckedAt, v.ExpiresAt, v.Source)
	return err
}

// GetValidation returns the cached record by hash, ok=false when missing.
func GetValidation(ctx context.Context, d *sql.DB, matchSHA256 string) (ValidationRecord, bool, error) {
	row := d.QueryRowContext(ctx, `
		SELECT match_sha256, validator_id, status, reason, http_status, checked_at, COALESCE(expires_at, ''), source
		FROM validations WHERE match_sha256 = ?
	`, matchSHA256)
	var v ValidationRecord
	err := row.Scan(&v.MatchSHA256, &v.ValidatorID, &v.Status, &v.Reason, &v.HTTPStatus, &v.CheckedAt, &v.ExpiresAt, &v.Source)
	if err == sql.ErrNoRows {
		return ValidationRecord{}, false, nil
	}
	if err != nil {
		return ValidationRecord{}, false, err
	}
	return v, true, nil
}

// IsFresh reports whether the cached row is within its TTL.
func (v ValidationRecord) IsFresh(now time.Time) bool {
	if v.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, v.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(t)
}

// GetValidationsForHashes returns all cached records whose hash is in
// the provided set, keyed by hash. Used by the bulk endpoint so it can
// short-circuit cache hits in a single SQL round-trip.
func GetValidationsForHashes(ctx context.Context, d *sql.DB, hashes []string) (map[string]ValidationRecord, error) {
	out := make(map[string]ValidationRecord, len(hashes))
	if len(hashes) == 0 {
		return out, nil
	}
	placeholders, args := inClause(hashes)
	q := `
		SELECT match_sha256, validator_id, status, reason, http_status, checked_at, COALESCE(expires_at, ''), source
		FROM validations WHERE match_sha256 IN (` + placeholders + `)
	`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var v ValidationRecord
		if err := rows.Scan(&v.MatchSHA256, &v.ValidatorID, &v.Status, &v.Reason, &v.HTTPStatus, &v.CheckedAt, &v.ExpiresAt, &v.Source); err != nil {
			return out, err
		}
		out[v.MatchSHA256] = v
	}
	return out, rows.Err()
}
