package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/vaultify/vaultify/internal/auditlog"
	"github.com/vaultify/vaultify/internal/buildinfo"
	"github.com/vaultify/vaultify/internal/db"
	"github.com/vaultify/vaultify/internal/logging"
	"github.com/vaultify/vaultify/internal/paths"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/server"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/vault"
)

func main() {
	port := flag.Int("port", 9471, "HTTP server port")
	noBrowser := flag.Bool("no-browser", false, "Do not open the browser automatically")
	showVersion := flag.Bool("version", false, "Print version and exit")
	logLevel := flag.String("log-level", envOr("VAULTIFY_LOG_LEVEL", "info"), "Log level for stderr: debug, info, warn, error")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Vaultify v%s (%s/%s) [%s]\n", buildinfo.Version(), runtime.GOOS, runtime.GOARCH, buildinfo.Edition())
		os.Exit(0)
	}

	url := fmt.Sprintf("http://localhost:%d", *port)

	// Already running? Open and exit.
	if resp, err := http.Get(url + "/api/ping"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			fmt.Println("  Vaultify is already running. Opening browser...")
			openBrowser(url)
			return
		}
	}

	// Print an immediate liveness line so a double-clicked terminal
	// always shows activity within the first few hundred milliseconds.
	// Without this, a large JSON store or slow disk can keep the
	// console silent for tens of seconds while the DB / session
	// importer / posture backfill warm up, and users (reasonably)
	// assume the app has hung and close the window before the browser
	// auto-opens. The full banner with paths/ports prints later, after
	// the heavy startup work is done.
	fmt.Printf("  Vaultify v%s starting on %s ...\n", buildinfo.Version(), url)

	if err := paths.Ensure(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create %s: %v\n", paths.Root(), err)
	}
	migrationReport, _ := paths.Migrate()

	logOpts := logging.Defaults(paths.LogFile("vaultify.log"))
	logOpts.StderrLevel = parseLevel(*logLevel)
	core, err := logging.New(logOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: logging init failed: %v\n", err)
	}
	if core != nil {
		slog.SetDefault(core.Logger())
		// Redirect stdlib log.Printf call sites into slog so legacy lines
		// show up in vaultify.log and the Logs tab without migration.
		log.SetFlags(0)
		log.SetOutput(core.StdlogAdapter())
		vault.SetLogger(core.Logger().With(slog.String("subsystem", "vault")))
	}

	sc := scanner.NewScanner()

	// Phase 6: open the embedded DB and run pending migrations. The
	// JSON Manager is always constructed as a fallback so a DB failure
	// (corrupt file, permission error, opt-out via flag) cannot block
	// startup. When the DB is healthy we run a non-destructive
	// importer to fold legacy JSON sessions into SQLite, then serve
	// reads/writes from the SQLite store.
	jsonStore := session.NewManager(paths.SessionsDir())
	dbHandle, dbInfo := openAppDB(core)
	if dbHandle != nil {
		defer dbHandle.Close()
	}

	var sm session.Store = jsonStore
	var postureStore *db.PostureStore
	if dbHandle != nil {
		sqliteStore := db.NewSessionStore(dbHandle, paths.SessionsDir())
		runSessionImporter(core, dbHandle, jsonStore)
		sm = sqliteStore
		postureStore = db.NewPostureStore(dbHandle, 30*24*time.Hour)
		runPostureBackfill(core, dbHandle, postureStore)
		dbInfo += " · sessions: sqlite · posture: 30d"
	} else {
		dbInfo += " · sessions: json (fallback) · posture: off"
	}

	auditLog, err := auditlog.New(paths.LogDir())
	if err != nil {
		slog.Error("audit_log_init_failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
	auditLog.Info("startup", fmt.Sprintf("vaultify v%s [%s] starting on port %d", buildinfo.Version(), buildinfo.Edition(), *port))

	srv := server.NewServer(sc, sm, auditLog)
	if core != nil {
		srv.SetLogging(core)
	}
	if postureStore != nil {
		srv.SetPosture(postureStore)
	}
	if dbHandle != nil {
		// Validation cache + Posture extension live in the same DB.
		srv.SetSQLiteHandle(dbHandle)
	}
	printBanner(*port, migrationReport, dbInfo)

	// Background re-validation for posture rows (no-op if SQLite/posture absent).
	srv.StartScheduledValidation()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(*port); err != nil {
			errCh <- err
		}
	}()

	if !*noBrowser {
		time.Sleep(300 * time.Millisecond)
		openBrowser(url)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
		slog.Info("shutdown", slog.String("reason", "signal"))
	case err := <-errCh:
		slog.Error("server_exited", slog.String("err", err.Error()))
		if core != nil {
			_ = core.Close()
		}
		os.Exit(1)
	}
	fmt.Println("\n  Shutting down...")
	if core != nil {
		_ = core.Close()
	}
}

func printBanner(port int, rep paths.MigrationReport, dbInfo string) {
	opInfo := "not installed"
	if opPath, err := exec.LookPath("op"); err == nil {
		opInfo = "found at " + opPath
	}
	fmt.Println()
	fmt.Println("  Vaultify — credential remediation toolkit")
	fmt.Printf("  Version:   v%s (%s)\n", buildinfo.Version(), buildinfo.Edition())
	fmt.Printf("  Port:      %d\n", port)
	fmt.Println()
	fmt.Printf("  Root:      %s\n", paths.Root())
	fmt.Printf("  Config:    %s\n", paths.ConfigFile("app-settings.json"))
	fmt.Printf("  Sessions:  %s\n", paths.SessionsDir())
	fmt.Printf("  Logs:      %s\n", paths.LogFile("vaultify.log"))
	fmt.Printf("  Database:  %s\n", dbInfo)
	fmt.Printf("  1Password: %s\n", opInfo)
	if rep.MovedSessions > 0 || rep.MovedLogFiles > 0 || rep.MovedAppSettings {
		fmt.Printf("  Migrated:  %d sessions, %d log files, app-settings=%v (from %s)\n",
			rep.MovedSessions, rep.MovedLogFiles, rep.MovedAppSettings, rep.LegacyRoot)
	}
	fmt.Println()
	fmt.Printf("  Dashboard: http://localhost:%d/\n", port)
	fmt.Printf("  Logs tab:  http://localhost:%d/#logs\n", port)
	fmt.Printf("  Audit:     http://localhost:%d/api/audit\n", port)
	fmt.Println()
}

// runPostureBackfill replays every active session row through the
// posture store on the FIRST boot after the posture feature shipped,
// so users see a populated rolling-30-day view immediately
// instead of having to wait for fresh scans to accumulate.
//
// Idempotent: a row in app_state pins the backfill to a single boot.
// Failures are logged but never block startup — Posture stays usable
// with whatever rows MergeScan can produce from the next live scan.
func runPostureBackfill(core *logging.Core, d *sql.DB, p *db.PostureStore) {
	logger := slog.Default()
	if core != nil {
		logger = core.Logger().With(slog.String("subsystem", "posture"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := db.BackfillPostureFromSessions(ctx, d, p)
	if err != nil {
		logger.Error("posture.backfill_failed", slog.String("err", err.Error()))
		return
	}
	if rep.AlreadyDone {
		logger.Debug("posture.backfill_skipped", slog.String("reason", "already_done"))
		return
	}
	logger.Info("posture.backfill_done",
		slog.Int("sessions_scanned", rep.SessionsScanned),
		slog.Int("sessions_replayed", rep.SessionsReplayed),
		slog.Int("upserts", rep.Upserts),
		slog.Int("deletions", rep.Deletions),
		slog.Int("pruned", rep.Pruned),
		slog.String("oldest", rep.OldestScannedAt),
		slog.String("newest", rep.NewestScannedAt),
	)
}

// runSessionImporter folds legacy JSON sessions into SQLite. Idempotent
// and non-destructive (the JSON files stay on disk so a downgrade still
// works). Failures are logged but never block startup; the SQLite store
// will simply start empty and the JSON store remains the cold-storage
// archive on disk.
func runSessionImporter(core *logging.Core, d *sql.DB, src session.Store) {
	logger := slog.Default()
	if core != nil {
		logger = core.Logger().With(slog.String("subsystem", "db"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := db.ImportFromStore(ctx, d, src)
	if err != nil {
		logger.Error("db.session_import_failed", slog.String("err", err.Error()))
		return
	}
	logger.Info("db.session_import_done",
		slog.Int("scanned", rep.SessionsScanned),
		slog.Int("imported", rep.SessionsImported),
		slog.Int("already", rep.SessionsAlready),
		slog.Int("remediation_hashes", rep.RemediationHashes),
		slog.Int("decision_files_seen", rep.DecisionFilesSeen),
	)
}

// openAppDB opens the embedded SQLite store and runs pending migrations.
// A failure is logged but does not abort startup — Vaultify falls back
// to the JSON session store so an unexpected DB problem can never block
// the app. The returned handle is nil on error; callers must check
// before using.
func openAppDB(core *logging.Core) (*sql.DB, string) {
	path := db.DefaultPath()
	logger := slog.Default()
	if core != nil {
		logger = core.Logger().With(slog.String("subsystem", "db"))
	}

	d, err := db.Open(path)
	if err != nil {
		logger.Error("db.open_failed", slog.String("path", path), slog.String("err", err.Error()))
		return nil, fmt.Sprintf("disabled (open failed: %v)", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	applied, err := db.Migrate(ctx, d)
	if err != nil {
		logger.Error("db.migrate_failed", slog.String("err", err.Error()))
		_ = d.Close()
		return nil, fmt.Sprintf("disabled (migrate failed: %v)", err)
	}
	cur, _ := db.CurrentVersion(ctx, d)
	logger.Info("db.ready",
		slog.String("path", path),
		slog.Int("schema_version", cur),
		slog.Int("applied_this_boot", applied),
	)
	return d, fmt.Sprintf("%s (schema v%d)", path, cur)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
