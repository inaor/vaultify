package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vaultify/vaultify/internal/auditlog"
	"github.com/vaultify/vaultify/internal/buildinfo"
	"github.com/vaultify/vaultify/internal/db"
	"github.com/vaultify/vaultify/internal/exclusions"
	"github.com/vaultify/vaultify/internal/logging"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/vault"
	"github.com/vaultify/vaultify/internal/web"
)

// Server is the main HTTP server for Vaultify.
type Server struct {
	scanner    *scanner.Scanner
	sessions   session.Store
	hub        *Hub
	state      scanState
	logger     *auditlog.Logger
	exclusions *exclusions.Store
	logging    *logging.Core    // structured slog sink + ring buffer; may be nil in tests
	posture    *db.PostureStore // 30-day rolling fingerprint store; nil when DB unavailable

	listenPort    int // set in Start; used for WebSocket Origin checks
	browseRootsMu sync.Mutex
	browseRoots   []string // absolute path prefixes allowed for GET /api/browse

	// Sidebar vault provider (op, aws, vault, doppler); only this backend runs vault/CLI ops.
	// veeVaultName is the 1Password vault Vee reads/writes LLM keys in.
	// Both live under the same mutex because they are persisted together
	// in app-settings.json.
	vaultSelectMu  sync.RWMutex
	vaultSelectCLI string
	veeVaultName   string

	// sqliteDB is the embedded SQLite handle, used by the validation
	// API for the cache table and the Posture extension. Optional:
	// when nil, validations run uncached.
	sqliteDB *sql.DB

	// veeKeyCache caches the (key, model) pair fetched from the Vee
	// 1Password vault for a short TTL. Without it, every chat message
	// + every concurrent validate-stored-key call pays for at least
	// two `op read` subprocesses, each of which can trigger a Windows
	// Hello / 1Password authorize prompt on systems set to "always
	// require unlock". See vee.go for the cache implementation and
	// invalidation rules.
	veeKeyCacheMu sync.Mutex
	veeKeyCache   map[string]veeCachedSecret
}

// SetLogging attaches a logging core so HTTP middleware emits structured
// records and /api/logs/* endpoints can serve them. Call once at startup.
func (srv *Server) SetLogging(core *logging.Core) { srv.logging = core }

// SetPosture wires the Posture store. Optional — when nil, the Posture
// API endpoint returns an empty payload and runScan skips the merge so
// Vaultify still works without the embedded DB.
func (srv *Server) SetPosture(p *db.PostureStore) { srv.posture = p }

// SetSQLiteHandle exposes the embedded SQLite handle to the validation
// endpoints (for the cache table and the Posture extension). Optional —
// when nil, validations run uncached and Posture validation columns
// stay empty. The handle remains owned by main.go.
func (srv *Server) SetSQLiteHandle(d *sql.DB) { srv.sqliteDB = d }

// pumpVaultAuthTransitions subscribes to the OpSessionController and
// forwards every transition to the scan WS hub as a `vault_auth`
// message. Runs for the life of the server; kept deliberately simple
// because the controller is a package singleton.
func (srv *Server) pumpVaultAuthTransitions() {
	ch, _ := vault.OpController().Subscribe()
	for t := range ch {
		srv.hub.Broadcast(map[string]any{
			"type":   "vault_auth",
			"cli":    "op",
			"state":  string(t.State),
			"reason": t.Reason,
			"at":     t.At.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}
}

// slogger returns the configured slog logger, or the default when logging
// has not been wired (tests, embedded usage).
func (srv *Server) slogger() *slog.Logger {
	if srv.logging != nil {
		return srv.logging.Logger()
	}
	return slog.Default()
}

// NewServer creates a Server with default dependencies. sm is any
// session.Store implementation (file-backed today, SQLite later).
func NewServer(sc *scanner.Scanner, sm session.Store, logger *auditlog.Logger) *Server {
	excPath := filepath.Join(sm.BaseDir(), "exclusions.json")
	exc := exclusions.New(excPath)
	_ = exc.Load()
	srv := &Server{
		scanner:    sc,
		sessions:   sm,
		hub:        NewHub(),
		logger:     logger,
		exclusions: exc,
	}
	srv.replaceBrowseRootsFromScanRoots(nil)
	srv.loadVaultSelection()
	return srv
}

// Start begins listening on the given port. It blocks until the server
// encounters a fatal error.
func (srv *Server) Start(port int) error {
	srv.listenPort = port
	go srv.hub.Run()
	go srv.pumpVaultAuthTransitions()

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv.slogger().Info("server.listening", slog.String("addr", addr))
	log.Printf("vaultify server listening on %s", addr)
	return http.ListenAndServe(addr, srv.withRequestLog(mux))
}

func (srv *Server) registerRoutes(mux *http.ServeMux) {
	webContent := web.Content
	fileServer := http.FileServer(http.FS(webContent))
	assetsNoCache := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Embedded UI assets must not be sticky-cached; stale app.js looks like "nothing changed" after rebuild.
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})

	mux.Handle("GET /assets/", assetsNoCache)

	serveSPA := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, webContent, "dashboard.html")
	}
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		serveSPA(w, r)
	})

	mux.HandleFunc("GET /api/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// ---- scan API ----
	mux.HandleFunc("POST /api/scan/start", srv.handleScanStart)
	mux.HandleFunc("POST /api/scan/archive", srv.handleScanArchive)
	mux.HandleFunc("POST /api/scan/stop", srv.handleScanStop)
	mux.HandleFunc("GET /api/scan/state", srv.handleScanState)
	mux.HandleFunc("GET /api/scan/ws", srv.handleScanWebSocket)

	// ---- sessions API ----
	mux.HandleFunc("GET /api/sessions", srv.handleSessionsList)
	mux.HandleFunc("GET /api/sessions/archived", srv.handleSessionsArchivedList)
	mux.HandleFunc("GET /api/sessions/{id}", srv.handleSessionDetail)
	mux.HandleFunc("POST /api/sessions/{id}/archive", srv.handleSessionArchive)
	mux.HandleFunc("POST /api/sessions/{id}/unarchive", srv.handleSessionUnarchive)

	// ---- apply / decisions ----
	mux.HandleFunc("POST /api/apply", srv.handleApply)
	mux.HandleFunc("POST /api/decisions/save", srv.handleDecisionsSave)

	// ---- global exclusions (junkyard / FP suppressions; action key remains graveyard) ----
	mux.HandleFunc("GET /api/exclusions", srv.handleExclusionsGet)
	mux.HandleFunc("POST /api/exclusions/add", srv.handleExclusionsAdd)
	mux.HandleFunc("POST /api/exclusions/remove", srv.handleExclusionsRemove)

	// ---- audit, catalogue, version ----
	mux.HandleFunc("GET /api/audit", srv.handleAuditLog)
	mux.HandleFunc("GET /api/patterns", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, scanner.RawPatterns())
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"version":  buildinfo.Version(),
			"build":    runtime.Version(),
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
			"edition":  buildinfo.Edition(),
			"file_cap": buildinfo.FileCapForAPI(),
		})
	})
	mux.HandleFunc("GET /api/version/check", srv.handleVersionCheck)

	// ---- Vee AI agent ----
	mux.HandleFunc("POST /api/vee/chat", srv.handleVeeChat)
	mux.HandleFunc("GET /api/vee/providers", srv.handleVeeProviders)
	mux.HandleFunc("POST /api/vee/models", srv.handleVeeModels)
	mux.HandleFunc("POST /api/vee/key", srv.handleVeeStoreKey)
	mux.HandleFunc("POST /api/vee/validate-stored-key", srv.handleVeeValidateStoredKey)
	mux.HandleFunc("GET /api/vee/settings", srv.handleVeeSettingsGet)
	mux.HandleFunc("POST /api/vee/settings", srv.handleVeeSettingsPost)
	mux.HandleFunc("POST /api/vee/fp-finder", srv.handleVeeFpFinder)

	// ---- directory browser ----
	mux.HandleFunc("GET /api/browse", srv.handleBrowseDirs)

	// ---- vaults API ----
	mux.HandleFunc("GET /api/vaults", srv.handleVaults)
	mux.HandleFunc("POST /api/vaults/install-op", srv.handleInstallOp)
	mux.HandleFunc("GET /api/vaults/auth-status", srv.handleVaultAuthStatus)
	mux.HandleFunc("POST /api/vaults/signin", srv.handleVaultSignIn)
	mux.HandleFunc("POST /api/vaults/op-developer-settings", srv.handleOpenOpDeveloperSettings)
	mux.HandleFunc("GET /api/vaults/list-1p", srv.handleVaultList1P)
	mux.HandleFunc("POST /api/vaults/create", srv.handleVaultCreate)
	mux.HandleFunc("GET /api/vaults/selected", srv.handleVaultSelectedGet)
	mux.HandleFunc("POST /api/vaults/selected", srv.handleVaultSelectedPost)

	// ---- live logs (Logs tab) ----
	mux.HandleFunc("GET /api/logs/tail", srv.handleLogsTail)
	mux.HandleFunc("GET /api/logs/ws", srv.handleLogsWebSocket)

	// ---- 30-day rolling Posture ----
	mux.HandleFunc("GET /api/posture", srv.handlePosture)

	// ---- Secret Validation (Slices B/C/D) ----
	mux.HandleFunc("POST /api/validate", srv.handleValidate)
	mux.HandleFunc("POST /api/validate/bulk", srv.handleValidateBulk)
	mux.HandleFunc("POST /api/playbook", srv.handlePlaybook)
}

// ------------------------------------------------------------------
// Request-logging middleware
// ------------------------------------------------------------------

type requestIDKey struct{}

// RequestIDFromContext returns the correlation ID injected by the
// request-logging middleware. Empty string when called outside an HTTP
// handler or when logging is disabled.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

func (srv *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.logging == nil {
			next.ServeHTTP(w, r)
			return
		}
		rid := newRequestID()
		ctx := context.WithValue(r.Context(), requestIDKey{}, rid)
		r = r.WithContext(ctx)
		rec := &statusRecorder{ResponseWriter: w, status: 200}

		start := time.Now()
		logger := srv.slogger().With(
			slog.String("rid", rid),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		)
		logger.Debug("http.start")
		next.ServeHTTP(rec, r)

		lvl := slog.LevelInfo
		switch {
		case rec.status >= 500:
			lvl = slog.LevelError
		case rec.status >= 400:
			lvl = slog.LevelWarn
		}
		logger.Log(ctx, lvl, "http.finish",
			slog.Int("status", rec.status),
			slog.String("duration", time.Since(start).Round(time.Millisecond).String()),
		)
	})
}

func newRequestID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Flush exposes underlying flushing for SSE endpoints.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack exposes underlying hijacking so WebSocket upgrades keep working
// when the middleware wraps the response writer.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	return h.Hijack()
}

// ------------------------------------------------------------------
// Live log endpoints
// ------------------------------------------------------------------

func (srv *Server) handleLogsTail(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if srv.logging == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, srv.logging.Recent(limit))
}

func (srv *Server) handleLogsWebSocket(w http.ResponseWriter, r *http.Request) {
	if srv.logging == nil {
		http.NotFound(w, r)
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: srv.wsCheckOrigin}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sub, cancel := srv.logging.Subscribe()
	defer cancel()

	// Prime the stream with the most recent records so the client has
	// context without waiting for the next event.
	for _, rec := range srv.logging.Recent(200) {
		if data, err := json.Marshal(rec); err == nil {
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case rec, ok := <-sub:
			if !ok {
				return
			}
			data, err := json.Marshal(rec)
			if err != nil {
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}
