package server

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/vaultify/vaultify/internal/auditlog"
	"github.com/vaultify/vaultify/internal/exclusions"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/web"
)

// Server is the main HTTP server for Vaultify.
type Server struct {
	scanner    *scanner.Scanner
	sessions   *session.Manager
	hub        *Hub
	state      scanState
	logger     *auditlog.Logger
	exclusions *exclusions.Store

	listenPort    int // set in Start; used for WebSocket Origin checks
	browseRootsMu sync.Mutex
	browseRoots   []string // absolute path prefixes allowed for GET /api/browse
}

// NewServer creates a Server with default dependencies.
func NewServer(sc *scanner.Scanner, sm *session.Manager, logger *auditlog.Logger) *Server {
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
	return srv
}

// Start begins listening on the given port. It blocks until the server
// encounters a fatal error.
func (srv *Server) Start(port int) error {
	srv.listenPort = port
	go srv.hub.Run()

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	log.Printf("vaultify server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
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
		resp := map[string]string{"version": "0.1.7", "build": "go1.22", "os": runtime.GOOS, "arch": runtime.GOARCH}
		writeJSON(w, http.StatusOK, resp)
	})

	// ---- Vee AI agent ----
	mux.HandleFunc("POST /api/vee/chat", srv.handleVeeChat)
	mux.HandleFunc("GET /api/vee/providers", srv.handleVeeProviders)
	mux.HandleFunc("POST /api/vee/models", srv.handleVeeModels)
	mux.HandleFunc("POST /api/vee/key", srv.handleVeeStoreKey)
	mux.HandleFunc("POST /api/vee/fp-finder", srv.handleVeeFpFinder)

	// ---- directory browser ----
	mux.HandleFunc("GET /api/browse", srv.handleBrowseDirs)

	// ---- vaults API ----
	mux.HandleFunc("GET /api/vaults", srv.handleVaults)
	mux.HandleFunc("POST /api/vaults/install-op", srv.handleInstallOp)
	mux.HandleFunc("GET /api/vaults/auth-status", srv.handleVaultAuthStatus)
	mux.HandleFunc("POST /api/vaults/signin", srv.handleVaultSignIn)
	mux.HandleFunc("GET /api/vaults/list-1p", srv.handleVaultList1P)
	mux.HandleFunc("POST /api/vaults/create", srv.handleVaultCreate)
}
