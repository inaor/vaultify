package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/web"
)

// Server is the main HTTP server for Vaultify.
type Server struct {
	scanner  *scanner.Scanner
	sessions *session.Manager
	hub      *Hub
	state    scanState
}

// NewServer creates a Server with default dependencies.
func NewServer(sc *scanner.Scanner, sm *session.Manager) *Server {
	return &Server{
		scanner:  sc,
		sessions: sm,
		hub:      NewHub(),
	}
}

// Start begins listening on the given port. It blocks until the server
// encounters a fatal error.
func (srv *Server) Start(port int) error {
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

	mux.Handle("GET /assets/", fileServer)

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
	mux.HandleFunc("GET /api/scan/ws", srv.hub.ServeWs)

	// ---- sessions API ----
	mux.HandleFunc("GET /api/sessions", srv.handleSessionsList)
	mux.HandleFunc("GET /api/sessions/{id}", srv.handleSessionDetail)

	// ---- apply / decisions ----
	mux.HandleFunc("POST /api/apply", srv.handleApply)
	mux.HandleFunc("POST /api/decisions/save", srv.handleDecisionsSave)

	// ---- Vee AI agent ----
	mux.HandleFunc("POST /api/vee/chat", srv.handleVeeChat)
	mux.HandleFunc("GET /api/vee/providers", srv.handleVeeProviders)
	mux.HandleFunc("POST /api/vee/key", srv.handleVeeStoreKey)

	// ---- vaults API ----
	mux.HandleFunc("GET /api/vaults", srv.handleVaults)
	mux.HandleFunc("GET /api/vaults/auth-status", srv.handleVaultAuthStatus)
	mux.HandleFunc("POST /api/vaults/signin", srv.handleVaultSignIn)
	mux.HandleFunc("GET /api/vaults/list-1p", srv.handleVaultList1P)
	mux.HandleFunc("POST /api/vaults/create", srv.handleVaultCreate)
}
