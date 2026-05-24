package server

import (
	"context"
	"net/http"
	"time"

	"github.com/vaultify/vaultify/internal/buildinfo"
	"github.com/vaultify/vaultify/internal/versioncheck"
)

func (srv *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := versioncheck.Check(ctx, buildinfo.Version(), http.DefaultClient)
	writeJSON(w, http.StatusOK, res)
}
