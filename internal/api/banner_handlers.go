package api

import (
	"net/http"

	"github.com/morandeirachema/pamv1/internal/banner"
)

// getBanner serves the login banner and the session notice for the caller's
// language (Phase 276) — public, because the login banner exists to be read
// BEFORE anyone authenticates. The texts are deployment configuration, not
// secrets; nothing else is exposed.
func (s *Server) getBanner(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	writeJSON(w, http.StatusOK, map[string]string{
		"login":   s.banners.Get(banner.Login, lang),
		"session": s.banners.Get(banner.Session, lang),
	})
}
