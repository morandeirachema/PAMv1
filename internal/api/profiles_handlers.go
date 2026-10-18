package api

import (
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

type profileIn struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

// createProfile defines a custom permission profile — a named capability set
// assignable to users as an alternative to the four built-in roles.
func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var in profileIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	// A profile name must not shadow a built-in role or the agent role.
	if _, err := auth.ParseGrantRole(in.Name); err == nil {
		writeError(w, http.StatusUnprocessableEntity, "name collides with a built-in role")
		return
	}
	caps, err := auth.ParseCapabilities(in.Capabilities)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// You cannot define a profile more capable than yourself (privilege-escalation
	// guard): a delegated user-admin can't forge an all-powerful profile.
	if !principalFrom(r.Context()).Covers(caps) {
		writeError(w, http.StatusForbidden, "cannot create a profile with capabilities you do not hold")
		return
	}
	p := store.Profile{Name: in.Name, Capabilities: in.Capabilities}
	if err := s.store.CreateProfile(r.Context(), &p); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "profile.create", fmt.Sprintf("%s caps:%d", p.Name, len(p.Capabilities)))
	writeJSON(w, http.StatusCreated, p)
}
