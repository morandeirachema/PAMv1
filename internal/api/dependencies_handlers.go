package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/store"
)

// --- dependent accounts (Phase 17): a credential's consumers (Windows Services,
// Scheduled Tasks, IIS App Pools) that pamv1 updates over WinRM when the
// credential is rotated, so rotation does not break production. ---

var validDependencyKind = map[string]bool{
	"windows_service": true,
	"scheduled_task":  true,
	"iis_apppool":     true,
}

type dependencyIn struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
}

// createDependency declares a consumer of a credential (CapManageCredentials).
func (s *Server) createDependency(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in dependencyIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case !validDependencyKind[in.Kind]:
		writeError(w, http.StatusUnprocessableEntity, `kind must be "windows_service", "scheduled_task" or "iis_apppool"`)
		return
	case in.Host == "" || in.Name == "":
		writeError(w, http.StatusUnprocessableEntity, "host and name are required")
		return
	case in.Port < 0 || in.Port > 65535:
		writeError(w, http.StatusUnprocessableEntity, "port must be 0-65535")
		return
	}
	d := store.CredentialDependency{CredentialID: id, Kind: in.Kind, Host: in.Host, Port: in.Port, Name: in.Name}
	if err := s.store.CreateCredentialDependency(r.Context(), &d); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "dependency.create", fmt.Sprintf("credential:%d %s:%s@%s", id, in.Kind, in.Name, in.Host))
	writeJSON(w, http.StatusCreated, d)
}

// listDependencies returns a credential's declared consumers (CapReadInventory).
func (s *Server) listDependencies(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	deps, err := s.store.ListCredentialDependencies(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, deps)
}

// deleteDependency removes a declared consumer (CapManageCredentials).
func (s *Server) deleteDependency(w http.ResponseWriter, r *http.Request) {
	cid, ok := idParam(w, r)
	if !ok {
		return
	}
	did, err := strconv.ParseInt(r.PathValue("did"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dependency id")
		return
	}
	// The route is scoped to a credential — only delete the dependency if it
	// belongs to that credential, so DELETE /credentials/1/dependencies/5 cannot
	// remove credential 2's consumer, and the audit names the credential that
	// lost it (mirrors deleteTargetGrant / deleteAppSecretGrant).
	deps, err := s.store.ListCredentialDependencies(r.Context(), cid)
	if err != nil {
		storeError(w, err)
		return
	}
	found := false
	for _, d := range deps {
		if d.ID == did {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "dependency not found for this credential")
		return
	}
	if err := s.store.DeleteCredentialDependency(r.Context(), did); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "dependency.delete", fmt.Sprintf("credential:%d dependency:%d", cid, did))
	w.WriteHeader(http.StatusNoContent)
}
