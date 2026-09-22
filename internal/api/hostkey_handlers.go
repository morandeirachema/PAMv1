package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/store"
)

// getTargetHostKey returns the SSH host key pinned for a target on first
// contact (Phase 272): type, fingerprint, the public key line, first and last
// seen. 404 when nothing has been pinned yet — the proxy has not reached the
// target since the pin store existed, or the pin was reset.
func (s *Server) getTargetHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.store.GetTarget(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	k, err := s.store.GetTargetHostKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no host key pinned for this target yet")
			return
		}
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// resetTargetHostKey forgets a target's pin so the NEXT connection's key is
// trusted and pinned (or, under strict mode, so the target is refused until
// re-pinned). This is the one sanctioned answer to a re-keyed host; the audit
// row names the fingerprint that was dropped, so a reset that precedes a
// mismatch is visible as the decision it was.
func (s *Server) resetTargetHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	old, err := s.store.GetTargetHostKey(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no host key pinned for this target")
			return
		}
		storeError(w, err)
		return
	}
	if err := s.store.DeleteTargetHostKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.hostkey_reset", fmt.Sprintf("target:%s key_type:%s fingerprint:%s", t.Name, old.KeyType, old.Fingerprint))
	w.WriteHeader(http.StatusNoContent)
}
