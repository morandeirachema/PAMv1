package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/discovery"
	"github.com/morandeirachema/pamv1/internal/store"
)

type discoveryIn struct {
	Hosts  []string `json:"hosts"`
	Ports  []int    `json:"ports"`
	Create bool     `json:"create"` // auto-create targets for new candidates
}

// discoveryScan probes the given hosts for reachable management ports (SSH,
// WinRM, RDP) and returns candidates. With create=true it onboards new ones as
// targets (skipping hosts already inventoried for that protocol). It only checks
// reachability — no credentials are used.
// maxDiscoveryScan bounds a single discovery request end to end.
const maxDiscoveryScan = 2 * time.Minute

func (s *Server) discoveryScan(w http.ResponseWriter, r *http.Request) {
	var in discoveryIn
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Hosts) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "hosts is required")
		return
	}
	if len(in.Hosts) > 1024 {
		writeError(w, http.StatusUnprocessableEntity, "too many hosts (max 1024)")
		return
	}
	// Bound the whole scan. Hosts are capped at 1024 but the host x port PRODUCT was
	// not, and the scanner dials sequentially with a per-connect timeout: 1024
	// unreachable hosts across the six default ports is ~100 minutes of a wedged
	// handler, long past the server's write timeout, so the caller sees nothing and
	// retries — stacking more. The deadline turns that into a partial result.
	scanCtx, cancelScan := context.WithTimeout(r.Context(), maxDiscoveryScan)
	defer cancelScan()
	candidates := discovery.Scanner{Dial: s.discoveryDial}.Scan(scanCtx, in.Hosts, in.Ports)
	s.audit(r.Context(), "discovery.scan", fmt.Sprintf("hosts:%d candidates:%d create:%t", len(in.Hosts), len(candidates), in.Create))

	created := []store.Target{}
	if in.Create {
		existing, err := s.store.ListTargets(r.Context(), 0, 0)
		if err != nil {
			storeError(w, err)
			return
		}
		have := map[string]bool{}
		for _, t := range existing {
			have[t.Host+"/"+t.Protocol] = true
		}
		for _, c := range candidates {
			if have[c.Host+"/"+c.Protocol] {
				continue
			}
			// Honor the protocol allowlist, exactly like createTarget — discovery
			// must not onboard a target the policy forbids connecting to.
			if !s.protocolAllowed(c.Protocol) {
				continue
			}
			t := store.Target{
				Name: fmt.Sprintf("%s-%s", c.Host, c.Protocol),
				Host: c.Host, Port: c.Port, OSType: c.OSType, Protocol: c.Protocol,
			}
			if err := s.store.CreateTarget(r.Context(), &t); err != nil {
				// A racing/duplicate name is non-fatal; skip it.
				continue
			}
			have[c.Host+"/"+c.Protocol] = true
			created = append(created, t)
			s.audit(r.Context(), "target.create", t.Name+" via:discovery")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		"created":    created,
	})
}
