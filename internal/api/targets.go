package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

var (
	validOS = map[string]bool{"linux": true, "windows": true}
	// "kubernetes" (Phase 155) is a cluster's API server rather than a host:
	// there is no session to proxy, only discrete, audited kubectl-shaped
	// operations over POST /api/targets/{id}/kubectl.
	validProtocol = map[string]bool{"ssh": true, "winrm": true, "rdp": true, "vnc": true, "postgres": true, "mssql": true, "kubernetes": true}
	// "ssh_ca" and "db_zsp" are Zero Standing Privilege credentials (Phase 22,
	// extended to databases in Phase 129): neither stores a secret — the proxy
	// mints a short-lived certificate, or provisions-and-drops an ephemeral
	// database role, just-in-time instead.
	validSecret = map[string]bool{store.SecretTypePassword: true, store.SecretTypeSSHKey: true, store.SecretTypeSSHCA: true, store.SecretTypeDBZSP: true, store.SecretTypeFile: true, store.SecretTypeK8sToken: true}
)

// validOverride reports whether v is "" (inherit) or a mode the rank map knows.
// The per-target RDP clipboard overrides (Phase 33 follow-on) must be a real
// mode when set — a typo that silently inherited would read as "this target is
// locked down" while it wasn't — and validity is derived from the SAME rank
// maps the strictest-merge uses, so a mode can never be accepted here yet rank
// as zero (the weakest) there.
func validOverride(rank map[string]int, v string) bool {
	if v == "" {
		return true
	}
	_, ok := rank[v]
	return ok
}

// --- targets ---

type targetIn struct {
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	OSType          string `json:"os_type"`
	Protocol        string `json:"protocol"`
	RequireApproval bool   `json:"require_approval"`
	// Per-target RDP clipboard tightening; "" inherits the global policy and the
	// effective mode is the stricter of the two.
	RDPClipboard      string `json:"rdp_clipboard"`
	RDPClipboardAudit string `json:"rdp_clipboard_audit"`
}

// validateTargetIn applies the create/update validation rules to in — one
// function shared by both handlers so they can never drift apart (a field
// validated on create but not update would let PUT smuggle in what POST
// refuses). It defaults the port to 22, writes the 422 itself on failure, and
// reports whether the input passed.
func (s *Server) validateTargetIn(w http.ResponseWriter, in *targetIn) bool {
	if in.Port == 0 {
		// 22 is the historical default (this started as an SSH-only vault);
		// a Kubernetes API server is 6443, and defaulting it to 22 would only
		// ever produce a connection refused on the first brokered call.
		in.Port = 22
		if in.Protocol == "kubernetes" {
			in.Port = 6443
		}
	}
	switch {
	case in.Host == "":
		writeError(w, http.StatusUnprocessableEntity, "name and host are required")
	case validName(in.Name) != nil:
		writeError(w, http.StatusUnprocessableEntity, "name "+validName(in.Name).Error())
	case in.Port < 1 || in.Port > 65535:
		writeError(w, http.StatusUnprocessableEntity, "port must be 1-65535")
	case !validOS[in.OSType]:
		writeError(w, http.StatusUnprocessableEntity, `os_type must be "linux" or "windows"`)
	case !validProtocol[in.Protocol]:
		writeError(w, http.StatusUnprocessableEntity, `protocol must be "ssh", "winrm", "rdp", "vnc", "postgres", "mssql" or "kubernetes"`)
	case !s.protocolAllowed(in.Protocol):
		writeError(w, http.StatusUnprocessableEntity, "protocol "+in.Protocol+" is not allowed by policy")
	case !validOverride(clipboardRank, in.RDPClipboard):
		writeError(w, http.StatusUnprocessableEntity, `rdp_clipboard must be "" (inherit), "allow", "readonly" or "deny"`)
	case !validOverride(clipAuditRank, in.RDPClipboardAudit):
		writeError(w, http.StatusUnprocessableEntity, `rdp_clipboard_audit must be "" (inherit), "off", "meta" or "full"`)
	default:
		return true
	}
	return false
}

// targetFromIn builds the store row both handlers persist.
func targetFromIn(in targetIn) store.Target {
	return store.Target{Name: in.Name, Host: in.Host, Port: in.Port, OSType: in.OSType, Protocol: in.Protocol,
		RequireApproval: in.RequireApproval, RDPClipboard: in.RDPClipboard, RDPClipboardAudit: in.RDPClipboardAudit}
}

// clipDetail renders the per-target clipboard overrides for an audit detail,
// "-" for inherit — the overrides are security policy, so setting, tightening
// or clearing one must be visible in the trail (a PUT that omits the fields
// clears them; without this, that reset would leave no forensic trace at all).
func clipDetail(t store.Target) string {
	orDash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	return fmt.Sprintf("clipboard:%s clip_audit:%s", orDash(t.RDPClipboard), orDash(t.RDPClipboardAudit))
}

// createTarget validates and persists a new target (defaulting the port to 22),
// then audits the creation.
func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var in targetIn
	if !readJSON(w, r, &in) {
		return
	}
	if !s.validateTargetIn(w, &in) {
		return
	}
	t := targetFromIn(in)
	if err := s.store.CreateTarget(r.Context(), &t); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.create", t.Name+" "+clipDetail(t))
	writeJSON(w, http.StatusCreated, t)
}

// listTargets returns a page of the target inventory (?limit=&after= cursor).

// updateTarget edits a target in place — the same validation and authorization
// as create, without the delete + recreate that would cascade away its
// credentials, grants, dependencies and safe assignment. The safe assignment
// itself is not editable here (PUT /api/targets/{id}/safe owns it).
func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in targetIn
	if !readJSON(w, r, &in) {
		return
	}
	if !s.validateTargetIn(w, &in) {
		return
	}
	// A protocol-bound credential (ssh_ca, db_zsp, k8s_token) is only ever
	// created on a target whose protocol can serve it (createCredential
	// enforces it); mirror that here, through the SAME table, so an edit
	// cannot strand one on a target no code path can serve it from.
	// Metadata-only is enough — the rule reads SecretType, never a secret.
	creds, err := s.store.ListCredentialsMeta(r.Context(), id, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	if c := strandedByProtocol(creds, in.Protocol); c != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf(
			"target has a %s credential (id %d); it is only valid on %s targets",
			c.SecretType, c.ID, strings.Join(protocolsFor(c.SecretType), " or ")))
		return
	}
	t := targetFromIn(in)
	t.ID = id
	if err := s.store.UpdateTarget(r.Context(), &t); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.update", fmt.Sprintf("target:%d name:%s host:%s:%d %s", t.ID, t.Name, auditField(t.Host, 255), t.Port, clipDetail(t)))
	writeJSON(w, http.StatusOK, t)
}

// getTarget returns a single target by its {id} path value.
func (s *Server) getTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// deleteTarget removes a target by id (its credentials cascade in the store) and
// audits the deletion.
func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteTarget(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// --- target access grants (per-target authorization) ---

type grantIn struct {
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
}

// createTargetGrant adds a per-target access grant for a user or role (validating
// the subject, and that a role subject is a known role) and audits it.
func (s *Server) createTargetGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in grantIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case in.SubjectType != "user" && in.SubjectType != "role":
		writeError(w, http.StatusUnprocessableEntity, `subject_type must be "user" or "role"`)
		return
	case validName(in.Subject) != nil:
		writeError(w, http.StatusUnprocessableEntity, "subject "+validName(in.Subject).Error())
		return
	}
	if in.SubjectType == "role" {
		if _, err := auth.ParseGrantRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, `subject must be a valid role (admin|user|auditor|approver|agent)`)
			return
		}
	}
	// The creator is recorded so a certification review can enforce four-eyes:
	// the principal who granted access may not be the one certifying it (Phase 46).
	g := store.TargetGrant{TargetID: id, SubjectType: in.SubjectType, Subject: in.Subject, CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateTargetGrant(r.Context(), &g); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "grant.create", fmt.Sprintf("target:%d %s:%s", id, in.SubjectType, in.Subject))
	writeJSON(w, http.StatusCreated, g)
}

// listTargetGrants returns the access grants for a target.
func (s *Server) listTargetGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListTargetGrants(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// deleteTargetGrant removes a target access grant by its {gid} path value and
// audits it.
func (s *Server) deleteTargetGrant(w http.ResponseWriter, r *http.Request) {
	tid, ok := idParam(w, r)
	if !ok {
		return
	}
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid grant id")
		return
	}
	// The route is scoped to a target — only delete the grant if it belongs to
	// that target, so DELETE /targets/1/grants/5 cannot remove target 2's grant.
	grants, err := s.store.ListTargetGrants(r.Context(), tid)
	if err != nil {
		storeError(w, err)
		return
	}
	var revoked *store.TargetGrant
	for i := range grants {
		if grants[i].ID == gid {
			revoked = &grants[i]
			break
		}
	}
	if revoked == nil {
		writeError(w, http.StatusNotFound, "grant not found for this target")
		return
	}
	if err := s.store.DeleteTargetGrant(r.Context(), gid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "grant.delete", fmt.Sprintf("target:%d grant:%d", tid, gid))
	// Cut any in-flight session the revoked *user* holds to this target (their
	// sessions to other still-authorized targets are left running). A revoked
	// *role* grant only affects new connections — the registry doesn't carry each
	// session actor's role set, so role-grant sessions aren't matched here.
	if revoked.SubjectType == "user" && s.sessions != nil {
		if t, terr := s.store.GetTarget(r.Context(), tid); terr == nil {
			killed := s.sessions.KillByActorTarget(revoked.Subject, t.Name)
			// Unconditional: killed == 0 in HA usually means "hosted elsewhere".
			s.audit(r.Context(), "session.killed", fmt.Sprintf("user:%s target:%s killed_here:%d reason:grant-revoked", revoked.Subject, t.Name, killed))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizedForTarget reports whether the caller may connect to a target under
// its access grants. A safe-scoped target (target.SafeID set) is default-deny
// when no grant matches; an ungated target is open to any connect-capable caller.
// When the target's safe is Personal (Phase 139) and the caller is admitted
// specifically via CapUnlimitedVaultAccess rather than ordinary membership,
// that use is audited loudly — safe.personal_override_used — mirroring how
// break-glass access always is.
func (s *Server) authorizedForTarget(ctx context.Context, target *store.Target) (bool, error) {
	grants, err := s.store.EffectiveTargetGrants(ctx, target.ID)
	if err != nil {
		return false, err
	}
	personal, err := store.EffectiveSafePersonal(ctx, s.store, target)
	if err != nil {
		return false, err
	}
	principal := principalFrom(ctx)
	ok := auth.CanConnectTarget(principal, grants, target.SafeID != nil, personal, s.rt().ungated)
	if ok && principal.PersonalOverrideUsed(personal) {
		s.audit(ctx, "safe.personal_override_used", "target:"+target.Name)
	}
	return ok, nil
}

// gateCredentialAccess enforces the per-target grant and four-eyes approval gates
// that guard EVERY credential-access path — the SSH/WinRM/RDP connect paths and,
// equally, reveal and checkout. `account` is the login account the caller will use
// (for the vendor contract gate; "" = any). It writes a 403 and returns false when
// the caller may not reach the target. action names the audited denial.
func (s *Server) gateCredentialAccess(w http.ResponseWriter, r *http.Request, target *store.Target, account, action string) bool {
	if ok, err := s.authorizedForTarget(r.Context(), target); err != nil {
		storeError(w, err)
		return false
	} else if !ok {
		s.audit(r.Context(), action+"_denied", "target:"+target.Name+" reason:target-policy")
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return false
	}
	if ok, err := s.enforceApproval(r.Context(), target); err != nil {
		storeError(w, err)
		return false
	} else if !ok {
		s.audit(r.Context(), "access.denied", "target:"+target.Name+" reason:approval-required")
		writeError(w, http.StatusForbidden, "access requires an approved access request")
		return false
	}
	// Vendor contract gate (Phase 29): a vendor reaches the target only in-contract.
	return s.vendorGate(w, r, target, account, action+"_denied")
}

// --- credentials ---
