package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
)

// ErrUnsupported marks a rotation that cannot be attempted (wrong secret type or
// a protocol with no rotator) — a client precondition, not a target failure.
var ErrUnsupported = errors.New("rotation unsupported")

// --- credential rotation ---

// rotateCredentialHandler generates a fresh strong secret, sets it on the target
// over the target's protocol (SSH/WinRM), then re-vaults it and stamps
// rotated_at. The new secret is never returned — it lives only in the vault, to
// be injected just-in-time by the proxy.
func (s *Server) rotateCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	// Rotation is a credential-touching path, so it obeys the same per-target
	// grants, approval window and vendor-contract gate as reveal, checkout and
	// connect. Without this, `manage_credentials` alone changed a production
	// password on a target the holder could neither connect to nor reveal —
	// outside any approval window, and for a vendor account after its contract
	// closed. The agent-facing rotate_credential tool was gated for exactly this
	// in Phase 52c (SECURITY-GAPS finding M); the human endpoint was not.
	if !s.gateCredentialAccess(w, r, target, cred.Username, "credential.rotate") {
		return
	}
	rotatedAt, err := s.rotateCredential(r.Context(), cred, target)
	if errors.Is(err, ErrUnsupported) {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		s.audit(r.Context(), "credential.rotate_failed",
			fmt.Sprintf("credential:%d target:%s error:%v", cred.ID, target.Name, err))
		s.log.Error("credential rotation failed", "credential", cred.ID, "target", target.Name, "err", err)
		writeError(w, http.StatusBadGateway, "rotation failed: "+err.Error())
		return
	}
	s.audit(r.Context(), "credential.rotate",
		fmt.Sprintf("credential:%d target:%s user:%s", cred.ID, target.Name, cred.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"id": cred.ID, "target": target.Name, "username": cred.Username,
		"rotated": true, "rotated_at": rotatedAt,
	})
}

// rotateCredential performs the rotation and vault update. Shared by the manual
// endpoint and reconciliation remediation.
func (s *Server) rotateCredential(ctx context.Context, cred *store.Credential, target *store.Target) (time.Time, error) {
	rotator, ok := s.rotators[target.Protocol]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: no rotator for protocol %q", ErrUnsupported, target.Protocol)
	}
	oldSecret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return time.Time{}, fmt.Errorf("vault decrypt failed")
	}

	// Record the attempt before the external password change, so a crash between
	// changing the target and persisting the new secret leaves a rotate_started
	// with no matching rotate/rotate_failed — a detectable trail on every path.
	s.audit(ctx, "credential.rotate_started", fmt.Sprintf("credential:%d target:%s", cred.ID, target.Name))

	// Generate the new secret and apply it on the target. Passwords use the
	// Rotator; ssh_key credentials install a fresh keypair via a KeyRotator.
	var newSecret string
	switch cred.SecretType {
	case "password":
		newSecret, err = rotate.GeneratePassword(24)
		if err != nil {
			return time.Time{}, fmt.Errorf("password generation failed")
		}
		if err := rotator.Rotate(ctx, *target, cred.Username, oldSecret, newSecret); err != nil {
			return time.Time{}, err
		}
	case "ssh_key":
		kr, ok := rotator.(rotate.KeyRotator)
		if !ok {
			return time.Time{}, fmt.Errorf("%w: key rotation not supported for protocol %q", ErrUnsupported, target.Protocol)
		}
		newSecret, err = rotate.GenerateSSHKey()
		if err != nil {
			return time.Time{}, fmt.Errorf("ssh key generation failed")
		}
		if err := kr.RotateKey(ctx, *target, cred.Username, oldSecret, newSecret); err != nil {
			return time.Time{}, err
		}
	default:
		return time.Time{}, fmt.Errorf("%w: unknown secret type %q", ErrUnsupported, cred.SecretType)
	}

	// The target's secret is now changed. Persist the new secret with a context
	// detached from cancellation: a client disconnect or graceful shutdown here
	// must not lose the new secret, which would lock PAM out of the target.
	pctx := context.WithoutCancel(ctx)
	// From here the target's secret is already changed; a persist failure orphans
	// the account (the vault still holds the now-invalid old secret). We can't undo
	// the external change without the new secret, so make the orphan LOUD and
	// actionable rather than a silent lockout.
	orphan := func(reason string, cause error) {
		s.audit(pctx, "credential.rotate_orphaned",
			fmt.Sprintf("credential:%d target:%s reason:%s ACTION:target password was changed but NOT vaulted — recover manually", cred.ID, target.Name, reason))
		s.log.Error("CREDENTIAL ORPHANED: target secret rotated but not persisted", "credential", cred.ID, "target", target.Name, "reason", reason, "err", cause)
	}
	enc, err := s.vault.Encrypt(pctx, newSecret, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		orphan("vault-encrypt-failed", err)
		return time.Time{}, fmt.Errorf("re-encrypt after rotation failed: %w", err)
	}
	now := time.Now().UTC()
	if err := s.store.RotateCredentialSecret(pctx, cred.ID, enc, now); err != nil {
		orphan("persist-failed", err)
		return time.Time{}, fmt.Errorf("persist rotated secret failed: %w", err)
	}
	// Propagate the new secret to declared consumers (Windows Services / Scheduled
	// Tasks / IIS App Pools) so the rotation does not break production (Phase 17).
	// A propagation failure does not fail the (already-persisted) rotation; each
	// consumer is audited so a stale consumer is visible and actionable.
	s.propagateDependencies(pctx, cred, newSecret)
	return now, nil
}

// propagateDependencies updates each of a credential's declared consumers with
// the new secret over WinRM. It never fails the rotation; failures are audited.
func (s *Server) propagateDependencies(ctx context.Context, cred *store.Credential, newSecret string) {
	deps, err := s.store.ListCredentialDependencies(ctx, cred.ID)
	if err != nil || len(deps) == 0 {
		return
	}
	if s.winrm == nil {
		s.audit(ctx, "credential.dependency_failed",
			fmt.Sprintf("credential:%d reason:winrm-not-configured deps:%d", cred.ID, len(deps)))
		return
	}
	for _, d := range deps {
		// Reject an unusable host before anything else — it is interpolated
		// nowhere, but an unvalidated one means the row was not written through
		// the API and should not be acted on.
		if !validDependencyHost.MatchString(d.Host) {
			s.audit(ctx, "credential.dependency_failed",
				fmt.Sprintf("credential:%d %s:%q reason:invalid-host", cred.ID, d.Kind, d.Host))
			continue
		}
		cmd, ok := dependencyCommand(d, newSecret)
		if !ok {
			// Either an unknown kind or a name that cannot safely reach a command
			// line. Both are refusals, and the name is quoted so the audit entry
			// itself cannot be forged by the value that caused the refusal.
			s.audit(ctx, "credential.dependency_failed",
				fmt.Sprintf("credential:%d %s:%q@%s reason:unusable-kind-or-name", cred.ID, d.Kind, d.Name, d.Host))
			continue
		}
		// Command control applies here too (Phase 38's principle: every path where
		// a discrete command is visible obeys one policy). Rotation runs
		// unattended, so the actor is the system.
		if err := s.guardCommand(ctx, actorFrom(ctx), d.Host, "dependency", cmd); err != nil {
			continue // guardCommand already audited command.blocked
		}
		port := d.Port
		if port == 0 {
			port = 5985
		}
		// Who pamv1 connects AS to make this change (Phase 61). A declared
		// management credential is used when there is one; otherwise this falls
		// back to the rotated account, which is what it always did.
		user, secret, via, cerr := s.dependencyLogin(ctx, cred, newSecret, d)
		if cerr != nil {
			s.audit(ctx, "credential.dependency_failed",
				fmt.Sprintf("credential:%d %s:%s@%s reason:%v", cred.ID, d.Kind, d.Name, d.Host, cerr))
			continue
		}
		if _, err := s.winrm.Run(ctx, d.Host, port, user, secret, cmd); err != nil {
			s.audit(ctx, "credential.dependency_failed",
				fmt.Sprintf("credential:%d %s:%s@%s managed_via:%s error:%v", cred.ID, d.Kind, d.Name, d.Host, via, err))
			continue
		}
		s.audit(ctx, "credential.dependency_updated",
			fmt.Sprintf("credential:%d %s:%s@%s managed_via:%s", cred.ID, d.Kind, d.Name, d.Host, via))
	}
}

// errManagementCredential describes why a declared management credential could
// not be used. It is deliberately a plain sentence: it goes straight into the
// audit trail, where an operator reads it without the code in front of them.
type errManagementCredential string

// Error renders the reason.
func (e errManagementCredential) Error() string { return string(e) }

// dependencyLogin resolves the account pamv1 authenticates to the consumer's
// host with, returning its username, its plaintext secret, and a short label
// for the audit trail (never the secret itself).
//
// Before Phase 61 this was always the rotated account with its brand-new
// password, which asked the wrong account for the wrong rights: reconfiguring a
// service, scheduled task or app pool needs remote management and local
// administrator rights on that host, exactly what a service account should not
// have — and a hardened one often cannot log on remotely at all, so propagation
// failed precisely where it mattered. A dependency may now name a management
// credential instead.
//
// FAIL CLOSED on a broken reference. If a management credential was declared
// and cannot be resolved, this refuses rather than quietly falling back to the
// rotated account: the operator chose to stop using that account for this, and
// silently resuming it would undo the decision at the least visible moment.
func (s *Server) dependencyLogin(ctx context.Context, cred *store.Credential, newSecret string, d store.CredentialDependency) (user, secret, via string, err error) {
	if d.ManagementCredentialID == 0 {
		return cred.Username, newSecret, "self", nil
	}
	mc, gerr := s.store.GetCredential(ctx, d.ManagementCredentialID)
	if gerr != nil || mc == nil {
		return "", "", "", errManagementCredential(fmt.Sprintf("management-credential-missing id:%d", d.ManagementCredentialID))
	}
	if mc.SecretEnc == "" {
		// A Zero Standing Privilege credential holds no secret to present over
		// WinRM; naming one here is a configuration error, not a runtime hiccup.
		return "", "", "", errManagementCredential(fmt.Sprintf("management-credential-has-no-secret id:%d", mc.ID))
	}
	// Re-checked here, not only at declaration (Phase 61a), for the same reason
	// the dependency's name is: this is the last point before the value leaves
	// pamv1, and a row could predate the rule or have been written straight into
	// the database. An SSH private key handed to WinRM as a password authenticates
	// nothing and discloses everything, so it never leaves.
	if mc.SecretType != "" && mc.SecretType != "password" {
		return "", "", "", errManagementCredential(fmt.Sprintf("management-credential-not-a-password id:%d type:%s", mc.ID, mc.SecretType))
	}
	plain, derr := s.vault.Decrypt(ctx, mc.SecretEnc, store.CredentialAAD(mc.TargetID, mc.ID))
	if derr != nil {
		return "", "", "", errManagementCredential(fmt.Sprintf("management-credential-undecryptable id:%d", mc.ID))
	}
	return mc.Username, plain, fmt.Sprintf("credential:%d", mc.ID), nil
}

// dependencyCommand builds the WinRM command that updates a consumer's stored
// password. The new secret is injected into the command (never audited or
// recorded), consistent with how rotation sets the account password itself.
//
// The name is re-validated here, not only at creation: this function is the last
// point before the value reaches a command line, and a row could predate the
// validation rule or have been written straight into the database. An
// unacceptable name makes this return ok=false (Go functions return several
// values at once; here it is "the command" plus "was it usable"), which the
// caller audits and skips — the consumer simply does not get updated, which is
// the safe failure.
func dependencyCommand(d store.CredentialDependency, newSecret string) (string, bool) {
	if !validDependencyName.MatchString(d.Name) {
		return "", false
	}
	switch d.Kind {
	case "windows_service":
		return fmt.Sprintf(`sc.exe config "%s" password= "%s"`, d.Name, newSecret), true
	case "scheduled_task":
		return fmt.Sprintf(`schtasks /Change /TN "%s" /RP "%s"`, d.Name, newSecret), true
	case "iis_apppool":
		return fmt.Sprintf(`%%windir%%\system32\inetsrv\appcmd.exe set apppool "%s" -processModel.password:"%s"`, d.Name, newSecret), true
	}
	return "", false
}

// --- credential checkout / check-in (exclusive time-boxed lease) ---

type checkoutIn struct {
	Reason string `json:"reason"`
}

// checkoutCredential grants an exclusive, time-boxed lease on a credential and
// returns the secret to the holder. Only one holder may have a credential
// checked out at a time. On check-in the credential is rotated, so the password
// the holder saw can no longer be used. Honors the reveal-disabled policy
// (break-glass excepted), since a checkout reveals the secret.
func (s *Server) checkoutCredential(w http.ResponseWriter, r *http.Request) {
	if s.rt().revealDisabled && !principalFrom(r.Context()).BreakGlass {
		s.audit(r.Context(), "credential.checkout_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "credential checkout is disabled by policy; connect through the proxy")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	// Checkout is a credential-access path: enforce the same per-target grants and
	// approval gate as connecting/reveal.
	if !s.gateCredentialAccess(w, r, target, cred.Username, "credential.checkout") {
		return
	}
	// A Zero Standing Privilege credential has no stored secret to lease. Refuse
	// before creating a lease (which we'd then have to roll back after a decrypt of
	// the empty SecretEnc failed, emitting a misleading credential.decrypt_failed).
	if cred.SecretType == "ssh_ca" {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege); connect through the proxy")
		return
	}
	var in checkoutIn
	if r.ContentLength != 0 {
		if !readJSON(w, r, &in) {
			return
		}
	}
	now := time.Now()
	// If a previous lease on this credential expired without a check-in, rotate the
	// secret its holder saw before issuing a new lease. The store auto-closes an
	// expired lease on the next checkout, so without this a re-checkout that beats
	// the periodic sweep would hand out (and then skip rotating) the prior holder's
	// still-valid secret.
	if rotated, ierr := s.invalidateExpiredCheckoutFor(r.Context(), cred.ID, now); ierr != nil {
		s.audit(r.Context(), "credential.checkout_denied",
			fmt.Sprintf("credential:%d reason:expired-lease-not-invalidated", cred.ID))
		writeError(w, http.StatusServiceUnavailable, "a previous lease on this credential could not be invalidated; try again")
		return
	} else if rotated {
		// Rotation replaced the vaulted secret; re-fetch so the new holder is handed
		// the fresh secret, not the one the expired holder saw.
		fresh, gerr := s.store.GetCredential(r.Context(), cred.ID)
		if gerr != nil {
			storeError(w, gerr)
			return
		}
		cred = fresh
	}
	co := store.Checkout{
		CredentialID: cred.ID, TargetID: target.ID, Holder: actorFrom(r.Context()),
		Reason: in.Reason, ExpiresAt: now.Add(s.rt().checkoutTTL).UTC(),
	}
	if err := s.store.CreateCheckout(r.Context(), &co, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "credential is already checked out")
			return
		}
		storeError(w, err)
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		// The lease was created but the secret can't be revealed — roll it back so
		// the credential isn't blocked from checkout for the whole TTL.
		_ = s.store.CheckinCheckout(r.Context(), co.ID, time.Now())
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:checkout", cred.ID, target.Name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	// Fail closed: the checkout must be durably audited before the secret leaves.
	// Roll the lease back if the audit can't be persisted, so the credential isn't
	// blocked for the whole TTL by a failed (and therefore denied) checkout.
	if !s.mustAudit(w, r.Context(), "credential.checkout",
		fmt.Sprintf("checkout:%d credential:%d target:%s until:%s", co.ID, cred.ID, target.Name, co.ExpiresAt.Format(time.RFC3339))) {
		_ = s.store.CheckinCheckout(r.Context(), co.ID, time.Now())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"checkout_id": co.ID, "credential_id": cred.ID, "target": target.Name,
		"username": cred.Username, "secret": secret, "expires_at": co.ExpiresAt,
		"note": "Returned automatically on check-in, which rotates this secret.",
	})
}

// checkinCredential ends a checkout and rotates the credential so the revealed
// secret is invalidated. If rotation is unsupported/fails the check-in still
// succeeds but the response flags that the secret was not rotated.
func (s *Server) checkinCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	co, err := s.store.GetActiveCheckout(r.Context(), cred.ID, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "credential is not checked out")
			return
		}
		storeError(w, err)
		return
	}
	// Only the lease holder (or an admin / break-glass) may check a credential back
	// in — otherwise another reveal-capable user could force-close and rotate an
	// active lease out from under its holder.
	p := principalFrom(r.Context())
	if co.Holder != actorFrom(r.Context()) && !p.IsAdmin() {
		s.audit(r.Context(), "credential.checkin_denied", fmt.Sprintf("checkout:%d holder:%s reason:not-holder", co.ID, co.Holder))
		writeError(w, http.StatusForbidden, "only the checkout holder may check this credential in")
		return
	}
	if err := s.store.CheckinCheckout(r.Context(), co.ID, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.checkin", fmt.Sprintf("checkout:%d credential:%d target:%s", co.ID, cred.ID, target.Name))

	rotated := true
	rotateNote := "secret rotated on check-in"
	if _, rerr := s.rotateCredential(r.Context(), cred, target); rerr != nil {
		rotated = false
		rotateNote = "WARNING: secret was NOT rotated on check-in (" + rerr.Error() + ") — rotate it manually"
		s.audit(r.Context(), "credential.checkin_rotate_failed", fmt.Sprintf("credential:%d error:%v", cred.ID, rerr))
	} else {
		s.audit(r.Context(), "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:checkin", cred.ID, target.Name))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"checkout_id": co.ID, "credential_id": cred.ID, "returned": true,
		"rotated": rotated, "note": rotateNote,
	})
}

// listCheckouts reports a page of checkouts (activeOnly via ?active=true;
// ?limit=&after= cursor).
func (s *Server) listCheckouts(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") == "true"
	limit, after := listWindow(r)
	cos, err := s.store.ListCheckouts(r.Context(), activeOnly, time.Now(), limit, after)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cos)
}

// --- account reconciliation (out-of-sync detection & remediation) ---

type reconcileResult struct {
	CredentialID int64  `json:"credential_id"`
	TargetID     int64  `json:"target_id"`
	Target       string `json:"target"`
	Username     string `json:"username"`
	Status       string `json:"status"` // in_sync | out_of_sync | unsupported
	Detail       string `json:"detail,omitempty"`
	Remediated   bool   `json:"remediated,omitempty"`
}

// reconcileCredentialHandler checks whether one credential's vaulted secret still
// authenticates to its target. With ?remediate=true, an out-of-sync password
// credential is reset to a fresh PAM-managed secret (rotation).
func (s *Server) reconcileCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	// Same gate as rotation: with ?remediate=true this path resets the target's
	// secret, so it must not be reachable for a target the caller is not
	// authorized for.
	if !s.gateCredentialAccess(w, r, target, cred.Username, "credential.reconcile") {
		return
	}
	remediate := r.URL.Query().Get("remediate") == "true"
	res := s.reconcileOne(r.Context(), cred, target, remediate)
	writeJSON(w, http.StatusOK, res)
}

// reconcileAllHandler reconciles every credential and reports drift. It is a
// read-only scan (no remediation) so it is safe to run on a schedule.
func (s *Server) reconcileAllHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListCredentials(r.Context(), 0, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	results := make([]reconcileResult, 0, len(creds))
	var drift int
	for i := range creds {
		cred := &creds[i]
		target, terr := s.store.GetTarget(r.Context(), cred.TargetID)
		if terr != nil {
			continue
		}
		res := s.reconcileOne(r.Context(), cred, target, false)
		if res.Status == "out_of_sync" {
			drift++
		}
		results = append(results, res)
	}
	s.audit(r.Context(), "credential.reconcile_scan", fmt.Sprintf("checked:%d out_of_sync:%d", len(results), drift))
	writeJSON(w, http.StatusOK, map[string]any{
		"checked": len(results), "out_of_sync": drift, "results": results,
	})
}

// reconcileOne verifies a single credential and, when asked and drifted,
// remediates by rotating to a PAM-managed secret. Every check is audited.
func (s *Server) reconcileOne(ctx context.Context, cred *store.Credential, target *store.Target, remediate bool) reconcileResult {
	res := reconcileResult{
		CredentialID: cred.ID, TargetID: target.ID, Target: target.Name, Username: cred.Username,
	}
	// A Zero Standing Privilege credential holds no stored secret — there is
	// nothing to reconcile (each certificate is minted JIT and already expired).
	if cred.SecretType == "ssh_ca" {
		res.Status = "unsupported"
		res.Detail = "zero standing privilege (no stored secret to reconcile)"
		return res
	}
	verifier, ok := s.verifiers[target.Protocol]
	if !ok {
		res.Status = "unsupported"
		res.Detail = "no verifier for protocol " + target.Protocol
		return res
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		res.Status = "out_of_sync"
		res.Detail = "vault decrypt failed"
		s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:out_of_sync detail:vault", cred.ID, target.Name))
		return res
	}
	if verr := verifier.Verify(ctx, *target, cred.Username, secret); verr != nil {
		res.Status = "out_of_sync"
		res.Detail = verr.Error()
		s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:out_of_sync", cred.ID, target.Name))
		if remediate {
			if _, rerr := s.rotateCredential(ctx, cred, target); rerr != nil {
				res.Detail += "; remediation failed: " + rerr.Error()
			} else {
				res.Remediated = true
				res.Detail += "; remediated (rotated to a PAM-managed secret)"
				s.audit(ctx, "credential.remediate", fmt.Sprintf("credential:%d target:%s", cred.ID, target.Name))
			}
		}
		return res
	}
	res.Status = "in_sync"
	s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:in_sync", cred.ID, target.Name))
	return res
}

// loadCredentialTarget fetches a credential and its target, writing the
// appropriate error response and returning ok=false on failure.
func (s *Server) loadCredentialTarget(w http.ResponseWriter, r *http.Request, id int64) (*store.Credential, *store.Target, bool) {
	cred, err := s.store.GetCredential(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return nil, nil, false
	}
	target, err := s.store.GetTarget(r.Context(), cred.TargetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnprocessableEntity, "credential's target no longer exists")
		} else {
			storeError(w, err)
		}
		return nil, nil, false
	}
	return cred, target, true
}
