package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/accountscan"
	"github.com/morandeirachema/pamv1/internal/store"
)

// discoverAccountsResult is the response shape for POST
// /api/targets/{id}/discover-accounts.
type discoverAccountsResult struct {
	Target              string                `json:"target"`
	Protocol            string                `json:"protocol"`
	ScannedAt           time.Time             `json:"scanned_at"`
	Accounts            []accountscan.Account `json:"accounts"`
	Managed             map[string]bool       `json:"managed"`
	UnmanagedCount      int                   `json:"unmanaged_count"`
	PrivilegedUnmanaged int                   `json:"privileged_unmanaged_count"`
	// Partial marks a scan whose target answer was cut short by the exec output
	// cap, so the account list is a subset of what the host actually has. It is
	// reported rather than hidden because the failure is invisible otherwise: a
	// truncated `/etc/passwd` parses cleanly and simply lists fewer accounts, so
	// an unmanaged — possibly privileged — account would go unreported while the
	// result looked like a clean bill of health.
	Partial bool `json:"partial,omitempty"`
}

// discoverAccounts runs a fixed, read-only enumeration command over a target's
// already-vaulted credential (SSH: `cat /etc/passwd`; WinRM: `net user` +
// `net localgroup Administrators`) and cross-references every discovered
// account name against the target's own vaulted credentials. An account with
// no matching credential is "unmanaged" — the CyberArk DNA-style finding this
// phase exists to surface: a login-capable account PAMv1 knows the *host*
// has, but isn't tracking, rotating or auditing access to. This is a
// management action (auth.CapManageTargets), not a connect/session action —
// it deliberately does not touch the live-session registry, recording
// requirements or per-target connect grants that a real interactive
// session would, matching runWinRM's execWinRM helper being the wrong fit
// here (that helper is built for a supervised, recorded operator session).
func (s *Server) discoverAccounts(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "ssh" && target.Protocol != "winrm" {
		writeError(w, http.StatusUnprocessableEntity, "account discovery is only supported for ssh and winrm targets")
		return
	}
	if !s.protocolAllowed(target.Protocol) {
		writeError(w, http.StatusForbidden, target.Protocol+" is not allowed by policy")
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), target.ID, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "target has no credential")
		return
	}
	// Managed = any account name matching ANY of the target's own vaulted
	// credentials, not just the one used to authenticate this scan — a target
	// commonly has more than one vaulted account.
	managed := make(map[string]bool, len(creds))
	for _, c := range creds {
		managed[c.Username] = true
	}
	cred := creds[0]
	actor := actorFrom(r.Context())

	accounts, partial, err := s.runAccountScan(r.Context(), target, &cred, actor)
	if err != nil {
		switch err {
		case errCommandBlocked:
			writeError(w, http.StatusForbidden, "command blocked by policy")
		case errDecryptFailed:
			writeError(w, http.StatusInternalServerError, "decryption failed")
		default:
			s.audit(r.Context(), "target.accounts_scan_failed", fmt.Sprintf("target:%s protocol:%s error:%v", target.Name, target.Protocol, err))
			writeError(w, http.StatusBadGateway, "account scan failed")
		}
		return
	}

	unmanaged, privilegedUnmanaged := 0, 0
	for _, a := range accounts {
		if !managed[a.Username] {
			unmanaged++
			if a.Privileged {
				privilegedUnmanaged++
			}
		}
	}
	detail := fmt.Sprintf("target:%s protocol:%s found:%d unmanaged:%d privileged_unmanaged:%d",
		target.Name, target.Protocol, len(accounts), unmanaged, privilegedUnmanaged)
	if partial {
		detail += " partial:true"
	}
	s.audit(r.Context(), "target.accounts_scanned", detail)

	writeJSON(w, http.StatusOK, discoverAccountsResult{
		Target:              target.Name,
		Protocol:            target.Protocol,
		ScannedAt:           time.Now(),
		Accounts:            accounts,
		Managed:             managed,
		UnmanagedCount:      unmanaged,
		PrivilegedUnmanaged: privilegedUnmanaged,
		Partial:             partial,
	})
}

// runAccountScan dials target fresh with cred's just-in-time-decrypted secret
// (a one-shot connection, never the live interactive one — matching
// rotate.SSHConnector.Exec's and the broker exec tools' existing shape, not a
// new pattern) and runs the fixed enumeration command(s) for target's
// protocol. Every command goes through guardCommand first, same chokepoint as
// the interactive SSH/WinRM command paths (Phase 38's principle: every path
// where a discrete command is visible obeys one policy) — these commands are
// PAMv1's own fixed literals, not operator input, but an operator-configured
// deny pattern that happens to match must still refuse the scan rather than
// silently bypass policy.
// It returns partial=true when the target's answer was cut short by the exec
// output cap (Phase 165). That distinction matters more here than anywhere else
// in the product: a truncated `/etc/passwd` parses perfectly and simply lists
// fewer accounts, so an unmanaged — possibly privileged — account would go
// unreported while the scan looked clean. A scan that cannot see everything must
// say so rather than be filed as authoritative.
func (s *Server) runAccountScan(ctx context.Context, target *store.Target, cred *store.Credential, actor string) ([]accountscan.Account, bool, error) {
	if target.Protocol == "ssh" {
		const cmd = "cat /etc/passwd"
		if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmd); err != nil {
			return nil, false, err
		}
		secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
		if err != nil {
			s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:discovery", cred.ID, target.Name))
			return nil, false, errDecryptFailed
		}
		res, err := s.sshConnector.Exec(ctx, *target, cred.Username, secret, cmd)
		if err != nil {
			return nil, false, err
		}
		return accountscan.ParseUnixAccounts(res.Output), res.Truncated, nil
	}

	const cmdUsers = "net user"
	const cmdAdmins = "net localgroup Administrators"
	if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmdUsers); err != nil {
		return nil, false, err
	}
	if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmdAdmins); err != nil {
		return nil, false, err
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:discovery", cred.ID, target.Name))
		return nil, false, errDecryptFailed
	}
	users, err := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, cmdUsers)
	if err != nil {
		return nil, false, err
	}
	// The admins listing is a refinement (which accounts are privileged), not
	// a precondition for reporting the account list itself — a failure here
	// degrades to "nothing flagged privileged" rather than losing the scan.
	admins, _ := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, cmdAdmins)
	// WinRM has capped its own output since Phase 13 and reports it in the text
	// rather than a flag, so the marker is the only signal available here.
	partial := strings.Contains(users.Stdout, "truncated") && strings.Contains(users.Stdout, "PAMv1")
	return accountscan.ParseWindowsAccounts(users.Stdout, admins.Stdout), partial, nil
}
