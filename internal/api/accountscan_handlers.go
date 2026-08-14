package api

import (
	"context"
	"fmt"
	"net/http"
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
}

// discoverAccounts runs a fixed, read-only enumeration command over a target's
// already-vaulted credential (SSH: `cat /etc/passwd`; WinRM: `net user` +
// `net localgroup Administrators`) and cross-references every discovered
// account name against the target's own vaulted credentials. An account with
// no matching credential is "unmanaged" — the CyberArk DNA-style finding this
// phase exists to surface: a login-capable account pamv1 knows the *host*
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

	accounts, err := s.runAccountScan(r.Context(), target, &cred, actor)
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
	s.audit(r.Context(), "target.accounts_scanned", fmt.Sprintf(
		"target:%s protocol:%s found:%d unmanaged:%d privileged_unmanaged:%d",
		target.Name, target.Protocol, len(accounts), unmanaged, privilegedUnmanaged))

	writeJSON(w, http.StatusOK, discoverAccountsResult{
		Target:              target.Name,
		Protocol:            target.Protocol,
		ScannedAt:           time.Now(),
		Accounts:            accounts,
		Managed:             managed,
		UnmanagedCount:      unmanaged,
		PrivilegedUnmanaged: privilegedUnmanaged,
	})
}

// runAccountScan dials target fresh with cred's just-in-time-decrypted secret
// (a one-shot connection, never the live interactive one — matching
// rotate.SSHConnector.Exec's and the broker exec tools' existing shape, not a
// new pattern) and runs the fixed enumeration command(s) for target's
// protocol. Every command goes through guardCommand first, same chokepoint as
// the interactive SSH/WinRM command paths (Phase 38's principle: every path
// where a discrete command is visible obeys one policy) — these commands are
// pamv1's own fixed literals, not operator input, but an operator-configured
// deny pattern that happens to match must still refuse the scan rather than
// silently bypass policy.
func (s *Server) runAccountScan(ctx context.Context, target *store.Target, cred *store.Credential, actor string) ([]accountscan.Account, error) {
	if target.Protocol == "ssh" {
		const cmd = "cat /etc/passwd"
		if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmd); err != nil {
			return nil, err
		}
		secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
		if err != nil {
			s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:discovery", cred.ID, target.Name))
			return nil, errDecryptFailed
		}
		res, err := s.sshConnector.Exec(ctx, *target, cred.Username, secret, cmd)
		if err != nil {
			return nil, err
		}
		return accountscan.ParseUnixAccounts(res.Output), nil
	}

	const cmdUsers = "net user"
	const cmdAdmins = "net localgroup Administrators"
	if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmdUsers); err != nil {
		return nil, err
	}
	if err := s.guardCommand(ctx, actor, target.Name, "discovery", cmdAdmins); err != nil {
		return nil, err
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:discovery", cred.ID, target.Name))
		return nil, errDecryptFailed
	}
	users, err := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, cmdUsers)
	if err != nil {
		return nil, err
	}
	// The admins listing is a refinement (which accounts are privileged), not
	// a precondition for reporting the account list itself — a failure here
	// degrades to "nothing flagged privileged" rather than losing the scan.
	admins, _ := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, cmdAdmins)
	return accountscan.ParseWindowsAccounts(users.Stdout, admins.Stdout), nil
}
