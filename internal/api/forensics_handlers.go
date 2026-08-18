package api

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/sessionforensics"
	"github.com/morandeirachema/pamv1/internal/store"
)

// SessionForensicsRequest is what the SSH proxy hands back after an interactive
// session ends: the facts pamv1 itself knows about the session, which are what
// scope the reconstruction to it (the target's audit log holds every session's
// execs, including other operators').
type SessionForensicsRequest struct {
	TargetID     int64
	CredentialID int64
	Actor        string
	SessionID    string
	Started      time.Time
	Ended        time.Time
}

// CollectSessionForensics reconstructs what actually EXECUTED during a finished
// interactive session and stores it beside the recording as a hash-chained,
// audited artifact (Phase 157).
//
// It runs ONE fixed, read-only command over the target's own vaulted credential
// on a FRESH connection — never the live session, which is gone by now — the
// same shape Phase 128's account discovery established, through the same
// `guardCommand` chokepoint so pamv1's own literal is not exempt from an
// operator's deny policy.
//
// It is called from a background goroutine the proxy tracks (so a graceful
// shutdown drains it), never from a request path, and it therefore reports
// every outcome to the audit trail rather than to a caller:
//
//   - `session.forensics` — a reconstruction was stored (with its event count,
//     file and hash);
//   - `session.forensics_unavailable` — the target could not tell us (no
//     auditd, exec auditing off, or the credential may not read the audit log).
//     That is a FINDING, not a silent no-op: a target whose sessions cannot be
//     reconstructed is exactly what an auditor wants to know;
//   - `session.forensics_failed` — pamv1 could not ask (dial/exec failure,
//     decrypt failure, policy refusal).
func (s *Server) CollectSessionForensics(ctx context.Context, in SessionForensicsRequest) {
	if !s.forensics {
		return
	}
	timeout := s.forensicsTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	actor := in.Actor
	fail := func(reason string) {
		_ = s.auditAs(ctx, actor, "session.forensics_failed",
			fmt.Sprintf("target:%d session:%s reason:%s", in.TargetID, auditField(in.SessionID, 64), reason))
	}
	target, err := s.store.GetTarget(ctx, in.TargetID)
	if err != nil {
		fail("target-not-found")
		return
	}
	// v1 covers the interactive SSH PTY, which is the path whose contents are
	// deliberately never parsed. The WinRM and database paths already audit every
	// discrete command they broker, so they have no equivalent blind spot.
	if target.Protocol != "ssh" {
		return
	}
	cred, err := s.store.GetCredential(ctx, in.CredentialID)
	if err != nil {
		fail("credential-not-found")
		return
	}
	// A Zero Standing Privilege credential stores no secret to re-authenticate
	// with: the session's certificate was minted for that session and is gone.
	// Minting a second one here would be a new privileged access, after the
	// session's approval was consumed — so this is refused, loudly, rather than
	// quietly widening what a ZSP credential authorizes.
	if cred.IsZSP() {
		_ = s.auditAs(ctx, actor, "session.forensics_unavailable",
			fmt.Sprintf("target:%s session:%s reason:zero-standing-privilege-credential", target.Name, auditField(in.SessionID, 64)))
		return
	}
	if err := s.guardCommand(ctx, actor, target.Name, "forensics", sessionforensics.Command); err != nil {
		fail("command-blocked")
		return
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:forensics", cred.ID, target.Name))
		fail("decrypt-failed")
		return
	}
	res, err := s.sshConnector.Exec(ctx, *target, cred.Username, secret, sessionforensics.Command)
	if err != nil {
		s.log.Warn("session forensics collection failed", "target", target.Name, "actor", actor, "err", err)
		fail("exec-failed")
		return
	}
	rep := sessionforensics.Parse(res.Output, in.Started, in.Ended, s.forensicsMaxEvents)
	// A pull cut short by the exec output cap is a PARTIAL reconstruction, and it
	// must say so: the parser is perfectly happy with a truncated record set and
	// would otherwise produce an artifact that reads as a complete account of what
	// ran. The command already asks the target for a bounded slice
	// (`tail -c 1048576`), so this fires only when a target answers with more than
	// the connector will hold — but "the evidence is incomplete" is exactly the
	// kind of thing that must never be inferred from silence.
	if res.Truncated {
		rep.Truncated = true
	}
	rep.Target, rep.Actor, rep.SessionID = target.Name, actor, in.SessionID
	rep.Started, rep.Ended = in.Started.UTC(), in.Ended.UTC()

	// Stored through the SAME transcript writer every other brokered-command
	// artifact uses (Phase 155's consolidation), so it is named, sealed at rest
	// and hashed exactly like a WinRM or Kubernetes transcript — and replays
	// from the console through the same playback path.
	file, sum := s.recordExecTranscript("Session forensics", ".forensics.log", target, cred.Username, actor,
		sessionforensics.Command, rep.Text(), "", fmt.Sprintf("events: %d", len(rep.Events)))
	if !rep.Available {
		_ = s.auditAs(ctx, actor, "session.forensics_unavailable", fmt.Sprintf(
			"target:%s session:%s reason:%s file:%s sha256:%s",
			target.Name, auditField(in.SessionID, 64), auditField(rep.Note, 200), file, sum))
		return
	}
	detail := fmt.Sprintf("target:%s session:%s events:%d scanned:%d window:%s..%s file:%s sha256:%s",
		target.Name, auditField(in.SessionID, 64), len(rep.Events), rep.Scanned,
		rep.Started.Format(time.RFC3339), rep.Ended.Format(time.RFC3339), file, sum)
	if rep.Truncated {
		detail += " truncated:true"
	}
	if err := s.auditAs(ctx, actor, "session.forensics", detail); err != nil {
		// The artifact is on disk but unaccounted for: say so loudly. There is no
		// caller to return 503 to here (this runs after the session closed), so
		// the log is the escalation path.
		s.log.Error("session forensics artifact not registered in the audit trail", "file", file, "err", err)
	}
}
