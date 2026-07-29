package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

type credentialIn struct {
	TargetID   int64  `json:"target_id"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
}

// createCredential vaults a secret for a target, encrypting it under the target's
// AAD (defaulting the type to password), and audits it. The stored ciphertext is
// never returned to the client.
func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var in credentialIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.SecretType == "" {
		in.SecretType = "password"
	}
	zsp := in.SecretType == "ssh_ca"
	switch {
	case in.Username == "":
		writeError(w, http.StatusUnprocessableEntity, "username is required")
		return
	case !validSecret[in.SecretType]:
		writeError(w, http.StatusUnprocessableEntity, `secret_type must be "password", "ssh_key" or "ssh_ca"`)
		return
	case !zsp && in.Secret == "":
		writeError(w, http.StatusUnprocessableEntity, "secret is required")
		return
	case zsp && in.Secret != "":
		writeError(w, http.StatusUnprocessableEntity, "an ssh_ca (zero standing privilege) credential must not carry a secret")
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	// A Zero Standing Privilege credential is served by minting a certificate over
	// SSH — it only makes sense on an ssh target.
	if zsp && target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "ssh_ca credentials are only valid on ssh targets")
		return
	}
	// Insert first so the row has an ID, then bind the ciphertext to (target,
	// credential) via the AAD and store it. Roll the row back if either fails.
	c := store.Credential{TargetID: target.ID, Username: in.Username, SecretType: in.SecretType}
	if err := s.store.CreateCredential(r.Context(), &c); err != nil {
		storeError(w, err)
		return
	}
	// Zero Standing Privilege credentials store no secret (SecretEnc stays empty):
	// there is nothing to vault — the proxy mints a short-lived certificate JIT.
	if !zsp {
		// Roll the half-built row back on a cancel-detached context, so a client
		// disconnect between the insert and the ciphertext write cannot orphan a
		// permanent empty-SecretEnc credential (which would be undecryptable).
		rollback := func() { _ = s.store.DeleteCredential(context.WithoutCancel(r.Context()), c.ID) }
		enc, err := s.vault.Encrypt(r.Context(), in.Secret, store.CredentialAAD(c.TargetID, c.ID))
		if err != nil {
			rollback()
			writeError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		if err := s.store.UpdateCredentialSecretEnc(r.Context(), c.ID, enc); err != nil {
			rollback()
			storeError(w, err)
			return
		}
		c.SecretEnc = enc
	}
	s.audit(r.Context(), "credential.create", fmt.Sprintf("%s/%s", target.Name, c.Username))
	writeJSON(w, http.StatusCreated, c)
}

// listCredentials returns credentials, optionally scoped to ?target_id=. Secret
// material is never included in the response.
func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	var targetID int64
	if q := r.URL.Query().Get("target_id"); q != "" {
		id, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "target_id must be an integer")
			return
		}
		targetID = id
	}
	limit, after := listWindow(r)
	creds, err := s.store.ListCredentials(r.Context(), targetID, limit, after)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

// revealCredential decrypts a secret on demand and audits who asked for it.
// Once the JIT-injection proxy lands, reveal becomes the exception (recorded
// proxy sessions inject the secret without ever showing it).
func (s *Server) revealCredential(w http.ResponseWriter, r *http.Request) {
	// When reveal is disabled by policy, only break-glass may still reveal —
	// everyone else must go through the recorded, JIT-injecting proxy.
	if s.rt().revealDisabled && !principalFrom(r.Context()).BreakGlass {
		s.audit(r.Context(), "credential.reveal_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "credential reveal is disabled by policy; connect through the proxy")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	c, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	// Reveal is a credential-access path: it obeys the same per-target grants and
	// four-eyes approval gate as connecting, so a reveal_secret holder can't read
	// a credential for a target it wasn't granted or bypass an approval window.
	if !s.gateCredentialAccess(w, r, target, c.Username, "credential.reveal") {
		return
	}
	// A Zero Standing Privilege credential stores no secret — there is nothing to
	// reveal. Refuse cleanly rather than trying to decrypt an empty SecretEnc
	// (which would 500 and log a misleading credential.decrypt_failed).
	if c.SecretType == "ssh_ca" {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege); connect through the proxy")
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), c.SecretEnc, store.CredentialAAD(c.TargetID, c.ID))
	if err != nil {
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%d op:reveal", c.ID, c.TargetID))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	// Fail closed: the reveal must be durably audited before the secret leaves.
	if !s.mustAudit(w, r.Context(), "credential.reveal", fmt.Sprintf("credential:%d target:%d user:%s", c.ID, c.TargetID, c.Username)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          c.ID,
		"target_id":   c.TargetID,
		"username":    c.Username,
		"secret_type": c.SecretType,
		"secret":      secret,
	})
}

// deleteCredential removes a credential by id and audits it.
func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteCredential(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// --- Windows targets (WinRM command execution) ---

type winrmRunIn struct {
	Command string `json:"command"`
}

// runWinRM executes a command on a Windows target over WinRM, injecting the
// target's vaulted credential just-in-time (the caller never sees it). The
// command + output are recorded and the run is audited.
func (s *Server) runWinRM(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in winrmRunIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Command == "" {
		writeError(w, http.StatusUnprocessableEntity, "command is required")
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "winrm" {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not winrm")
		return
	}
	if !s.protocolAllowed("winrm") {
		writeError(w, http.StatusForbidden, "winrm is not allowed by policy")
		return
	}
	if ok, err := s.authorizedForTarget(r.Context(), target); err != nil {
		storeError(w, err)
		return
	} else if !ok {
		s.audit(r.Context(), "winrm.denied", "target:"+target.Name+" reason:target-policy")
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return
	}
	if ok, err := s.enforceApproval(r.Context(), target); err != nil {
		storeError(w, err)
		return
	} else if !ok {
		s.audit(r.Context(), "access.denied", "target:"+target.Name+" reason:approval-required")
		writeError(w, http.StatusForbidden, "connection requires an approved access request")
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
	cred := creds[0]
	// The vendor gate needs the login account (the credential username) to enforce
	// the contract's per-account scope, so it runs after the credential is resolved.
	if !s.vendorGate(w, r, target, cred.Username, "winrm.denied") {
		return
	}

	// A WinRM run is a brokered privileged session like any other, so it belongs in
	// the live-session registry (Phase 40).
	actor := actorFrom(r.Context())
	ctx, release, sid, err := s.superviseSession(r.Context(), actor, target.Name, "winrm", r.RemoteAddr)
	if errors.Is(err, errSessionLimit) {
		writeError(w, http.StatusTooManyRequests, "session limit reached")
		return
	}
	defer release()

	res, err := s.execWinRM(ctx, target, &cred, in.Command, actor, sid)
	if errors.Is(err, errCommandBlocked) {
		writeError(w, http.StatusForbidden, "command blocked by policy")
		return
	}
	if errors.Is(err, errDecryptFailed) {
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	if errors.Is(err, errRecordingRequired) {
		writeError(w, http.StatusServiceUnavailable, "recording is required but no recording directory is configured")
		return
	}
	if errors.Is(err, errAuditUnavailable) {
		// The command ran; the record of it did not. Withhold the output rather
		// than hand back a result the system of record cannot account for.
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable; result withheld")
		return
	}
	// A kill (or the client going away) cancels ctx: report it as a terminated
	// session rather than blaming the target for an upstream failure.
	if err != nil && ctx.Err() != nil {
		s.audit(r.Context(), "session.killed", "target:"+target.Name+" protocol:winrm")
		writeError(w, http.StatusServiceUnavailable, "session terminated")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "winrm execution failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
	})
}

// errSessionLimit reports that the concurrent-session cap refused a new session.
var errSessionLimit = errors.New("session limit reached")

// superviseSession puts a brokered execution under the live-session registry:
// it enforces the concurrent-session caps BEFORE any secret is decrypted, then
// registers the session so it is listed by GET /api/sessions, terminated by the
// kill switch, and reachable by the analytics auto-response and the vendor
// sweeper (both of which kill by actor). The returned context is cancelled when
// a kill arrives; release removes the registration.
//
// Every path that executes something privileged goes through this — the REST
// WinRM endpoint and the agent broker's exec tools alike — so an AI agent's run
// is exactly as supervisable as an operator's. A nil registry is a no-op.
func (s *Server) superviseSession(ctx context.Context, actor, target, protocol, remote string) (context.Context, func(), string, error) {
	if s.sessions == nil {
		cctx, cancel := context.WithCancel(ctx)
		return cctx, cancel, "", nil
	}
	if !s.sessions.AllowNew(actor) {
		s.auditAs(ctx, actor, "session.denied", "target:"+target+" reason:session-limit")
		return ctx, func() {}, "", errSessionLimit
	}
	cctx, cancel := context.WithCancel(ctx)
	sid := s.sessions.Register(session.Info{
		Actor: actor, Target: target, Protocol: protocol, Remote: remote, Started: time.Now(),
	}, cancel)
	// The session id is returned so the execution can also tee what it does to
	// the live-monitoring hub under it — a registered-but-silent session is
	// listable and killable yet not watchable, which is how WinRM behaved for a
	// long time while SSH and PostgreSQL streamed.
	return cctx, func() { s.sessions.Remove(sid); cancel() }, sid, nil
}

// errDecryptFailed marks a just-in-time vault decrypt failure, so callers can map
// it to an internal-error status distinct from a target execution failure.
var errDecryptFailed = errors.New("decryption failed")

// errCommandBlocked marks a command refused by command control, so callers can
// map it to a 403 (the request was understood and deliberately refused) rather
// than a target failure.
var errCommandBlocked = errors.New("command blocked by policy")

// errRecordingRequired marks a refusal because PAM_REQUIRE_RECORDING is set and
// no transcript can be produced. Callers map it to 503: the request was valid,
// the deployment is misconfigured for it, and the operator should learn that
// rather than get an unrecorded execution.
var errRecordingRequired = errors.New("recording is required but not configured")

// errAuditUnavailable marks an execution whose durable audit write failed. The
// command has already run, so this cannot undo it — but the caller withholds the
// result and returns 503, so nobody acts on output that the system of record
// never accounted for.
var errAuditUnavailable = errors.New("audit log unavailable")

// guardCommand refuses a command matching the deny policy before anything
// reaches the target — and before the credential is decrypted, so a blocked
// command never causes a secret to exist in memory. The block is audited
// `command.blocked` with the matched pattern, the same vocabulary the session
// proxies use, so one query finds every refusal whatever path it came in on.
// A nil guard blocks nothing.
func (s *Server) guardCommand(ctx context.Context, actor, targetName, path, command string) error {
	pattern, blocked := s.cmdGuard.Blocked(command)
	if !blocked {
		return nil
	}
	s.log.Warn("command blocked", "actor", actor, "target", targetName, "path", path, "pattern", pattern)
	s.auditAs(ctx, actor, "command.blocked",
		fmt.Sprintf("target:%s path:%s pattern:%s", targetName, path, pattern))
	return errCommandBlocked
}

// execWinRM injects target's vaulted credential just-in-time, runs command over
// WinRM, records the transcript, and audits the run — returning only the result.
// The plaintext secret never leaves this function. Shared by the REST handler and
// the agent-broker winrm_exec tool.
func (s *Server) execWinRM(ctx context.Context, target *store.Target, cred *store.Credential, command, actor string, sid string) (winrm.Result, error) {
	// Live monitoring (Phase 16 follow-on): a supervisor watching this session
	// sees the command as it is attempted — echoed the way the PostgreSQL proxy
	// echoes `psql> ` lines — then whatever it produced. WinRM never echoes
	// input, so without this the watch pane would show output with no cause.
	// Every early-return below publishes a notice too: an echoed command whose
	// stream then just closes reads as "ran silently", which is exactly wrong
	// for a command that was refused.
	s.live.Publish(sid, []byte("winrm> "+command+"\r\n"))
	// Command control, before the credential is decrypted: this is the one
	// chokepoint the REST WinRM endpoint and the broker's winrm_exec tool share,
	// so the deny policy covers a human and an agent identically.
	if err := s.guardCommand(ctx, actor, target.Name, "winrm", command); err != nil {
		s.live.Publish(sid, []byte("pamv1: command blocked by policy\r\n"))
		// The attempt is evidence: the proxy path tees this refusal into its
		// .cast, so the REST/broker path writes a transcript too — otherwise a
		// supervisor could watch a denied attempt live and later find no
		// recording of it.
		s.recordWinRMRefusal(ctx, target, cred, actor, command, "pamv1: command blocked by policy")
		return winrm.Result{}, err
	}
	// PAM_REQUIRE_RECORDING covers this path too now. The check must come BEFORE
	// the command runs: the transcript is written from the result, so refusing
	// afterwards would report a failure the command had already caused on the
	// target. This was one of two paths the flag never reached, despite being a
	// way to run a privileged command on a machine.
	if s.recordingRequired(s.recordingDir) {
		s.auditAs(ctx, actor, "winrm.refused", "target:"+target.Name+" reason:recording-required") //nolint:errcheck // refusal already returned below
		s.live.Publish(sid, []byte("pamv1: recording is required but unavailable; command refused\r\n"))
		return winrm.Result{}, errRecordingRequired
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:winrm", cred.ID, target.Name))
		s.live.Publish(sid, []byte("pamv1: credential decryption failed; command refused\r\n"))
		return winrm.Result{}, errDecryptFailed
	}
	res, err := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, command)
	if err != nil {
		s.log.Error("winrm run failed", "target", target.Name, "err", err)
		s.audit(ctx, "winrm.error", fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		s.live.Publish(sid, []byte(fmt.Sprintf("pamv1: winrm error: %v\r\n", err)))
		s.recordWinRMRefusal(ctx, target, cred, actor, command, fmt.Sprintf("pamv1: winrm error: %v", err))
		return winrm.Result{}, err
	}
	file, sum := s.recordWinRM(target, cred.Username, actor, command, res)
	// The command has already run on the target, so this audit cannot refuse it —
	// but it MUST be durable, and a failure here is a genuine integrity event
	// rather than a log line to shrug at. Surfacing the error makes the caller
	// return 503 with the result withheld, so an operator learns the record is
	// missing instead of receiving output that was never accounted for.
	if err := s.auditAs(ctx, actor, "winrm.run",
		fmt.Sprintf("target:%s cred_user:%s exit:%d file:%s sha256:%s", target.Name, cred.Username, res.ExitCode, file, sum)); err != nil {
		s.live.Publish(sid, []byte("pamv1: audit log unavailable; output withheld\r\n"))
		return winrm.Result{}, errAuditUnavailable
	}
	// Output reaches live watchers only AFTER the durable audit above: the
	// withheld-result contract would be defeated by a stream that had already
	// delivered what the 503 withholds. Payloads are built only when someone is
	// actually watching — a run's output is unbounded and a watcher is the
	// exception, not the rule.
	if s.live.HasSubscribers(sid) {
		if res.Stdout != "" {
			s.live.Publish(sid, []byte(res.Stdout))
		}
		if res.Stderr != "" {
			s.live.Publish(sid, []byte(res.Stderr))
		}
	}
	return res, nil
}

// recordWinRMRefusal writes a transcript for a run that was refused or failed —
// the attempt is evidence even when nothing executed — and registers the
// artifact's hash in the audit trail as session.record, the action playback
// verification already checks. Best-effort, like recordWinRM itself: the
// refusal was already audited by the caller, so a failure here costs the
// transcript, not the record of the refusal.
func (s *Server) recordWinRMRefusal(ctx context.Context, target *store.Target, cred *store.Credential, actor, command, notice string) {
	file, sum := s.recordWinRM(target, cred.Username, actor, command, winrm.Result{Stderr: notice, ExitCode: 1})
	if file == "" {
		return
	}
	if err := s.auditAs(ctx, actor, "session.record",
		fmt.Sprintf("target:%s cred_user:%s file:%s sha256:%s", target.Name, cred.Username, file, sum)); err != nil {
		s.log.Error("refusal transcript not registered in the audit trail", "file", file, "err", err)
	}
}

// recordWinRM writes a transcript of the command and its output, returning the
// file path and its SHA-256 (tamper evidence in the audit trail). Best-effort:
// a recording failure is logged but does not fail the request.
func (s *Server) recordWinRM(target *store.Target, credUser, actor, command string, res winrm.Result) (string, string) {
	if s.recordingDir == "" {
		return "", ""
	}
	if err := os.MkdirAll(s.recordingDir, 0o700); err != nil {
		s.log.Error("winrm recording dir", "err", err)
		return "", ""
	}
	ts := time.Now()
	name := recording.Title(s.opaqueRecNames, ts, sanitizeName(target.Name), sanitizeName(actor)) + ".winrm.log"
	path := filepath.Join(s.recordingDir, name)
	transcript := fmt.Sprintf(
		"# pamv1 WinRM session\n# target: %s (%s:%d)\n# user: %s\n# actor: %s\n# time: %s\n\n$ %s\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n--- exit: %d ---\n",
		target.Name, target.Host, target.Port, credUser, actor, ts.Format(time.RFC3339),
		command, res.Stdout, res.Stderr, res.ExitCode)
	// Seal the transcript at rest when configured, and hash the bytes that land ON
	// DISK — not the plaintext. Playback re-hashes the stored file to check it
	// against the audit trail, so the two must describe the same bytes or every
	// sealed transcript would replay as "never audited".
	var stored bytes.Buffer
	if s.recKey != nil {
		sealer, serr := recording.NewSealer(context.Background(), &stored, s.recKey, name)
		if serr != nil {
			s.log.Error("winrm recording seal", "err", serr)
			return "", ""
		}
		if _, werr := sealer.Write([]byte(transcript)); werr != nil {
			s.log.Error("winrm recording seal", "err", werr)
			return "", ""
		}
		_ = sealer.Close()
	} else {
		stored.WriteString(transcript)
	}
	if err := os.WriteFile(path, stored.Bytes(), 0o600); err != nil {
		s.log.Error("winrm recording write", "err", err)
		return "", ""
	}
	return path, hashHex(stored.String())
}

// sanitizeName reduces a string to filename-safe characters (alphanumerics and
// -_.@), replacing anything else with a dash.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '@':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// --- login sessions (Active Directory / password identities) ---

// sessionTTL is how long a login session token is valid.
