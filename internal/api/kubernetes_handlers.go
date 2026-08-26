package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/k8s"
	"github.com/morandeirachema/pamv1/internal/store"
)

// kubectlIn is the body of POST /api/targets/{id}/kubectl: one discrete,
// kubectl-shaped operation. It is deliberately a vocabulary rather than a
// passthrough — an operator cannot describe an operation PAMv1 would not be
// able to name in a command string, guard with a policy, record in a
// transcript and put on the audit trail.
type kubectlIn struct {
	Verb       string `json:"verb"`        // get | logs | apply | delete
	APIVersion string `json:"api_version"` // "v1" (default) or "group/version"
	Resource   string `json:"resource"`    // lowercase plural; implied "pods" for logs
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Selector   string `json:"selector"`   // get only
	Container  string `json:"container"`  // logs only
	TailLines  int    `json:"tail_lines"` // logs only (default 200)
	Manifest   string `json:"manifest"`   // apply only, YAML or JSON, verbatim
}

// runKubectl brokers one Kubernetes operation against a `kubernetes` target.
//
// It is the WinRM REST endpoint's twin, deliberately: both are ONE discrete
// privileged operation on a machine PAMv1 holds the credential for, so both run
// the same gate sequence in the same order — protocol allowed by policy,
// per-target grants (`authorizedForTarget`), the four-eyes approval gate
// (`enforceApproval`), the vendor contract gate, then the concurrent-session
// cap and live-session registration (`superviseSession`) — before anything is
// decrypted. The plan for this phase assumed a Kubernetes handler would have to
// hand-roll that sequence the way `viewerTunnel` does; it does not, because
// viewerTunnel only hand-rolls it to resolve a principal from a WebSocket URL
// token. Riding the ordinary `authz` middleware instead means the IP allowlist
// (Phase 118), device/posture checks (Phase 133) and break-glass auditing cover
// this route for free, and there is one fewer copy of the gate order to drift.
func (s *Server) runKubectl(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in kubectlIn
	if !readJSON(w, r, &in) {
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "kubernetes" {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not kubernetes")
		return
	}
	if !s.protocolAllowed("kubernetes") {
		writeError(w, http.StatusForbidden, "kubernetes is not allowed by policy")
		return
	}
	req := k8s.Request{
		Verb: in.Verb, APIVersion: in.APIVersion, Resource: in.Resource, Name: in.Name,
		Namespace: in.Namespace, Selector: in.Selector, Container: in.Container,
		TailLines: in.TailLines, Manifest: []byte(in.Manifest),
	}
	// Normalize + validate BEFORE any authorization work: a request that could
	// never be sent should be refused as malformed rather than audited as a
	// denied access attempt, and the command string every gate below records
	// must describe the request as it will actually be sent.
	req.Normalize()
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	command := req.Command()
	if ok, err := s.authorizedForTarget(r.Context(), target); err != nil {
		storeError(w, err)
		return
	} else if !ok {
		s.audit(r.Context(), "k8s.denied", "target:"+target.Name+" reason:target-policy")
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
	cred := kubeCredential(creds)
	if cred == nil {
		writeError(w, http.StatusUnprocessableEntity, "target has no k8s_token credential")
		return
	}
	// The vendor gate needs the login account (here: the service account the
	// token belongs to) to enforce the contract's per-account scope.
	if !s.vendorGate(w, r, target, cred.Username, "k8s.denied") {
		return
	}

	actor := actorFrom(r.Context())
	ctx, release, sid, err := s.superviseSession(r.Context(), actor, target.Name, "kubernetes", r.RemoteAddr)
	if errors.Is(err, errSessionLimit) {
		writeError(w, http.StatusTooManyRequests, "session limit reached")
		return
	}
	defer release()

	res, err := s.execKubectl(ctx, target, cred, req, command, actor, sid)
	switch {
	case errors.Is(err, errCommandBlocked):
		writeError(w, http.StatusForbidden, "command blocked by policy")
		return
	case errors.Is(err, errDecryptFailed):
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	case errors.Is(err, errRecordingRequired):
		writeError(w, http.StatusServiceUnavailable, "recording is required but no recording directory is configured")
		return
	case errors.Is(err, errAuditUnavailable):
		// The operation already ran against the cluster; the record of it did
		// not. Withhold the result rather than hand back something the system
		// of record cannot account for — the same contract as WinRM.
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable; result withheld")
		return
	case err != nil && ctx.Err() != nil:
		s.audit(r.Context(), "session.killed", "target:"+target.Name+" protocol:kubernetes")
		writeError(w, http.StatusServiceUnavailable, "session terminated")
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, "kubernetes request failed")
		return
	}
	// A non-2xx from the cluster is an ANSWER, not a PAMv1 failure: the
	// cluster's own RBAC refusing this service account (403), or the object not
	// existing (404), is exactly what the operator asked to find out. It comes
	// back in the envelope with its status, the way the WinRM endpoint returns a
	// non-zero exit code with 200.
	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target.Name,
		"command": command,
		"status":  res.Status,
		"path":    res.Path,
		"method":  res.Method,
		"body":    res.Body,
	})
}

// kubeCredential picks the target's Kubernetes bearer credential. A kubernetes
// target may also hold `file` credentials (a kubeconfig kept for humans, a CA
// bundle), so this selects by type rather than taking creds[0] the way the
// single-credential SSH/WinRM paths do — picking a file secret and sending it
// as a bearer token would produce a baffling 401 instead of a clear refusal.
func kubeCredential(creds []store.Credential) *store.Credential {
	for i, c := range creds {
		if c.SecretType == store.SecretTypeK8sToken {
			return &creds[i]
		}
	}
	return nil
}

// execKubectl is the chokepoint every brokered Kubernetes operation passes
// through — the twin of execWinRM, in the same order and with the same
// contract: echo to live watchers, command control, recording policy, JIT
// decrypt, run, transcript, durable audit, and only then release the output.
// The plaintext token never leaves this function.
func (s *Server) execKubectl(ctx context.Context, target *store.Target, cred *store.Credential,
	req k8s.Request, command, actor, sid string) (k8s.Result, error) {
	// A supervisor watching this session sees the operation as it is attempted,
	// the way the WinRM path echoes `winrm> ` and the PostgreSQL proxy echoes
	// `psql> ` — an output with no visible cause is exactly what live monitoring
	// must not show.
	s.live.Publish(sid, []byte("kubectl> "+command+"\r\n"))
	// Command control, before the credential is decrypted. The canonical
	// `kubectl …` string is what the deny (and, with PAM_COMMAND_ALLOW_FILE,
	// the allow) patterns match, so a site that forbids `kubectl delete` or
	// permits only `kubectl get` gets the same policy here as on every other
	// path where a discrete command is visible (Phase 38's principle).
	if err := s.guardCommand(ctx, actor, target.Name, "kubernetes", command); err != nil {
		s.live.Publish(sid, []byte("PAMv1: command blocked by policy\r\n"))
		s.recordKubectlNotice(ctx, target, cred, actor, command, "PAMv1: command blocked by policy")
		return k8s.Result{}, err
	}
	if s.recordingRequired(s.recordingDir) {
		_ = s.auditAs(ctx, actor, "k8s.refused", "target:"+target.Name+" reason:recording-required")
		s.live.Publish(sid, []byte("PAMv1: recording is required but unavailable; command refused\r\n"))
		return k8s.Result{}, errRecordingRequired
	}
	token, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:kubectl", cred.ID, target.Name))
		s.live.Publish(sid, []byte("PAMv1: credential decryption failed; command refused\r\n"))
		return k8s.Result{}, errDecryptFailed
	}
	cfg := s.k8sConfig
	cfg.Server = fmt.Sprintf("https://%s:%d", target.Host, target.Port)
	cfg.Token = token
	client, err := k8s.New(cfg)
	if err != nil {
		s.log.Error("kubernetes client", "target", target.Name, "err", err)
		s.audit(ctx, "k8s.error", fmt.Sprintf("target:%s error:%v", target.Name, err))
		s.live.Publish(sid, []byte(fmt.Sprintf("PAMv1: kubernetes error: %v\r\n", err)))
		return k8s.Result{}, err
	}
	res, err := client.Do(ctx, req)
	if err != nil {
		s.log.Error("kubernetes request failed", "target", target.Name, "err", err)
		s.audit(ctx, "k8s.error", fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		s.live.Publish(sid, []byte(fmt.Sprintf("PAMv1: kubernetes error: %v\r\n", err)))
		s.recordKubectlNotice(ctx, target, cred, actor, command, fmt.Sprintf("PAMv1: kubernetes error: %v", err))
		return k8s.Result{}, err
	}
	file, sum := s.recordExecTranscript("Kubernetes", ".k8s.log", target, cred.Username, actor, command,
		res.Body, "", fmt.Sprintf("status: %d", res.Status))
	// The operation has already reached the cluster, so this audit cannot refuse
	// it — but it MUST be durable. A failure here is an integrity event: the
	// caller turns it into a 503 with the result withheld, so an operator learns
	// the record is missing instead of receiving output nothing accounts for.
	if err := s.auditAs(ctx, actor, "k8s.run", fmt.Sprintf("target:%s cred_user:%s command:%s status:%d file:%s sha256:%s",
		target.Name, cred.Username, auditField(command, 300), res.Status, file, sum)); err != nil {
		s.live.Publish(sid, []byte("PAMv1: audit log unavailable; output withheld\r\n"))
		return k8s.Result{}, errAuditUnavailable
	}
	// Output reaches live watchers only AFTER the durable audit above, or the
	// withheld-result contract would be defeated by a stream that already
	// delivered what the 503 withholds.
	if s.live.HasSubscribers(sid) && res.Body != "" {
		s.live.Publish(sid, []byte(res.Body))
	}
	return res, nil
}

// recordKubectlNotice writes a transcript for an operation that was refused or
// failed — the attempt is evidence even when nothing reached the cluster — and
// registers its hash as session.record, the action playback verification
// checks. Best-effort: the refusal itself was already audited by the caller.
func (s *Server) recordKubectlNotice(ctx context.Context, target *store.Target, cred *store.Credential, actor, command, notice string) {
	file, sum := s.recordExecTranscript("Kubernetes", ".k8s.log", target, cred.Username, actor, command, "", notice, "status: -")
	if file == "" {
		return
	}
	if err := s.auditAs(ctx, actor, "session.record",
		fmt.Sprintf("target:%s cred_user:%s file:%s sha256:%s", target.Name, cred.Username, file, sum)); err != nil {
		s.log.Error("refusal transcript not registered in the audit trail", "file", file, "err", err)
	}
}
