package api

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// registerBrokerTools populates the broker's tool registry with the pamv1
// operations exposed to AI agents. Each tool re-checks target grants and injects
// the credential just-in-time inside Execute, returning only the result (except
// reveal_credential, the deliberate secret-returning tool, shipped default-deny).
func (s *Server) registerBrokerTools(reg *broker.Registry) {
	reg.Register(&winrmExecTool{s: s})
	reg.Register(&sshExecTool{s: s})
	reg.Register(&listTargetsTool{s: s})
	reg.Register(&listCredentialsTool{s: s})
	reg.Register(&rotateCredentialTool{s: s})
	reg.Register(&revealCredentialTool{s: s})
}

// targetByName resolves a target by its unique name.
func (s *Server) targetByName(ctx context.Context, name string) (*store.Target, error) {
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		if targets[i].Name == name {
			return &targets[i], nil
		}
	}
	return nil, fmt.Errorf("target %q not found", name)
}

// agentCanSeeTarget reports whether p may reach target at all: the target's
// direct grants unioned with its safe's membership, evaluated by the same
// auth.CanConnectTarget every operator path uses. It is the single definition of
// "this agent and this target are related", shared by the tools that ACT on a
// target and by the inventory tools that merely name one — an agent that may not
// connect to a host has no business being told the host exists.
//
// A RoleAgent identity's fixed two-capability set (read_inventory, call_tool —
// see AGENT-THREAT-MODEL.md) never includes CapUnlimitedVaultAccess, so the
// personal-safe override this fetches can structurally never fire; the call
// exists for correctness (an agent must be default-deny on a personal safe like
// anyone else), not because an agent is expected to ever use the override.
func (s *Server) agentCanSeeTarget(ctx context.Context, p *auth.Principal, target *store.Target) (bool, error) {
	grants, err := s.store.EffectiveTargetGrants(ctx, target.ID)
	if err != nil {
		return false, err
	}
	personal, err := store.EffectiveSafePersonal(ctx, s.store, target)
	if err != nil {
		return false, err
	}
	return auth.CanConnectTarget(p, grants, target.SafeID != nil, personal), nil
}

// agentVisibleTargets returns the subset of the inventory p is authorized to
// reach, in the store's order.
//
// It is the subject-indexed query (Phase 189) rather than the per-target loop it
// used to be. The loop was two store reads PER TARGET on a listing an agent
// makes on every run, and it was written that way because no subject-indexed
// query existed — grants are stored target-side, so "everything this subject may
// reach" could only be answered by asking each target in turn. auth.ReachableTargets
// asks it directly in four reads regardless of estate size, and reproduces
// CanConnectTarget target for target (auth.TestReachMatchesCanConnect), so the
// thing the old comment was right to fear — a second, drifting definition of a
// grant — is pinned by a test rather than avoided by doing the slow thing.
//
// A read failure still aborts the whole listing rather than dropping the target
// it failed on: a partial inventory that looks complete is worse than an error.
func (s *Server) agentVisibleTargets(ctx context.Context, p *auth.Principal) ([]store.Target, error) {
	reaches, err := auth.ReachableTargets(ctx, s.store, p)
	if err != nil {
		return nil, err
	}
	visible := make([]store.Target, 0, len(reaches))
	for _, rc := range reaches {
		visible = append(visible, rc.Target)
	}
	return visible, nil
}

// authorizeAgentTarget resolves a named target and enforces, in one place, the
// target-scoped gates an agent tool must pass before touching it: an optional
// expected protocol, the protocol allowlist, the agent's target grants, and the
// four-eyes approval gate (skipped only when the call was itself human-approved).
// It centralizes the checks winrm_exec and ssh_exec share. One gate cannot live
// here: the vendor-contract gate is scoped to the login *account*, so each tool
// applies vendorGateAgent as soon as it has resolved the credential.
func (s *Server) authorizeAgentTarget(ctx context.Context, p *auth.Principal, name, wantProto string) (*store.Target, error) {
	target, err := s.targetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if wantProto != "" && target.Protocol != wantProto {
		return nil, fmt.Errorf("target %q is not a %s target", name, wantProto)
	}
	if !s.protocolAllowed(target.Protocol) {
		return nil, fmt.Errorf("%s is not allowed by policy", target.Protocol)
	}
	allowed, err := s.agentCanSeeTarget(ctx, p, target)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("agent not authorized for target %q", name)
	}
	if !broker.Approved(ctx) {
		if ok, err := s.enforceApproval(ctx, target); err != nil {
			return nil, err
		} else if !ok {
			return nil, fmt.Errorf("target %q requires an approved access request", name)
		}
	}
	return target, nil
}

// firstCredential returns a target's first credential, or an error if it has none.
func (s *Server) firstCredential(ctx context.Context, target *store.Target) (*store.Credential, error) {
	creds, err := s.store.ListCredentials(ctx, target.ID, 0, 0)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("target %q has no credential", target.Name)
	}
	return &creds[0], nil
}

// authorizeAgentCredential resolves a credential by id and applies the SAME
// gates the connect tools apply — the target grant, then (unless the call
// already carries an approval) the four-eyes/maintenance-window requirement,
// and finally the vendor-contract gate on the credential's account.
//
// The approval half used to be missing here, which meant the least-trusted actor
// in the system had the weakest gate: with `require_approval` set on a target, a
// human holding `reveal_secret` needs an approved access request, while an agent
// permitted `reveal_credential` by broker policy received the plaintext at any
// hour and outside every window. `rotate_credential` could likewise change a
// production password ungated. `reveal_credential` ships default-deny, which
// limited the blast radius, but the omission was silent the moment an operator
// enabled it.
func (s *Server) authorizeAgentCredential(ctx context.Context, p *auth.Principal, credID int64) (*store.Credential, *store.Target, error) {
	cred, err := s.store.GetCredential(ctx, credID)
	if err != nil {
		return nil, nil, err
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		return nil, nil, err
	}
	allowed, err := s.agentCanSeeTarget(ctx, p, target)
	if err != nil {
		return nil, nil, err
	}
	if !allowed {
		return nil, nil, fmt.Errorf("agent not authorized for target %q", target.Name)
	}
	if !broker.Approved(ctx) {
		if ok, err := s.enforceApproval(ctx, target); err != nil {
			return nil, nil, err
		} else if !ok {
			return nil, nil, fmt.Errorf("target %q requires an approved access request", target.Name)
		}
	}
	if err := s.vendorGateAgent(ctx, p, target, cred.Username); err != nil {
		return nil, nil, err
	}
	return cred, target, nil
}

// vendorGateAgent enforces the vendor-contract gate (Phase 29) on an agent
// tool's access to a target account, exactly as every operator path enforces
// it: a vendor identity reaches a target account only while an approved,
// in-window contract grant covers that account. Non-vendor principals pass
// untouched. The gate needs the login account, so it runs after the tool has
// resolved the credential — always before any secret exists. A refusal is
// audited under the same access.denied/vendor-contract vocabulary the proxies
// and the REST paths use, so SIEM export and risk analytics see broker
// refusals like every other kind, on top of the broker's own chained record
// of the failed call.
func (s *Server) vendorGateAgent(ctx context.Context, p *auth.Principal, target *store.Target, account string) error {
	isVendor, allowed, err := s.store.VendorSessionAllowed(ctx, p.Name, target.Name, account, time.Now())
	if err != nil {
		return err
	}
	if isVendor && !allowed {
		s.auditAs(ctx, p.Name, "access.denied", "target:"+target.Name+" reason:vendor-contract")
		return fmt.Errorf("vendor access requires an approved, in-window contract grant for this account")
	}
	return nil
}

// argInt64 reads a numeric argument (JSON numbers decode to float64).
func argInt64(args broker.Args, key string) (int64, bool) {
	switch v := args[key].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

// winrmExecTool runs a command on a Windows target over WinRM using the target's
// vaulted credential (injected just-in-time), returning only the command output.
type winrmExecTool struct{ s *Server }

// Name is the tool's identifier used in policy rules and tool calls.
func (t *winrmExecTool) Name() string { return "winrm_exec" }

// Description is shown to agents in MCP tools/list.
func (t *winrmExecTool) Description() string {
	return "Run a command on a Windows target over WinRM; returns exit_code, stdout, stderr."
}

// InputSchema declares the tool's arguments.
func (t *winrmExecTool) InputSchema() map[string]string {
	return map[string]string{"target": "string", "command": "string"}
}

// Capability is the role capability an agent must hold to invoke any tool.
func (t *winrmExecTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute resolves the target + credential, checks the agent's target grants,
// and runs the command with a just-in-time credential. The credential is never
// part of the returned result.
func (t *winrmExecTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	name, _ := args["target"].(string)
	command, _ := args["command"].(string)
	if name == "" || command == "" {
		return broker.Result{}, fmt.Errorf("winrm_exec requires target and command")
	}
	target, err := t.s.authorizeAgentTarget(ctx, p, name, "winrm")
	if err != nil {
		return broker.Result{}, err
	}
	cred, err := t.s.firstCredential(ctx, target)
	if err != nil {
		return broker.Result{}, err
	}
	// Vendor contract gate (Phase 29): account-scoped, so it runs once the
	// credential — and with it the login account — is known.
	if err := t.s.vendorGateAgent(ctx, p, target, cred.Username); err != nil {
		return broker.Result{}, err
	}
	// An agent's execution is a supervised session too: capped, listed and killable
	// exactly like an operator's (Phase 40).
	sctx, release, sid, err := t.s.superviseSession(ctx, p.Name, target.Name, "winrm", "broker")
	if err != nil {
		return broker.Result{}, err
	}
	defer release()
	res, err := t.s.execWinRM(sctx, target, cred, command, p.Name, sid)
	if err != nil {
		return broker.Result{}, err
	}
	return broker.Result{Data: map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
	}}, nil
}

// sshExecTool runs a one-shot command on a Linux/SSH target using the target's
// vaulted credential (injected just-in-time), returning only the output. It is a
// non-interactive exec (no PTY/shell); interactive sessions still go through the
// recording proxy.
type sshExecTool struct{ s *Server }

// Name is the tool's identifier used in policy rules and tool calls.
func (t *sshExecTool) Name() string { return "ssh_exec" }

// Description is shown to agents in MCP tools/list.
func (t *sshExecTool) Description() string {
	return "Run a one-shot command on an SSH target; returns exit_code and output."
}

// InputSchema declares the tool's arguments.
func (t *sshExecTool) InputSchema() map[string]string {
	return map[string]string{"target": "string", "command": "string"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *sshExecTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute authorizes the target, decrypts the credential just-in-time, and runs
// the command over a one-shot SSH connection. The credential never leaves.
func (t *sshExecTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	name, _ := args["target"].(string)
	command, _ := args["command"].(string)
	if name == "" || command == "" {
		return broker.Result{}, fmt.Errorf("ssh_exec requires target and command")
	}
	target, err := t.s.authorizeAgentTarget(ctx, p, name, "ssh")
	if err != nil {
		return broker.Result{}, err
	}
	// Command control applies to an agent exactly as it does to an operator's
	// `ssh target "cmd"` on the session proxy — same policy, same audit event.
	if err := t.s.guardCommand(ctx, p.Name, target.Name, "ssh_exec", command); err != nil {
		return broker.Result{}, err
	}
	cred, err := t.s.firstCredential(ctx, target)
	if err != nil {
		return broker.Result{}, err
	}
	// Vendor contract gate (Phase 29): account-scoped, so it runs once the
	// credential — and with it the login account — is known.
	if err := t.s.vendorGateAgent(ctx, p, target, cred.Username); err != nil {
		return broker.Result{}, err
	}
	if cred.IsZSP() {
		// Zero Standing Privilege credentials have no stored secret; the ephemeral
		// certificate path is the interactive proxy, not this one-shot exec.
		return broker.Result{}, fmt.Errorf("ssh_exec does not support zero-standing-privilege (ssh_ca) credentials")
	}
	// Supervise BEFORE the just-in-time decrypt, so a run refused by the
	// concurrent-session cap never causes a secret to exist (Phase 40). The
	// command guard stays ABOVE the supervision on purpose: a blocked command
	// never registers a session, so it cannot consume a session slot.
	sctx, release, sid, err := t.s.superviseSession(ctx, p.Name, target.Name, "ssh_exec", "broker")
	if err != nil {
		return broker.Result{}, err
	}
	defer release()
	// Live monitoring: an agent's ssh_exec is watchable exactly like its
	// winrm_exec — a registered session a supervisor can open and see nothing on
	// is worse than no session at all. One-shot exec output never echoes its
	// cause, so the command is echoed first, the way execWinRM does.
	t.s.live.Publish(sid, []byte("ssh_exec> "+command+"\r\n"))
	secret, err := t.s.vault.Decrypt(sctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.s.live.Publish(sid, []byte("pamv1: credential decryption failed; command refused\r\n"))
		return broker.Result{}, fmt.Errorf("credential decrypt failed")
	}
	res, err := t.s.sshConnector.Exec(sctx, *target, cred.Username, secret, command)
	if err != nil {
		t.s.live.Publish(sid, []byte(fmt.Sprintf("pamv1: ssh error: %v\r\n", err)))
		return broker.Result{}, err
	}
	// Durable audit BEFORE the agent (or a live watcher) receives the output —
	// the same withheld-result contract as execWinRM: nobody acts on output the
	// system of record never accounted for.
	detail := fmt.Sprintf("target:%s user:%s exit:%d", target.Name, cred.Username, res.ExitCode)
	if res.Truncated {
		detail += " output_truncated:true"
	}
	if err := t.s.auditAs(ctx, p.Name, "ssh.exec", detail); err != nil {
		t.s.live.Publish(sid, []byte("pamv1: audit log unavailable; output withheld\r\n"))
		return broker.Result{}, errAuditUnavailable
	}
	if res.Output != "" && t.s.live.HasSubscribers(sid) {
		t.s.live.Publish(sid, []byte(res.Output))
	}
	// Durable transcript, the same one every other brokered-command path writes
	// (Phase 165). Until now `ssh_exec` was the only one without: WinRM has had
	// `.winrm.log` since Phase 13, Kubernetes got `.k8s.log` in 155, the
	// post-session reconstruction `.forensics.log` in 157 — and a human's SSH
	// session has been recorded as an asciicast since Phase 2. So the single path
	// where an AI agent runs a command on a Linux host was the one place output
	// existed only in the agent's own context.
	//
	// It also carries the FULL output, which is what makes the result cap
	// acceptable: the agent's copy may be a bounded slice, but nothing is lost.
	// Best-effort, like the WinRM twin — the run itself was already audited above.
	if file, sum := t.s.recordExecTranscript("SSH", ".ssh.log", target, cred.Username, p.Name, command,
		res.Output, "", fmt.Sprintf("exit: %d", res.ExitCode)); file != "" {
		if err := t.s.auditAs(ctx, p.Name, "session.record",
			fmt.Sprintf("target:%s cred_user:%s file:%s sha256:%s", target.Name, cred.Username, file, sum)); err != nil {
			t.s.log.Error("ssh_exec transcript not registered in the audit trail", "file", file, "err", err)
		}
	}
	data := map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"output":    res.Output,
	}
	// Structural, not just the marker embedded in the text: the marker travels
	// inside output the REMOTE HOST controls, so an agent matching on it could be
	// fooled by a target that prints the same words. A field pamv1 sets cannot be.
	if res.Truncated {
		data["truncated"] = true
	}
	return broker.Result{Data: data}, nil
}

// listTargetsTool returns target inventory metadata (never secrets).
type listTargetsTool struct{ s *Server }

// Name is the tool's identifier.
func (t *listTargetsTool) Name() string { return "list_targets" }

// Description is shown to agents in MCP tools/list.
func (t *listTargetsTool) Description() string {
	return "List targets (metadata only: id, name, host, os_type, protocol)."
}

// InputSchema declares the tool's arguments (none).
func (t *listTargetsTool) InputSchema() map[string]string { return map[string]string{} }

// Capability is the capability an agent must hold to invoke any tool.
func (t *listTargetsTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute returns target metadata; credential material is never included.
//
// Scoped to the agent's own grants (agentVisibleTargets). It listed the WHOLE
// estate until Phase 169 — the principal was literally discarded — so an agent
// with no grant at all still learned every hostname, OS and protocol pamv1
// knows about, which is reconnaissance handed to the least-trusted actor in the
// system and the one tool in this file that ignored the grants every sibling
// enforces. Ungated targets (no grants, no safe) stay visible to everyone, as
// they are everywhere else: this narrows an agent's view to what it may reach,
// it does not invent a second authorization model.
func (t *listTargetsTool) Execute(ctx context.Context, p *auth.Principal, _ broker.Args) (broker.Result, error) {
	targets, err := t.s.agentVisibleTargets(ctx, p)
	if err != nil {
		return broker.Result{}, err
	}
	list := make([]map[string]any, 0, len(targets))
	for _, tg := range targets {
		list = append(list, map[string]any{"id": tg.ID, "name": tg.Name, "host": tg.Host, "os_type": tg.OSType, "protocol": tg.Protocol})
	}
	return broker.Result{Data: map[string]any{"targets": list}}, nil
}

// listCredentialsTool returns credential metadata (never the secret; SecretEnc is
// json:"-" and is not read here).
type listCredentialsTool struct{ s *Server }

// Name is the tool's identifier.
func (t *listCredentialsTool) Name() string { return "list_credentials" }

// Description is shown to agents in MCP tools/list.
func (t *listCredentialsTool) Description() string {
	return "List credential metadata (id, target_id, username, secret_type); never the secret."
}

// InputSchema declares the tool's arguments (optional target name filter).
// InputSchema declares `target` as OPTIONAL — the "?" is load-bearing here, and
// this is the tool the Phase 163 marker exists for. Omitting the filter lists
// EVERY credential's metadata, so a policy rule that block-lists a few targets
// used to be bypassable by simply not sending the argument. The marker keeps the
// unfiltered form callable (it is a legitimate inventory read) while making it
// something an operator can name and refuse with `target: { present: true }`.
func (t *listCredentialsTool) InputSchema() map[string]string {
	return map[string]string{"target": "string?"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *listCredentialsTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute lists credential metadata for the targets the agent may reach,
// optionally filtered to one named target.
//
// Scoped like its sibling (Phase 169). A named target the agent has no grant on
// is refused with the same message every other tool uses, rather than answered
// with an empty list, because "you may not" and "there is nothing" are different
// facts and an operator debugging a policy needs to tell them apart. The
// unfiltered form — the one the Phase 163 argument-presence marker exists to let
// a rule refuse — now lists only the accounts on targets the agent is authorized
// for, so login names on the rest of the estate stop being free.
func (t *listCredentialsTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	var targetID int64
	visible := map[int64]bool{}
	if name, _ := args["target"].(string); name != "" {
		target, err := t.s.targetByName(ctx, name)
		if err != nil {
			return broker.Result{}, err
		}
		allowed, err := t.s.agentCanSeeTarget(ctx, p, target)
		if err != nil {
			return broker.Result{}, err
		}
		if !allowed {
			return broker.Result{}, fmt.Errorf("agent not authorized for target %q", name)
		}
		targetID = target.ID
		visible[target.ID] = true
	} else {
		targets, err := t.s.agentVisibleTargets(ctx, p)
		if err != nil {
			return broker.Result{}, err
		}
		for _, tg := range targets {
			visible[tg.ID] = true
		}
	}
	// This tool reports id/target_id/username/secret_type only — never a
	// secret — so the metadata-only listing is enough.
	creds, err := t.s.store.ListCredentialsMeta(ctx, targetID, 0, 0)
	if err != nil {
		return broker.Result{}, err
	}
	list := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		if !visible[c.TargetID] {
			continue
		}
		list = append(list, map[string]any{"id": c.ID, "target_id": c.TargetID, "username": c.Username, "secret_type": c.SecretType})
	}
	return broker.Result{Data: map[string]any{"credentials": list}}, nil
}

// rotateCredentialTool rotates a credential's secret. The new secret is vaulted
// and never returned to the agent.
type rotateCredentialTool struct{ s *Server }

// Name is the tool's identifier.
func (t *rotateCredentialTool) Name() string { return "rotate_credential" }

// Description is shown to agents in MCP tools/list.
func (t *rotateCredentialTool) Description() string {
	return "Rotate a credential's secret (by credential_id); returns success only, never the new secret."
}

// InputSchema declares the tool's arguments.
func (t *rotateCredentialTool) InputSchema() map[string]string {
	return map[string]string{"credential_id": "int"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *rotateCredentialTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute rotates the credential after checking the agent's target grant. The
// rotated secret stays in the vault; only a rotated-at timestamp is returned.
func (t *rotateCredentialTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	credID, ok := argInt64(args, "credential_id")
	if !ok {
		return broker.Result{}, fmt.Errorf("rotate_credential requires credential_id")
	}
	cred, target, err := t.s.authorizeAgentCredential(ctx, p, credID)
	if err != nil {
		return broker.Result{}, err
	}
	rotatedAt, err := t.s.rotateCredential(ctx, cred, target)
	if err != nil {
		return broker.Result{}, err
	}
	// A rotation is a production change; if the trail cannot record who caused it,
	// report that rather than swallow it.
	if aerr := t.s.auditAs(ctx, p.Name, "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:agent-broker", cred.ID, target.Name)); aerr != nil {
		return broker.Result{}, errAuditUnavailable
	}
	return broker.Result{Data: map[string]any{"credential_id": cred.ID, "rotated": true, "rotated_at": rotatedAt}}, nil
}

// revealCredentialTool is the deliberate secret-returning tool: it decrypts and
// returns a credential to the agent. It breaks the "agent never holds a secret"
// default, so it is shipped default-deny (no policy rule allows it unless an
// operator adds one) and additionally honors PAM_REVEAL_DISABLED. The plaintext
// is returned only in the agent response, never written to any audit record.
type revealCredentialTool struct{ s *Server }

// Name is the tool's identifier.
func (t *revealCredentialTool) Name() string { return "reveal_credential" }

// Description is shown to agents in MCP tools/list.
func (t *revealCredentialTool) Description() string {
	return "Reveal a credential's secret to the agent (by credential_id). Default-deny; breaks JIT confinement."
}

// InputSchema declares the tool's arguments.
func (t *revealCredentialTool) InputSchema() map[string]string {
	return map[string]string{"credential_id": "int"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *revealCredentialTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute decrypts and returns the credential after the reveal-disabled check and
// the agent's target grant. The secret goes only to the agent response; the
// broker audit chain records the reveal action, never the plaintext.
func (t *revealCredentialTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	if t.s.rt().revealDisabled {
		return broker.Result{}, fmt.Errorf("credential reveal is disabled by policy")
	}
	credID, ok := argInt64(args, "credential_id")
	if !ok {
		return broker.Result{}, fmt.Errorf("reveal_credential requires credential_id")
	}
	cred, target, err := t.s.authorizeAgentCredential(ctx, p, credID)
	if err != nil {
		return broker.Result{}, err
	}
	if cred.IsZSP() {
		return broker.Result{}, fmt.Errorf("this credential has no stored secret (zero standing privilege)")
	}
	secret, err := t.s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return broker.Result{}, fmt.Errorf("credential decrypt failed")
	}
	// Fail closed, as sshExecTool already does and as the human reveal path does
	// with mustAudit. The broker chain records the tool call itself, but the
	// PRIMARY trail's credential.reveal is the row an auditor queries, the SIEM
	// forwards and the risk engine scores — losing it silently is not acceptable
	// for a path that returns a plaintext credential.
	if aerr := t.s.auditAs(ctx, p.Name, "credential.reveal", fmt.Sprintf("credential:%d target:%s user:%s via:agent-broker", cred.ID, target.Name, cred.Username)); aerr != nil {
		return broker.Result{}, errAuditUnavailable
	}
	return broker.Result{Sensitive: true, Data: map[string]any{
		"credential_id": cred.ID,
		"target":        target.Name,
		"username":      cred.Username,
		"secret_type":   cred.SecretType,
		"secret":        secret,
	}}, nil
}
