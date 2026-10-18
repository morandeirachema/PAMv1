package api

import (
	"net/http"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/inventorycsv"
	"github.com/morandeirachema/pamv1/internal/web"
)

// routes registers every HTTP route on the server's mux.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)         // liveness
	s.mux.HandleFunc("GET /readyz", s.readyz)          // readiness (store reachable)
	s.mux.HandleFunc("GET /metrics", s.metricsHandler) // Prometheus exposition
	s.mux.HandleFunc("GET /{$}", web.Index)
	s.mux.HandleFunc("GET /static/guacamole-common.min.js", web.GuacamoleJS) // vendored RDP viewer client
	s.mux.HandleFunc("GET /static/xterm.js", web.XtermJS)                    // vendored terminal renderer (Phase 254)
	s.mux.HandleFunc("GET /share.html", web.Share)                           // Phase 116 guest viewer, no PAMv1 login
	s.mux.HandleFunc("GET /approve.html", web.Approve)                       // Phase 137 magic-link approval, no PAMv1 login

	// Authentication endpoints are rate-limited per client IP.
	s.mux.Handle("POST /api/login", s.rateLimit(http.HandlerFunc(s.login)))     // public: this IS authentication
	s.mux.Handle("GET /api/banner", s.rateLimit(http.HandlerFunc(s.getBanner))) // public: the login banner is shown BEFORE authentication (Phase 276)
	s.mux.Handle("POST /api/logout", s.authenticated(s.logout))
	s.mux.Handle("GET /api/auth/oidc/start", s.rateLimit(http.HandlerFunc(s.oidcStart)))
	s.mux.Handle("GET /api/auth/oidc/callback", s.rateLimit(http.HandlerFunc(s.oidcCallback)))
	// SAML 2.0 SP (Phase 151): start = AuthnRequest redirect, acs = the IdP's
	// HTTP-POST Response, metadata = the SP descriptor an IdP admin imports.
	s.mux.Handle("GET /api/auth/saml/start", s.rateLimit(http.HandlerFunc(s.samlStart)))
	s.mux.Handle("POST /api/auth/saml/acs", s.rateLimit(http.HandlerFunc(s.samlACS)))
	s.mux.Handle("GET /api/auth/saml/metadata", s.rateLimit(http.HandlerFunc(s.samlMetadata)))
	s.mux.Handle("POST /api/breakglass/unseal", s.rateLimit(http.HandlerFunc(s.breakGlassUnseal)))

	// Identity of the caller (drives the portal's role-aware menu).
	s.mux.Handle("GET /api/me", s.authenticated(s.me))

	// Self-service MFA (any authenticated identity manages its own second factor).
	s.mux.Handle("GET /api/mfa", s.authenticated(s.mfaStatus))
	s.mux.Handle("POST /api/mfa/enroll", s.authenticated(s.mfaEnroll))
	s.mux.Handle("POST /api/mfa/verify", s.rateLimit(s.authenticated(s.mfaVerify)))
	s.mux.Handle("POST /api/mfa/recovery-codes", s.authenticated(s.mfaRecoveryCodes))
	s.mux.Handle("DELETE /api/mfa", s.authenticated(s.mfaDisable))

	// WebAuthn (Phase 124): self-service registration of a new authenticator
	// follows the same "any authenticated identity manages its own second
	// factor" shape as /api/mfa/* above. The two login-ceremony routes are
	// different in kind — unauthenticated-by-username, authenticated-by-
	// MFAPending-token instead — so they get mfaPendingOnly, not authenticated,
	// and sit with /api/login rather than with self-service MFA.
	s.mux.Handle("POST /api/webauthn/register/begin", s.authenticated(s.webauthnRegisterBegin))
	s.mux.Handle("POST /api/webauthn/register/finish", s.authenticated(s.webauthnRegisterFinish))
	s.mux.Handle("GET /api/webauthn/credentials", s.authenticated(s.webauthnListCredentials))
	s.mux.Handle("DELETE /api/webauthn/credentials/{id}", s.authenticated(s.webauthnDeleteCredential))
	s.mux.Handle("POST /api/webauthn/login/begin", s.rateLimit(s.mfaPendingOnly(s.webauthnLoginBegin)))
	s.mux.Handle("POST /api/webauthn/login/finish", s.rateLimit(s.mfaPendingOnly(s.webauthnLoginFinish)))

	// Per-session MFA (Phase 244): a single-use ticket bound to ONE target,
	// minted only after a fresh second factor — a one-time code, or a WebAuthn
	// assertion. Rate-limited like login: each code is a guess.
	s.mux.Handle("POST /api/session-mfa", s.rateLimit(s.authenticated(s.mintSessionMFATicket)))
	s.mux.Handle("POST /api/session-mfa/webauthn/begin", s.rateLimit(s.authenticated(s.sessionMFAWebAuthnBegin)))
	s.mux.Handle("POST /api/session-mfa/webauthn/finish", s.rateLimit(s.authenticated(s.sessionMFAWebAuthnFinish)))

	s.mux.Handle("POST /api/targets", s.authz(auth.CapManageTargets, s.createTarget))
	s.mux.Handle("GET /api/targets", s.authz(auth.CapReadInventory, pagedList(s.store.ListTargets)))
	s.mux.Handle("GET /api/targets/{id}", s.authz(auth.CapReadInventory, s.getTarget))
	s.mux.Handle("PUT /api/targets/{id}", s.authz(auth.CapManageTargets, s.updateTarget))
	s.mux.Handle("DELETE /api/targets/{id}", s.authz(auth.CapManageTargets, s.deleteTarget))

	// Label rules (Phase 250): the third authorization path, and the only one
	// that can DENY. Writing one is a statement about the estate, so it takes
	// the capability that labels the targets; reading the policy is inventory,
	// so an auditor can review what denies whom without being able to change it.
	s.mux.Handle("POST /api/label-rules", s.authz(auth.CapManageTargets, s.createLabelRule))
	s.mux.Handle("GET /api/label-rules", s.authz(auth.CapReadInventory, listAll(s.store.ListLabelRules)))
	s.mux.Handle("DELETE /api/label-rules/{id}", s.authz(auth.CapManageTargets, s.deleteLabelRule))
	s.mux.Handle("POST /api/targets/{id}/grants", s.authz(auth.CapManageTargets, s.createTargetGrant))
	s.mux.Handle("GET /api/targets/{id}/grants", s.authz(auth.CapManageTargets, listByParent(s.store.ListTargetGrants)))
	s.mux.Handle("DELETE /api/targets/{id}/grants/{gid}", s.authz(auth.CapManageTargets, s.deleteTargetGrant))
	s.mux.Handle("PUT /api/targets/{id}/safe", s.authz(auth.CapManageTargets, s.setTargetSafe))
	// Authenticated post-login account discovery (Phase 128): enumerate local/
	// service accounts over the target's own vaulted credential and flag ones
	// with no matching PAMv1 credential. A management action, not a connect
	// action — CapManageTargets, not CapConnect.
	s.mux.Handle("POST /api/targets/{id}/discover-accounts", s.authz(auth.CapManageTargets, s.discoverAccounts))

	// Safes (Phase 17): named containers grouping targets with delegated members.
	// Membership management is open to inventory readers so a delegated can_manage
	// member can grant access to their own safe (canManageSafe enforces it).
	s.mux.Handle("POST /api/safes", s.authz(auth.CapManageTargets, s.createSafe))
	s.mux.Handle("GET /api/safes", s.authz(auth.CapReadInventory, pagedList(s.store.ListSafes)))
	s.mux.Handle("PUT /api/safes/{id}", s.authz(auth.CapManageTargets, s.updateSafe))
	s.mux.Handle("DELETE /api/safes/{id}", s.authz(auth.CapManageTargets, s.deleteSafe))
	s.mux.Handle("GET /api/safes/{id}/members", s.authz(auth.CapReadInventory, listByParent(s.store.ListSafeMembers)))
	s.mux.Handle("POST /api/safes/{id}/members", s.authz(auth.CapReadInventory, s.addSafeMember))
	s.mux.Handle("DELETE /api/safes/{id}/members/{mid}", s.authz(auth.CapReadInventory, s.deleteSafeMember))

	s.mux.Handle("POST /api/targets/{id}/winrm", s.authz(auth.CapConnect, s.runWinRM))
	// One discrete, audited Kubernetes operation against a `kubernetes` target
	// (Phase 155) — the same capability the WinRM twin needs, since both are a
	// privileged action on a machine PAMv1 holds the credential for.
	s.mux.Handle("POST /api/targets/{id}/kubectl", s.authz(auth.CapConnect, s.runKubectl))
	s.mux.Handle("POST /api/ssh-token", s.authz(auth.CapConnect, s.sshTerminalToken))                  // mint a short-lived, single-use WS token for the in-portal terminal (Phase 254)
	s.mux.HandleFunc("GET /api/targets/{id}/ssh/terminal", s.sshTerminal)                              // the terminal WebSocket; token in the query (browsers cannot set WS headers)
	s.mux.Handle("POST /api/rdp-token", s.authz(auth.CapConnect, s.rdpToken))                          // mint a short-lived WS token for the viewer
	s.mux.Handle("POST /api/vnc-token", s.authz(auth.CapConnect, s.vncToken))                          // same, for the VNC viewer
	s.mux.Handle("POST /api/extension-token", s.authz(auth.CapRevealSecret, s.extensionToken))         // mint a browser-extension autofill token (Phase 147)
	s.mux.HandleFunc("GET /api/targets/{id}/rdp", s.rdpTunnel)                                         // WebSocket; auths via query token
	s.mux.HandleFunc("GET /api/targets/{id}/vnc", s.vncTunnel)                                         // WebSocket; auths via query token
	s.mux.Handle("POST /api/sessions/{id}/view-token", s.authz(auth.CapReadAudit, s.sessionViewToken)) // mint a single-use watch token for a live RDP/VNC session (Phase 258)
	s.mux.HandleFunc("GET /api/sessions/{id}/view", s.sessionView)                                     // WebSocket: join a live RDP/VNC session read-only; token in the query

	// Zero Standing Privilege (Phase 22): publish the SSH CA public key so an
	// operator can install it in a target's TrustedUserCAKeys. 404 when ZSP is off.
	s.mux.Handle("GET /api/ca/ssh", s.authz(auth.CapReadInventory, s.sshCAPublicKey))
	// Operator-issued SSH certificates + KRL revocation (Phase 28).
	s.mux.Handle("POST /api/ca/ssh/challenge", s.authz(auth.CapConnect, s.sshCACertChallenge))
	s.mux.Handle("POST /api/ca/ssh/sign", s.authz(auth.CapConnect, s.signOperatorCert))
	s.mux.Handle("POST /api/ca/ssh/revoke", s.authz(auth.CapManageTargets, s.revokeOperatorCert))
	s.mux.Handle("GET /api/ca/ssh/krl", s.authz(auth.CapReadInventory, s.sshCAKRL))
	s.mux.Handle("GET /api/ca/ssh/certs", s.authz(auth.CapReadInventory, s.listSSHCertsHandler))

	s.mux.Handle("POST /api/credentials", s.authz(auth.CapManageCredentials, s.createCredential))
	s.mux.Handle("GET /api/credentials", s.authz(auth.CapReadInventory, s.listCredentials))
	s.mux.Handle("POST /api/credentials/{id}/reveal", s.authzExtOK(auth.CapRevealSecret, s.revealCredential)) // browser-extension tokens (Phase 147) reach only this route
	s.mux.Handle("POST /api/credentials/{id}/doublelock", s.authz(auth.CapRevealSecret, s.setDoubleLock))
	s.mux.Handle("DELETE /api/credentials/{id}/doublelock", s.authz(auth.CapRevealSecret, s.clearDoubleLock))
	s.mux.Handle("POST /api/credentials/{id}/rotate", s.authz(auth.CapManageCredentials, s.rotateCredentialHandler))
	s.mux.Handle("POST /api/credentials/{id}/reconcile", s.authz(auth.CapManageCredentials, s.reconcileCredentialHandler))
	s.mux.Handle("GET /api/reconcile", s.authz(auth.CapManageCredentials, s.reconcileAllHandler))
	s.mux.Handle("POST /api/credentials/{id}/checkout", s.authz(auth.CapRevealSecret, s.checkoutCredential))
	s.mux.Handle("POST /api/credentials/{id}/checkin", s.authz(auth.CapRevealSecret, s.checkinCredential))
	s.mux.Handle("POST /api/credentials/{id}/checkout/extend", s.authz(auth.CapRevealSecret, s.extendCheckout))
	s.mux.Handle("GET /api/checkouts", s.authz(auth.CapReadAudit, s.listCheckouts))
	s.mux.Handle("POST /api/discovery/scan", s.authz(auth.CapManageTargets, s.discoveryScan))
	s.mux.Handle("DELETE /api/credentials/{id}", s.authz(auth.CapManageCredentials, s.deleteCredential))

	// Dependent accounts (Phase 17): a credential's consumers, updated over WinRM
	// on rotation so it does not break production.
	s.mux.Handle("POST /api/credentials/{id}/dependencies", s.authz(auth.CapManageCredentials, s.createDependency))
	s.mux.Handle("GET /api/credentials/{id}/dependencies", s.authz(auth.CapReadInventory, listByParent(s.store.ListCredentialDependencies)))
	s.mux.Handle("DELETE /api/credentials/{id}/dependencies/{did}", s.authz(auth.CapManageCredentials, s.deleteDependency))

	// Access-request approval workflow (4-eyes). A connect-capable user files a
	// request; an approver (a *different* principal) approves or denies it.
	s.mux.Handle("POST /api/access-requests", s.authz(auth.CapConnect, s.createAccessRequest))
	// Listing and deciding are open to inventory readers since Phase 246, so a
	// member holding a safe's approve permission can reach them; the handlers
	// admit CapApprove or that scoped right (requireDecider) and refuse
	// everyone else exactly as the capability middleware did.
	s.mux.Handle("GET /api/access-requests", s.authz(auth.CapReadInventory, s.listAccessRequests))
	s.mux.Handle("POST /api/access-requests/{id}/approve", s.authz(auth.CapReadInventory, s.approveAccessRequest))
	s.mux.Handle("POST /api/access-requests/{id}/deny", s.authz(auth.CapReadInventory, s.denyAccessRequest))
	s.mux.Handle("POST /api/access-requests/{id}/stop-recurrence", s.authz(auth.CapApprove, s.stopAccessRequestRecurrence))
	s.mux.Handle("POST /api/access-requests/{id}/cancel", s.authz(auth.CapApprove, s.cancelAccessRequest)) // Phase 274: end an approved request, cutting its sessions

	// Magic-link approval (Phase 137): a CapApprove holder delegates one
	// decision to a named person via an emailed link, instead of that person
	// logging into PAMv1. The redeem/preview pair below is registered
	// WITHOUT the authz(...) wrapper — reached from the unauthenticated
	// approve.html guest page, the same way the session-share guest routes
	// and RDP/VNC viewer tunnels are.
	s.mux.Handle("POST /api/access-requests/{id}/invite", s.authz(auth.CapApprove, s.createApprovalInvite))
	s.mux.Handle("GET /api/access-requests/{id}/invites", s.authz(auth.CapApprove, listByParent(s.store.ListApprovalInvitesForRequest)))
	s.mux.Handle("POST /api/approval-invites/{id}/revoke", s.authz(auth.CapApprove, s.revokeApprovalInvite))
	s.mux.HandleFunc("GET /api/approval/preview/{token}", s.previewApprovalInvite)
	s.mux.HandleFunc("POST /api/approval/redeem/{token}", s.redeemApprovalInvite)

	// Slack chat-ops approval (Phase 234): the notify route needs
	// CapApprove exactly like the magic-link invite above; the
	// interactivity callback is registered WITHOUT authz(...) for the same
	// reason the redeem route above is — Slack's own request signature is
	// the authentication, checked first inside the handler.
	s.mux.Handle("POST /api/access-requests/{id}/slack-notify", s.authz(auth.CapApprove, s.notifySlackAccessRequest))
	s.mux.HandleFunc("POST /api/slack/interactivity", s.slackInteractivity)

	s.mux.Handle("GET /api/audit", s.authz(auth.CapReadAudit, s.listAudit))
	s.mux.Handle("GET /api/audit/export", s.authz(auth.CapReadAudit, s.exportAudit))
	s.mux.Handle("GET /api/audit/ocsf", s.authz(auth.CapReadAudit, s.exportOCSF))
	s.mux.Handle("GET /api/audit/verify", s.authz(auth.CapReadAudit, s.verifyAudit))
	s.mux.Handle("GET /api/audit/head", s.authz(auth.CapReadAudit, s.auditHead))
	s.mux.Handle("GET /api/compliance/nis2", s.authz(auth.CapReadAudit, s.nis2Report)) // Phase 114
	// Operational reports (Phase 277): unused users/targets and connection
	// statistics, both read back from the audit trail — review reads, so the
	// same gate as the trail itself.
	s.mux.Handle("GET /api/reports/unused", s.authz(auth.CapReadAudit, s.reportUnused))
	s.mux.Handle("GET /api/reports/connections", s.authz(auth.CapReadAudit, s.reportConnections))
	// Bulk inventory export (Phase 278): one CSV per class, each behind the
	// capability its own list route already requires.
	s.mux.Handle("GET /api/inventory/safes.csv", s.authz(auth.CapReadInventory, s.exportInventory(inventorycsv.Safes)))
	s.mux.Handle("GET /api/inventory/targets.csv", s.authz(auth.CapReadInventory, s.exportInventory(inventorycsv.Targets)))
	s.mux.Handle("GET /api/inventory/credentials.csv", s.authz(auth.CapReadInventory, s.exportInventory(inventorycsv.Credentials)))
	s.mux.Handle("GET /api/inventory/users.csv", s.authz(auth.CapManageUsers, s.exportInventory(inventorycsv.Users)))
	s.mux.Handle("GET /api/inventory/grants.csv", s.authz(auth.CapManageTargets, s.exportInventory(inventorycsv.Grants)))
	// Bulk inventory import (Phase 278): each class behind its create route's
	// capability, every row replayed through that create handler.
	s.mux.Handle("POST /api/inventory/safes.csv", s.authz(auth.CapManageTargets, s.importInventory(inventorycsv.Safes)))
	s.mux.Handle("POST /api/inventory/targets.csv", s.authz(auth.CapManageTargets, s.importInventory(inventorycsv.Targets)))
	s.mux.Handle("POST /api/inventory/credentials.csv", s.authz(auth.CapManageCredentials, s.importInventory(inventorycsv.Credentials)))
	s.mux.Handle("POST /api/inventory/users.csv", s.authz(auth.CapManageUsers, s.importInventory(inventorycsv.Users)))
	s.mux.Handle("POST /api/inventory/grants.csv", s.authz(auth.CapManageTargets, s.importInventory(inventorycsv.Grants)))
	// The subject-indexed grant query (Phase 189): every other grant route is
	// target-indexed, this one answers "what can this subject reach?". A review
	// read, so CapReadAudit — the same gate as the audit trail it complements.
	s.mux.Handle("GET /api/access/reach", s.authz(auth.CapReadAudit, s.subjectReach))

	s.mux.Handle("GET /api/sessions", s.authz(auth.CapReadAudit, s.listSessions))
	s.mux.Handle("GET /api/sessions/{id}/stream", s.authz(auth.CapReadAudit, s.streamSession))
	s.mux.Handle("POST /api/blast/analyze", s.authz(auth.CapReadAudit, s.analyzeBlast))  // Phase 31 (CIEM)
	s.mux.Handle("GET /api/sessions/stepups", s.authz(auth.CapReadAudit, s.listStepUps)) // Phase 30
	// Listing paused statements is a monitoring read (CapReadAudit, the same gate as
	// the live stream); DECIDING one releases a statement the policy flagged, which
	// is an execution-authorizing act — CapApprove, so a read-only auditor cannot
	// grant it (Phase 39).
	s.mux.Handle("POST /api/sessions/{id}/stepup", s.authz(auth.CapApprove, s.decideStepUp)) // Phase 30
	// Suspend/resume (Phase 122): a rung below kill — freeze an operator's
	// input without ending their session. Deciding is CapApprove, the same
	// authorization-decision class as deciding a step-up; reading current
	// status is CapReadAudit, the same monitoring-read gate as the live
	// stream and the step-up list.
	s.mux.Handle("GET /api/sessions/{id}/suspend", s.authz(auth.CapReadAudit, s.sessionSuspendStatus))
	s.mux.Handle("POST /api/sessions/{id}/suspend", s.authz(auth.CapApprove, s.suspendSession))
	s.mux.Handle("POST /api/sessions/{id}/resume", s.authz(auth.CapApprove, s.resumeSession))
	s.mux.Handle("DELETE /api/sessions/{id}", s.authz(auth.CapManageTargets, s.killSession))

	// Live session-sharing / "Session Invite" (Phase 116): four-eyes request →
	// approve, same shape as access-requests above. Filing a request needs
	// only CapConnect (the requester is inviting someone into a session they
	// are themselves entitled to hold); reading a session's invite roster
	// reuses CapReadAudit, the same gate the live stream itself uses (an
	// approver's CapApprove already implies CapReadAudit — see auth.go's role
	// matrix). Deciding and revoking mirror vendor-grants' split exactly:
	// approve/deny is an approval decision (CapApprove), revoke is target/session
	// administration (CapManageTargets).
	s.mux.Handle("POST /api/sessions/{id}/share", s.authz(auth.CapConnect, s.createShareInvite))
	s.mux.Handle("GET /api/sessions/{id}/share", s.authz(auth.CapReadAudit, s.listShareInvites))
	s.mux.Handle("POST /api/share-invites/{id}/approve", s.authz(auth.CapApprove, s.approveShareInvite))
	s.mux.Handle("POST /api/share-invites/{id}/deny", s.authz(auth.CapApprove, s.denyShareInvite))
	s.mux.Handle("POST /api/share-invites/{id}/revoke", s.authz(auth.CapManageTargets, s.revokeShareInvite))
	// Joined-parties roster + kick (Phase 116 console): CapReadAudit for the
	// read, matching the live stream itself; CapManageTargets for kick,
	// matching DELETE /api/sessions/{id}'s own gate — ending someone's live
	// access is session/target administration, the same class of action.
	s.mux.Handle("GET /api/sessions/{id}/share/roster", s.authz(auth.CapReadAudit, s.rosterShareInvite))
	s.mux.Handle("POST /api/sessions/{id}/share/kick", s.authz(auth.CapManageTargets, s.kickShareJoin))
	// The external/vendor guest surface is reached from the emailed link/QR's
	// own unauthenticated page (internal/web's Share handler, registered
	// below) — these three routes authenticate via their own token/guest-key
	// query values, not X-API-Key, so — like the RDP/VNC viewer's tunnel
	// routes — they are registered WITHOUT the s.authz(...) wrapper.
	s.mux.HandleFunc("POST /api/share/redeem/{token}", s.redeemShareInvite)
	s.mux.HandleFunc("GET /api/share/stream", s.streamShareGuest)
	s.mux.HandleFunc("POST /api/share/input", s.inputShareGuest)
	// Sharing a live desktop (Phase 260): an internal invitee redeems in the
	// portal with their own key, and both kinds of sharer then join over one
	// WebSocket that authenticates with the guest key in its query.
	s.mux.Handle("POST /api/share/desktop/redeem", s.authenticated(s.redeemDesktopInvite))
	s.mux.HandleFunc("GET /api/share/desktop", s.shareDesktop)

	// Session-recording playback (Phase 26): list stored recordings and serve one
	// for replay, hash-verified against the audit trail. Content search over
	// stored SSH recordings (Phase 110) is a literal route, not a path value,
	// so it takes precedence over {name} at the same segment without any
	// recording ever being named "search" (recordingNameRe would refuse it).
	s.mux.Handle("GET /api/recordings", s.authz(auth.CapReadAudit, s.listRecordings))
	s.mux.Handle("GET /api/recordings/search", s.authz(auth.CapReadAudit, s.searchRecordings))
	// Portable recording archives (Phase 283). Registered before the
	// {name} route; "archive" never matches recordingNameRe either way.
	s.mux.Handle("GET /api/recordings/archive", s.authz(auth.CapReadAudit, s.exportRecordingArchive))
	s.mux.Handle("POST /api/recordings/archive", s.authz(auth.CapManageUsers, s.importRecordingArchive))
	s.mux.Handle("POST /api/recordings/purge", s.authz(auth.CapManageUsers, s.purgeRecordingArchive))
	s.mux.Handle("GET /api/recordings/{name}", s.authz(auth.CapReadAudit, s.playRecording))

	// Privileged threat analytics (Phase 23): behavioral risk scores over the
	// audit trail. Read-only, so an auditor may review risk without changing state.
	if s.analytics != nil {
		s.mux.Handle("GET /api/analytics/risk", s.authz(auth.CapReadAudit, s.analyticsRisk))
	}

	// Application-secrets API (Phase 24, Tier-4): Conjur-style secret delivery for
	// non-agent applications, opt-in via PAM_APP_SECRETS_ENABLED. The fetch path
	// authenticates an application bearer key; the admin routes reuse human RBAC —
	// app identity CRUD needs CapManageUsers, and delegating a secret to an app
	// needs CapRevealSecret (you can only hand out a secret you could reveal).
	if s.appSecretsEnabled {
		s.mux.HandleFunc("GET /v1/app-secrets/{id}", s.appAuth(s.fetchAppSecret))
		// Addressed by the grant's stable alias rather than a row id, for
		// declarative consumers such as an External Secrets Operator SecretStore
		// whose manifest lives in git (Phase 197).
		s.mux.HandleFunc("GET /v1/app-secrets/by-alias/{alias}", s.appAuth(s.fetchAppSecretByAlias))
		s.mux.Handle("POST /v1/apps/{id}/grants/{gid}/alias", s.authz(auth.CapRevealSecret, s.setAppGrantAlias))
		s.mux.Handle("POST /v1/apps", s.authz(auth.CapManageUsers, s.createAppKey))
		s.mux.Handle("GET /v1/apps", s.authz(auth.CapManageUsers, listAll(s.store.ListAppKeys)))
		// Revoking an application stops its bearer token resolving; its secret
		// grants cascade away.
		s.mux.Handle("DELETE /v1/apps/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteAppKey, "app.revoke", "app")))
		s.mux.Handle("GET /v1/apps/{id}/grants", s.authz(auth.CapManageUsers, listByParent(s.store.ListAppSecretGrants)))
		s.mux.Handle("POST /v1/apps/{id}/grants", s.authz(auth.CapRevealSecret, s.grantAppSecret))
		s.mux.Handle("DELETE /v1/apps/{id}/grants/{gid}", s.authz(auth.CapRevealSecret, s.deleteAppSecretGrant))
	}

	// Outbound-only endpoint agents (Phase 153): target infrastructure, so
	// managed under the target-management capability; the list is inventory.
	if s.endpointAgents != nil {
		s.mux.Handle("POST /api/endpoint-agents", s.authz(auth.CapManageTargets, s.createEndpointAgent))
		s.mux.Handle("GET /api/endpoint-agents", s.authz(auth.CapReadInventory, s.listEndpointAgents))
		s.mux.Handle("DELETE /api/endpoint-agents/{id}", s.authz(auth.CapManageTargets, s.revokeEndpointAgent))
	}
	// Per-subject restriction rules (Phase 275): what a user or role may not
	// do inside a session — a policy on people, so managed with users.
	// Read by those who review policy, not by those it watches (review of
	// 274-280): a plain user who could list the notify patterns aimed at
	// them could simply avoid them.
	s.mux.Handle("GET /api/restriction-rules", s.authz(auth.CapReadAudit, s.listRestrictionRules))
	s.mux.Handle("POST /api/restriction-rules", s.authz(auth.CapManageUsers, s.createRestrictionRule))
	// Deleting a rule does not reach sessions already admitted: they keep it.
	s.mux.Handle("DELETE /api/restriction-rules/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteRestrictionRule, "restriction.delete", "rule")))
	// Per-target SSH host-key pins (Phase 272): reading one is inventory,
	// resetting one — telling the proxy to trust the next key it sees — is
	// target management and is audited.
	s.mux.Handle("GET /api/targets/{id}/host-key", s.authz(auth.CapReadInventory, s.getTargetHostKey))
	s.mux.Handle("DELETE /api/targets/{id}/host-key", s.authz(auth.CapManageTargets, s.resetTargetHostKey))
	// Session probes (Phase 266): telemetry from inside an operator's logon
	// session is audit-grade data, so reading it takes the audit capability;
	// the block rules and a kill are target infrastructure, like the agents.
	if s.probeHub != nil {
		s.mux.Handle("GET /api/probes", s.authz(auth.CapReadAudit, s.listProbes))
		s.mux.Handle("GET /api/probes/{id}", s.authz(auth.CapReadAudit, s.getProbe))
		s.mux.Handle("POST /api/probes/{id}/kill", s.authz(auth.CapManageTargets, s.killProbeProcess))
		s.mux.Handle("GET /api/sessions/{id}/probes", s.authz(auth.CapReadAudit, s.sessionProbes))
		s.mux.Handle("GET /api/probe-rules", s.authz(auth.CapReadInventory, s.listProbeRules))
		s.mux.Handle("POST /api/probe-rules", s.authz(auth.CapManageTargets, s.createProbeRule))
		s.mux.Handle("DELETE /api/probe-rules/{id}", s.authz(auth.CapManageTargets, s.deleteProbeRule))
	}
	// SCIM 2.0 provisioning API (Phase 149), opt-in via PAM_SCIM_ENABLED: an
	// IdP pushes user create/deactivate/reactivate over /scim/v2/Users,
	// authenticated by a narrowly-scoped bearer key (never a human's own
	// capability set — the same non-human shape appAuth already uses). Key
	// admin routes reuse human RBAC, matching the app-secrets pattern above.
	if s.scimEnabled {
		s.mux.Handle("POST /v1/scim-keys", s.authz(auth.CapManageUsers, s.createScimKey))
		s.mux.Handle("GET /v1/scim-keys", s.authz(auth.CapManageUsers, listAll(s.store.ListScimKeys)))
		s.mux.Handle("DELETE /v1/scim-keys/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteScimKey, "scim.key_revoke", "scim_key")))
		s.mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", s.scimAuth(s.scimServiceProviderConfig))
		s.mux.HandleFunc("GET /scim/v2/Users", s.scimAuth(s.listScimUsers))
		s.mux.HandleFunc("POST /scim/v2/Users", s.scimAuth(s.createScimUser))
		s.mux.HandleFunc("GET /scim/v2/Users/{id}", s.scimAuth(s.getScimUser))
		s.mux.HandleFunc("PUT /scim/v2/Users/{id}", s.scimAuth(s.replaceScimUser))
		s.mux.HandleFunc("PATCH /scim/v2/Users/{id}", s.scimAuth(s.patchScimUser))
		s.mux.HandleFunc("DELETE /scim/v2/Users/{id}", s.scimAuth(s.deleteScimUser))
	}

	s.mux.Handle("POST /api/users", s.authz(auth.CapManageUsers, s.createUser))
	s.mux.Handle("GET /api/users", s.authz(auth.CapManageUsers, pagedList(s.store.ListUsers)))
	s.mux.Handle("PUT /api/users/{id}", s.authz(auth.CapManageUsers, s.updateUser))
	s.mux.Handle("DELETE /api/users/{id}", s.authz(auth.CapManageUsers, s.deleteUser))
	// Identity lock and token rotation (Phase 242).
	s.mux.Handle("POST /api/users/{id}/lock", s.authz(auth.CapManageUsers, s.lockUser))
	s.mux.Handle("DELETE /api/users/{id}/lock", s.authz(auth.CapManageUsers, s.unlockUser))
	s.mux.Handle("POST /api/users/{id}/token", s.authz(auth.CapManageUsers, s.rotateUserToken))
	// Password/SSO login sessions (never their token hashes), so an admin can
	// see who is logged in and revoke them — not GET /api/sessions, which lists
	// live proxied target sessions.
	s.mux.Handle("GET /api/login-sessions", s.authz(auth.CapManageUsers, listAll(s.store.ListSessions)))
	s.mux.Handle("POST /api/login-sessions/revoke", s.authz(auth.CapManageUsers, s.revokeLoginSessions))
	s.mux.Handle("POST /api/identity/reconcile", s.authz(auth.CapManageUsers, s.reconcileIdentities))

	// Third-party vendor access gate (Phase 29).
	s.mux.Handle("POST /api/vendors", s.authz(auth.CapManageUsers, s.createVendor))
	s.mux.Handle("GET /api/vendors", s.authz(auth.CapReadInventory, pagedList(s.store.ListVendors)))
	s.mux.Handle("PUT /api/vendors/{id}", s.authz(auth.CapManageUsers, s.updateVendor))
	s.mux.Handle("POST /api/vendors/{id}/offboard", s.authz(auth.CapManageUsers, s.offboardVendor))
	s.mux.Handle("POST /api/vendors/{id}/grants", s.authz(auth.CapManageTargets, s.createVendorGrant))
	s.mux.Handle("GET /api/vendors/{id}/grants", s.authz(auth.CapReadInventory, listByParent(s.store.ListVendorGrants)))
	s.mux.Handle("GET /api/vendors/{id}/evidence", s.authz(auth.CapReadAudit, s.vendorEvidence))
	s.mux.Handle("POST /api/vendor-grants/{gid}/approve", s.authz(auth.CapApprove, s.approveVendorGrant))
	s.mux.Handle("POST /api/vendor-grants/{gid}/revoke", s.authz(auth.CapManageTargets, s.revokeVendorGrant))

	// Access certification / attestation campaigns (Phase 19): a periodic review
	// of who has access to what; a revoke decision removes the underlying grant.
	s.mux.Handle("POST /api/campaigns", s.authz(auth.CapManageUsers, s.createCampaign))
	s.mux.Handle("GET /api/campaigns", s.authz(auth.CapReadAudit, listAll(s.store.ListCampaigns)))
	s.mux.Handle("GET /api/campaigns/{id}", s.authz(auth.CapReadAudit, s.getCampaign))
	// Certifying or revoking an item is a review decision, not user administration:
	// CapApprove lets a dedicated reviewer run the campaign without holding the
	// access-granting capability (Phase 39). Creating and closing a campaign stay
	// CapManageUsers.
	s.mux.Handle("POST /api/campaigns/{id}/items/{iid}/decision", s.authz(auth.CapApprove, s.decideCampaignItem))
	s.mux.Handle("POST /api/campaigns/{id}/close", s.authz(auth.CapManageUsers, s.closeCampaign))
	// Assignment is administration (who reviews what), so manage_users — the same
	// gate as creating the campaign. Deciding stays approve.
	s.mux.Handle("PUT /api/campaigns/{id}/items/{itemID}/reviewer", s.authz(auth.CapManageUsers, s.assignCampaignItem))
	// A reviewer's own queue across every open campaign.
	s.mux.Handle("GET /api/campaigns/mine", s.authz(auth.CapApprove, s.myReviewQueue))

	// Custom permission profiles (Phase 12): named capability sets for users.
	s.mux.Handle("POST /api/profiles", s.authz(auth.CapManageUsers, s.createProfile))
	s.mux.Handle("GET /api/profiles", s.authz(auth.CapManageUsers, listAll(s.store.ListProfiles)))
	s.mux.Handle("DELETE /api/profiles/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteProfile, "profile.delete", "profile")))

	// System configuration overrides (Phase 12): DB-persisted PAM_* settings.
	s.mux.Handle("GET /api/config", s.authz(auth.CapManageUsers, s.listConfig))
	s.mux.Handle("GET /api/config/effective", s.authz(auth.CapManageUsers, s.effectiveConfig))
	s.mux.Handle("GET /api/config/iac", s.authz(auth.CapManageUsers, s.iacConfig))
	s.mux.Handle("PUT /api/config", s.authz(auth.CapManageUsers, s.putConfig))
	s.mux.Handle("DELETE /api/config/{key}", s.authz(auth.CapManageUsers, s.deleteConfig))

	// AI-agent access broker (Phase 13), served only when a policy is configured.
	// Agent-facing routes authenticate an agent bearer key/SVID; operator-facing
	// routes reuse the human RBAC capabilities.
	if s.broker != nil {
		s.mux.HandleFunc("POST /v1/tool-calls", s.agentAuth(s.processToolCall))
		s.mux.HandleFunc("GET /v1/tool-calls/{id}", s.agentAuth(s.getToolCall))
		s.mux.HandleFunc("POST /v1/tool-calls/{id}/resume", s.agentAuth(s.resumeToolCall))
		s.mux.HandleFunc("POST /mcp", s.agentAuth(s.serveMCP))
		s.mux.HandleFunc("GET /mcp", s.agentAuth(s.serveMCPStream)) // MCP SSE transport (Phase 27)
		s.mux.Handle("GET /v1/approvals", s.authz(auth.CapApprove, s.listBrokerApprovals))
		s.mux.Handle("POST /v1/approvals/{id}/decision", s.authz(auth.CapApprove, s.decideBrokerApproval))
		s.mux.Handle("POST /v1/agents", s.authz(auth.CapManageUsers, s.createAgentKey))
		s.mux.Handle("GET /v1/agents", s.authz(auth.CapManageUsers, s.listAgentKeys))
		s.mux.Handle("DELETE /v1/agents/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteAgentKey, "agent.revoke", "agent")))
		// Containment (Phase 159): suspend/resume one key, and the subject-keyed
		// quarantine that also covers an SVID agent with no key row. The literal
		// "quarantine" segment is registered before "{id}" only for readability —
		// ServeMux prefers the more specific pattern regardless of order.
		s.mux.Handle("POST /v1/agents/quarantine", s.authz(auth.CapManageUsers, s.quarantineAgent))
		s.mux.Handle("GET /v1/agents/quarantine", s.authz(auth.CapManageUsers, listAll(s.store.ListAgentQuarantine)))
		s.mux.Handle("DELETE /v1/agents/quarantine/{id}", s.authz(auth.CapManageUsers, s.releaseAgentQuarantine))
		// Accountability for the identity kind PAMv1 never issued a key to
		// (Phase 170): who owns a SPIFFE-attested agent. Read by the broker's
		// four-eyes refusal and by the offboarding cascade. Like "quarantine",
		// the literal "identities" segment is registered before "{id}" only for
		// readability — ServeMux prefers the more specific pattern regardless.
		s.mux.Handle("POST /v1/agents/identities", s.authz(auth.CapManageUsers, s.createAgentIdentity))
		s.mux.Handle("GET /v1/agents/identities", s.authz(auth.CapManageUsers, s.listAgentIdentities))
		s.mux.Handle("POST /v1/agents/identities/{id}/owner", s.authz(auth.CapManageUsers, s.setAgentIdentityOwner))
		// Removing a registration is audited as loudly as creating one: that SPIFFE
		// identity has no recorded owner again, and its parked calls can no longer
		// be approved by anyone until one is recorded — a fail-closed consequence an
		// operator should be able to trace.
		s.mux.Handle("DELETE /v1/agents/identities/{id}", s.authz(auth.CapManageUsers, s.deleteByID(s.store.DeleteAgentIdentity, "agent.identity_remove", "identity")))
		s.mux.Handle("POST /v1/agents/{id}/disable", s.authz(auth.CapManageUsers, s.disableAgentKey))
		s.mux.Handle("POST /v1/agents/{id}/enable", s.authz(auth.CapManageUsers, s.enableAgentKey))
		s.mux.Handle("POST /v1/agents/{id}/budget", s.authz(auth.CapManageUsers, s.setAgentBudget))
		s.mux.Handle("GET /v1/audit", s.authz(auth.CapReadAudit, s.listBrokerAudit))
		s.mux.Handle("GET /v1/audit/verify", s.authz(auth.CapReadAudit, s.verifyBrokerAudit))
		s.mux.Handle("GET /v1/audit/head", s.authz(auth.CapReadAudit, s.brokerAuditHead))
		s.mux.Handle("GET /v1/audit/jwks", s.authz(auth.CapReadAudit, s.brokerAuditJWKS))
		// RFC 8693 token exchange (Phase 57). Mounted with the broker but 404s
		// unless a signing key was configured, like the app-secrets surface.
		s.mux.HandleFunc("POST /v1/token", s.agentAuth(s.exchangeToken))
		s.mux.Handle("GET /v1/token/jwks", s.authz(auth.CapReadAudit, s.tokenJWKS))
	}
}
