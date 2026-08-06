package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- dependent accounts (Phase 17): a credential's consumers (Windows Services,
// Scheduled Tasks, IIS App Pools) that pamv1 updates over WinRM when the
// credential is rotated, so rotation does not break production. ---

var validDependencyKind = map[string]bool{
	"windows_service": true,
	"scheduled_task":  true,
	"iis_apppool":     true,
}

// A dependency's name and host are interpolated into a WinRM command line, so
// they are restricted to an ALLOWLIST rather than screened by a blocklist: a
// service, scheduled-task or app-pool name legitimately needs letters, digits,
// spaces and a few separators, and nothing else. Everything a shell could act on
// — quotes, &, |, ^, <, >, %, backticks, semicolons, newlines — is simply not a
// legal name here.
//
// This is enforced at creation AND again where the command is built, so a row
// written before this rule existed (or straight into the database) still cannot
// reach a command line.
//
// `$` is in the allowlist because Windows requires it: a named SQL Server
// instance registers services as `MSSQL$INSTANCE` and `SQLAgent$INSTANCE`, which
// is the textbook credential-dependency case for a PAM. It is inert in cmd.exe
// (where these commands run — the iis_apppool command relies on `%windir%`
// expanding, which is a cmd.exe behaviour), so admitting it costs nothing. The
// sibling allowlist for `net user` accepts `$` for the same reason, for gMSA
// accounts; the two must not disagree about what a legal Windows name looks
// like.
//
// MustCompile panics if the pattern is malformed, which is what you want for a
// constant: the failure happens once at program start, not on the first request
// that needs it.
var (
	validDependencyName = regexp.MustCompile(`^[A-Za-z0-9 ._$\-()\\/]{1,128}$`)
	// Hostname or IPv4/IPv6 literal; no metacharacters, no spaces.
	validDependencyHost = regexp.MustCompile(`^[A-Za-z0-9._\-:\[\]]{1,253}$`)
)

type dependencyIn struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Name string `json:"name"`
	// ManagementCredentialID is the credential pamv1 connects to Host WITH to
	// update this consumer (Phase 61). Omitted or 0 keeps the original
	// behaviour of connecting as the account being rotated.
	ManagementCredentialID int64 `json:"management_credential_id"`
}

// createDependency declares a consumer of a credential (CapManageCredentials).
func (s *Server) createDependency(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in dependencyIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case !validDependencyKind[in.Kind]:
		writeError(w, http.StatusUnprocessableEntity, `kind must be "windows_service", "scheduled_task" or "iis_apppool"`)
		return
	case in.Host == "" || in.Name == "":
		writeError(w, http.StatusUnprocessableEntity, "host and name are required")
		return
	case !validDependencyName.MatchString(in.Name):
		writeError(w, http.StatusUnprocessableEntity,
			"name may contain only letters, digits, spaces and . _ - ( ) \\ / — it is used in a command line")
		return
	case !validDependencyHost.MatchString(in.Host):
		writeError(w, http.StatusUnprocessableEntity, "host must be a hostname or IP address")
		return
	case in.Port < 0 || in.Port > 65535:
		writeError(w, http.StatusUnprocessableEntity, "port must be 0-65535")
		return
	case in.ManagementCredentialID < 0:
		writeError(w, http.StatusUnprocessableEntity, "management_credential_id must be a credential id")
		return
	}
	// A management credential is checked to exist — and the caller checked to be
	// allowed to point it at Host — HERE, at the only point where a human is
	// present to be told. Propagation runs unattended after a rotation, so a
	// typo discovered there is an audit line nobody is reading.
	if in.ManagementCredentialID != 0 && !s.gateManagementCredential(w, r, in.ManagementCredentialID, in.Host) {
		return
	}
	d := store.CredentialDependency{
		CredentialID: id, Kind: in.Kind, Host: in.Host, Port: in.Port, Name: in.Name,
		ManagementCredentialID: in.ManagementCredentialID,
	}
	if err := s.store.CreateCredentialDependency(r.Context(), &d); err != nil {
		storeError(w, err)
		return
	}
	via := "self"
	if d.ManagementCredentialID != 0 {
		via = fmt.Sprintf("credential:%d", d.ManagementCredentialID)
	}
	s.audit(r.Context(), "dependency.create", fmt.Sprintf("credential:%d %s:%s@%s managed_via:%s", id, in.Kind, in.Name, in.Host, via))
	writeJSON(w, http.StatusCreated, d)
}

// gateManagementCredential authorizes naming credID as a dependency's
// management credential (Phase 61a). It writes the refusal and returns false
// when the caller may not.
//
// WHY THIS IS A CREDENTIAL-ACCESS PATH. Phase 61 read the reference as
// configuration — a caller with CapManageCredentials could name any credential
// at all, and only its existence was checked. But naming it means pamv1 will
// later decrypt that secret and present it, over WinRM, to `host` — a host the
// same caller chooses freely on the same request. That is a reveal with extra
// steps: it hands the plaintext to a machine the caller controls without the
// caller ever holding CapRevealSecret or a grant on the credential's target.
// So the bar here is the reveal bar, applied to the MANAGEMENT credential's
// target rather than to the target being rotated.
//
// WHY IT DOES NOT CONSUME AN APPROVAL. Declaring a dependency is not the use;
// the use happens unattended, after some later rotation. Burning a single-use
// approval on a configuration change would spend the operator's session
// approval on paperwork, so this checks the same approval condition without
// claiming it (`HasActiveApproval`, the status-only twin the approval gate
// documents) — the one deliberate difference from `gateCredentialAccess`.
func (s *Server) gateManagementCredential(w http.ResponseWriter, r *http.Request, credID int64, host string) bool {
	ctx := r.Context()
	// The capability is checked BEFORE the credential is looked up, so a caller
	// who may not reveal anything gets the same refusal for every id and cannot
	// use this endpoint to map which credential ids exist.
	if !principalFrom(ctx).Can(auth.CapRevealSecret) {
		s.audit(ctx, "dependency.create_denied",
			fmt.Sprintf("management_credential:%d host:%s reason:reveal-secret-required", credID, host))
		writeError(w, http.StatusForbidden,
			"naming a management credential presents its secret to the consumer's host, which requires reveal_secret")
		return false
	}
	mc, err := s.store.GetCredential(ctx, credID)
	if err != nil || mc == nil {
		writeError(w, http.StatusUnprocessableEntity, "management_credential_id does not name an existing credential")
		return false
	}
	// Only a password can be presented as a WinRM password. An SSH private key
	// sent into that field is not authentication, it is disclosure: the key
	// travels to `host` in full and cannot log anything in. A Zero Standing
	// Privilege credential (`ssh_ca`) holds no secret at all. Both are refused
	// here rather than at use time, while a human is present to be told.
	if mc.SecretType != "" && mc.SecretType != "password" {
		writeError(w, http.StatusUnprocessableEntity,
			"a management credential must hold a password; this one holds "+mc.SecretType)
		return false
	}
	mt, err := s.store.GetTarget(ctx, mc.TargetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnprocessableEntity, "the management credential's target no longer exists")
			return false
		}
		storeError(w, err)
		return false
	}
	if ok, err := s.authorizedForTarget(ctx, mt); err != nil {
		storeError(w, err)
		return false
	} else if !ok {
		s.audit(ctx, "dependency.create_denied",
			fmt.Sprintf("management_credential:%d target:%s host:%s reason:target-policy", credID, mt.Name, host))
		writeError(w, http.StatusForbidden, "not authorized for the management credential's target")
		return false
	}
	if !principalFrom(ctx).BreakGlass {
		required, err := s.requireApprovalFor(ctx, mt)
		if err != nil {
			storeError(w, err)
			return false
		}
		if required {
			held, err := s.store.HasActiveApproval(ctx, actorFrom(ctx), mt.ID, time.Now())
			if err != nil {
				storeError(w, err)
				return false
			}
			if !held {
				s.audit(ctx, "dependency.create_denied",
					fmt.Sprintf("management_credential:%d target:%s host:%s reason:approval-required", credID, mt.Name, host))
				writeError(w, http.StatusForbidden,
					"the management credential's target requires an approved access request")
				return false
			}
		}
	}
	return s.vendorGate(w, r, mt, mc.Username, "dependency.create_denied")
}

// listDependencies returns a credential's declared consumers (CapReadInventory).
func (s *Server) listDependencies(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	deps, err := s.store.ListCredentialDependencies(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, deps)
}

// deleteDependency removes a declared consumer (CapManageCredentials).
func (s *Server) deleteDependency(w http.ResponseWriter, r *http.Request) {
	cid, ok := idParam(w, r)
	if !ok {
		return
	}
	did, err := strconv.ParseInt(r.PathValue("did"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dependency id")
		return
	}
	// The route is scoped to a credential — only delete the dependency if it
	// belongs to that credential, so DELETE /credentials/1/dependencies/5 cannot
	// remove credential 2's consumer, and the audit names the credential that
	// lost it (mirrors deleteTargetGrant / deleteAppSecretGrant).
	deps, err := s.store.ListCredentialDependencies(r.Context(), cid)
	if err != nil {
		storeError(w, err)
		return
	}
	found := false
	for _, d := range deps {
		if d.ID == did {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "dependency not found for this credential")
		return
	}
	if err := s.store.DeleteCredentialDependency(r.Context(), did); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "dependency.delete", fmt.Sprintf("credential:%d dependency:%d", cid, did))
	w.WriteHeader(http.StatusNoContent)
}
