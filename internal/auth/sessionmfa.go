package auth

// sessionmfa.go holds the two decisions per-session MFA (Phase 244) needs on
// every path that opens access to a target — the three session proxies, the
// RDP/VNC viewer and the REST access paths — written once so no door can hold
// a shorter version of them:
//
//   - VerifySecondFactor: is this code a valid second factor for this user,
//     spent so it cannot be replayed? Shared by the login endpoint, the ticket
//     mint and the SSH proxy's in-band code prompt.
//   - CheckSessionMFA: may this principal open this session under the policy,
//     and if it presented a ticket, spend it.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
)

// The factor names recorded on session.mfa_verified and on the ticket mint.
const (
	FactorTOTP     = "totp"
	FactorRecovery = "recovery"
	FactorWebAuthn = "webauthn"
	FactorTicket   = "ticket"
)

// The refusal reasons every enforcement site audits, identical on every path.
const (
	ReasonSessionMFARequired     = "session-mfa-required"
	ReasonSessionMFATicketTarget = "session-mfa-ticket-target"
	ReasonSessionMFATicketUsed   = "session-mfa-ticket-used"
	// ReasonSessionMFATicketInvalid is the REST paths' refusal for a header
	// that does not resolve to a live ticket of the caller's own identity; a
	// proxy password that does not resolve fails authentication instead.
	ReasonSessionMFATicketInvalid = "session-mfa-ticket-invalid"
	// ReasonSessionMFAExtension is the refusal for a browser-extension token
	// on a target that requires a factor (Phase 248). Its scope reaches one
	// route, so it can never mint a ticket: the operator reveals in the
	// portal. Distinct from ReasonSessionMFARequired so the audit trail
	// separates "did not present one" from "could not".
	ReasonSessionMFAExtension = "session-mfa-extension-unsupported"
)

// Decrypter opens a vault-sealed value (vault.Vault satisfies it).
type Decrypter interface {
	Decrypt(ctx context.Context, token, aad string) (string, error)
}

// SecondFactorStore is the slice of the store a second-factor check spends.
type SecondFactorStore interface {
	ConsumeTOTPStep(ctx context.Context, username string, step int64) (bool, error)
	ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error)
}

// VerifySecondFactor reports which factor code is for username — FactorTOTP
// for a valid, not-yet-used TOTP code, FactorRecovery for an unused recovery
// code (consumed) — or "" when it is neither. enr must be the user's confirmed
// enrollment. A valid TOTP code whose time step was already spent is refused
// WITHOUT falling through to the recovery-code check, and a store error on the
// replay guard refuses and is returned so the caller can log it: the guard is
// a security control, so failing to record the step must not accept the code.
func VerifySecondFactor(ctx context.Context, st SecondFactorStore, dec Decrypter, enr *store.MFAEnrollment, username, code string, now time.Time) (string, error) {
	if secret, err := dec.Decrypt(ctx, enr.SecretEnc, store.MFAAAD(username)); err == nil {
		if step, ok := mfa.ValidateStep(secret, code, now); ok {
			consumed, cerr := st.ConsumeTOTPStep(ctx, username, step)
			if cerr != nil {
				return "", cerr
			}
			if consumed {
				return FactorTOTP, nil
			}
			return "", nil
		}
	}
	c := strings.ToLower(strings.TrimSpace(code))
	// The store error is RETURNED, not swallowed (Phase 248): this function's
	// contract says a store failure on a factor check is reported so the
	// caller can log it, and the recovery branch was the one place that
	// dropped it — an operator locked out by an unreachable database saw the
	// same "invalid code" as one who mistyped, with nothing in the log to
	// tell the two apart. The refusal itself is unchanged: no factor, no pass.
	consumed, err := st.ConsumeMFARecoveryCode(ctx, username, TokenHash(c))
	if err != nil {
		return "", err
	}
	if consumed {
		return FactorRecovery, nil
	}
	return "", nil
}

// SessionSpender is what spending a ticket needs: deleting its session row,
// atomically, reporting store.ErrNotFound when another use got there first.
type SessionSpender interface {
	DeleteSession(ctx context.Context, tokenHashHex string) error
}

// CheckSessionMFA decides the per-session MFA gate for p opening a session to
// targetID, given whether the policy requires it (store.EffectiveSessionMFA).
// It returns the factor that satisfied the gate ("" when none was needed), or
// a non-empty refusal reason.
//
//   - A ticket is SPENT first, whatever follows — single-use means single
//     attempt, so a ticket presented to the wrong target is burned rather than
//     left for another try — and admits only the target it was minted for.
//     Spent even where the policy does not require one, so "single-use" never
//     depends on the target's settings.
//   - Break-glass bypasses, as it bypasses every other gate.
//   - A factor proven in-band for this session (SessionMFAFactor) satisfies it.
//   - Otherwise a required gate refuses.
func CheckSessionMFA(ctx context.Context, st SessionSpender, p *Principal, targetID int64, required bool) (factor, reason string, err error) {
	if p.SessionMFATicket {
		if derr := st.DeleteSession(ctx, p.sessionMFAHash); derr != nil {
			if errors.Is(derr, store.ErrNotFound) {
				return "", ReasonSessionMFATicketUsed, nil
			}
			return "", "", derr
		}
		if p.SessionMFATarget != targetID {
			return "", ReasonSessionMFATicketTarget, nil
		}
		return FactorTicket, "", nil
	}
	if !required || p.BreakGlass {
		return "", "", nil
	}
	if p.SessionMFAFactor != "" {
		return p.SessionMFAFactor, "", nil
	}
	return "", ReasonSessionMFARequired, nil
}
