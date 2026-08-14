package store

// mfapolicy.go answers one question in one place: **does this user have a
// usable second factor?** Before WebAuthn, every caller inlined a check
// against MFAEnrollment.Confirmed directly (login, re-enroll, disable,
// recovery-code generation) — TOTP was the only factor, so there was nothing
// to fold. WebAuthn makes that a lie: a user with a registered authenticator
// and no TOTP enrollment has MFA, and a bare Confirmed check would say they
// don't. EffectiveMFAFactors is the one place that widens "has TOTP" to "has
// any factor", modeled on EffectiveApprovalPolicy's shape (a narrow reader
// interface, a pure function, fail-closed on a store error).

import (
	"context"
	"errors"
)

// MFAReader is the slice of the store EffectiveMFAFactors needs. Taking an
// interface this narrow means a test can supply a two-line fake.
type MFAReader interface {
	GetMFAEnrollment(ctx context.Context, username string) (*MFAEnrollment, error)
	ListWebAuthnCredentials(ctx context.Context, username string) ([]WebAuthnCredential, error)
}

// MFAFactors reports which second factors a user currently has confirmed.
type MFAFactors struct {
	TOTP     bool
	WebAuthn bool
}

// Any reports whether the user has at least one usable second factor.
func (f MFAFactors) Any() bool { return f.TOTP || f.WebAuthn }

// EffectiveMFAFactors checks both factor types for username. A store error
// from either check is returned as-is (fail closed: a caller that only looks
// at the zero-value MFAFactors on error sees Any() == false, which is the
// safe direction — it can never make an unconfirmed user look confirmed).
func EffectiveMFAFactors(ctx context.Context, st MFAReader, username string) (MFAFactors, error) {
	var f MFAFactors
	enr, err := st.GetMFAEnrollment(ctx, username)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return MFAFactors{}, err
	}
	f.TOTP = err == nil && enr.Confirmed
	creds, err := st.ListWebAuthnCredentials(ctx, username)
	if err != nil {
		return MFAFactors{}, err
	}
	f.WebAuthn = len(creds) > 0
	return f, nil
}
