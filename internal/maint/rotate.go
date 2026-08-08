// Package maint holds offline maintenance operations for pamv1.
package maint

import (
	"context"
	"fmt"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// RotateVaultKEK re-encrypts every vaulted secret from the `from` vault to the
// `to` vault, preserving each secret's AAD binding, and returns how many were
// re-encrypted. Run it offline (nothing else writing secrets), then switch the
// server to the new key.
//
// "Every vaulted secret" means all four kinds, and the list is exhaustive on
// purpose — anything missed here is a secret the server can no longer decrypt
// after the switch:
//
//  1. credentials          (store.CredentialAAD)
//  2. TOTP enrollments     (store.MFAAAD)
//  3. secret config values (store.ConfigAAD) — LDAP bind password, SSO secrets
//  4. key custody          (store.KeyMaterialAAD) — SSH host key, ZSP CA key,
//     and the broker audit-chain HMAC key + signing seed when they are
//     custody-held rather than set in the environment
//
// Each step is idempotent: if a secret already decrypts under `to`, a previous
// interrupted run rotated it, so it is skipped rather than failed on. That makes
// the whole operation safely resumable instead of leaving a half-rotated store.
//
// NOT covered, and it cannot be: sealed session recordings carry their own data
// key wrapped by the KEK inside each FILE, not in the store. Re-wrapping them
// here would rewrite the file bytes and so invalidate the SHA-256 recorded in
// the audit trail and the recording hash chain — destroying the tamper evidence
// the recordings exist to provide. The old KEK must therefore be retained for as
// long as sealed recordings are kept; the caller warns about this.
// VaultRotationStore is the slice of the store -rotate-kek needs: every place a
// KEK-wrapped value is persisted, listed as four explicit pairs rather than
// taken as the whole 149-method store.Store.
//
// The list is the point. The bug this function shipped once was OMISSION — key
// custody was added in Phase 42 and the rotation was never taught about it, so
// the documented procedure re-wrapped three kinds, reported success, and left
// the server unable to start because the fourth was still sealed under the old
// KEK. Naming the four in the signature puts the exhaustive set where a reviewer
// reads it, instead of leaving them to reconstruct it from the body.
type VaultRotationStore interface {
	// Credentials — the vaulted secrets themselves.
	ListCredentials(ctx context.Context, targetID int64, limit int, afterID int64) ([]store.Credential, error)
	UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error
	// MFA enrollments — each TOTP secret is wrapped too.
	ListMFAEnrollments(ctx context.Context) ([]store.MFAEnrollment, error)
	UpsertMFAEnrollment(ctx context.Context, e *store.MFAEnrollment) error
	// Settings — a stored configuration override may hold a secret.
	ListSettings(ctx context.Context) ([]store.Setting, error)
	PutSetting(ctx context.Context, s *store.Setting) error
	// Key custody — the SSH host key, the ZSP CA, the broker and bus keys. The
	// kind that was missed.
	ListKeyMaterial(ctx context.Context) ([]store.KeyMaterial, error)
	UpdateKeyMaterial(ctx context.Context, name, value string) error
}

func RotateVaultKEK(ctx context.Context, st VaultRotationStore, from, to *vault.Vault) (int, error) {
	n := 0

	creds, err := st.ListCredentials(ctx, 0, 0, 0)
	if err != nil {
		return n, fmt.Errorf("list credentials: %w", err)
	}
	for _, c := range creds {
		aad := store.CredentialAAD(c.TargetID, c.ID)
		// Idempotent/resumable: if this secret already decrypts under the new KEK
		// (a prior run rotated it before crashing), skip it rather than failing on
		// the `from` decrypt and stranding the store in a mixed-key state.
		if _, err := to.Decrypt(ctx, c.SecretEnc, aad); err == nil {
			continue
		}
		plain, err := from.Decrypt(ctx, c.SecretEnc, aad)
		if err != nil {
			return n, fmt.Errorf("credential %d decrypt: %w", c.ID, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("credential %d encrypt: %w", c.ID, err)
		}
		if err := st.UpdateCredentialSecretEnc(ctx, c.ID, enc); err != nil {
			return n, fmt.Errorf("credential %d update: %w", c.ID, err)
		}
		n++
	}

	enrollments, err := st.ListMFAEnrollments(ctx)
	if err != nil {
		return n, fmt.Errorf("list mfa: %w", err)
	}
	for _, e := range enrollments {
		aad := store.MFAAAD(e.Username)
		if _, err := to.Decrypt(ctx, e.SecretEnc, aad); err == nil {
			continue // already rotated under the new KEK
		}
		plain, err := from.Decrypt(ctx, e.SecretEnc, aad)
		if err != nil {
			return n, fmt.Errorf("mfa %s decrypt: %w", e.Username, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("mfa %s encrypt: %w", e.Username, err)
		}
		e.SecretEnc = enc
		if err := st.UpsertMFAEnrollment(ctx, &e); err != nil {
			return n, fmt.Errorf("mfa %s update: %w", e.Username, err)
		}
		n++
	}

	// Config settings (Phase 12): the secret ones (LDAP bind password, SSO client
	// secrets) are vault-encrypted with ConfigAAD and MUST be re-wrapped too, or the
	// server can't decrypt them after the master key is switched (and can't boot).
	settings, err := st.ListSettings(ctx)
	if err != nil {
		return n, fmt.Errorf("list settings: %w", err)
	}
	for _, sg := range settings {
		if !sg.Secret {
			continue
		}
		aad := store.ConfigAAD(sg.Key)
		if _, err := to.Decrypt(ctx, sg.Value, aad); err == nil {
			continue // already rotated under the new KEK
		}
		plain, err := from.Decrypt(ctx, sg.Value, aad)
		if err != nil {
			return n, fmt.Errorf("setting %s decrypt: %w", sg.Key, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("setting %s encrypt: %w", sg.Key, err)
		}
		sg.Value = enc
		if err := st.PutSetting(ctx, &sg); err != nil {
			return n, fmt.Errorf("setting %s update: %w", sg.Key, err)
		}
		n++
	}

	// Shared key custody (Phase 42): the SSH proxy host key and the Zero Standing
	// Privilege CA key live in the store as vault envelopes too. They MUST be
	// re-wrapped here. Leaving them out was a real outage: `-rotate-kek` reported
	// success, and the next startup called keycustody.Ensure, read back an
	// envelope still sealed under the OLD key, failed to unwrap it, and treated
	// that as fatal — correctly, since silently regenerating a host key or a CA is
	// exactly the MITM-shaped event Phase 42 exists to prevent. The naive recovery
	// (deleting the rows) causes that very event.
	keys, err := st.ListKeyMaterial(ctx)
	if err != nil {
		return n, fmt.Errorf("list key material: %w", err)
	}
	for _, k := range keys {
		aad := store.KeyMaterialAAD(k.Name)
		if _, err := to.Decrypt(ctx, k.Value, aad); err == nil {
			continue // already rotated under the new KEK
		}
		plain, err := from.Decrypt(ctx, k.Value, aad)
		if err != nil {
			return n, fmt.Errorf("key material %s decrypt: %w", k.Name, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("key material %s encrypt: %w", k.Name, err)
		}
		if err := st.UpdateKeyMaterial(ctx, k.Name, enc); err != nil {
			return n, fmt.Errorf("key material %s update: %w", k.Name, err)
		}
		n++
	}

	return n, nil
}
