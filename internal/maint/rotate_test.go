package maint

import (
	"context"
	"fmt"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newVault builds a vault with a fresh random master key for the test.
func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRotateVaultKEKSettings proves the KEK rotation also re-wraps vault-encrypted
// config settings (Phase 12) — without this the server can't decrypt them after
// the master key changes.
func TestRotateVaultKEKSettings(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)

	secEnc, _ := from.Encrypt(ctx, "bind-pw", store.ConfigAAD("PAM_LDAP_BIND_PASSWORD"))
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_BIND_PASSWORD", Value: secEnc, Secret: true}); err != nil {
		t.Fatal(err)
	}
	// A non-secret setting must be left untouched (not double-processed).
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_URL", Value: "ldaps://dc", Secret: false}); err != nil {
		t.Fatal(err)
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 1 {
		t.Fatalf("rotated %d, want 1 (the secret setting)", n)
	}
	got, _ := st.GetSetting(ctx, "PAM_LDAP_BIND_PASSWORD")
	if pt, err := to.Decrypt(ctx, got.Value, store.ConfigAAD("PAM_LDAP_BIND_PASSWORD")); err != nil || pt != "bind-pw" {
		t.Fatalf("secret setting not re-wrapped under new KEK: pt=%q err=%v", pt, err)
	}
	if plain, _ := st.GetSetting(ctx, "PAM_LDAP_URL"); plain.Value != "ldaps://dc" {
		t.Fatalf("non-secret setting was altered: %q", plain.Value)
	}
}

// TestRotateVaultKEK checks re-encryption moves every secret from the old vault
// to the new one, preserving plaintext, AAD binding, and the confirmed flag.
func TestRotateVaultKEK(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)

	// Seed a credential and an MFA enrollment encrypted under `from`.
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	credEnc, _ := from.Encrypt(ctx, "cred-secret", store.CredentialAAD(target.ID, cred.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, credEnc); err != nil {
		t.Fatal(err)
	}
	mfaEnc, _ := from.Encrypt(ctx, "TOTPSECRET", store.MFAAAD("alice"))
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "alice", SecretEnc: mfaEnc, Confirmed: true}); err != nil {
		t.Fatal(err)
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 2 {
		t.Fatalf("rotated %d secrets, want 2", n)
	}

	// The secrets now decrypt with the new vault, not the old one.
	got, _ := st.GetCredential(ctx, cred.ID)
	if pt, err := to.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, cred.ID)); err != nil || pt != "cred-secret" {
		t.Fatalf("new vault should decrypt credential: %q %v", pt, err)
	}
	if _, err := from.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, cred.ID)); err == nil {
		t.Fatal("old vault must no longer decrypt the rotated credential")
	}

	enr, _ := st.GetMFAEnrollment(ctx, "alice")
	if !enr.Confirmed {
		t.Fatal("rotation must preserve the confirmed flag")
	}
	if pt, err := to.Decrypt(ctx, enr.SecretEnc, store.MFAAAD("alice")); err != nil || pt != "TOTPSECRET" {
		t.Fatalf("new vault should decrypt MFA secret: %q %v", pt, err)
	}

	// Idempotent/resumable: re-running against the same store must not fail on the
	// already-rotated rows (it would strand a partially-rotated store otherwise).
	n2, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("re-run after full rotation should be a no-op, got: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("re-run rotated %d secrets, want 0 (all already rotated)", n2)
	}
}

// TestCredentialAADBindsToCredential proves a vaulted secret is bound to its
// specific credential row: a ciphertext for one credential cannot be decrypted
// as another credential, even on the same target.
func TestCredentialAADBindsToCredential(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	const targetID = int64(7)
	encA, err := v.Encrypt(ctx, "secret-A", store.CredentialAAD(targetID, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Decrypt(ctx, encA, store.CredentialAAD(targetID, 2)); err == nil {
		t.Fatal("ciphertext for cred 1 must not decrypt as cred 2 on the same target")
	}
	if pt, err := v.Decrypt(ctx, encA, store.CredentialAAD(targetID, 1)); err != nil || pt != "secret-A" {
		t.Fatalf("correct AAD should decrypt: %q %v", pt, err)
	}
}

// TestRotateVaultKEKResumesPartial proves a rotation interrupted partway can be
// resumed: rows already under the new KEK are skipped, and the remaining ones
// are rotated, without either KEK having to decrypt the whole store.
func TestRotateVaultKEKResumesPartial(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	// Two credentials: one already under the NEW KEK (as if a prior run rotated it
	// before crashing), one still under the OLD KEK.
	credA := &store.Credential{TargetID: target.ID, Username: "a", SecretType: "password"}
	if err := st.CreateCredential(ctx, credA); err != nil {
		t.Fatal(err)
	}
	rotatedEnc, _ := to.Encrypt(ctx, "already", store.CredentialAAD(target.ID, credA.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, credA.ID, rotatedEnc); err != nil {
		t.Fatal(err)
	}
	credB := &store.Credential{TargetID: target.ID, Username: "b", SecretType: "password"}
	if err := st.CreateCredential(ctx, credB); err != nil {
		t.Fatal(err)
	}
	pendingEnc, _ := from.Encrypt(ctx, "pending", store.CredentialAAD(target.ID, credB.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, credB.ID, pendingEnc); err != nil {
		t.Fatal(err)
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("resume should not fail on the already-rotated row: %v", err)
	}
	if n != 1 {
		t.Fatalf("rotated %d, want 1 (only the pending row)", n)
	}
	creds, _ := st.ListCredentials(ctx, target.ID, 0, 0)
	for _, c := range creds {
		if _, err := to.Decrypt(ctx, c.SecretEnc, store.CredentialAAD(target.ID, c.ID)); err != nil {
			t.Fatalf("credential %q should decrypt under the new KEK after resume: %v", c.Username, err)
		}
	}
}

// TestRotateVaultKEKKeyMaterial proves shared key custody (Phase 42) is
// re-wrapped by a KEK rotation.
//
// Why it earns its own test: the SSH proxy host key and the Zero Standing
// Privilege CA key are the only vaulted secrets NOT reached through a
// credential, an MFA enrollment or a setting, and leaving them out was a real
// outage rather than a cosmetic omission. `-rotate-kek` reported success, and
// the next startup read back an envelope still sealed under the OLD key, failed
// to unwrap it, and refused to boot — correctly, because silently regenerating
// a host key or a CA is exactly the MITM-shaped event Phase 42 exists to
// prevent. This test fails if that path is ever dropped again.
func TestRotateVaultKEKKeyMaterial(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)

	const hostPEM, caPEM = "-----BEGIN OPENSSH PRIVATE KEY----- host", "-----BEGIN OPENSSH PRIVATE KEY----- ca"
	for name, pem := range map[string]string{"ssh_host_key": hostPEM, "ssh_ca_key": caPEM} {
		enc, err := from.Encrypt(ctx, pem, store.KeyMaterialAAD(name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.EnsureKeyMaterial(ctx, name, enc); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := RotateVaultKEK(ctx, st, from, to); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	keys, err := st.ListKeyMaterial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	want := map[string]string{"ssh_ca_key": caPEM, "ssh_host_key": hostPEM}
	for _, k := range keys {
		// The new KEK must unwrap it — this is what startup will do.
		got, err := to.Decrypt(ctx, k.Value, store.KeyMaterialAAD(k.Name))
		if err != nil {
			t.Fatalf("key %q does not decrypt under the new KEK (the server would refuse to boot): %v", k.Name, err)
		}
		if got != want[k.Name] {
			t.Fatalf("key %q round-tripped to %q, want %q", k.Name, got, want[k.Name])
		}
		// And the old KEK must NOT, or the rotation did not actually move it.
		if _, err := from.Decrypt(ctx, k.Value, store.KeyMaterialAAD(k.Name)); err == nil {
			t.Fatalf("key %q still decrypts under the OLD KEK; it was not re-wrapped", k.Name)
		}
	}

	// Rotation is resumable: a second run is a no-op rather than a failure.
	if n, err := RotateVaultKEK(ctx, st, from, to); err != nil || n != 0 {
		t.Fatalf("second run rotated %d with err %v; want 0, nil (idempotent)", n, err)
	}
}

// TestRotateVaultKEKCoversEveryCredentialPastOnePage pins a completeness
// property of KEK rotation that today rests on an unstated convention two
// packages away: RotateVaultKEK reads every credential with
// ListCredentials(ctx, 0, 0, 0), where limit=0 means "no limit". A future
// refactor that made limit=0 mean a default page size would silently re-wrap
// only the first page and report success — the omission-class outage the
// four-kinds interface was written to prevent, arriving through a different
// door. This seeds well past any plausible default page and asserts EVERY
// credential rotates.
func TestRotateVaultKEKCoversEveryCredentialPastOnePage(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}

	const count = 250 // past the 100 default / 500 max page sizes used elsewhere
	want := make(map[int64]string, count)
	for i := range count {
		cred := &store.Credential{TargetID: target.ID, Username: fmt.Sprintf("u%03d", i), SecretType: "password"}
		if err := st.CreateCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		plain := fmt.Sprintf("secret-%03d", i)
		enc, err := from.Encrypt(ctx, plain, store.CredentialAAD(target.ID, cred.ID))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
			t.Fatal(err)
		}
		want[cred.ID] = plain
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != count {
		t.Fatalf("rotated %d of %d credentials — rotation stopped short of the full set", n, count)
	}
	// Every single one must now decrypt under the new KEK and not the old.
	for id, plain := range want {
		got, err := st.GetCredential(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := to.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, id)); err != nil || pt != plain {
			t.Fatalf("credential %d not rotated under the new KEK: %q %v", id, pt, err)
		}
		if _, err := from.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, id)); err == nil {
			t.Fatalf("credential %d still decrypts under the OLD KEK", id)
		}
	}
}
