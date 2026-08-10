package store_test

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestCredentialIsZSP pins the Zero Standing Privilege predicate that guards
// every secret-delivering path: only a SecretTypeSSHCA credential is ZSP (it
// carries no stored secret to decrypt or reveal), and the check must key off the
// named constant, not a bare literal a future path could mistype.
func TestCredentialIsZSP(t *testing.T) {
	if store.SecretTypeSSHCA != "ssh_ca" {
		t.Fatalf("SecretTypeSSHCA = %q, want ssh_ca (the stored/wire value must not change)", store.SecretTypeSSHCA)
	}
	for _, tc := range []struct {
		secretType string
		want       bool
	}{
		{store.SecretTypeSSHCA, true},
		{store.SecretTypePassword, false},
		{store.SecretTypeSSHKey, false},
		{"", false},
		{"sshca", false}, // a near-miss must NOT read as ZSP
	} {
		if got := (store.Credential{SecretType: tc.secretType}).IsZSP(); got != tc.want {
			t.Errorf("Credential{SecretType:%q}.IsZSP() = %v, want %v", tc.secretType, got, tc.want)
		}
	}
}
