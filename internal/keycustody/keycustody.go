// Package keycustody gives pamv1's long-lived SSH keys — the proxy host key and
// the Zero Standing Privilege CA key — a single custodian shared by every replica.
//
// Both keys used to live in a local file. That is correct on one node and wrong
// the moment a second replica starts: each pod generated its own, so operators
// saw the proxy's host key change depending on which pod answered (indistinguishable
// from a MITM), a certificate minted by one pod was not trusted by targets
// configured with another pod's CA, and the operator-certificate challenge — an
// HMAC keyed off the CA private key — failed across pods. The Helm chart ships a
// ReadWriteOnce PVC that defaults to emptyDir, so nothing stopped that happening.
//
// Custody now works like this:
//
//  1. If a file path is configured and holds a key, that key is the candidate —
//     an existing single-node deployment seeds the shared custody with the key it
//     already has, so its host key does not change under it.
//  2. Otherwise a fresh key is generated as the candidate.
//  3. The candidate is encrypted with the vault KEK and offered to the store,
//     which stores it only if no key is held yet and returns whatever is stored.
//     N replicas racing at startup therefore converge on one key: exactly one
//     wins the claim and the rest adopt it.
//  4. If a path is configured, the authoritative key is mirrored back to it, so
//     tooling that reads the file keeps working and a later single-node start
//     seeds the same value.
//
// The database only ever holds the vault envelope, never usable key material, and
// the AAD binds each envelope to its name so a host key cannot be substituted for
// the CA key.
package keycustody

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/morandeirachema/pamv1/internal/store"
)

// Names of the keys under custody. They are stable strings: changing one would
// orphan the key a deployment already holds.
const (
	NameSSHHostKey = "ssh_host_key"
	NameSSHCAKey   = "ssh_ca_key"
)

// Store is the slice of the store this package needs.
type Store interface {
	EnsureKeyMaterial(ctx context.Context, name, value string) (string, error)
}

// Vault wraps and unwraps the key material with the deployment's KEK.
type Vault interface {
	Encrypt(ctx context.Context, plaintext, aad string) (string, error)
	Decrypt(ctx context.Context, token, aad string) (string, error)
}

// Ensure returns the authoritative PEM for the named key, claiming custody in the
// store if nobody holds it yet. generate produces a fresh key when there is no
// file to seed from; path may be empty, in which case nothing is read or written
// on disk and the key lives only in the store.
//
// Adopted reports whether this process took over a key another replica had
// already claimed — worth logging, because it is the moment a deployment stops
// having two different host keys.
func Ensure(ctx context.Context, st Store, v Vault, name, path string, generate func() ([]byte, error)) (pem []byte, adopted bool, err error) {
	if st == nil || v == nil {
		return nil, false, errors.New("keycustody: a store and a vault are required")
	}
	candidate, fromFile, err := candidateKey(path, generate)
	if err != nil {
		return nil, false, err
	}
	sealed, err := v.Encrypt(ctx, string(candidate), store.KeyMaterialAAD(name))
	if err != nil {
		return nil, false, fmt.Errorf("keycustody: seal %s: %w", name, err)
	}
	storedToken, err := st.EnsureKeyMaterial(ctx, name, sealed)
	if err != nil {
		return nil, false, fmt.Errorf("keycustody: claim %s: %w", name, err)
	}
	storedPEM, err := v.Decrypt(ctx, storedToken, store.KeyMaterialAAD(name))
	if err != nil {
		// A key we cannot unwrap is fatal, never a reason to fall back to a fresh
		// one: silently rotating the host key or the CA would break every target.
		return nil, false, fmt.Errorf("keycustody: unwrap %s (wrong master key?): %w", name, err)
	}
	authoritative := []byte(storedPEM)
	adopted = string(authoritative) != string(candidate)

	if path != "" && (adopted || !fromFile) {
		if werr := os.WriteFile(path, authoritative, 0o600); werr != nil {
			// The key itself is fine — only the on-disk mirror failed — so report it
			// without failing startup.
			return authoritative, adopted, fmt.Errorf("keycustody: mirror %s to %s: %w", name, path, werr)
		}
	}
	return authoritative, adopted, nil
}

// candidateKey reads the key at path, or generates one when there is nothing to
// read. fromFile distinguishes the two so the caller knows whether the on-disk
// mirror is already up to date.
func candidateKey(path string, generate func() ([]byte, error)) (key []byte, fromFile bool, err error) {
	if path != "" {
		data, rerr := os.ReadFile(path)
		if rerr == nil && len(data) > 0 {
			return data, true, nil
		}
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, false, fmt.Errorf("keycustody: read %s: %w", path, rerr)
		}
	}
	generated, err := generate()
	if err != nil {
		return nil, false, err
	}
	return generated, false, nil
}
