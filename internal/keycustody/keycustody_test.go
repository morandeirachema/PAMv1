package keycustody

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newVault builds a real local-KEK vault, so the tests exercise the actual
// envelope and AAD binding rather than a stub.
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

// genCounter returns a generator that produces a distinct key each call, so a
// test can tell whose key won the claim.
func genCounter(prefix string) (func() ([]byte, error), *int) {
	n := 0
	return func() ([]byte, error) {
		n++
		return []byte(prefix + "-key-" + string(rune('A'+n-1))), nil
	}, &n
}

// TestReplicasConvergeOnOneKey is the whole point of the package: several
// replicas starting at once, each generating its own candidate, must all end up
// serving the same key. Before Phase 42 each kept its own — which is what made a
// scaled deployment hand out different SSH host keys and different CA keys.
func TestReplicasConvergeOnOneKey(t *testing.T) {
	st, v := memstore.New(), newVault(t)
	const replicas = 8

	var wg sync.WaitGroup
	got := make([][]byte, replicas)
	errs := make([]error, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			gen, _ := genCounter("replica" + string(rune('0'+i)))
			pem, _, err := Ensure(context.Background(), st, v, NameSSHHostKey, "", gen)
			got[i], errs[i] = pem, err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	for i := 1; i < replicas; i++ {
		if string(got[i]) != string(got[0]) {
			t.Fatalf("replica %d holds %q but replica 0 holds %q — the cluster has two host keys",
				i, got[i], got[0])
		}
	}
	if len(got[0]) == 0 {
		t.Fatal("no key was returned")
	}
}

// TestExistingFileSeedsCustody proves an upgrade does not rotate the key out from
// under a single-node deployment: the key already on disk becomes the shared one.
func TestExistingFileSeedsCustody(t *testing.T) {
	st, v := memstore.New(), newVault(t)
	path := filepath.Join(t.TempDir(), "host_key")
	const existing = "the-key-this-deployment-already-serves"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	gen, calls := genCounter("fresh")

	pem, adopted, err := Ensure(context.Background(), st, v, NameSSHHostKey, path, gen)
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != existing {
		t.Fatalf("key changed on upgrade: got %q, want %q", pem, existing)
	}
	if adopted {
		t.Fatal("the seeding replica should not report adopting someone else's key")
	}
	if *calls != 0 {
		t.Fatal("a fresh key was generated even though the file held one")
	}

	// A second replica with no file of its own adopts the seeded key and mirrors it.
	path2 := filepath.Join(t.TempDir(), "host_key")
	gen2, _ := genCounter("other")
	pem2, adopted2, err := Ensure(context.Background(), st, v, NameSSHHostKey, path2, gen2)
	if err != nil {
		t.Fatal(err)
	}
	if string(pem2) != existing {
		t.Fatalf("second replica holds %q, want the shared %q", pem2, existing)
	}
	if !adopted2 {
		t.Fatal("the second replica should report that it adopted the shared key")
	}
	mirrored, err := os.ReadFile(path2)
	if err != nil || string(mirrored) != existing {
		t.Fatalf("the adopted key was not mirrored to disk: %q %v", mirrored, err)
	}
}

// TestKeysAreSealedAndNameBound proves the store never holds usable key material,
// and that an envelope is bound to its own name — a host key cannot be served up
// as the CA key.
func TestKeysAreSealedAndNameBound(t *testing.T) {
	st, v := memstore.New(), newVault(t)
	gen := func() ([]byte, error) { return []byte("PRIVATE-KEY-BYTES"), nil }

	if _, _, err := Ensure(context.Background(), st, v, NameSSHHostKey, "", gen); err != nil {
		t.Fatal(err)
	}
	stored, err := st.EnsureKeyMaterial(context.Background(), NameSSHHostKey, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "PRIVATE-KEY-BYTES") {
		t.Fatalf("the store holds usable key material: %q", stored)
	}
	// The host key's envelope must not unwrap as the CA key.
	if _, err := v.Decrypt(context.Background(), stored, "keymaterial:"+NameSSHCAKey); err == nil {
		t.Fatal("a host-key envelope unwrapped under the CA key's AAD")
	}
}

// TestUnwrappableKeyIsFatal proves a key that cannot be decrypted stops startup
// instead of silently generating a new one — quietly rotating the host key or the
// CA would break every target that pinned them.
func TestUnwrappableKeyIsFatal(t *testing.T) {
	st := memstore.New()
	first, second := newVault(t), newVault(t) // second has a different master key
	gen := func() ([]byte, error) { return []byte("original"), nil }

	if _, _, err := Ensure(context.Background(), st, first, NameSSHCAKey, "", gen); err != nil {
		t.Fatal(err)
	}
	pem, _, err := Ensure(context.Background(), st, second, NameSSHCAKey, "", gen)
	if err == nil {
		t.Fatal("expected an error when the stored key cannot be unwrapped")
	}
	if pem != nil {
		t.Fatalf("a key was returned despite the failure: %q", pem)
	}
	if !strings.Contains(err.Error(), "master key") {
		t.Fatalf("error %q should point at the likely cause (wrong master key)", err)
	}
}

// TestGeneratorFailurePropagates proves a failing generator is reported rather
// than yielding an empty key.
func TestGeneratorFailurePropagates(t *testing.T) {
	st, v := memstore.New(), newVault(t)
	want := errors.New("no entropy")
	if _, _, err := Ensure(context.Background(), st, v, NameSSHHostKey, "",
		func() ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
