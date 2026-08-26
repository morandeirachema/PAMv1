// Package storetest provides a reusable conformance suite for the store.Store
// contract. Both memstore and pgstore run RunStoreContract against a fresh,
// empty store so the two implementations are held to identical behavior — and so
// the PostgreSQL SQL (which memstore's map-based tests can't exercise) is
// actually verified against a live database in CI.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// testAuditKey is a fixed 32-byte HMAC key for the audit-chain contract.
func testAuditKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// RunAuditChainContract verifies the tamper-evident primary-audit chain against a
// store: enabling it links each appended event to the previous one's HMAC, and
// the chain verifies intact. Tamper *detection* is store-specific (it needs to
// mutate a stored row) and lives in each store's own tests.
func RunAuditChainContract(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	st.EnableAuditChain(testAuditKey())

	var events []store.AuditEvent
	for i := 0; i < 3; i++ {
		e := store.AuditEvent{Actor: "alice", Action: "credential.reveal", Detail: fmt.Sprintf("credential:%d", i)}
		if err := st.AppendAudit(ctx, &e); err != nil {
			t.Fatalf("AppendAudit(chained): %v", err)
		}
		if len(e.HMAC) == 0 {
			t.Fatalf("event %d: chain HMAC was not set", i)
		}
		events = append(events, e)
	}
	if !bytes.Equal(events[1].PrevHash, events[0].HMAC) || !bytes.Equal(events[2].PrevHash, events[1].HMAC) {
		t.Fatal("audit chain not linked: an event's prev_hash != the previous event's hmac")
	}
	ok, brokeAt, err := st.VerifyAuditChain(ctx)
	if err != nil || !ok || brokeAt != 0 {
		t.Fatalf("VerifyAuditChain(intact): ok=%v brokeAt=%d err=%v", ok, brokeAt, err)
	}

	// GetAuditHead returns the most recent chained event (for signed checkpoints).
	head, err := st.GetAuditHead(ctx)
	if err != nil || head == nil {
		t.Fatalf("GetAuditHead: head=%v err=%v", head, err)
	}
	if head.ID != events[2].ID || !bytes.Equal(head.HMAC, events[2].HMAC) {
		t.Fatalf("GetAuditHead returned id=%d, want the last appended event id=%d", head.ID, events[2].ID)
	}
}

// RunStoreContract exercises the full Store interface against an empty st,
// asserting the shared semantics (IDs populated, sentinel errors, expiry,
// exclusivity, single-use consumption).
func RunStoreContract(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	future := now.Add(time.Hour)

	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// --- key material (Phase 42): the claim must be atomic, because the whole
	// point is that racing replicas converge on ONE key instead of each keeping
	// its own. ---
	first, err := st.EnsureKeyMaterial(ctx, "contract_key", "sealed-A")
	if err != nil {
		t.Fatalf("EnsureKeyMaterial: %v", err)
	}
	if first != "sealed-A" {
		t.Fatalf("first claim returned %q, want the value it stored", first)
	}
	second, err := st.EnsureKeyMaterial(ctx, "contract_key", "sealed-B")
	if err != nil {
		t.Fatalf("EnsureKeyMaterial (second): %v", err)
	}
	if second != "sealed-A" {
		t.Fatalf("second claim returned %q, want the already-stored %q — a late replica must adopt, not overwrite", second, first)
	}
	if other, err := st.EnsureKeyMaterial(ctx, "contract_key_2", "sealed-C"); err != nil || other != "sealed-C" {
		t.Fatalf("a different name must have its own custody: %q %v", other, err)
	}
	var keyWG sync.WaitGroup
	raced := make([]string, 6)
	for i := range raced {
		keyWG.Add(1)
		go func(i int) {
			defer keyWG.Done()
			v, rerr := st.EnsureKeyMaterial(ctx, "contract_key_race", fmt.Sprintf("sealed-%d", i))
			if rerr == nil {
				raced[i] = v
			}
		}(i)
	}
	keyWG.Wait()
	for i, v := range raced {
		if v == "" {
			t.Fatalf("racer %d failed to claim", i)
		}
		if v != raced[0] {
			t.Fatalf("racers disagreed: %q vs %q", v, raced[0])
		}
	}
	// List + Update exist so a KEK rotation can RE-WRAP these envelopes. Without
	// them `-rotate-kek` re-encrypted credentials, MFA secrets and settings but
	// left the SSH host key and the ZSP CA key sealed under the old key, and the
	// next startup refused to boot — the rotation the documentation tells you to
	// run. List must be ordered by name so a rotation is deterministic.
	mats, err := st.ListKeyMaterial(ctx)
	if err != nil {
		t.Fatalf("ListKeyMaterial: %v", err)
	}
	if len(mats) < 3 {
		t.Fatalf("ListKeyMaterial returned %d keys, want at least the 3 claimed above", len(mats))
	}
	for i := 1; i < len(mats); i++ {
		if mats[i-1].Name >= mats[i].Name {
			t.Fatalf("ListKeyMaterial is not ordered by name: %q before %q", mats[i-1].Name, mats[i].Name)
		}
	}
	if err := st.UpdateKeyMaterial(ctx, "contract_key", "sealed-REWRAPPED"); err != nil {
		t.Fatalf("UpdateKeyMaterial: %v", err)
	}
	if got, _ := st.EnsureKeyMaterial(ctx, "contract_key", "ignored"); got != "sealed-REWRAPPED" {
		t.Fatalf("after re-wrap the stored envelope is %q, want the re-wrapped one", got)
	}
	// A name nobody claimed must fail, so a rotation cannot invent custody of a
	// key that does not exist.
	if err := st.UpdateKeyMaterial(ctx, "contract_key_absent", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateKeyMaterial on an unknown name = %v, want ErrNotFound", err)
	}

	// --- targets ---
	tgt := &store.Target{Name: "web-01", Host: "10.0.0.5", Port: 22, OSType: "linux", Protocol: "ssh", RequireApproval: true,
		RDPClipboard: "deny", RDPClipboardAudit: "meta"}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if tgt.ID == 0 || tgt.CreatedAt.IsZero() {
		t.Fatal("CreateTarget did not populate ID/CreatedAt")
	}
	if got, err := st.GetTarget(ctx, tgt.ID); err != nil || !got.RequireApproval || got.RDPClipboard != "deny" || got.RDPClipboardAudit != "meta" {
		t.Fatalf("GetTarget require_approval/clipboard override: %+v err %v", got, err)
	}
	if err := st.CreateTarget(ctx, &store.Target{Name: "web-01", Host: "x", Port: 22, OSType: "linux", Protocol: "ssh"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate target name: want ErrConflict, got %v", err)
	}
	if ts, err := st.ListTargets(ctx, 0, 0); err != nil || len(ts) != 1 {
		t.Fatalf("ListTargets: %d err %v", len(ts), err)
	}
	if _, err := st.GetTarget(ctx, 99999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTarget missing: want ErrNotFound, got %v", err)
	}

	// --- list windows (Phase 44): id-ascending, strictly after the cursor,
	// capped at limit; limit <= 0 returns everything (in-process sweeps). ---
	tgt2 := &store.Target{Name: "web-02", Host: "10.0.0.6", Port: 22, OSType: "linux", Protocol: "ssh"}
	tgt3 := &store.Target{Name: "web-03", Host: "10.0.0.7", Port: 22, OSType: "linux", Protocol: "ssh"}
	for _, extra := range []*store.Target{tgt2, tgt3} {
		if err := st.CreateTarget(ctx, extra); err != nil {
			t.Fatalf("CreateTarget(%s): %v", extra.Name, err)
		}
	}
	if page, err := st.ListTargets(ctx, 2, 0); err != nil || len(page) != 2 || page[0].ID != tgt.ID || page[1].ID != tgt2.ID {
		t.Fatalf("ListTargets(limit=2): %+v err %v", page, err)
	}
	if page, err := st.ListTargets(ctx, 2, tgt2.ID); err != nil || len(page) != 1 || page[0].ID != tgt3.ID {
		t.Fatalf("ListTargets(after=%d): %+v err %v", tgt2.ID, page, err)
	}
	if page, err := st.ListTargets(ctx, 0, tgt3.ID); err != nil || len(page) != 0 {
		t.Fatalf("ListTargets(after=last): %+v err %v", page, err)
	}

	// --- UpdateTarget (Phase 44): edits in place — no delete + recreate, so
	// dependents survive; ErrConflict on a name collision, ErrNotFound when absent. ---
	tgt.Host, tgt.Port, tgt.RequireApproval = "10.0.0.50", 2222, false
	tgt.RDPClipboard, tgt.RDPClipboardAudit = "readonly", ""
	if err := st.UpdateTarget(ctx, tgt); err != nil {
		t.Fatalf("UpdateTarget: %v", err)
	}
	if got, err := st.GetTarget(ctx, tgt.ID); err != nil || got.Host != "10.0.0.50" || got.Port != 2222 || got.RequireApproval ||
		got.RDPClipboard != "readonly" || got.RDPClipboardAudit != "" {
		t.Fatalf("after UpdateTarget: %+v err %v", got, err)
	}
	if err := st.UpdateTarget(ctx, &store.Target{ID: tgt2.ID, Name: "web-01", Host: "x", Port: 22, OSType: "linux", Protocol: "ssh"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("UpdateTarget onto a taken name: want ErrConflict, got %v", err)
	}
	if err := st.UpdateTarget(ctx, &store.Target{ID: 99999, Name: "ghost", Host: "x", Port: 22, OSType: "linux", Protocol: "ssh"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateTarget missing: want ErrNotFound, got %v", err)
	}
	// Renaming to its OWN current name is not a conflict.
	if err := st.UpdateTarget(ctx, tgt); err != nil {
		t.Fatalf("UpdateTarget(same name): %v", err)
	}
	for _, extra := range []*store.Target{tgt2, tgt3} {
		if err := st.DeleteTarget(ctx, extra.ID); err != nil {
			t.Fatalf("DeleteTarget(%s): %v", extra.Name, err)
		}
	}

	// --- credentials ---
	cred := &store.Credential{TargetID: tgt.ID, Username: "root", SecretType: "password", SecretEnc: "v2:one"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{TargetID: 99999, Username: "x", SecretType: "password", SecretEnc: "v2:z"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential for missing target: want ErrNotFound, got %v", err)
	}
	if cs, err := st.ListCredentials(ctx, tgt.ID, 0, 0); err != nil || len(cs) != 1 {
		t.Fatalf("ListCredentials: %d err %v", len(cs), err)
	} else if cs[0].SecretEnc != "v2:one" {
		// ListCredentials MUST stay full-fidelity — real internal callers
		// (findProvisioner, lookupTargetCred, the lifecycle reconciler,
		// -rotate-kek) list first and decrypt from the result afterward.
		// Regression guard: Phase 145 briefly stripped this and broke every
		// one of them before the mistake was caught by the proxy test suite.
		t.Fatalf("ListCredentials must return SecretEnc, got %q", cs[0].SecretEnc)
	}
	if cs, err := st.ListCredentials(ctx, tgt.ID, 5, cred.ID); err != nil || len(cs) != 0 {
		t.Fatalf("ListCredentials(after=last): %d err %v", len(cs), err)
	}
	// ListCredentialsMeta (Phase 145) is the narrower, display-only sibling —
	// SecretEnc must be empty here, the opposite of ListCredentials above.
	if cs, err := st.ListCredentialsMeta(ctx, tgt.ID, 0, 0); err != nil || len(cs) != 1 {
		t.Fatalf("ListCredentialsMeta: %d err %v", len(cs), err)
	} else if cs[0].SecretEnc != "" {
		t.Fatalf("ListCredentialsMeta must not populate SecretEnc, got %q", cs[0].SecretEnc)
	}
	if err := st.RotateCredentialSecret(ctx, cred.ID, "v2:two", now); err != nil {
		t.Fatalf("RotateCredentialSecret: %v", err)
	}
	got, _ := st.GetCredential(ctx, cred.ID)
	if got.SecretEnc != "v2:two" || got.RotatedAt == nil {
		t.Fatalf("after rotate: secret=%q rotated_at=%v", got.SecretEnc, got.RotatedAt)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, "v2:three"); err != nil {
		t.Fatalf("UpdateCredentialSecretEnc: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.SecretEnc != "v2:three" || got.RotatedAt == nil {
		t.Fatal("UpdateCredentialSecretEnc must not clear rotated_at")
	}

	// --- DoubleLock (Phase 135) ---
	if err := st.SetCredentialDoubleLock(ctx, cred.ID, "alice", "verifier-1", "dl-enc-1"); err != nil {
		t.Fatalf("SetCredentialDoubleLock: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.DoubleLockHolder != "alice" || got.DoubleLockVerifier != "verifier-1" || got.DoubleLockEnc != "dl-enc-1" {
		t.Fatalf("after SetCredentialDoubleLock: %+v", got)
	}
	// ListCredentials must carry the DoubleLock fields too (the reconciler and
	// -rotate-kek's callers see the same struct shape either way).
	if cs, err := st.ListCredentials(ctx, tgt.ID, 0, 0); err != nil || len(cs) != 1 {
		t.Fatalf("ListCredentials: %d err %v", len(cs), err)
	} else if cs[0].DoubleLockHolder != "alice" || cs[0].DoubleLockVerifier != "verifier-1" || cs[0].DoubleLockEnc != "dl-enc-1" {
		t.Fatalf("ListCredentials DoubleLock fields: holder=%q verifier=%q enc=%q", cs[0].DoubleLockHolder, cs[0].DoubleLockVerifier, cs[0].DoubleLockEnc)
	}
	// ListCredentialsMeta strips DoubleLockVerifier/DoubleLockEnc (proven
	// non-empty above, so this is the query actually doing its job, not a
	// coincidence of zero values) but keeps DoubleLockHolder — the one
	// DoubleLock field that is json-visible and meant for display.
	if cs, err := st.ListCredentialsMeta(ctx, tgt.ID, 0, 0); err != nil || len(cs) != 1 {
		t.Fatalf("ListCredentialsMeta: %d err %v", len(cs), err)
	} else if cs[0].DoubleLockHolder != "alice" || cs[0].DoubleLockVerifier != "" || cs[0].DoubleLockEnc != "" {
		t.Fatalf("ListCredentialsMeta DoubleLock fields: holder=%q verifier=%q enc=%q", cs[0].DoubleLockHolder, cs[0].DoubleLockVerifier, cs[0].DoubleLockEnc)
	}
	if err := st.SetCredentialDoubleLock(ctx, 999999, "x", "y", "z"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetCredentialDoubleLock missing: want ErrNotFound, got %v", err)
	}
	// UpdateCredentialSecretEnc is the KEK re-wrap path (same plaintext, new
	// KEK) and must NOT disturb DoubleLock.
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, "v2:four"); err != nil {
		t.Fatalf("UpdateCredentialSecretEnc: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.DoubleLockHolder != "alice" || got.DoubleLockVerifier != "verifier-1" || got.DoubleLockEnc != "dl-enc-1" {
		t.Fatalf("UpdateCredentialSecretEnc (KEK re-wrap) must not clear DoubleLock: %+v", got)
	}
	// RotateCredentialSecret is a REAL secret change and must clear DoubleLock —
	// the password-derived DoubleLockEnc now seals a stale secret.
	if err := st.RotateCredentialSecret(ctx, cred.ID, "v2:five", now); err != nil {
		t.Fatalf("RotateCredentialSecret: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.DoubleLockHolder != "" || got.DoubleLockVerifier != "" || got.DoubleLockEnc != "" {
		t.Fatalf("RotateCredentialSecret must clear DoubleLock: %+v", got)
	}
	// ClearCredentialDoubleLock on its own.
	if err := st.SetCredentialDoubleLock(ctx, cred.ID, "bob", "verifier-2", "dl-enc-2"); err != nil {
		t.Fatalf("SetCredentialDoubleLock: %v", err)
	}
	if err := st.ClearCredentialDoubleLock(ctx, cred.ID); err != nil {
		t.Fatalf("ClearCredentialDoubleLock: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.DoubleLockHolder != "" || got.DoubleLockVerifier != "" || got.DoubleLockEnc != "" {
		t.Fatalf("after ClearCredentialDoubleLock: %+v", got)
	}
	if err := st.ClearCredentialDoubleLock(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ClearCredentialDoubleLock missing: want ErrNotFound, got %v", err)
	}

	// --- grants ---
	g := &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "alice", CreatedBy: "grantor-gary"}
	if err := st.CreateTargetGrant(ctx, g); err != nil {
		t.Fatalf("CreateTargetGrant: %v", err)
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "alice"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate grant: want ErrConflict, got %v", err)
	}
	// The creator round-trips (Phase 46): the certification four-eyes check
	// depends on it.
	if gs, err := st.ListTargetGrants(ctx, tgt.ID); err != nil || len(gs) != 1 || gs[0].CreatedBy != "grantor-gary" {
		t.Fatalf("ListTargetGrants: %+v err %v", gs, err)
	}
	if err := st.DeleteTargetGrant(ctx, g.ID); err != nil {
		t.Fatalf("DeleteTargetGrant: %v", err)
	}

	// --- safes (Phase 17): container membership as an effective grant ---
	// The safe carries its own access policy since Phase 58 (require_approval +
	// a dual-control floor), so it must round-trip through create, get, list and
	// update — a policy field that silently reverts to zero on one of those paths
	// would read as "no policy" at every enforcement site.
	sf := &store.Safe{Name: "prod-db", Description: "production databases",
		RequireApproval: true, MinApprovers: 2}
	if err := st.CreateSafe(ctx, sf); err != nil {
		t.Fatalf("CreateSafe: %v", err)
	}
	if got, err := st.GetSafe(ctx, sf.ID); err != nil || !got.RequireApproval || got.MinApprovers != 2 {
		t.Fatalf("safe policy round-trip = %+v, %v; want require_approval + 2 approvers", got, err)
	}
	if err := st.CreateSafe(ctx, &store.Safe{Name: "prod-db"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate safe: want ErrConflict, got %v", err)
	}
	if got, err := st.GetSafe(ctx, sf.ID); err != nil || got.Name != "prod-db" {
		t.Fatalf("GetSafe: %+v err %v", got, err)
	}
	sm := &store.SafeMember{SafeID: sf.ID, SubjectType: "role", Subject: "user", CanManage: false, CreatedBy: "grantor-gary"}
	if err := st.AddSafeMember(ctx, sm); err != nil {
		t.Fatalf("AddSafeMember: %v", err)
	}
	if ms, err := st.ListSafeMembers(ctx, sf.ID); err != nil || len(ms) != 1 || ms[0].CreatedBy != "grantor-gary" {
		t.Fatalf("ListSafeMembers created_by: %+v err %v", ms, err)
	}
	if err := st.AddSafeMember(ctx, &store.SafeMember{SafeID: sf.ID, SubjectType: "role", Subject: "user"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate safe member: want ErrConflict, got %v", err)
	}
	if err := st.AddSafeMember(ctx, &store.SafeMember{SafeID: 999999, SubjectType: "user", Subject: "x"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("member on missing safe: want ErrNotFound, got %v", err)
	}
	// A target with no grants is unrestricted; placing it in a safe restricts it
	// to the safe's members, surfaced through EffectiveTargetGrants.
	if eg, err := st.EffectiveTargetGrants(ctx, tgt.ID); err != nil || len(eg) != 0 {
		t.Fatalf("EffectiveTargetGrants(ungated): %d err %v", len(eg), err)
	}
	if err := st.AssignTargetSafe(ctx, tgt.ID, &sf.ID); err != nil {
		t.Fatalf("AssignTargetSafe: %v", err)
	}
	eg, err := st.EffectiveTargetGrants(ctx, tgt.ID)
	if err != nil || len(eg) != 1 || eg[0].SubjectType != "role" || eg[0].Subject != "user" {
		t.Fatalf("EffectiveTargetGrants(in safe): %+v err %v", eg, err)
	}
	// The target now carries its safe id.
	if tt, _ := st.GetTarget(ctx, tgt.ID); tt.SafeID == nil || *tt.SafeID != sf.ID {
		t.Fatalf("target safe_id not persisted: %+v", tt)
	}
	// UpdateTarget edits fields but never touches the safe assignment — and it
	// refreshes the caller's struct with the stored SafeID.
	tgt.Host = "10.0.0.51"
	if err := st.UpdateTarget(ctx, tgt); err != nil {
		t.Fatalf("UpdateTarget(in safe): %v", err)
	}
	if tgt.SafeID == nil || *tgt.SafeID != sf.ID {
		t.Fatalf("UpdateTarget did not refresh SafeID from the stored row: %+v", tgt.SafeID)
	}
	if tt, _ := st.GetTarget(ctx, tgt.ID); tt.SafeID == nil || *tt.SafeID != sf.ID || tt.Host != "10.0.0.51" {
		t.Fatalf("UpdateTarget must preserve the safe assignment: %+v", tt)
	}
	// UpdateSafe renames in place; members and assignment are untouched.
	sf.Name, sf.Description = "prod-db-renamed", "renamed"
	sf.MinApprovers = 3 // raising the dual-control floor must persist
	if err := st.UpdateSafe(ctx, sf); err != nil {
		t.Fatalf("UpdateSafe: %v", err)
	}
	if got, err := st.GetSafe(ctx, sf.ID); err != nil || got.Name != "prod-db-renamed" || got.Description != "renamed" {
		t.Fatalf("after UpdateSafe: %+v err %v", got, err)
	}
	if got, err := st.GetSafe(ctx, sf.ID); err != nil || !got.RequireApproval || got.MinApprovers != 3 {
		t.Fatalf("UpdateSafe dropped the policy: %+v, %v", got, err)
	}
	if listed, err := st.ListSafes(ctx, 10, 0); err != nil || len(listed) == 0 || listed[0].MinApprovers != 3 {
		t.Fatalf("ListSafes does not carry the policy: %+v, %v", listed, err)
	}
	otherSafe := &store.Safe{Name: "dmz"}
	if err := st.CreateSafe(ctx, otherSafe); err != nil {
		t.Fatalf("CreateSafe(other): %v", err)
	}
	if err := st.UpdateSafe(ctx, &store.Safe{ID: otherSafe.ID, Name: "prod-db-renamed"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("UpdateSafe onto a taken name: want ErrConflict, got %v", err)
	}
	if err := st.UpdateSafe(ctx, &store.Safe{ID: 999999, Name: "ghost"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateSafe missing: want ErrNotFound, got %v", err)
	}
	if safes, err := st.ListSafes(ctx, 1, sf.ID); err != nil || len(safes) != 1 || safes[0].ID != otherSafe.ID {
		t.Fatalf("ListSafes(after=%d): %+v err %v", sf.ID, safes, err)
	}
	if err := st.DeleteSafe(ctx, otherSafe.ID); err != nil {
		t.Fatalf("DeleteSafe(other): %v", err)
	}
	if err := st.DeleteSafeMember(ctx, sm.ID); err != nil {
		t.Fatalf("DeleteSafeMember: %v", err)
	}
	// Deleting the safe unassigns the target (ON DELETE SET NULL) rather than
	// deleting it.
	if err := st.DeleteSafe(ctx, sf.ID); err != nil {
		t.Fatalf("DeleteSafe: %v", err)
	}
	if tt, _ := st.GetTarget(ctx, tgt.ID); tt == nil || tt.SafeID != nil {
		t.Fatalf("target should survive safe deletion with a nil safe_id: %+v", tt)
	}

	// --- Safe.Personal (Phase 139): set at creation, immutable after ---
	// Round-trips through create/get/list, and — the property that actually
	// matters — UpdateSafe must never change it, even when the caller's
	// struct carries a different value, the same way it never changes
	// CreatedAt.
	psf := &store.Safe{Name: "alice-personal", Personal: true}
	if err := st.CreateSafe(ctx, psf); err != nil {
		t.Fatalf("CreateSafe(personal): %v", err)
	}
	if got, err := st.GetSafe(ctx, psf.ID); err != nil || !got.Personal {
		t.Fatalf("GetSafe did not round-trip Personal: %+v err %v", got, err)
	}
	if listed, err := st.ListSafes(ctx, 10, 0); err != nil {
		t.Fatalf("ListSafes: %v", err)
	} else {
		found := false
		for _, s := range listed {
			if s.ID == psf.ID && s.Personal {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListSafes did not carry Personal for safe %d: %+v", psf.ID, listed)
		}
	}
	// UpdateSafe's incoming struct explicitly claims Personal:false — a bug
	// here would silently un-personalize the safe.
	if err := st.UpdateSafe(ctx, &store.Safe{ID: psf.ID, Name: "alice-personal-renamed", Personal: false}); err != nil {
		t.Fatalf("UpdateSafe(personal): %v", err)
	}
	if got, err := st.GetSafe(ctx, psf.ID); err != nil || !got.Personal {
		t.Fatalf("UpdateSafe must never change Personal: %+v err %v", got, err)
	}
	if err := st.DeleteSafe(ctx, psf.ID); err != nil {
		t.Fatalf("DeleteSafe(personal): %v", err)
	}

	// --- subject-indexed grants (Phase 189): the same relation, read backwards ---
	// GrantsForSubjects and GatedTargetIDs must agree with EffectiveTargetGrants
	// target for target — they are one relation read from two sides, and a store
	// where they disagree would let a review report access the connect gate does
	// not actually give (or hide access it does).
	subjSafe := &store.Safe{Name: "subject-index-safe"}
	if err := st.CreateSafe(ctx, subjSafe); err != nil {
		t.Fatalf("CreateSafe(subject): %v", err)
	}
	subjTargets := map[string]int64{}
	for _, name := range []string{"si-open", "si-direct", "si-role", "si-safe", "si-other"} {
		tt := &store.Target{Name: name, Host: "10.9.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
		if err := st.CreateTarget(ctx, tt); err != nil {
			t.Fatalf("CreateTarget(%s): %v", name, err)
		}
		subjTargets[name] = tt.ID
		// The safe assignment is AssignTargetSafe's job, never a field on the
		// struct handed to CreateTarget — see store.TargetStore.CreateTarget.
		if name == "si-safe" {
			if err := st.AssignTargetSafe(ctx, tt.ID, &subjSafe.ID); err != nil {
				t.Fatalf("AssignTargetSafe(%s): %v", name, err)
			}
		}
	}
	for _, g := range []store.TargetGrant{
		{TargetID: subjTargets["si-direct"], SubjectType: "user", Subject: "si-alice"},
		{TargetID: subjTargets["si-role"], SubjectType: "role", Subject: "auditor"},
		{TargetID: subjTargets["si-other"], SubjectType: "user", Subject: "si-mallory"},
	} {
		gg := g
		if err := st.CreateTargetGrant(ctx, &gg); err != nil {
			t.Fatalf("CreateTargetGrant(subject): %v", err)
		}
	}
	subjMember := &store.SafeMember{SafeID: subjSafe.ID, SubjectType: "user", Subject: "si-alice"}
	if err := st.AddSafeMember(ctx, subjMember); err != nil {
		t.Fatalf("AddSafeMember(subject): %v", err)
	}
	subjects := []store.GrantSubject{{Type: "user", Name: "si-alice"}, {Type: "role", Name: "auditor"}}
	sgs, err := st.GrantsForSubjects(ctx, subjects)
	if err != nil {
		t.Fatalf("GrantsForSubjects: %v", err)
	}
	seen := map[string]store.SubjectGrant{}
	for _, sg := range sgs {
		if sg.TargetID == subjTargets["si-other"] {
			t.Fatalf("GrantsForSubjects returned a grant naming somebody else: %+v", sg)
		}
		seen[sg.TargetName] = sg
	}
	if got, ok := seen["si-direct"]; !ok || got.Via != store.GrantViaGrant || got.SubjectType != "user" || got.Subject != "si-alice" {
		t.Fatalf("direct grant not reported subject-side: %+v (present=%v)", got, ok)
	}
	if got, ok := seen["si-role"]; !ok || got.Via != store.GrantViaGrant || got.SubjectType != "role" {
		t.Fatalf("role grant not reported subject-side: %+v (present=%v)", got, ok)
	}
	if got, ok := seen["si-safe"]; !ok || got.Via != store.GrantViaSafe || got.SafeID == nil || *got.SafeID != subjSafe.ID {
		t.Fatalf("safe membership not reported subject-side: %+v (present=%v)", got, ok)
	}
	if _, ok := seen["si-open"]; ok {
		t.Fatalf("an ungated target must not appear as a grant: it is open, which is a fact about the target")
	}
	// TargetName is joined in: the answer is read by a person, not by an id.
	if seen["si-direct"].TargetName != "si-direct" {
		t.Fatalf("GrantsForSubjects did not join the target name: %+v", seen["si-direct"])
	}
	// Ordering is target id ascending, so a caller can group without sorting.
	for i := 1; i < len(sgs); i++ {
		if sgs[i-1].TargetID > sgs[i].TargetID {
			t.Fatalf("GrantsForSubjects out of target order: %+v", sgs)
		}
	}
	// No subjects ⇒ no grants, and never an error: a principal with no
	// identifiers is a legitimate (if useless) question to ask.
	aliasContract(t, st, appAliasFixture(t, st))

	if none, err := st.GrantsForSubjects(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("GrantsForSubjects(nil) = %+v, %v", none, err)
	}
	// GatedTargetIDs must equal "EffectiveTargetGrants is non-empty", for every
	// target in the estate — that is the whole contract, so check it that way.
	gatedIDs, err := st.GatedTargetIDs(ctx)
	if err != nil {
		t.Fatalf("GatedTargetIDs: %v", err)
	}
	gatedSet := map[int64]bool{}
	for _, id := range gatedIDs {
		gatedSet[id] = true
	}
	allTargets, err := st.ListTargets(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	for i := range allTargets {
		eg, err := st.EffectiveTargetGrants(ctx, allTargets[i].ID)
		if err != nil {
			t.Fatalf("EffectiveTargetGrants(%d): %v", allTargets[i].ID, err)
		}
		if want := len(eg) > 0; want != gatedSet[allTargets[i].ID] {
			t.Fatalf("target %q: EffectiveTargetGrants says gated=%v, GatedTargetIDs says %v",
				allTargets[i].Name, want, gatedSet[allTargets[i].ID])
		}
	}
	for i := 1; i < len(gatedIDs); i++ {
		if gatedIDs[i-1] >= gatedIDs[i] {
			t.Fatalf("GatedTargetIDs must be ascending and distinct: %v", gatedIDs)
		}
	}
	// ReachGrantSnapshot must return exactly what the two calls return
	// separately, AND from one consistent view. Parity is what is checkable here
	// on a quiet estate; the consistency is what the method exists for, and is
	// exercised under concurrent writers in auth's own test.
	snapGrants, snapGated, err := st.ReachGrantSnapshot(ctx, subjects)
	if err != nil {
		t.Fatalf("ReachGrantSnapshot: %v", err)
	}
	if len(snapGrants) != len(sgs) {
		t.Fatalf("ReachGrantSnapshot grants = %d, GrantsForSubjects = %d", len(snapGrants), len(sgs))
	}
	// Compare by VALUE, not by struct equality: SubjectGrant carries a *int64
	// SafeID, so == would compare pointer identity and two equal answers from
	// two calls would never match.
	sameSafe := func(a, b *int64) bool {
		if a == nil || b == nil {
			return a == b
		}
		return *a == *b
	}
	for i := range snapGrants {
		a, b := snapGrants[i], sgs[i]
		if a.TargetID != b.TargetID || a.TargetName != b.TargetName ||
			a.SubjectType != b.SubjectType || a.Subject != b.Subject ||
			a.Via != b.Via || !sameSafe(a.SafeID, b.SafeID) {
			t.Fatalf("ReachGrantSnapshot grant %d = %+v, want %+v", i, a, b)
		}
	}
	if len(snapGated) != len(gatedIDs) {
		t.Fatalf("ReachGrantSnapshot gated = %v, GatedTargetIDs = %v", snapGated, gatedIDs)
	}
	for i := range snapGated {
		if snapGated[i] != gatedIDs[i] {
			t.Fatalf("ReachGrantSnapshot gated = %v, GatedTargetIDs = %v", snapGated, gatedIDs)
		}
	}
	// The invariant that only a snapshot can guarantee: every target a returned
	// grant names must be in the gated set. A grant IS what gates a target, so a
	// grant pointing at an ungated target means the two halves came from
	// different moments.
	snapGatedSet := map[int64]bool{}
	for _, id := range snapGated {
		snapGatedSet[id] = true
	}
	for _, g := range snapGrants {
		if !snapGatedSet[g.TargetID] {
			t.Fatalf("ReachGrantSnapshot: grant on target %d that the same snapshot says nothing gates: %+v", g.TargetID, g)
		}
	}
	// Removing the last member of a safe un-gates its target again (containment
	// is membership, not the safe's existence).
	if err := st.DeleteSafeMember(ctx, subjMember.ID); err != nil {
		t.Fatalf("DeleteSafeMember(subject): %v", err)
	}
	gatedIDs, err = st.GatedTargetIDs(ctx)
	if err != nil {
		t.Fatalf("GatedTargetIDs(after member removal): %v", err)
	}
	for _, id := range gatedIDs {
		if id == subjTargets["si-safe"] {
			t.Fatalf("target in an empty safe still reported as gated")
		}
	}
	for _, name := range []string{"si-open", "si-direct", "si-role", "si-safe", "si-other"} {
		if err := st.DeleteTarget(ctx, subjTargets[name]); err != nil {
			t.Fatalf("DeleteTarget(%s): %v", name, err)
		}
	}
	if err := st.DeleteSafe(ctx, subjSafe.ID); err != nil {
		t.Fatalf("DeleteSafe(subject): %v", err)
	}

	// --- dependent accounts (Phase 17): a credential's consumers ---
	dep := &store.CredentialDependency{CredentialID: cred.ID, Kind: "windows_service", Host: "app-01", Name: "MyService"}
	if err := st.CreateCredentialDependency(ctx, dep); err != nil {
		t.Fatalf("CreateCredentialDependency: %v", err)
	}
	if dep.Port != 5985 {
		t.Fatalf("dependency port default = %d, want 5985", dep.Port)
	}
	if err := st.CreateCredentialDependency(ctx, &store.CredentialDependency{CredentialID: 999999, Kind: "iis_apppool", Host: "h", Name: "n"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dependency on missing credential: want ErrNotFound, got %v", err)
	}
	if ds, err := st.ListCredentialDependencies(ctx, cred.ID); err != nil || len(ds) != 1 || ds[0].Name != "MyService" {
		t.Fatalf("ListCredentialDependencies: %+v err %v", ds, err)
	} else if ds[0].ManagementCredentialID != 0 {
		t.Fatalf("an undeclared management credential must read back as 0, got %d", ds[0].ManagementCredentialID)
	}
	// A declared management credential round-trips (Phase 61): it decides which
	// account pamv1 authenticates to the consumer's host as, so losing it in
	// storage would silently revert to logging in as the rotated account.
	managed := &store.CredentialDependency{
		CredentialID: cred.ID, Kind: "scheduled_task", Host: "app-02", Name: "NightlyJob",
		ManagementCredentialID: cred.ID,
	}
	if err := st.CreateCredentialDependency(ctx, managed); err != nil {
		t.Fatalf("CreateCredentialDependency(managed): %v", err)
	}
	if ds, err := st.ListCredentialDependencies(ctx, cred.ID); err != nil || len(ds) != 2 {
		t.Fatalf("ListCredentialDependencies(2): %+v err %v", ds, err)
	} else {
		var found bool
		for _, d := range ds {
			if d.ID == managed.ID {
				found = true
				if d.ManagementCredentialID != cred.ID {
					t.Fatalf("management credential did not round-trip: %+v", d)
				}
			}
		}
		if !found {
			t.Fatal("the managed dependency is missing from the listing")
		}
	}
	if err := st.DeleteCredentialDependency(ctx, managed.ID); err != nil {
		t.Fatalf("DeleteCredentialDependency(managed): %v", err)
	}
	if err := st.DeleteCredentialDependency(ctx, dep.ID); err != nil {
		t.Fatalf("DeleteCredentialDependency: %v", err)
	}
	if _, err := st.ListCredentialDependencies(ctx, cred.ID); err != nil {
		t.Fatalf("ListCredentialDependencies(empty): %v", err)
	}

	// --- access certification campaigns (Phase 19) ---
	camp := &store.Campaign{Name: "Q3 access review", CreatedBy: "alice"}
	if err := st.CreateCampaign(ctx, camp); err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if camp.Status != "open" {
		t.Fatalf("new campaign status = %q, want open", camp.Status)
	}
	it := &store.CampaignItem{CampaignID: camp.ID, Kind: "target_grant", RefID: 42, SubjectType: "user", Subject: "bob", Detail: "grant on target x", GrantedBy: "grantor-gary"}
	if err := st.AddCampaignItem(ctx, it); err != nil {
		t.Fatalf("AddCampaignItem: %v", err)
	}
	if got, err := st.GetCampaignItem(ctx, it.ID); err != nil || got.GrantedBy != "grantor-gary" {
		t.Fatalf("campaign item granted_by not round-tripped: %+v err %v", got, err)
	}
	if err := st.AddCampaignItem(ctx, &store.CampaignItem{CampaignID: 999999, Kind: "target_grant", RefID: 1, SubjectType: "user", Subject: "z"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("item on missing campaign: want ErrNotFound, got %v", err)
	}
	if items, err := st.ListCampaignItems(ctx, camp.ID); err != nil || len(items) != 1 || items[0].Decision != "pending" {
		t.Fatalf("ListCampaignItems: %+v err %v", items, err)
	}
	if got, err := st.GetCampaignItem(ctx, it.ID); err != nil || got.Subject != "bob" {
		t.Fatalf("GetCampaignItem: %+v err %v", got, err)
	}
	if err := st.DecideCampaignItem(ctx, it.ID, "revoked", "carol", now); err != nil {
		t.Fatalf("DecideCampaignItem: %v", err)
	}
	if got, _ := st.GetCampaignItem(ctx, it.ID); got.Decision != "revoked" || got.DecidedBy != "carol" || got.DecidedAt == nil {
		t.Fatalf("decided item: %+v", got)
	}
	if err := st.CloseCampaign(ctx, camp.ID, now); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	if got, _ := st.GetCampaign(ctx, camp.ID); got.Status != "closed" || got.ClosedAt == nil {
		t.Fatalf("closed campaign: %+v", got)
	}
	if cs, err := st.ListCampaigns(ctx); err != nil || len(cs) != 1 {
		t.Fatalf("ListCampaigns: %d err %v", len(cs), err)
	}

	// --- campaign reminders (Phase 70) ---
	remCamp := &store.Campaign{Name: "reminder", CreatedBy: "alice"}
	remPast := now.Add(-time.Minute)
	remCamp.RemindAt = &remPast
	if err := st.CreateCampaign(ctx, remCamp); err != nil {
		t.Fatalf("CreateCampaign(reminder): %v", err)
	}
	if back, err := st.GetCampaign(ctx, remCamp.ID); err != nil || back.RemindAt == nil {
		t.Fatalf("remind_at did not round-trip: %+v err %v", back, err)
	}
	if r, err := st.ListCampaignsToRemind(ctx, now); err != nil || len(r) != 1 || r[0].ID != remCamp.ID {
		t.Fatalf("ListCampaignsToRemind = %+v err %v, want just %d", r, err, remCamp.ID)
	}
	// Rescheduling takes it out of the window; cancelling removes it entirely.
	later := now.Add(24 * time.Hour)
	if err := st.SetCampaignRemindAt(ctx, remCamp.ID, &later); err != nil {
		t.Fatalf("SetCampaignRemindAt: %v", err)
	}
	if r, _ := st.ListCampaignsToRemind(ctx, now); len(r) != 0 {
		t.Fatalf("a rescheduled reminder is still due: %+v", r)
	}
	if err := st.SetCampaignRemindAt(ctx, remCamp.ID, nil); err != nil {
		t.Fatalf("SetCampaignRemindAt(nil): %v", err)
	}
	if back, _ := st.GetCampaign(ctx, remCamp.ID); back.RemindAt != nil {
		t.Fatalf("a cancelled reminder must be nil, got %v", back.RemindAt)
	}
	if r, _ := st.ListCampaignsToRemind(ctx, now.Add(1000*time.Hour)); len(r) != 0 {
		t.Fatalf("a cancelled reminder came back: %+v", r)
	}
	if err := st.SetCampaignRemindAt(ctx, 999999, &later); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetCampaignRemindAt(missing): want ErrNotFound, got %v", err)
	}
	// A CLOSED campaign never reminds, whatever its schedule says.
	closedRem := &store.Campaign{Name: "closed reminder", CreatedBy: "alice"}
	closedRem.RemindAt = &remPast
	if err := st.CreateCampaign(ctx, closedRem); err != nil {
		t.Fatalf("CreateCampaign(closed reminder): %v", err)
	}
	if err := st.CloseCampaign(ctx, closedRem.ID, now); err != nil {
		t.Fatalf("CloseCampaign: %v", err)
	}
	if r, err := st.ListCampaignsToRemind(ctx, now); err != nil || len(r) != 0 {
		t.Fatalf("a closed campaign reminded: %+v err %v", r, err)
	}

	// --- reviewer assignment (Phase 69) ---
	//
	// A queue is "my PENDING items in OPEN campaigns". Each half of that matters:
	// a decided item is finished work and a closed campaign's leftovers are not
	// work anybody should still be shown.
	qCamp := &store.Campaign{Name: "queue", CreatedBy: "alice", Reviewer: "carol"}
	if err := st.CreateCampaign(ctx, qCamp); err != nil {
		t.Fatalf("CreateCampaign(queue): %v", err)
	}
	if back, err := st.GetCampaign(ctx, qCamp.ID); err != nil || back.Reviewer != "carol" {
		t.Fatalf("campaign reviewer did not round-trip: %+v err %v", back, err)
	}
	mine := &store.CampaignItem{CampaignID: qCamp.ID, Kind: "target_grant", RefID: 1,
		SubjectType: "user", Subject: "u1", Detail: "d", Reviewer: "carol"}
	theirs := &store.CampaignItem{CampaignID: qCamp.ID, Kind: "target_grant", RefID: 2,
		SubjectType: "user", Subject: "u2", Detail: "d", Reviewer: "dave"}
	for _, it := range []*store.CampaignItem{mine, theirs} {
		if err := st.AddCampaignItem(ctx, it); err != nil {
			t.Fatalf("AddCampaignItem: %v", err)
		}
	}
	if got, err := st.GetCampaignItem(ctx, mine.ID); err != nil || got.Reviewer != "carol" {
		t.Fatalf("item reviewer did not round-trip: %+v err %v", got, err)
	}
	if q, err := st.ListItemsForReviewer(ctx, "carol"); err != nil || len(q) != 1 || q[0].ID != mine.ID {
		t.Fatalf("carol's queue = %+v err %v, want just item %d", q, err, mine.ID)
	}
	// Reassignment moves it between queues.
	if err := st.SetCampaignItemReviewer(ctx, mine.ID, "dave"); err != nil {
		t.Fatalf("SetCampaignItemReviewer: %v", err)
	}
	if q, _ := st.ListItemsForReviewer(ctx, "carol"); len(q) != 0 {
		t.Fatalf("carol's queue should be empty after reassignment, got %+v", q)
	}
	if q, _ := st.ListItemsForReviewer(ctx, "dave"); len(q) != 2 {
		t.Fatalf("dave's queue = %d items, want 2", len(q))
	}
	if err := st.SetCampaignItemReviewer(ctx, 999999, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetCampaignItemReviewer(missing): want ErrNotFound, got %v", err)
	}
	// A decided item leaves the queue.
	if err := st.DecideCampaignItem(ctx, mine.ID, "certified", "dave", now); err != nil {
		t.Fatalf("DecideCampaignItem: %v", err)
	}
	if q, _ := st.ListItemsForReviewer(ctx, "dave"); len(q) != 1 {
		t.Fatalf("a decided item stayed in the queue: %+v", q)
	}
	// ...and so does everything in a CLOSED campaign.
	if err := st.CloseCampaign(ctx, qCamp.ID, now); err != nil {
		t.Fatalf("CloseCampaign(queue): %v", err)
	}
	if q, err := st.ListItemsForReviewer(ctx, "dave"); err != nil || len(q) != 0 {
		t.Fatalf("a closed campaign's items are not work: %+v err %v", q, err)
	}

	// --- campaign scope + recurrence (Phase 68) ---
	//
	// Scope fields must SURVIVE a round trip: a campaign whose scope is dropped
	// on read snapshots the whole estate on its next occurrence, which is the
	// failure scoping exists to prevent and would look like nothing at all.
	safeID := int64(4242)
	scoped := &store.Campaign{
		Name: "PCI safe, quarterly", CreatedBy: "alice",
		ScopeKind: store.CampaignScopeSafe, ScopeSafeID: &safeID, RecurDays: 90,
	}
	// A real safe id, so the FK in migration 0029 is satisfied on PostgreSQL.
	pciSafe := &store.Safe{Name: "pci-safe-for-campaign"}
	if err := st.CreateSafe(ctx, pciSafe); err != nil {
		t.Fatalf("CreateSafe: %v", err)
	}
	scoped.ScopeSafeID = &pciSafe.ID
	past := now.Add(-time.Hour)
	scoped.NextRunAt = &past
	if err := st.CreateCampaign(ctx, scoped); err != nil {
		t.Fatalf("CreateCampaign(scoped): %v", err)
	}
	gotCamp, err := st.GetCampaign(ctx, scoped.ID)
	if err != nil {
		t.Fatalf("GetCampaign(scoped): %v", err)
	}
	if gotCamp.ScopeKind != store.CampaignScopeSafe || gotCamp.ScopeSafeID == nil || *gotCamp.ScopeSafeID != pciSafe.ID {
		t.Fatalf("scope did not round-trip: %+v", gotCamp)
	}
	if gotCamp.RecurDays != 90 || gotCamp.NextRunAt == nil {
		t.Fatalf("recurrence did not round-trip: %+v", gotCamp)
	}
	// It is due, so the scheduler must see it.
	dueList, err := st.ListDueCampaigns(ctx, now)
	if err != nil {
		t.Fatalf("ListDueCampaigns: %v", err)
	}
	if len(dueList) != 1 || dueList[0].ID != scoped.ID {
		t.Fatalf("ListDueCampaigns = %+v, want just the due anchor %d", dueList, scoped.ID)
	}
	// Advancing the schedule takes it out of the due set.
	nextQuarter := now.Add(24 * time.Hour)
	if err := st.SetCampaignNextRun(ctx, scoped.ID, nextQuarter); err != nil {
		t.Fatalf("SetCampaignNextRun: %v", err)
	}
	if due, err := st.ListDueCampaigns(ctx, now); err != nil || len(due) != 0 {
		t.Fatalf("advanced anchor still due: %+v err %v", due, err)
	}
	if err := st.SetCampaignNextRun(ctx, 999999, nextQuarter); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetCampaignNextRun(missing): want ErrNotFound, got %v", err)
	}
	// CLOSING THE ANCHOR ENDS THE SERIES — the stop button. Bring it back into
	// the due window first, so the only thing the assertion can be measuring is
	// the close.
	if err := st.SetCampaignNextRun(ctx, scoped.ID, past); err != nil {
		t.Fatalf("SetCampaignNextRun(back): %v", err)
	}
	if due, _ := st.ListDueCampaigns(ctx, now); len(due) != 1 {
		t.Fatalf("anchor should be due again before the close, got %d", len(due))
	}
	if err := st.CloseCampaign(ctx, scoped.ID, now); err != nil {
		t.Fatalf("CloseCampaign(anchor): %v", err)
	}
	if due, err := st.ListDueCampaigns(ctx, now); err != nil || len(due) != 0 {
		t.Fatalf("a CLOSED anchor must not keep spawning: %+v err %v", due, err)
	}
	// A one-off is never due, whatever the clock says.
	oneOff := &store.Campaign{Name: "one-off", CreatedBy: "alice"}
	if err := st.CreateCampaign(ctx, oneOff); err != nil {
		t.Fatalf("CreateCampaign(one-off): %v", err)
	}
	if due, _ := st.ListDueCampaigns(ctx, now.Add(10000*time.Hour)); len(due) != 0 {
		t.Fatalf("a non-recurring campaign must never be due: %+v", due)
	}

	// --- access requests (4-eyes) ---
	ar := &store.AccessRequest{Requester: "alice", TargetID: tgt.ID, Reason: "patch", Status: "pending", ExpiresAt: future, Ticket: "CHG1001"}
	if err := st.CreateAccessRequest(ctx, ar); err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	if a, _ := st.GetAccessRequest(ctx, ar.ID); a == nil || a.Ticket != "CHG1001" {
		t.Fatalf("access-request ticket not round-tripped: %+v", a)
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, now); ok {
		t.Fatal("pending request must not count as an active approval")
	}
	if err := st.DecideAccessRequest(ctx, ar.ID, "approved", "bob", now); err != nil {
		t.Fatalf("DecideAccessRequest: %v", err)
	}
	if a, _ := st.GetAccessRequest(ctx, ar.ID); a.Status != "approved" || a.Approver != "bob" || a.DecidedAt == nil {
		t.Fatalf("decided request: %+v", a)
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, now); !ok {
		t.Fatal("approved unexpired request must be active")
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, future.Add(time.Minute)); ok {
		t.Fatal("expired approval must not be active")
	}
	if reqs, err := st.ListAccessRequests(ctx, "approved", 0, 0); err != nil || len(reqs) != 1 {
		t.Fatalf("ListAccessRequests(approved): %d err %v", len(reqs), err)
	}
	if reqs, err := st.ListAccessRequests(ctx, "approved", 10, ar.ID); err != nil || len(reqs) != 0 {
		t.Fatalf("ListAccessRequests(after=last): %d err %v", len(reqs), err)
	}

	// --- decision is compare-and-set on pending (2026-08-26 audit, M-4) ---
	// A decided request cannot be re-decided: the concurrency guarantee the
	// handler's read-then-write cannot make on its own. Both DecideAccessRequest
	// and SetApprovalState refuse a non-pending row with ErrConflict, so a
	// racing approve can never overwrite a deny.
	casAR := &store.AccessRequest{Requester: "erin", TargetID: tgt.ID, Reason: "cas", Status: "pending", ExpiresAt: future}
	if err := st.CreateAccessRequest(ctx, casAR); err != nil {
		t.Fatalf("CreateAccessRequest(cas): %v", err)
	}
	if err := st.DecideAccessRequest(ctx, casAR.ID, "denied", "frank", now); err != nil {
		t.Fatalf("first decision (deny): %v", err)
	}
	// A second decision — the racing approve — must be refused, not silently win.
	if err := st.DecideAccessRequest(ctx, casAR.ID, "approved", "grace", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("re-deciding a denied request returned %v, want ErrConflict", err)
	}
	if err := st.SetApprovalState(ctx, casAR.ID, "grace", "approved", "grace", &now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("SetApprovalState on a denied request returned %v, want ErrConflict", err)
	}
	if a, _ := st.GetAccessRequest(ctx, casAR.ID); a.Status != "denied" || a.Approver != "frank" {
		t.Fatalf("the deny was overwritten by a racing approve: %+v", a)
	}

	// --- access request recurrence (Phase 120) ---
	//
	// Mirrors the campaign recurrence section above exactly: an anchor must be
	// APPROVED (not merely pending) to ever be due, advancing the schedule
	// takes it out of the due set, and stopping recurrence is the stop button.
	recurAR := &store.AccessRequest{Requester: "carol", TargetID: tgt.ID, Reason: "weekly patch window", ExpiresAt: future, RecurDays: 7}
	if err := st.CreateAccessRequest(ctx, recurAR); err != nil {
		t.Fatalf("CreateAccessRequest(recurring): %v", err)
	}
	if a, _ := st.GetAccessRequest(ctx, recurAR.ID); a.RecurDays != 7 || a.NextRunAt != nil {
		t.Fatalf("a freshly-created anchor must not be due yet (still pending): %+v", a)
	}
	if due, _ := st.ListDueAccessRequests(ctx, now); len(due) != 0 {
		t.Fatalf("a pending anchor must never be due: %+v", due)
	}
	// Approving it alone still does not make it due — NextRunAt is set
	// separately, the way the API layer does it (at approval time, not
	// creation time, so a slow approval doesn't fire the first recurrence
	// immediately).
	if err := st.DecideAccessRequest(ctx, recurAR.ID, "approved", "dave", now); err != nil {
		t.Fatalf("DecideAccessRequest(recurring): %v", err)
	}
	if due, _ := st.ListDueAccessRequests(ctx, now); len(due) != 0 {
		t.Fatalf("an approved anchor with no NextRunAt set yet must not be due: %+v", due)
	}
	// Reuses `past` (now.Add(-time.Hour)), already declared above by the
	// campaign recurrence section.
	if err := st.SetAccessRequestNextRun(ctx, recurAR.ID, past); err != nil {
		t.Fatalf("SetAccessRequestNextRun: %v", err)
	}
	// Reuses `err`, already declared above by the campaign recurrence section
	// (dueAR is its own variable — ListDueAccessRequests returns
	// []AccessRequest, not []Campaign, so it cannot share `due`'s type).
	dueAR, err := st.ListDueAccessRequests(ctx, now)
	if err != nil || len(dueAR) != 1 || dueAR[0].ID != recurAR.ID {
		t.Fatalf("ListDueAccessRequests = %+v err %v, want just the due anchor %d", dueAR, err, recurAR.ID)
	}
	if err := st.SetAccessRequestNextRun(ctx, 999999, past); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAccessRequestNextRun(missing): want ErrNotFound, got %v", err)
	}
	nextWeek := now.Add(24 * time.Hour)
	if err := st.SetAccessRequestNextRun(ctx, recurAR.ID, nextWeek); err != nil {
		t.Fatalf("SetAccessRequestNextRun(advance): %v", err)
	}
	if due, _ := st.ListDueAccessRequests(ctx, now); len(due) != 0 {
		t.Fatalf("advanced anchor still due: %+v", due)
	}
	// STOPPING RECURRENCE is the anchor's stop button. Bring it back into the
	// due window first, so the only thing the assertion can be measuring is
	// the stop.
	if err := st.SetAccessRequestNextRun(ctx, recurAR.ID, past); err != nil {
		t.Fatalf("SetAccessRequestNextRun(back): %v", err)
	}
	if due, _ := st.ListDueAccessRequests(ctx, now); len(due) != 1 {
		t.Fatalf("anchor should be due again before stopping, got %d", len(due))
	}
	if err := st.StopAccessRequestRecurrence(ctx, recurAR.ID); err != nil {
		t.Fatalf("StopAccessRequestRecurrence: %v", err)
	}
	if due, err := st.ListDueAccessRequests(ctx, now); err != nil || len(due) != 0 {
		t.Fatalf("a stopped anchor must not keep spawning: %+v err %v", due, err)
	}
	if a, _ := st.GetAccessRequest(ctx, recurAR.ID); a.RecurDays != 0 || a.NextRunAt != nil {
		t.Fatalf("stopped anchor should read back as a one-off: %+v", a)
	}
	if err := st.StopAccessRequestRecurrence(ctx, recurAR.ID); err != nil {
		t.Fatalf("StopAccessRequestRecurrence must be idempotent: %v", err)
	}
	if err := st.StopAccessRequestRecurrence(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("StopAccessRequestRecurrence(missing): want ErrNotFound, got %v", err)
	}
	// A one-off request (RecurDays 0, the default) is never due, whatever the
	// clock says — ar itself, approved above, already covers this: it has no
	// recurrence and must not appear in any due list.
	if due, _ := st.ListDueAccessRequests(ctx, now.Add(10000*time.Hour)); len(due) != 0 {
		t.Fatalf("a non-recurring request must never be due: %+v", due)
	}

	// --- multi-approver chain + scheduled window (Phase 21) ---
	nb := now.Add(2 * time.Hour) // window opens in 2h
	na := now.Add(3 * time.Hour) // and closes in 3h (after not_before)
	mreq := &store.AccessRequest{Requester: "dave", TargetID: tgt.ID, Reason: "chain", Status: "pending", ExpiresAt: na, RequiredApprovals: 2, NotBefore: &nb}
	if err := st.CreateAccessRequest(ctx, mreq); err != nil {
		t.Fatalf("CreateAccessRequest(chain): %v", err)
	}
	if m, _ := st.GetAccessRequest(ctx, mreq.ID); m == nil || m.RequiredApprovals != 2 || m.NotBefore == nil {
		t.Fatalf("chain request not round-tripped: %+v", m)
	}
	// One approval — still pending (2 required).
	if err := st.SetApprovalState(ctx, mreq.ID, "eve", "pending", "", nil); err != nil {
		t.Fatalf("SetApprovalState(partial): %v", err)
	}
	if m, _ := st.GetAccessRequest(ctx, mreq.ID); m.Status != "pending" || m.ApprovedBy != "eve" {
		t.Fatalf("partial approval: %+v", m)
	}
	// Second approval — now approved.
	dec := now
	if err := st.SetApprovalState(ctx, mreq.ID, "eve,frank", "approved", "frank", &dec); err != nil {
		t.Fatalf("SetApprovalState(complete): %v", err)
	}
	// Approved, but the maintenance window hasn't opened yet → not active now,
	// active once not_before passes.
	if ok, _ := st.HasActiveApproval(ctx, "dave", tgt.ID, now); ok {
		t.Fatal("scheduled approval must not be active before its window")
	}
	if ok, _ := st.HasActiveApproval(ctx, "dave", tgt.ID, nb.Add(time.Minute)); !ok {
		t.Fatal("scheduled approval must be active inside its window")
	}

	// --- the admitting approvals, without consuming them (Phase 60/60a) ---
	// A use-time check needs to see WHICH requests could admit — and their
	// tickets — before deciding which to burn, so ActiveApprovals must agree
	// with ConsumeApproval about the order and leave nothing consumed.
	if as, err := st.ActiveApprovals(ctx, "alice", tgt.ID, now, 8); err != nil || len(as) != 1 {
		t.Fatalf("ActiveApprovals(alice): %+v err %v", as, err)
	} else if as[0].ID != ar.ID || as[0].Ticket != "CHG1001" {
		t.Fatalf("ActiveApprovals must return the admitting request with its ticket: %+v", as[0])
	}
	if as, err := st.ActiveApprovals(ctx, "alice", tgt.ID, future.Add(time.Minute), 8); err != nil || len(as) != 0 {
		t.Fatalf("an expired approval must not be returned: %+v err %v", as, err)
	}
	if as, err := st.ActiveApprovals(ctx, "nobody", tgt.ID, now, 8); err != nil || len(as) != 0 {
		t.Fatalf("ActiveApprovals with no approval must be empty: %+v err %v", as, err)
	}
	if as, err := st.ActiveApprovals(ctx, "dave", tgt.ID, now, 8); err != nil || len(as) != 0 {
		t.Fatalf("a scheduled approval outside its window must not be returned: %+v err %v", as, err)
	}

	// --- one-time (single-use) approvals (Phase 26) ---
	// A standing approval satisfies ConsumeApproval repeatedly without burning
	// anything (alice's approval from above is standing).
	if ok, id, err := st.ConsumeApproval(ctx, "alice", tgt.ID, now); err != nil || !ok || id != 0 {
		t.Fatalf("ConsumeApproval(standing): ok=%v id=%d err=%v", ok, id, err)
	}
	if ok, id, _ := st.ConsumeApproval(ctx, "alice", tgt.ID, now); !ok || id != 0 {
		t.Fatalf("standing approval must keep admitting: ok=%v id=%d", ok, id)
	}
	// A single-use approval admits exactly once, then is consumed everywhere.
	ot := &store.AccessRequest{Requester: "gina", TargetID: tgt.ID, Reason: "one shot", Status: "pending", ExpiresAt: future, OneTime: true}
	if err := st.CreateAccessRequest(ctx, ot); err != nil {
		t.Fatalf("CreateAccessRequest(one-time): %v", err)
	}
	if g, _ := st.GetAccessRequest(ctx, ot.ID); g == nil || !g.OneTime || g.ConsumedAt != nil {
		t.Fatalf("one-time flag not round-tripped: %+v", g)
	}
	if ok, id, _ := st.ConsumeApproval(ctx, "gina", tgt.ID, now); ok || id != 0 {
		t.Fatal("a pending one-time request must not admit")
	}
	if err := st.DecideAccessRequest(ctx, ot.ID, "approved", "bob", now); err != nil {
		t.Fatalf("DecideAccessRequest(one-time): %v", err)
	}
	if ok, _ := st.HasActiveApproval(ctx, "gina", tgt.ID, now); !ok {
		t.Fatal("an approved unconsumed one-time approval must be active")
	}
	if ok, id, err := st.ConsumeApproval(ctx, "gina", tgt.ID, now); err != nil || !ok || id != ot.ID {
		t.Fatalf("ConsumeApproval(one-time): ok=%v id=%d err=%v (want ok, id=%d)", ok, id, err, ot.ID)
	}
	if g, _ := st.GetAccessRequest(ctx, ot.ID); g == nil || g.ConsumedAt == nil {
		t.Fatalf("consumed approval must carry ConsumedAt: %+v", g)
	}
	if as, err := st.ActiveApprovals(ctx, "gina", tgt.ID, now, 8); err != nil || len(as) != 0 {
		t.Fatalf("a consumed one-time approval must not be returned as admitting: %+v err %v", as, err)
	}
	if ok, _ := st.HasActiveApproval(ctx, "gina", tgt.ID, now); ok {
		t.Fatal("a consumed one-time approval must not be active")
	}
	if ok, id, _ := st.ConsumeApproval(ctx, "gina", tgt.ID, now); ok || id != 0 {
		t.Fatal("a consumed one-time approval must not admit a second use")
	}
	// Racing consumers: one single-use approval admits exactly one of N.
	race := &store.AccessRequest{Requester: "hank", TargetID: tgt.ID, Status: "approved", ExpiresAt: future, OneTime: true}
	if err := st.CreateAccessRequest(ctx, race); err != nil {
		t.Fatalf("CreateAccessRequest(race): %v", err)
	}
	var wg sync.WaitGroup
	admitted := make(chan int64, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, id, err := st.ConsumeApproval(ctx, "hank", tgt.ID, now); err == nil && ok {
				admitted <- id
			}
		}()
	}
	wg.Wait()
	close(admitted)
	var wins int
	for id := range admitted {
		wins++
		if id != race.ID {
			t.Fatalf("racing consumer burned request %d, want %d", id, race.ID)
		}
	}
	if wins != 1 {
		t.Fatalf("one single-use approval admitted %d racing consumers, want exactly 1", wins)
	}
	// When both a standing and a one-time approval are active, the standing one
	// is preferred and the single-use survives.
	both := &store.AccessRequest{Requester: "alice", TargetID: tgt.ID, Status: "approved", ExpiresAt: future, OneTime: true}
	if err := st.CreateAccessRequest(ctx, both); err != nil {
		t.Fatalf("CreateAccessRequest(both): %v", err)
	}
	if ok, id, _ := st.ConsumeApproval(ctx, "alice", tgt.ID, now); !ok || id != 0 {
		t.Fatalf("standing approval must be preferred over a one-time one: ok=%v id=%d", ok, id)
	}
	if g, _ := st.GetAccessRequest(ctx, both.ID); g == nil || g.ConsumedAt != nil {
		t.Fatalf("the one-time approval must survive while a standing one admits: %+v", g)
	}

	// --- claiming ONE NAMED approval (Phase 60a) ---
	// The use-time gate inspects an approval's ticket and must then burn THAT
	// approval rather than whichever the store would have picked, or a
	// concurrent use is admitted on a ticket nobody ever checked. Alice now has
	// exactly two active approvals: the standing one and the single-use one.
	if as, err := st.ActiveApprovals(ctx, "alice", tgt.ID, now, 8); err != nil || len(as) != 2 {
		t.Fatalf("alice should have a standing and a single-use approval: %+v err %v", as, err)
	} else if as[0].ID != ar.ID || as[1].ID != both.ID {
		t.Fatalf("ActiveApprovals must order standing first, then by id: %+v", as)
	}
	if as, err := st.ActiveApprovals(ctx, "alice", tgt.ID, now, 1); err != nil || len(as) != 1 || as[0].ID != ar.ID {
		t.Fatalf("the limit must cap the list at the most-preferred: %+v err %v", as, err)
	}
	// Naming the single-use approval burns exactly it.
	if ok, err := st.ConsumeApprovalByID(ctx, both.ID, "alice", tgt.ID, now); err != nil || !ok {
		t.Fatalf("ConsumeApprovalByID(one-time): ok=%v err=%v", ok, err)
	}
	if g, _ := st.GetAccessRequest(ctx, both.ID); g == nil || g.ConsumedAt == nil {
		t.Fatalf("the named approval must be burned: %+v", g)
	}
	if ok, err := st.ConsumeApprovalByID(ctx, both.ID, "alice", tgt.ID, now); err != nil || ok {
		t.Fatalf("a burned approval must not be claimable twice: ok=%v err=%v", ok, err)
	}
	// A standing approval is confirmed and left untouched, however often.
	for i := 0; i < 2; i++ {
		if ok, err := st.ConsumeApprovalByID(ctx, ar.ID, "alice", tgt.ID, now); err != nil || !ok {
			t.Fatalf("ConsumeApprovalByID(standing): ok=%v err=%v", ok, err)
		}
	}
	if g, _ := st.GetAccessRequest(ctx, ar.ID); g == nil || g.ConsumedAt != nil {
		t.Fatalf("a standing approval must never be burned: %+v", g)
	}
	// An id alone claims nothing — the requester, the target and the clock are
	// all re-checked, so a known id cannot borrow somebody else's approval.
	if ok, _ := st.ConsumeApprovalByID(ctx, ar.ID, "mallory", tgt.ID, now); ok {
		t.Fatal("another requester's approval must not be claimable by id")
	}
	if ok, _ := st.ConsumeApprovalByID(ctx, ar.ID, "alice", tgt.ID+9999, now); ok {
		t.Fatal("an approval for another target must not be claimable by id")
	}
	if ok, _ := st.ConsumeApprovalByID(ctx, ar.ID, "alice", tgt.ID, future.Add(time.Minute)); ok {
		t.Fatal("an expired approval must not be claimable by id")
	}
	if ok, err := st.ConsumeApprovalByID(ctx, 0, "alice", tgt.ID, now); err != nil || ok {
		t.Fatalf("an id that names nothing must refuse, not error: ok=%v err=%v", ok, err)
	}
	// Racing claims of the SAME single-use approval: exactly one wins, and the
	// losers are told to look elsewhere rather than handed an error.
	byID := &store.AccessRequest{Requester: "ivy", TargetID: tgt.ID, Status: "approved", ExpiresAt: future, OneTime: true}
	if err := st.CreateAccessRequest(ctx, byID); err != nil {
		t.Fatalf("CreateAccessRequest(byID): %v", err)
	}
	var wgID sync.WaitGroup
	wonByID := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		wgID.Add(1)
		go func() {
			defer wgID.Done()
			if ok, err := st.ConsumeApprovalByID(ctx, byID.ID, "ivy", tgt.ID, now); err == nil && ok {
				wonByID <- struct{}{}
			}
		}()
	}
	wgID.Wait()
	close(wonByID)
	if n := len(wonByID); n != 1 {
		t.Fatalf("one single-use approval admitted %d racing claims by id, want exactly 1", n)
	}

	// --- checkouts (exclusive lease) ---
	co := &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "alice", ExpiresAt: future}
	if err := st.CreateCheckout(ctx, co, now); err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "eve", ExpiresAt: future}, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("double checkout: want ErrConflict, got %v", err)
	}
	if active, err := st.GetActiveCheckout(ctx, cred.ID, now); err != nil || active.Holder != "alice" {
		t.Fatalf("GetActiveCheckout: %+v err %v", active, err)
	}
	if err := st.CheckinCheckout(ctx, co.ID, now); err != nil {
		t.Fatalf("CheckinCheckout: %v", err)
	}
	if _, err := st.GetActiveCheckout(ctx, cred.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after checkin: want ErrNotFound, got %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "carol", ExpiresAt: future}, now); err != nil {
		t.Fatalf("re-checkout after checkin: %v", err)
	}
	if all, err := st.ListCheckouts(ctx, false, now, 0, 0); err != nil || len(all) != 2 {
		t.Fatalf("ListCheckouts(all): %d err %v", len(all), err)
	}
	if act, err := st.ListCheckouts(ctx, true, now, 0, 0); err != nil || len(act) != 1 {
		t.Fatalf("ListCheckouts(active): %d err %v", len(act), err)
	}
	if one, err := st.ListCheckouts(ctx, false, now, 1, 0); err != nil || len(one) != 1 || one[0].ID != co.ID {
		t.Fatalf("ListCheckouts(limit=1): %+v err %v", one, err)
	}
	// An expired-but-unreturned lease must not block a new checkout, and it is no
	// longer the active one.
	carol, err := st.GetActiveCheckout(ctx, cred.ID, now)
	if err != nil {
		t.Fatalf("GetActiveCheckout(carol): %v", err)
	}
	if err := st.CheckinCheckout(ctx, carol.ID, now); err != nil {
		t.Fatalf("checkin carol: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "stale", ExpiresAt: now.Add(-time.Hour)}, now); err != nil {
		t.Fatalf("create expired lease: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "fresh", ExpiresAt: future}, now); err != nil {
		t.Fatalf("checkout over an expired lease should succeed, got %v", err)
	}
	if active, err := st.GetActiveCheckout(ctx, cred.ID, now); err != nil || active.Holder != "fresh" {
		t.Fatalf("active checkout after expiry = %+v err %v, want holder fresh", active, err)
	}

	// --- checkout extension (Phase 120) ---
	dana := &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "dana", ExpiresAt: now.Add(10 * time.Minute)}
	freshActive, err := st.GetActiveCheckout(ctx, cred.ID, now)
	if err != nil {
		t.Fatalf("GetActiveCheckout(fresh): %v", err)
	}
	if err := st.CheckinCheckout(ctx, freshActive.ID, now); err != nil {
		t.Fatalf("checkin fresh (making room for dana): %v", err)
	}
	if err := st.CreateCheckout(ctx, dana, now); err != nil {
		t.Fatalf("CreateCheckout(dana): %v", err)
	}
	if got, err := st.GetCheckout(ctx, dana.ID); err != nil || got.Holder != "dana" {
		t.Fatalf("GetCheckout: %+v err %v", got, err)
	}
	if _, err := st.GetCheckout(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetCheckout(missing): want ErrNotFound, got %v", err)
	}
	// Truncated to microsecond precision: PostgreSQL's TIMESTAMPTZ has no finer
	// resolution than that, so a nanosecond-precision time.Now()-derived value
	// would silently lose its sub-microsecond digits on the pgstore round trip
	// and never compare equal again — memstore has no such loss, which is
	// exactly the kind of backend divergence this contract test exists to
	// catch rather than paper over by testing only the more forgiving side.
	extended := now.Add(2 * time.Hour).Truncate(time.Microsecond)
	if err := st.ExtendCheckout(ctx, dana.ID, extended, now); err != nil {
		t.Fatalf("ExtendCheckout: %v", err)
	}
	if got, err := st.GetCheckout(ctx, dana.ID); err != nil || !got.ExpiresAt.Equal(extended) {
		t.Fatalf("extended expiry did not round-trip: %+v err %v", got, err)
	}
	if err := st.ExtendCheckout(ctx, 999999, extended, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ExtendCheckout(missing): want ErrNotFound, got %v", err)
	}
	// A RETURNED lease cannot be extended — extension is a continuation of a
	// live lease, not a resurrection of a dead one.
	if err := st.CheckinCheckout(ctx, dana.ID, now); err != nil {
		t.Fatalf("checkin dana: %v", err)
	}
	if err := st.ExtendCheckout(ctx, dana.ID, extended.Add(time.Hour), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ExtendCheckout(returned): want ErrNotFound, got %v", err)
	}
	// An EXPIRED-but-unreturned lease cannot be extended either.
	expiredCO := &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "later", ExpiresAt: now.Add(time.Minute)}
	if err := st.CreateCheckout(ctx, expiredCO, now); err != nil {
		t.Fatalf("CreateCheckout(later): %v", err)
	}
	afterExpiry := now.Add(time.Hour)
	if err := st.ExtendCheckout(ctx, expiredCO.ID, afterExpiry.Add(time.Hour), afterExpiry); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ExtendCheckout(expired): want ErrNotFound, got %v", err)
	}
	if err := st.CheckinCheckout(ctx, expiredCO.ID, afterExpiry); err != nil {
		t.Fatalf("checkin later (cleanup): %v", err)
	}

	// --- password reuse history (Phase 120) ---
	//
	// Secrets are never stored here, only their hashes — this section never
	// constructs anything that looks like a real password, deliberately.
	if hashes, err := st.RecentPasswordHashes(ctx, cred.ID, 5); err != nil || len(hashes) != 0 {
		t.Fatalf("RecentPasswordHashes(none recorded): %+v err %v", hashes, err)
	}
	t0, t1, t2, t3 := now, now.Add(time.Minute), now.Add(2*time.Minute), now.Add(3*time.Minute)
	if err := st.RecordPasswordHistory(ctx, cred.ID, "hash-1", t0, 3); err != nil {
		t.Fatalf("RecordPasswordHistory(1): %v", err)
	}
	if err := st.RecordPasswordHistory(ctx, cred.ID, "hash-2", t1, 3); err != nil {
		t.Fatalf("RecordPasswordHistory(2): %v", err)
	}
	if hashes, err := st.RecentPasswordHashes(ctx, cred.ID, 5); err != nil || len(hashes) != 2 || hashes[0] != "hash-2" || hashes[1] != "hash-1" {
		t.Fatalf("RecentPasswordHashes(2 recorded, newest first): %+v err %v", hashes, err)
	}
	if hashes, err := st.RecentPasswordHashes(ctx, cred.ID, 1); err != nil || len(hashes) != 1 || hashes[0] != "hash-2" {
		t.Fatalf("RecentPasswordHashes(limit=1): %+v err %v", hashes, err)
	}
	// Recording beyond `keep` PRUNES the oldest — the history never grows
	// unbounded relative to what reuse-prevention can actually check against.
	if err := st.RecordPasswordHistory(ctx, cred.ID, "hash-3", t2, 3); err != nil {
		t.Fatalf("RecordPasswordHistory(3): %v", err)
	}
	if err := st.RecordPasswordHistory(ctx, cred.ID, "hash-4", t3, 3); err != nil {
		t.Fatalf("RecordPasswordHistory(4): %v", err)
	}
	if hashes, err := st.RecentPasswordHashes(ctx, cred.ID, 10); err != nil || len(hashes) != 3 {
		t.Fatalf("RecentPasswordHashes after pruning to keep=3: %+v err %v", hashes, err)
	} else if hashes[0] != "hash-4" || hashes[1] != "hash-3" || hashes[2] != "hash-2" {
		t.Fatalf("pruning kept the wrong entries: %+v, want [hash-4 hash-3 hash-2]", hashes)
	}
	// A different credential's history is independent.
	otherCred := &store.Credential{TargetID: tgt.ID, Username: "other-history-cred", SecretType: "password", SecretEnc: "v2:one"}
	if err := st.CreateCredential(ctx, otherCred); err != nil {
		t.Fatalf("CreateCredential(otherCred): %v", err)
	}
	if hashes, err := st.RecentPasswordHashes(ctx, otherCred.ID, 5); err != nil || len(hashes) != 0 {
		t.Fatalf("RecentPasswordHashes(other credential): %+v err %v", hashes, err)
	}

	// --- audit + export ---
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "tester", Action: "unit.test", Detail: "hello"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if evs, err := st.ListAudit(ctx, 10); err != nil || len(evs) == 0 {
		t.Fatalf("ListAudit: %d err %v", len(evs), err)
	}
	if evs, err := st.ExportAudit(ctx, time.Time{}, future); err != nil || len(evs) == 0 {
		t.Fatalf("ExportAudit: %d err %v", len(evs), err)
	}

	// --- FindAuditDetail (recording-hash verification, Phase 26) ---
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "proxy", Action: "session.record", Detail: "target:t file:a.cast sha256:abcd1234 chain:ff"}); err != nil {
		t.Fatalf("AppendAudit(record): %v", err)
	}
	if ok, err := st.FindAuditDetail(ctx, "session.record", "sha256:abcd1234"); err != nil || !ok {
		t.Fatalf("FindAuditDetail(hit): ok=%v err=%v", ok, err)
	}
	if ok, _ := st.FindAuditDetail(ctx, "winrm.run", "sha256:abcd1234"); ok {
		t.Fatal("FindAuditDetail must match the action, not just the detail")
	}
	if ok, _ := st.FindAuditDetail(ctx, "session.record", "sha256:ffff0000"); ok {
		t.Fatal("FindAuditDetail must not match a different detail")
	}
	// The substring is literal: SQL LIKE wildcards must not widen the match.
	if ok, _ := st.FindAuditDetail(ctx, "session.record", "sha256:a_cd1234"); ok {
		t.Fatal("FindAuditDetail must treat _ literally, not as a wildcard")
	}
	if ok, _ := st.FindAuditDetail(ctx, "session.record", "sha256:%"); ok {
		t.Fatal("FindAuditDetail must treat % literally, not as a wildcard")
	}

	// --- users ---
	u := &store.User{Username: "u1", Role: "admin", TokenHash: "tokhash1"}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// CreateUser always creates an active user (Phase 149) — Active on the
	// input struct (the zero value here, since the literal above never set
	// it) is ignored, not read; a caller who has never heard of this field
	// must never silently create a deactivated account.
	if !u.Active {
		t.Fatal("CreateUser must always create an active user, regardless of the input struct's Active field")
	}
	if err := st.CreateUser(ctx, &store.User{Username: "u1", Role: "user", TokenHash: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate username: want ErrConflict, got %v", err)
	}
	if err := st.CreateUser(ctx, &store.User{Username: "u2", Role: "user", TokenHash: "tokhash1"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate token hash: want ErrConflict, got %v", err)
	}
	if by, err := st.GetUserByTokenHash(ctx, "tokhash1"); err != nil || by.Username != "u1" {
		t.Fatalf("GetUserByTokenHash: %+v err %v", by, err)
	}
	if _, err := st.GetUserByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByTokenHash missing: want ErrNotFound, got %v", err)
	}
	if by, err := st.GetUser(ctx, u.ID); err != nil || by.Username != "u1" {
		t.Fatalf("GetUser: %+v err %v", by, err)
	}
	if _, err := st.GetUser(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUser missing: want ErrNotFound, got %v", err)
	}
	// UpdateUserRole changes the role in place — username and token survive, so
	// a promotion does not re-key the identity.
	if err := st.UpdateUserRole(ctx, u.ID, "auditor"); err != nil {
		t.Fatalf("UpdateUserRole: %v", err)
	}
	if by, err := st.GetUserByTokenHash(ctx, "tokhash1"); err != nil || by.Role != "auditor" || by.Username != "u1" {
		t.Fatalf("after UpdateUserRole: %+v err %v", by, err)
	}
	if err := st.UpdateUserRole(ctx, 999999, "user"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUserRole missing: want ErrNotFound, got %v", err)
	}
	// UpdateUserIPAllowlist (Phase 118): a fresh user's allowlist is empty
	// (unrestricted) by default; setting it persists and round-trips.
	if u.IPAllowlist != "" {
		t.Fatalf("new user's IPAllowlist = %q, want empty", u.IPAllowlist)
	}
	if err := st.UpdateUserIPAllowlist(ctx, u.ID, "10.0.0.0/8,192.168.1.0/24"); err != nil {
		t.Fatalf("UpdateUserIPAllowlist: %v", err)
	}
	if by, err := st.GetUser(ctx, u.ID); err != nil || by.IPAllowlist != "10.0.0.0/8,192.168.1.0/24" {
		t.Fatalf("after UpdateUserIPAllowlist: %+v err %v", by, err)
	}
	if err := st.UpdateUserIPAllowlist(ctx, 999999, "10.0.0.0/8"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUserIPAllowlist missing: want ErrNotFound, got %v", err)
	}
	// UpdateUserDeviceFingerprint (Phase 133): a fresh user's fingerprint is
	// empty (unbound) by default; setting it persists and round-trips.
	if u.DeviceFingerprint != "" {
		t.Fatalf("new user's DeviceFingerprint = %q, want empty", u.DeviceFingerprint)
	}
	if err := st.UpdateUserDeviceFingerprint(ctx, u.ID, "aa:bb:cc:dd"); err != nil {
		t.Fatalf("UpdateUserDeviceFingerprint: %v", err)
	}
	if by, err := st.GetUser(ctx, u.ID); err != nil || by.DeviceFingerprint != "aa:bb:cc:dd" {
		t.Fatalf("after UpdateUserDeviceFingerprint: %+v err %v", by, err)
	}
	if err := st.UpdateUserDeviceFingerprint(ctx, 999999, "aa:bb:cc:dd"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUserDeviceFingerprint missing: want ErrNotFound, got %v", err)
	}
	// GetUserByUsername / GetUserByExternalID (Phase 149): the two lookups
	// SCIM's idempotent-provisioning filter depends on.
	if by, err := st.GetUserByUsername(ctx, "u1"); err != nil || by.ID != u.ID {
		t.Fatalf("GetUserByUsername: %+v err %v", by, err)
	}
	if _, err := st.GetUserByUsername(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByUsername missing: want ErrNotFound, got %v", err)
	}
	// A fresh user's ExternalID is empty, and empty must never resolve —
	// every non-SCIM user shares that same default, so it must not be a
	// usable lookup key.
	if _, err := st.GetUserByExternalID(ctx, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByExternalID(\"\") must always miss, got %v", err)
	}
	if err := st.UpdateUserExternalID(ctx, u.ID, "idp-ext-1"); err != nil {
		t.Fatalf("UpdateUserExternalID: %v", err)
	}
	if by, err := st.GetUserByExternalID(ctx, "idp-ext-1"); err != nil || by.ID != u.ID {
		t.Fatalf("GetUserByExternalID: %+v err %v", by, err)
	}
	if err := st.UpdateUserExternalID(ctx, 999999, "idp-ext-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUserExternalID missing: want ErrNotFound, got %v", err)
	}
	// A second user cannot claim the same non-empty ExternalID.
	u2 := &store.User{Username: "u2-ext", Role: "user", TokenHash: "tokhash-ext2"}
	if err := st.CreateUser(ctx, u2); err != nil {
		t.Fatalf("CreateUser u2: %v", err)
	}
	if err := st.UpdateUserExternalID(ctx, u2.ID, "idp-ext-1"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate ExternalID: want ErrConflict, got %v", err)
	}
	// ...but two users may each keep the shared empty default — the partial
	// unique index must exclude "", not just deduplicate non-empty values.
	if err := st.UpdateUserExternalID(ctx, u2.ID, ""); err != nil {
		t.Fatalf("clearing ExternalID back to empty: %v", err)
	}
	if err := st.DeleteUser(ctx, u2.ID); err != nil {
		t.Fatalf("DeleteUser u2: %v", err)
	}
	// UpdateUserActive (Phase 149): SCIM's deprovisioning switch.
	if err := st.UpdateUserActive(ctx, u.ID, false); err != nil {
		t.Fatalf("UpdateUserActive(false): %v", err)
	}
	if by, err := st.GetUser(ctx, u.ID); err != nil || by.Active {
		t.Fatalf("after UpdateUserActive(false): %+v err %v", by, err)
	}
	if err := st.UpdateUserActive(ctx, u.ID, true); err != nil {
		t.Fatalf("UpdateUserActive(true): %v", err)
	}
	if by, err := st.GetUser(ctx, u.ID); err != nil || !by.Active {
		t.Fatalf("after UpdateUserActive(true): %+v err %v", by, err)
	}
	if err := st.UpdateUserActive(ctx, 999999, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateUserActive missing: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// --- SCIM client keys (Phase 149) ---
	sk := &store.ScimKey{Name: "okta", Owner: "idp-team", TokenHash: "scimhash1"}
	if err := st.CreateScimKey(ctx, sk); err != nil {
		t.Fatalf("CreateScimKey: %v", err)
	}
	if err := st.CreateScimKey(ctx, &store.ScimKey{Name: "dup", TokenHash: "scimhash1"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate scim token hash: want ErrConflict, got %v", err)
	}
	if by, err := st.GetScimKeyByTokenHash(ctx, "scimhash1"); err != nil || by.Name != "okta" {
		t.Fatalf("GetScimKeyByTokenHash: %+v err %v", by, err)
	}
	if _, err := st.GetScimKeyByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetScimKeyByTokenHash missing: want ErrNotFound, got %v", err)
	}
	keys, err := st.ListScimKeys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListScimKeys: %+v err %v", keys, err)
	}
	if err := st.DeleteScimKey(ctx, sk.ID); err != nil {
		t.Fatalf("DeleteScimKey: %v", err)
	}
	if _, err := st.GetScimKeyByTokenHash(ctx, "scimhash1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetScimKeyByTokenHash after delete: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteScimKey(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteScimKey missing: want ErrNotFound, got %v", err)
	}
	// A disabled key is treated as not found, the same fail-closed shape
	// AgentKey/AppKey already use.
	dk := &store.ScimKey{Name: "disabled-one", TokenHash: "scimhash-disabled", Disabled: true}
	if err := st.CreateScimKey(ctx, dk); err != nil {
		t.Fatalf("CreateScimKey(disabled): %v", err)
	}
	if _, err := st.GetScimKeyByTokenHash(ctx, "scimhash-disabled"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled scim key must resolve as not found, got %v", err)
	}

	// --- endpoint agents (Phase 153) ---
	eaTarget := &store.Target{Name: "branch-box", Host: "127.0.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, eaTarget); err != nil {
		t.Fatalf("CreateTarget(endpoint-agent): %v", err)
	}
	ea := &store.EndpointAgent{Name: "branch-agent", TargetID: eaTarget.ID, KeyHash: "eahash1", CreatedBy: "admin"}
	if err := st.CreateEndpointAgent(ctx, ea); err != nil || ea.ID == 0 || ea.CreatedAt.IsZero() {
		t.Fatalf("CreateEndpointAgent: %+v err %v", ea, err)
	}
	// One live agent per target, unique key hash, and the target must exist.
	if err := st.CreateEndpointAgent(ctx, &store.EndpointAgent{Name: "second", TargetID: eaTarget.ID, KeyHash: "eahash2"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second live agent for the same target: want ErrConflict, got %v", err)
	}
	if err := st.CreateEndpointAgent(ctx, &store.EndpointAgent{Name: "dup-key", TargetID: tgt.ID, KeyHash: "eahash1"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate endpoint agent key hash: want ErrConflict, got %v", err)
	}
	if err := st.CreateEndpointAgent(ctx, &store.EndpointAgent{Name: "orphan", TargetID: 999999, KeyHash: "eahash3"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("endpoint agent for a missing target: want ErrNotFound, got %v", err)
	}
	if by, err := st.GetEndpointAgentByKeyHash(ctx, "eahash1"); err != nil || by.ID != ea.ID || !by.Active() {
		t.Fatalf("GetEndpointAgentByKeyHash: %+v err %v", by, err)
	}
	if _, err := st.GetEndpointAgentByKeyHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetEndpointAgentByKeyHash missing: want ErrNotFound, got %v", err)
	}
	if by, err := st.GetEndpointAgentForTarget(ctx, eaTarget.ID); err != nil || by.ID != ea.ID {
		t.Fatalf("GetEndpointAgentForTarget: %+v err %v", by, err)
	}
	if _, err := st.GetEndpointAgentForTarget(ctx, tgt.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetEndpointAgentForTarget(direct target): want ErrNotFound, got %v", err)
	}
	seenAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := st.TouchEndpointAgent(ctx, ea.ID, seenAt); err != nil {
		t.Fatalf("TouchEndpointAgent: %v", err)
	}
	if err := st.TouchEndpointAgent(ctx, 999999, seenAt); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TouchEndpointAgent missing: want ErrNotFound, got %v", err)
	}
	if by, _ := st.GetEndpointAgentByKeyHash(ctx, "eahash1"); by.LastSeen == nil || !by.LastSeen.Equal(seenAt) {
		t.Fatalf("LastSeen not recorded: %+v", by)
	}
	if err := st.RevokeEndpointAgent(ctx, ea.ID, time.Now()); err != nil {
		t.Fatalf("RevokeEndpointAgent: %v", err)
	}
	if err := st.RevokeEndpointAgent(ctx, 999999, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeEndpointAgent missing: want ErrNotFound, got %v", err)
	}
	// A revoked agent still resolves by key hash (so the refusal can be
	// audited as "revoked"), but is no longer the target's agent — and the
	// target may now bind a fresh one.
	if by, err := st.GetEndpointAgentByKeyHash(ctx, "eahash1"); err != nil || by.Active() {
		t.Fatalf("revoked agent should resolve inactive: %+v err %v", by, err)
	}
	if _, err := st.GetEndpointAgentForTarget(ctx, eaTarget.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetEndpointAgentForTarget after revoke: want ErrNotFound, got %v", err)
	}
	ea2 := &store.EndpointAgent{Name: "branch-agent-2", TargetID: eaTarget.ID, KeyHash: "eahash2"}
	if err := st.CreateEndpointAgent(ctx, ea2); err != nil {
		t.Fatalf("CreateEndpointAgent after revoke: %v", err)
	}
	if list, err := st.ListEndpointAgents(ctx); err != nil || len(list) != 2 || list[0].ID != ea.ID || list[1].ID != ea2.ID {
		t.Fatalf("ListEndpointAgents: %+v err %v", list, err)
	}
	// Deleting the target cascades to its agents.
	if err := st.DeleteTarget(ctx, eaTarget.ID); err != nil {
		t.Fatalf("DeleteTarget(endpoint-agent): %v", err)
	}
	if list, _ := st.ListEndpointAgents(ctx); len(list) != 0 {
		t.Fatalf("endpoint agents should cascade with their target: %+v", list)
	}

	// --- sessions (with expiry) ---
	sess := &store.Session{Username: "u1", Role: "admin", TokenHash: "sesshash", ExpiresAt: future}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s, err := st.GetSessionByTokenHash(ctx, "sesshash"); err != nil || s.Username != "u1" {
		t.Fatalf("GetSessionByTokenHash: %+v err %v", s, err)
	}
	if err := st.CreateSession(ctx, &store.Session{Username: "u1", Role: "admin", TokenHash: "expired", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if _, err := st.GetSessionByTokenHash(ctx, "expired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteSession(ctx, "sesshash"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	// Expiry must be enforced by REMOVING rows, not only by filtering reads. It
	// used to be filtering alone, so every portal login, break-glass activation
	// and 60-second RDP viewer token left a row behind forever — bloat in
	// PostgreSQL and a genuine leak in the in-memory store.
	if err := st.CreateSession(ctx, &store.Session{Username: "gc-live", Role: "user", TokenHash: "gc-live", ExpiresAt: future}); err != nil {
		t.Fatalf("CreateSession(live): %v", err)
	}
	for i, h := range []string{"gc-old-1", "gc-old-2"} {
		if err := st.CreateSession(ctx, &store.Session{
			Username: "gc-old", Role: "user", TokenHash: h, ExpiresAt: now.Add(-time.Duration(i+1) * time.Hour),
		}); err != nil {
			t.Fatalf("CreateSession(expired %d): %v", i, err)
		}
	}
	swept, err := st.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if swept < 2 {
		t.Fatalf("DeleteExpiredSessions removed %d rows, want at least the 2 expired ones", swept)
	}
	// The live session must survive — a sweep that took it would log everyone out.
	if s, err := st.GetSessionByTokenHash(ctx, "gc-live"); err != nil || s.Username != "gc-live" {
		t.Fatalf("the sweep removed a live session: %+v err %v", s, err)
	}
	// And it is idempotent: a second pass finds nothing left to do.
	if again, err := st.DeleteExpiredSessions(ctx, now); err != nil || again != 0 {
		t.Fatalf("second DeleteExpiredSessions = %d, %v; want 0, nil", again, err)
	}
	if err := st.DeleteSession(ctx, "gc-live"); err != nil {
		t.Fatalf("DeleteSession(gc-live): %v", err)
	}

	// --- MFA enrollment + recovery codes ---
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "u1", SecretEnc: "v2:totp", Confirmed: false}); err != nil {
		t.Fatalf("UpsertMFAEnrollment: %v", err)
	}
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "u1", SecretEnc: "v2:totp", Confirmed: true}); err != nil {
		t.Fatalf("UpsertMFAEnrollment(confirm): %v", err)
	}
	if e, err := st.GetMFAEnrollment(ctx, "u1"); err != nil || !e.Confirmed {
		t.Fatalf("GetMFAEnrollment: %+v err %v", e, err)
	}
	if es, err := st.ListMFAEnrollments(ctx); err != nil || len(es) != 1 {
		t.Fatalf("ListMFAEnrollments: %d err %v", len(es), err)
	}
	// TOTP anti-replay: a step is accepted once, then rejected; a newer step wins.
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 100); err != nil || !ok {
		t.Fatalf("ConsumeTOTPStep(100) = %v, %v; want true", ok, err)
	}
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 100); err != nil || ok {
		t.Fatalf("ConsumeTOTPStep(100) replay = %v, %v; want false", ok, err)
	}
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 101); err != nil || !ok {
		t.Fatalf("ConsumeTOTPStep(101) = %v, %v; want true", ok, err)
	}
	// ListMFAEnrollments must preserve last_totp_step too (a KEK-rotation re-Upsert
	// of a listed enrollment would otherwise reset the anti-replay counter to 0).
	if es, err := st.ListMFAEnrollments(ctx); err != nil || len(es) != 1 || es[0].LastTOTPStep != 101 {
		t.Fatalf("ListMFAEnrollments last step = %v err %v; want [101]", es, err)
	}
	if e, err := st.GetMFAEnrollment(ctx, "u1"); err != nil || e.LastTOTPStep != 101 {
		t.Fatalf("GetMFAEnrollment last step = %d err %v; want 101", e.LastTOTPStep, err)
	}
	if err := st.ReplaceMFARecoveryCodes(ctx, "u1", []string{"h1", "h2"}); err != nil {
		t.Fatalf("ReplaceMFARecoveryCodes: %v", err)
	}
	if n, _ := st.CountMFARecoveryCodes(ctx, "u1"); n != 2 {
		t.Fatalf("CountMFARecoveryCodes: got %d, want 2", n)
	}
	if ok, err := st.ConsumeMFARecoveryCode(ctx, "u1", "h1"); err != nil || !ok {
		t.Fatalf("ConsumeMFARecoveryCode: ok=%v err=%v", ok, err)
	}
	if ok, _ := st.ConsumeMFARecoveryCode(ctx, "u1", "h1"); ok {
		t.Fatal("recovery code must be single-use")
	}
	if n, _ := st.CountMFARecoveryCodes(ctx, "u1"); n != 1 {
		t.Fatalf("after consume: got %d, want 1", n)
	}
	if err := st.DeleteMFAEnrollment(ctx, "u1"); err != nil {
		t.Fatalf("DeleteMFAEnrollment: %v", err)
	}

	// --- OIDC login state (single-use, expiry) ---
	if err := st.PutOIDCState(ctx, "state1", "verifier1", "nonce1", future); err != nil {
		t.Fatalf("PutOIDCState: %v", err)
	}
	v, n, ok, err := st.TakeOIDCState(ctx, "state1", now)
	if err != nil || !ok || v != "verifier1" || n != "nonce1" {
		t.Fatalf("TakeOIDCState: v=%q n=%q ok=%v err=%v", v, n, ok, err)
	}
	if _, _, ok, _ := st.TakeOIDCState(ctx, "state1", now); ok {
		t.Fatal("OIDC state must be single-use")
	}
	if err := st.PutOIDCState(ctx, "state2", "v", "n", now.Add(-time.Minute)); err != nil {
		t.Fatalf("PutOIDCState(expired): %v", err)
	}
	if _, _, ok, _ := st.TakeOIDCState(ctx, "state2", now); ok {
		t.Fatal("expired OIDC state must not be returned")
	}

	// --- WebAuthn credentials (Phase 124): a user may register more than one,
	// unlike MFAEnrollment, so ID is a surrogate rather than username. ---
	wc1 := store.WebAuthnCredential{
		Username: "wa1", CredentialID: []byte("cred-1"), PublicKey: []byte("pubkey-1"),
		AttestationType: "none", Transports: "usb", Name: "YubiKey",
	}
	if err := st.CreateWebAuthnCredential(ctx, &wc1); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}
	if wc1.ID == 0 {
		t.Fatal("CreateWebAuthnCredential did not populate ID")
	}
	if wc1.CreatedAt.IsZero() {
		t.Fatal("CreateWebAuthnCredential did not populate CreatedAt")
	}
	wc2 := store.WebAuthnCredential{
		Username: "wa1", CredentialID: []byte("cred-2"), PublicKey: []byte("pubkey-2"), Name: "Phone",
	}
	if err := st.CreateWebAuthnCredential(ctx, &wc2); err != nil {
		t.Fatalf("CreateWebAuthnCredential(2nd): %v", err)
	}
	if creds, err := st.ListWebAuthnCredentials(ctx, "wa1"); err != nil || len(creds) != 2 {
		t.Fatalf("ListWebAuthnCredentials: %d creds, err %v; want 2", len(creds), err)
	} else if creds[0].ID != wc1.ID || creds[1].ID != wc2.ID {
		t.Fatalf("ListWebAuthnCredentials order = [%d %d], want [%d %d]", creds[0].ID, creds[1].ID, wc1.ID, wc2.ID)
	}
	if creds, err := st.ListWebAuthnCredentials(ctx, "nobody"); err != nil || len(creds) != 0 {
		t.Fatalf("ListWebAuthnCredentials(nobody): %d creds, err %v; want 0", len(creds), err)
	}
	if got, err := st.GetWebAuthnCredentialByCredentialID(ctx, []byte("cred-1")); err != nil || got.ID != wc1.ID || got.Username != "wa1" {
		t.Fatalf("GetWebAuthnCredentialByCredentialID: %+v err %v", got, err)
	}
	if _, err := st.GetWebAuthnCredentialByCredentialID(ctx, []byte("no-such-cred")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetWebAuthnCredentialByCredentialID(missing) err = %v, want ErrNotFound", err)
	}
	usedAt := now.Truncate(time.Microsecond)
	if err := st.UpdateWebAuthnSignCount(ctx, wc1.ID, 42, true, usedAt); err != nil {
		t.Fatalf("UpdateWebAuthnSignCount: %v", err)
	}
	if got, err := st.GetWebAuthnCredentialByCredentialID(ctx, []byte("cred-1")); err != nil || got.SignCount != 42 || !got.CloneWarning || got.LastUsedAt == nil || !got.LastUsedAt.Equal(usedAt) {
		t.Fatalf("after UpdateWebAuthnSignCount: %+v err %v", got, err)
	}
	if err := st.UpdateWebAuthnSignCount(ctx, 999999, 1, false, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateWebAuthnSignCount(missing id) err = %v, want ErrNotFound", err)
	}
	// DeleteWebAuthnCredential is scoped to username — a wrong owner must not
	// be able to delete someone else's credential even with the right id.
	if err := st.DeleteWebAuthnCredential(ctx, wc1.ID, "someone-else"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteWebAuthnCredential(wrong owner) err = %v, want ErrNotFound", err)
	}
	if err := st.DeleteWebAuthnCredential(ctx, wc1.ID, "wa1"); err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	if creds, err := st.ListWebAuthnCredentials(ctx, "wa1"); err != nil || len(creds) != 1 || creds[0].ID != wc2.ID {
		t.Fatalf("ListWebAuthnCredentials after delete: %+v err %v; want just [%d]", creds, err, wc2.ID)
	}

	// --- WebAuthn ceremony challenges: single-use, expiring, isolated by
	// (username, purpose) — the same atomic put/take-with-expiry shape as
	// OIDC state above. A fresh Put for the same key supersedes the old one. ---
	if err := st.PutWebAuthnChallenge(ctx, "wa1", "register", []byte("session-a"), future); err != nil {
		t.Fatalf("PutWebAuthnChallenge: %v", err)
	}
	if err := st.PutWebAuthnChallenge(ctx, "wa1", "login", []byte("session-b"), future); err != nil {
		t.Fatalf("PutWebAuthnChallenge(login): %v", err)
	}
	sd, ok, err := st.TakeWebAuthnChallenge(ctx, "wa1", "register", now)
	if err != nil || !ok || string(sd) != "session-a" {
		t.Fatalf("TakeWebAuthnChallenge(register): sd=%q ok=%v err=%v", sd, ok, err)
	}
	if _, ok, _ := st.TakeWebAuthnChallenge(ctx, "wa1", "register", now); ok {
		t.Fatal("webauthn challenge must be single-use")
	}
	// The "login" purpose challenge for the same user is untouched by taking
	// "register" — the two purposes do not share state.
	if sd, ok, err := st.TakeWebAuthnChallenge(ctx, "wa1", "login", now); err != nil || !ok || string(sd) != "session-b" {
		t.Fatalf("TakeWebAuthnChallenge(login): sd=%q ok=%v err=%v", sd, ok, err)
	}
	if err := st.PutWebAuthnChallenge(ctx, "wa1", "register", []byte("expired"), now.Add(-time.Minute)); err != nil {
		t.Fatalf("PutWebAuthnChallenge(expired): %v", err)
	}
	if _, ok, _ := st.TakeWebAuthnChallenge(ctx, "wa1", "register", now); ok {
		t.Fatal("expired webauthn challenge must not be returned")
	}
	// A second Put for the same (username, purpose) supersedes the first —
	// an abandoned Begin call must not linger once a fresh one replaces it.
	if err := st.PutWebAuthnChallenge(ctx, "wa1", "register", []byte("first"), future); err != nil {
		t.Fatalf("PutWebAuthnChallenge(first): %v", err)
	}
	if err := st.PutWebAuthnChallenge(ctx, "wa1", "register", []byte("second"), future); err != nil {
		t.Fatalf("PutWebAuthnChallenge(second): %v", err)
	}
	if sd, ok, err := st.TakeWebAuthnChallenge(ctx, "wa1", "register", now); err != nil || !ok || string(sd) != "second" {
		t.Fatalf("TakeWebAuthnChallenge after supersede: sd=%q ok=%v err=%v; want %q", sd, ok, err, "second")
	}

	// --- ListUsers ---
	if err := st.CreateUser(ctx, &store.User{Username: "list-check", Role: "auditor", TokenHash: "listuserhash"}); err != nil {
		t.Fatalf("CreateUser(list): %v", err)
	}
	if users, err := st.ListUsers(ctx, 0, 0); err != nil || len(users) == 0 {
		t.Fatalf("ListUsers: %d users, err %v", len(users), err)
	}
	if users, err := st.ListUsers(ctx, 1, 0); err != nil || len(users) != 1 {
		t.Fatalf("ListUsers(limit=1): %d users, err %v", len(users), err)
	}

	// --- delete cascades (memstore hand-codes what pgstore FK ON DELETE CASCADE does; assert parity) ---
	checkoutGone := func(credID int64) bool {
		cos, _ := st.ListCheckouts(ctx, false, now, 0, 0)
		for _, c := range cos {
			if c.CredentialID == credID {
				return false
			}
		}
		return true
	}
	casc := &store.Target{Name: "cascade-tgt", Host: "h", OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, casc); err != nil {
		t.Fatalf("CreateTarget(cascade): %v", err)
	}
	cc := &store.Credential{TargetID: casc.ID, Username: "root", SecretType: "password", SecretEnc: "v2:x"}
	if err := st.CreateCredential(ctx, cc); err != nil {
		t.Fatalf("CreateCredential(cascade): %v", err)
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: casc.ID, SubjectType: "role", Subject: "user"}); err != nil {
		t.Fatalf("CreateTargetGrant(cascade): %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cc.ID, TargetID: casc.ID, Holder: "h", ExpiresAt: future}, now); err != nil {
		t.Fatalf("CreateCheckout(cascade): %v", err)
	}
	// Deleting the target cascades to its credentials, grants and checkouts.
	if err := st.DeleteTarget(ctx, casc.ID); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if _, err := st.GetCredential(ctx, cc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("credential was not cascaded on target delete")
	}
	if g, _ := st.ListTargetGrants(ctx, casc.ID); len(g) != 0 {
		t.Fatalf("grants not cascaded on target delete: %d", len(g))
	}
	if !checkoutGone(cc.ID) {
		t.Fatal("checkout not cascaded on target delete")
	}

	// Deleting a credential cascades its checkouts.
	casc2 := &store.Target{Name: "cascade-tgt2", Host: "h", OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, casc2); err != nil {
		t.Fatal(err)
	}
	cc2 := &store.Credential{TargetID: casc2.ID, Username: "root", SecretType: "password", SecretEnc: "v2:x"}
	if err := st.CreateCredential(ctx, cc2); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cc2.ID, TargetID: casc2.ID, Holder: "h", ExpiresAt: future}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCredential(ctx, cc2.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if !checkoutGone(cc2.ID) {
		t.Fatal("checkout not cascaded on credential delete")
	}

	// --- settings (config overrides, Phase 12) ---
	if _, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSetting(missing): want ErrNotFound, got %v", err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_MFA_REQUIRED", Value: "true"}); err != nil {
		t.Fatalf("PutSetting: %v", err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_MFA_REQUIRED", Value: "false"}); err != nil { // upsert
		t.Fatalf("PutSetting(upsert): %v", err)
	}
	if got, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); err != nil || got.Value != "false" {
		t.Fatalf("GetSetting: %+v err %v", got, err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_BIND_PASSWORD", Value: "v2:enc", Secret: true}); err != nil {
		t.Fatalf("PutSetting(secret): %v", err)
	}
	if ss, err := st.ListSettings(ctx); err != nil || len(ss) != 2 {
		t.Fatalf("ListSettings: %d err %v", len(ss), err)
	}
	if err := st.DeleteSetting(ctx, "PAM_MFA_REQUIRED"); err != nil {
		t.Fatalf("DeleteSetting: %v", err)
	}
	if _, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted setting must be gone")
	}

	// --- profiles (custom RBAC, Phase 12) ---
	if _, err := st.GetProfile(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetProfile(missing): want ErrNotFound, got %v", err)
	}
	prof := &store.Profile{Name: "readonly", Capabilities: []string{"read_inventory", "read_audit"}}
	if err := st.CreateProfile(ctx, prof); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if err := st.CreateProfile(ctx, &store.Profile{Name: "readonly"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate profile: want ErrConflict, got %v", err)
	}
	if got, err := st.GetProfile(ctx, "readonly"); err != nil || len(got.Capabilities) != 2 || got.Capabilities[0] != "read_inventory" {
		t.Fatalf("GetProfile: %+v err %v", got, err)
	}
	if ps, err := st.ListProfiles(ctx); err != nil || len(ps) != 1 {
		t.Fatalf("ListProfiles: %d err %v", len(ps), err)
	}
	if err := st.DeleteProfile(ctx, prof.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := st.GetProfile(ctx, "readonly"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted profile must be gone")
	}

	// --- agent keys + broker audit chain (Phase 13) ---
	if head, err := st.GetBrokerAuditHead(ctx); err != nil || head != nil {
		t.Fatalf("GetBrokerAuditHead(empty): head=%v err=%v", head, err)
	}
	ak := &store.AgentKey{Name: "bot", Owner: "alice", TokenHash: "agenthash1"}
	if err := st.CreateAgentKey(ctx, ak); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	if got, err := st.GetAgentKeyByTokenHash(ctx, "agenthash1"); err != nil || got.Name != "bot" || got.Owner != "alice" {
		t.Fatalf("GetAgentKeyByTokenHash: %+v err %v", got, err)
	}
	// GetAgentKey by id (used for approval-time revocation checks).
	if got, err := st.GetAgentKey(ctx, ak.ID); err != nil || got.Name != "bot" {
		t.Fatalf("GetAgentKey(%d): %+v err %v", ak.ID, got, err)
	}
	if _, err := st.GetAgentKey(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgentKey(missing): want ErrNotFound, got %v", err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgentKeyByTokenHash(missing): want ErrNotFound, got %v", err)
	}
	if err := st.CreateAgentKey(ctx, &store.AgentKey{Name: "off", TokenHash: "agenthash2", Disabled: true}); err != nil {
		t.Fatalf("CreateAgentKey(disabled): %v", err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "agenthash2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a disabled agent key must not resolve")
	}
	if keys, err := st.ListAgentKeys(ctx); err != nil || len(keys) != 2 {
		t.Fatalf("ListAgentKeys: %d err %v", len(keys), err)
	}

	// At most one ACTIVE key per name (2026-08-26 audit, M-3): the budget and the
	// audit actor key on the name, so two active keys sharing one name would pool
	// one usage count under two different limits. Self-contained and cleaned up
	// so the counts above and below are undisturbed.
	m3a := &store.AgentKey{Name: "m3", Owner: "eve", TokenHash: "m3-hash-a"}
	if err := st.CreateAgentKey(ctx, m3a); err != nil {
		t.Fatalf("CreateAgentKey(m3a): %v", err)
	}
	if err := st.CreateAgentKey(ctx, &store.AgentKey{Name: "m3", Owner: "eve", TokenHash: "m3-hash-b"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second ACTIVE key named m3 was allowed: %v, want ErrConflict", err)
	}
	// Revoke-then-remint under the same name is rotation, and must be allowed.
	if err := st.SetAgentKeyDisabled(ctx, m3a.ID, true); err != nil {
		t.Fatalf("disable m3a: %v", err)
	}
	m3b := &store.AgentKey{Name: "m3", Owner: "eve", TokenHash: "m3-hash-b"}
	if err := st.CreateAgentKey(ctx, m3b); err != nil {
		t.Fatalf("re-minting m3 after revoke was refused: %v", err)
	}
	// Clean up both so the running set stays as the sections below expect.
	_ = st.DeleteAgentKey(ctx, m3a.ID)
	_ = st.DeleteAgentKey(ctx, m3b.ID)
	if err := st.DeleteAgentKey(ctx, ak.ID); err != nil {
		t.Fatalf("DeleteAgentKey: %v", err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "agenthash1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a deleted agent key must not resolve")
	}

	// --- agent key lifecycle: suspend, expiry, last-used (Phase 159) ---
	// Before this an agent identity could only be created or destroyed:
	// Disabled was honoured on read but nothing could set it, and a key had no
	// end date and no record of use.
	akLive := &store.AgentKey{Name: "lifecycle", Owner: "carol", TokenHash: "agenthash3"}
	if err := st.CreateAgentKey(ctx, akLive); err != nil {
		t.Fatalf("CreateAgentKey(lifecycle): %v", err)
	}
	// Default shape — not disabled, no expiry — is active forever, which is
	// what every pre-Phase-159 row looks like: adding the fields must not
	// retire keys that already exist.
	if !akLive.Active(now) {
		t.Fatal("a fresh agent key with no expiry must be active")
	}
	if akLive.ExpiresAt != nil || akLive.LastUsedAt != nil {
		t.Fatalf("a fresh agent key must have no expiry and no last-use: %+v", akLive)
	}
	// Expiry is carried through the store, not just held in the caller's
	// struct — otherwise a restart would resurrect an expired key.
	// Truncated to microsecond precision: PostgreSQL's TIMESTAMPTZ has no finer
	// resolution, so an untruncated wall clock would not compare equal.
	agentExpiry := past.Truncate(time.Microsecond)
	expiring := &store.AgentKey{Name: "expiring", Owner: "carol", TokenHash: "agenthash4", ExpiresAt: &agentExpiry}
	if err := st.CreateAgentKey(ctx, expiring); err != nil {
		t.Fatalf("CreateAgentKey(expiring): %v", err)
	}
	expGot, expErr := st.GetAgentKey(ctx, expiring.ID)
	if expErr != nil || expGot.ExpiresAt == nil || !expGot.ExpiresAt.Equal(agentExpiry) {
		t.Fatalf("GetAgentKey(expiring): %+v err %v", expGot, expErr)
	}
	// Both halves of Active() are independent: an unsuspended key past its
	// expiry is dead on the clock alone, with no operator involved.
	if expGot.Disabled {
		t.Fatal("the expiring key was never disabled")
	}
	if expGot.Active(now) {
		t.Fatal("a key past ExpiresAt must be inactive even though it is not disabled")
	}
	// ...and the other half: suspension kills a key that has not expired.
	if err := st.SetAgentKeyDisabled(ctx, akLive.ID, true); err != nil {
		t.Fatalf("SetAgentKeyDisabled(true): %v", err)
	}
	if got, err := st.GetAgentKey(ctx, akLive.ID); err != nil || !got.Disabled || got.Active(now) {
		t.Fatalf("a suspended key must read back disabled and inactive: %+v err %v", got, err)
	}
	// A suspended key must stop authenticating — the whole point of the
	// control is that it takes effect on the lookup path, not just in the UI.
	if _, err := st.GetAgentKeyByTokenHash(ctx, "agenthash3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a suspended agent key must not resolve by token hash")
	}
	// Idempotent: re-suspending an already-suspended key is a no-op success,
	// so a retried or duplicated admin action is never an error.
	if err := st.SetAgentKeyDisabled(ctx, akLive.ID, true); err != nil {
		t.Fatalf("SetAgentKeyDisabled(true, again): %v", err)
	}
	// Suspension is reversible — that is what makes it different from delete:
	// the row, its ID and its audit history survive.
	if err := st.SetAgentKeyDisabled(ctx, akLive.ID, false); err != nil {
		t.Fatalf("SetAgentKeyDisabled(false): %v", err)
	}
	if got, err := st.GetAgentKey(ctx, akLive.ID); err != nil || got.Disabled || !got.Active(now) {
		t.Fatalf("a restored key must be enabled and active again: %+v err %v", got, err)
	}
	if err := st.SetAgentKeyDisabled(ctx, 999999, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAgentKeyDisabled(missing): want ErrNotFound, got %v", err)
	}
	// Last-used is what makes a dormant-agent report possible; it must
	// round-trip the exact instant, not merely be non-nil.
	agentUsedAt := now.Truncate(time.Microsecond)
	if err := st.TouchAgentKey(ctx, akLive.ID, agentUsedAt); err != nil {
		t.Fatalf("TouchAgentKey: %v", err)
	}
	if got, err := st.GetAgentKey(ctx, akLive.ID); err != nil || got.LastUsedAt == nil || !got.LastUsedAt.Equal(agentUsedAt) {
		t.Fatalf("TouchAgentKey did not record the instant: %+v err %v", got, err)
	}
	if err := st.TouchAgentKey(ctx, 999999, agentUsedAt); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TouchAgentKey(missing): want ErrNotFound, got %v", err)
	}
	// Owner filtering: an owner sees their own agents and nobody else's, and
	// an owner with none gets an empty slice rather than a nil the caller
	// would have to special-case when serialising.
	if keys, err := st.ListAgentKeysByOwner(ctx, "carol"); err != nil || len(keys) != 2 ||
		keys[0].ID != akLive.ID || keys[1].ID != expiring.ID {
		t.Fatalf("ListAgentKeysByOwner(carol): %+v err %v", keys, err)
	}
	if keys, err := st.ListAgentKeysByOwner(ctx, "nobody"); err != nil || keys == nil || len(keys) != 0 {
		t.Fatalf("ListAgentKeysByOwner(nobody): want empty non-nil, got %+v err %v", keys, err)
	}

	// --- agent quarantine (Phase 159) ---
	// Keyed by subject, not by agent_keys ID, because an SVID-authenticated
	// agent has no key row at all — a SPIFFE ID must be quarantinable even
	// though pamv1 never issued it anything to disable.
	if q, err := st.IsAgentQuarantined(ctx, "spiffe://example.org/agent/planner"); err != nil || q {
		t.Fatalf("IsAgentQuarantined(clean): %v err %v", q, err)
	}
	if list, err := st.ListAgentQuarantine(ctx); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("ListAgentQuarantine(empty): want empty non-nil, got %+v err %v", list, err)
	}
	qz := &store.AgentQuarantine{Subject: "spiffe://example.org/agent/planner", Reason: "exfil attempt", CreatedBy: "alice"}
	if err := st.QuarantineAgent(ctx, qz); err != nil {
		t.Fatalf("QuarantineAgent: %v", err)
	}
	if qz.ID == 0 || qz.CreatedAt.IsZero() {
		t.Fatalf("QuarantineAgent did not populate ID/CreatedAt: %+v", qz)
	}
	if q, err := st.IsAgentQuarantined(ctx, "spiffe://example.org/agent/planner"); err != nil || !q {
		t.Fatalf("IsAgentQuarantined(quarantined): %v err %v", q, err)
	}
	// Quarantine is per-subject: stopping one agent must not stop another.
	if q, err := st.IsAgentQuarantined(ctx, "lifecycle"); err != nil || q {
		t.Fatal("quarantining one subject must not quarantine a different one")
	}
	// Set membership, not a log: a duplicate is a conflict, so releasing once
	// really releases (no stacked rows needing reference counting).
	dup := &store.AgentQuarantine{Subject: "spiffe://example.org/agent/planner", Reason: "again", CreatedBy: "bob"}
	if err := st.QuarantineAgent(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("QuarantineAgent(duplicate subject): want ErrConflict, got %v", err)
	}
	// A static agent-key name is just as valid a subject as a SPIFFE ID —
	// one control covering both authentication paths.
	qk := &store.AgentQuarantine{Subject: "lifecycle", Reason: "under review", CreatedBy: "alice"}
	if err := st.QuarantineAgent(ctx, qk); err != nil {
		t.Fatalf("QuarantineAgent(key name): %v", err)
	}
	// Ordered by ID, and the reason/actor round-trip — quarantine is an
	// accountable act, so "who stopped this agent and why" must survive.
	if list, err := st.ListAgentQuarantine(ctx); err != nil || len(list) != 2 ||
		list[0].ID != qz.ID || list[1].ID != qk.ID ||
		list[0].Reason != "exfil attempt" || list[0].CreatedBy != "alice" {
		t.Fatalf("ListAgentQuarantine: %+v err %v", list, err)
	}
	if err := st.ReleaseAgentQuarantine(ctx, qz.ID); err != nil {
		t.Fatalf("ReleaseAgentQuarantine: %v", err)
	}
	if q, err := st.IsAgentQuarantined(ctx, "spiffe://example.org/agent/planner"); err != nil || q {
		t.Fatal("a released subject must no longer be quarantined")
	}
	// Releasing quarantine leaves the key's own disabled/expiry state alone:
	// two independent controls, neither overwriting the other.
	if got, err := st.GetAgentKey(ctx, akLive.ID); err != nil || got.Disabled {
		t.Fatalf("releasing quarantine must not touch the agent key row: %+v err %v", got, err)
	}
	if err := st.ReleaseAgentQuarantine(ctx, qz.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReleaseAgentQuarantine(already released): want ErrNotFound, got %v", err)
	}
	if err := st.ReleaseAgentQuarantine(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReleaseAgentQuarantine(missing): want ErrNotFound, got %v", err)
	}
	// Clean up so later sections (and ListAgentKeys counts) see a tidy set.
	if err := st.ReleaseAgentQuarantine(ctx, qk.ID); err != nil {
		t.Fatalf("ReleaseAgentQuarantine(cleanup): %v", err)
	}

	// --- SPIFFE agent-owner registry (Phase 170) ---
	// The fact an SVID-authenticated agent had nowhere to record: who is
	// accountable for it. Four-eyes approval and the offboarding cascade both
	// read this, and both were inert for that identity kind without it.
	if list, err := st.ListAgentIdentities(ctx); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("ListAgentIdentities(empty): want empty non-nil, got %+v err %v", list, err)
	}
	if _, err := st.GetAgentIdentity(ctx, "spiffe://example.org/agent/planner"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgentIdentity(unregistered): want ErrNotFound, got %v", err)
	}
	ai := &store.AgentIdentity{
		SPIFFEID: "spiffe://example.org/agent/planner", Owner: "carol",
		Note: "release planner", CreatedBy: "alice",
	}
	if err := st.CreateAgentIdentity(ctx, ai); err != nil {
		t.Fatalf("CreateAgentIdentity: %v", err)
	}
	if ai.ID == 0 || ai.CreatedAt.IsZero() {
		t.Fatalf("CreateAgentIdentity did not populate ID/CreatedAt: %+v", ai)
	}
	if got, err := st.GetAgentIdentity(ctx, "spiffe://example.org/agent/planner"); err != nil ||
		got.Owner != "carol" || got.Note != "release planner" || got.CreatedBy != "alice" {
		t.Fatalf("GetAgentIdentity: %+v err %v", got, err)
	}
	// One identity, one owner: a second registration for the same SPIFFE ID
	// would make "who is accountable" ambiguous at the four-eyes decision.
	dupID := &store.AgentIdentity{SPIFFEID: "spiffe://example.org/agent/planner", Owner: "dave"}
	if err := st.CreateAgentIdentity(ctx, dupID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("CreateAgentIdentity(duplicate spiffe_id): want ErrConflict, got %v", err)
	}
	secondIdent := &store.AgentIdentity{SPIFFEID: "spiffe://example.org/agent/worker", Owner: "dave", CreatedBy: "alice"}
	if err := st.CreateAgentIdentity(ctx, secondIdent); err != nil {
		t.Fatalf("CreateAgentIdentity(second): %v", err)
	}
	// Owner filtering is the offboarding cascade's query.
	if list, err := st.ListAgentIdentitiesByOwner(ctx, "carol"); err != nil || len(list) != 1 || list[0].ID != ai.ID {
		t.Fatalf("ListAgentIdentitiesByOwner(carol): %+v err %v", list, err)
	}
	if list, err := st.ListAgentIdentitiesByOwner(ctx, "nobody"); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("ListAgentIdentitiesByOwner(nobody): want empty non-nil, got %+v err %v", list, err)
	}
	// Ownership outlives people: reassignment keeps the row, so when the
	// identity was first registered and by whom survives the handover.
	if err := st.SetAgentIdentityOwner(ctx, ai.ID, "dave"); err != nil {
		t.Fatalf("SetAgentIdentityOwner: %v", err)
	}
	if got, err := st.GetAgentIdentity(ctx, "spiffe://example.org/agent/planner"); err != nil ||
		got.Owner != "dave" || got.CreatedBy != "alice" || !got.CreatedAt.Equal(ai.CreatedAt) {
		t.Fatalf("reassignment must change only the owner: %+v err %v", got, err)
	}
	if err := st.SetAgentIdentityOwner(ctx, 999999, "dave"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAgentIdentityOwner(missing): want ErrNotFound, got %v", err)
	}
	if list, err := st.ListAgentIdentities(ctx); err != nil || len(list) != 2 ||
		list[0].ID != ai.ID || list[1].ID != secondIdent.ID {
		t.Fatalf("ListAgentIdentities: %+v err %v", list, err)
	}
	if err := st.DeleteAgentIdentity(ctx, ai.ID); err != nil {
		t.Fatalf("DeleteAgentIdentity: %v", err)
	}
	if err := st.DeleteAgentIdentity(ctx, ai.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteAgentIdentity(twice): want ErrNotFound, got %v", err)
	}
	if err := st.DeleteAgentIdentity(ctx, secondIdent.ID); err != nil {
		t.Fatalf("DeleteAgentIdentity(cleanup): %v", err)
	}
	// --- SVID enrollment and inventory (Phase 174) ---
	// An operator-created row is ENROLLED; a row pamv1 creates on first sight is
	// not, and that difference is what an inventory review reads.
	enrolledIdent := &store.AgentIdentity{SPIFFEID: "spiffe://example.org/agent/enrolled", Owner: "carol", CreatedBy: "alice"}
	if err := st.CreateAgentIdentity(ctx, enrolledIdent); err != nil {
		t.Fatalf("CreateAgentIdentity(enrolled): %v", err)
	}
	if got, gerr := st.GetAgentIdentity(ctx, enrolledIdent.SPIFFEID); gerr != nil || !got.Enrolled || got.FirstSeen != nil {
		t.Fatalf("an operator-created registration must be enrolled and unseen: %+v err %v", got, gerr)
	}
	const stranger = "spiffe://example.org/agent/stranger"
	firstSeenAt := now.Truncate(time.Microsecond)
	if fresh, serr := st.SeeAgentIdentity(ctx, stranger, firstSeenAt); serr != nil || !fresh {
		t.Fatalf("SeeAgentIdentity(first): created=%v err %v", fresh, serr)
	}
	sighted, gerr := st.GetAgentIdentity(ctx, stranger)
	if gerr != nil || sighted.Enrolled || sighted.Attributed() ||
		sighted.FirstSeen == nil || !sighted.FirstSeen.Equal(firstSeenAt) ||
		sighted.LastSeen == nil || !sighted.LastSeen.Equal(firstSeenAt) {
		t.Fatalf("a first sighting must record an unenrolled, unattributed row with both stamps: %+v err %v", sighted, gerr)
	}
	// A second sighting moves last-seen and leaves first-seen alone: the pair is
	// what answers "new here" versus "dormant".
	seenAgainAt := firstSeenAt.Add(90 * time.Minute)
	if fresh, serr := st.SeeAgentIdentity(ctx, stranger, seenAgainAt); serr != nil || fresh {
		t.Fatalf("SeeAgentIdentity(second): created=%v err %v, want false", fresh, serr)
	}
	again, gerr2 := st.GetAgentIdentity(ctx, stranger)
	if gerr2 != nil || again.ID != sighted.ID || !again.FirstSeen.Equal(firstSeenAt) || !again.LastSeen.Equal(seenAgainAt) {
		t.Fatalf("a later sighting must move only last_seen: %+v err %v", again, gerr2)
	}
	// Naming an owner IS enrolling — the act by which a human takes it on — and
	// a later sighting must never undo that.
	if err := st.SetAgentIdentityOwner(ctx, sighted.ID, "carol"); err != nil {
		t.Fatalf("SetAgentIdentityOwner(enrol): %v", err)
	}
	if _, serr := st.SeeAgentIdentity(ctx, stranger, seenAgainAt.Add(time.Minute)); serr != nil {
		t.Fatalf("SeeAgentIdentity(enrolled): %v", serr)
	}
	if got, gerr3 := st.GetAgentIdentity(ctx, stranger); gerr3 != nil || !got.Enrolled || got.Owner != "carol" ||
		got.LastSeen == nil || !got.LastSeen.Equal(seenAgainAt.Add(time.Minute)) {
		t.Fatalf("a sighting must stamp an enrolled row without downgrading it: %+v err %v", got, gerr3)
	}
	for _, id := range []int64{sighted.ID, enrolledIdent.ID} {
		if err := st.DeleteAgentIdentity(ctx, id); err != nil {
			t.Fatalf("DeleteAgentIdentity(cleanup %d): %v", id, err)
		}
	}
	if err := st.DeleteAgentKey(ctx, akLive.ID); err != nil {
		t.Fatalf("DeleteAgentKey(lifecycle): %v", err)
	}
	if err := st.DeleteAgentKey(ctx, expiring.ID); err != nil {
		t.Fatalf("DeleteAgentKey(expiring): %v", err)
	}

	// --- agent daily call budget (Phase 167) ---
	// The only volume control before this was an opt-in per-minute rate limit,
	// which bounds a burst but never a day: 60 calls/minute still allows
	// 86,400 privileged tool calls in 24 hours. The budget is the cumulative
	// "how much in total" limit; these assertions pin the two halves of it —
	// the setting (a three-state pointer) and the spend (what actually counts
	// against it).
	budgeted := &store.AgentKey{Name: "budgeted", Owner: "dave", TokenHash: "agenthash5"}
	if err := st.CreateAgentKey(ctx, budgeted); err != nil {
		t.Fatalf("CreateAgentKey(budgeted): %v", err)
	}
	// A brand-new key has NO per-agent setting — nil, not zero. Reading it as
	// zero would silently forbid every call the agent makes; reading a
	// deliberate zero as nil would silently allow them. Both directions are
	// bugs, so the nil-ness is asserted on the freshly created struct and
	// again after a round-trip through the store.
	if budgeted.BudgetPerDay != nil {
		t.Fatalf("a fresh agent key must have no budget setting, got %v", *budgeted.BudgetPerDay)
	}
	if got, err := st.GetAgentKey(ctx, budgeted.ID); err != nil || got.BudgetPerDay != nil {
		t.Fatalf("a fresh agent key must read back with a nil budget: %+v err %v", got, err)
	}
	// A budget supplied at creation time must be persisted by the INSERT, not
	// only held in the caller's struct — memstore stores the whole struct, so
	// a pgstore INSERT that forgot the column would pass every other test here
	// and then silently drop the setting in production.
	atCreate := 7
	created := &store.AgentKey{Name: "born-budgeted", Owner: "dave", TokenHash: "agenthash6", BudgetPerDay: &atCreate}
	if err := st.CreateAgentKey(ctx, created); err != nil {
		t.Fatalf("CreateAgentKey(born-budgeted): %v", err)
	}
	if got, err := st.GetAgentKey(ctx, created.ID); err != nil || got.BudgetPerDay == nil || *got.BudgetPerDay != 7 {
		t.Fatalf("a budget set at creation must survive the insert: %+v err %v", got, err)
	}
	// Set, then change: the ordinary edit path.
	five := 5
	if err := st.SetAgentKeyBudget(ctx, budgeted.ID, &five); err != nil {
		t.Fatalf("SetAgentKeyBudget(5): %v", err)
	}
	if got, err := st.GetAgentKey(ctx, budgeted.ID); err != nil || got.BudgetPerDay == nil || *got.BudgetPerDay != 5 {
		t.Fatalf("SetAgentKeyBudget(5) did not round-trip: %+v err %v", got, err)
	}
	hundred := 100
	if err := st.SetAgentKeyBudget(ctx, budgeted.ID, &hundred); err != nil {
		t.Fatalf("SetAgentKeyBudget(100): %v", err)
	}
	if got, err := st.GetAgentKey(ctx, budgeted.ID); err != nil || got.BudgetPerDay == nil || *got.BudgetPerDay != 100 {
		t.Fatalf("SetAgentKeyBudget(100) did not round-trip: %+v err %v", got, err)
	}
	// Zero is a VALUE, not an absence: an explicit "this agent may make no
	// calls at all". It must read back as a non-nil pointer to 0, because the
	// enforcement gate treats nil as "fall back to the server default" — if
	// zero collapsed to nil, a deliberate hard stop would quietly become an
	// allowance.
	zeroBudget := 0
	if err := st.SetAgentKeyBudget(ctx, budgeted.ID, &zeroBudget); err != nil {
		t.Fatalf("SetAgentKeyBudget(0): %v", err)
	}
	gotZero, zeroErr := st.GetAgentKey(ctx, budgeted.ID)
	if zeroErr != nil || gotZero.BudgetPerDay == nil {
		t.Fatalf("a budget of 0 must read back as a non-nil pointer, not as \"unset\": %+v err %v", gotZero, zeroErr)
	}
	if *gotZero.BudgetPerDay != 0 {
		t.Fatalf("SetAgentKeyBudget(0) round-tripped as %d", *gotZero.BudgetPerDay)
	}
	// Clearing with nil is the opposite of setting 0: it removes the per-agent
	// setting so the server-wide default applies again.
	if err := st.SetAgentKeyBudget(ctx, budgeted.ID, nil); err != nil {
		t.Fatalf("SetAgentKeyBudget(nil): %v", err)
	}
	gotNil, nilErr := st.GetAgentKey(ctx, budgeted.ID)
	if nilErr != nil || gotNil.BudgetPerDay != nil {
		t.Fatalf("SetAgentKeyBudget(nil) must clear the setting: %+v err %v", gotNil, nilErr)
	}
	// The whole point of the pointer, stated once, explicitly: three keys in
	// the three states must still be telling apart after a round-trip. nil is
	// not 0, and 0 is not 5.
	stateNil := &store.AgentKey{Name: "state-default", Owner: "erin", TokenHash: "agenthash7"}
	stateZero := &store.AgentKey{Name: "state-stopped", Owner: "erin", TokenHash: "agenthash8"}
	stateFive := &store.AgentKey{Name: "state-limited", Owner: "erin", TokenHash: "agenthash9"}
	for _, k := range []*store.AgentKey{stateNil, stateZero, stateFive} {
		if err := st.CreateAgentKey(ctx, k); err != nil {
			t.Fatalf("CreateAgentKey(%s): %v", k.Name, err)
		}
	}
	stopped, limited := 0, 5
	if err := st.SetAgentKeyBudget(ctx, stateZero.ID, &stopped); err != nil {
		t.Fatalf("SetAgentKeyBudget(stopped): %v", err)
	}
	if err := st.SetAgentKeyBudget(ctx, stateFive.ID, &limited); err != nil {
		t.Fatalf("SetAgentKeyBudget(limited): %v", err)
	}
	rtNil, err1 := st.GetAgentKey(ctx, stateNil.ID)
	rtZero, err2 := st.GetAgentKey(ctx, stateZero.ID)
	rtFive, err3 := st.GetAgentKey(ctx, stateFive.ID)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("GetAgentKey(three states): %v / %v / %v", err1, err2, err3)
	}
	if rtNil.BudgetPerDay != nil {
		t.Fatalf("state 1 of 3 (no setting) must be nil, got %d", *rtNil.BudgetPerDay)
	}
	if rtZero.BudgetPerDay == nil || *rtZero.BudgetPerDay != 0 {
		t.Fatalf("state 2 of 3 (hard stop) must be a pointer to 0, got %v", rtZero.BudgetPerDay)
	}
	if rtFive.BudgetPerDay == nil || *rtFive.BudgetPerDay != 5 {
		t.Fatalf("state 3 of 3 (limit 5) must be a pointer to 5, got %v", rtFive.BudgetPerDay)
	}
	// The list read paths must carry the column too. A SELECT that forgot it
	// would leave every listed key looking unset — the most dangerous failure
	// mode in this feature, because "unset" means "use the default", so a hard
	// stop or a tight limit would read as permission.
	listed, listErr := st.ListAgentKeysByOwner(ctx, "erin")
	if listErr != nil || len(listed) != 3 {
		t.Fatalf("ListAgentKeysByOwner(erin): %+v err %v", listed, listErr)
	}
	if listed[0].BudgetPerDay != nil ||
		listed[1].BudgetPerDay == nil || *listed[1].BudgetPerDay != 0 ||
		listed[2].BudgetPerDay == nil || *listed[2].BudgetPerDay != 5 {
		t.Fatalf("ListAgentKeysByOwner dropped or flattened the budgets: %+v", listed)
	}
	allKeys, allErr := st.ListAgentKeys(ctx)
	if allErr != nil {
		t.Fatalf("ListAgentKeys: %v", allErr)
	}
	foundLimited := false
	for _, k := range allKeys {
		if k.ID == stateFive.ID {
			foundLimited = true
			if k.BudgetPerDay == nil || *k.BudgetPerDay != 5 {
				t.Fatalf("ListAgentKeys dropped the budget: %+v", k)
			}
		}
	}
	if !foundLimited {
		t.Fatal("ListAgentKeys did not return the budgeted key")
	}
	// ...and the token-hash lookup, which is the read the broker itself does
	// on every call, so a missing column there would disable the budget
	// entirely while every admin screen still showed it.
	if got, err := st.GetAgentKeyByTokenHash(ctx, "agenthash9"); err != nil ||
		got.BudgetPerDay == nil || *got.BudgetPerDay != 5 {
		t.Fatalf("GetAgentKeyByTokenHash dropped the budget: %+v err %v", got, err)
	}
	if err := st.SetAgentKeyBudget(ctx, 999999, &five); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SetAgentKeyBudget(missing): want ErrNotFound, got %v", err)
	}

	// Spend: what actually counts against the budget. The trail below mixes
	// every broker outcome for two different agents, because the count is only
	// meaningful if it ignores the right things.
	budgetOld := &store.AuditEvent{Actor: "budgetbot", Action: "broker.tool_call.executed", Detail: "yesterday's work"}
	if err := st.AppendAudit(ctx, budgetOld); err != nil {
		t.Fatalf("AppendAudit(budget old): %v", err)
	}
	// The window starts at the first in-window event's OWN stored timestamp
	// rather than at the test process's clock: pgstore stamps rows from the
	// database server's clock, and the two machines need not agree.
	budgetFirst := &store.AuditEvent{Actor: "budgetbot", Action: "broker.tool_call.executed", Detail: "did the work"}
	if err := st.AppendAudit(ctx, budgetFirst); err != nil {
		t.Fatalf("AppendAudit(budget executed): %v", err)
	}
	budgetSince := budgetFirst.TS
	if !budgetOld.TS.Before(budgetSince) {
		t.Fatalf("audit timestamps did not advance between two appends (%v then %v) — the window test cannot be meaningful",
			budgetOld.TS, budgetSince)
	}
	rest := []store.AuditEvent{
		// Counts: the agent collecting the result of a call a human approved.
		// This is the other way work gets done; leaving it out would make
		// every approved call free.
		{Actor: "budgetbot", Action: "broker.tool_call.resumed", Detail: "collected an approved result"},
		// Does not count: policy said no, so no privileged work happened.
		// Charging refusals would let a misconfigured agent burn its own quota
		// and then have a legitimate call refused for the wrong reason.
		{Actor: "budgetbot", Action: "broker.tool_call.denied", Detail: "policy refused"},
		// Does not count: the call broke rather than did anything.
		{Actor: "budgetbot", Action: "broker.tool_call.failed", Detail: "upstream error"},
		// Does not count: a broker.tool_call.* action that is not one of the
		// two spending outcomes. Matching by prefix would wrongly count this.
		{Actor: "budgetbot", Action: "broker.tool_call.requested", Detail: "asked, not yet run"},
		// Does not count: not a broker action at all.
		{Actor: "budgetbot", Action: "target.read", Detail: "listed inventory"},
		// Does not count: a different agent's spend is not this one's.
		{Actor: "otherbot", Action: "broker.tool_call.executed", Detail: "someone else's work"},
	}
	for i := range rest {
		if err := st.AppendAudit(ctx, &rest[i]); err != nil {
			t.Fatalf("AppendAudit(%s): %v", rest[i].Action, err)
		}
	}
	// Exactly the executed + resumed rows for this agent inside the window.
	if n, err := st.CountAgentToolCallsSince(ctx, "budgetbot", budgetSince); err != nil || n != 2 {
		t.Fatalf("CountAgentToolCallsSince(budgetbot, window) = %d (err %v), want 2 (executed + resumed)", n, err)
	}
	// Widening the window picks up the older executed call, which proves the
	// 2 above was a `since` exclusion and not an accidental miss.
	if n, err := st.CountAgentToolCallsSince(ctx, "budgetbot", past); err != nil || n != 3 {
		t.Fatalf("CountAgentToolCallsSince(budgetbot, past) = %d (err %v), want 3", n, err)
	}
	// A window that has not started yet counts nothing — this is what "the
	// budget resets" looks like from the store's side.
	if n, err := st.CountAgentToolCallsSince(ctx, "budgetbot", future); err != nil || n != 0 {
		t.Fatalf("CountAgentToolCallsSince(budgetbot, future) = %d (err %v), want 0", n, err)
	}

	// --- per-TOKEN ceiling (Phase 209) ---
	//
	// The same trail, grouped by the presented token's `jti` instead of by the
	// agent. Every row below is written with the field the API actually writes,
	// through store.AgentTokenAuditField, so this contract fails if a backend
	// searches for something the writer never produces.
	tokenRows := []store.AuditEvent{
		{Actor: "tokenbot", Action: store.AuditActionToolCallExecuted,
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-aaa")},
		{Actor: "tokenbot", Action: store.AuditActionToolCallResumed,
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-aaa")},
		// A second token's spend is not the first token's — this is the whole
		// point of the method: a fresh token starts with a fresh ceiling.
		{Actor: "tokenbot", Action: store.AuditActionToolCallExecuted,
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-bbb")},
		// Same jti, different agent: must not be counted, or one agent could
		// spend another's ceiling by quoting its token id.
		{Actor: "tokenbot2", Action: store.AuditActionToolCallExecuted,
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-aaa")},
		// A refusal carrying the same token does not count, exactly as it does
		// not for the daily budget: a ceiling measures work done, not work
		// refused.
		{Actor: "tokenbot", Action: "broker.tool_call.denied",
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-aaa")},
		// A jti that is a strict PREFIX of another must not match it. This is
		// what the quoting in AgentTokenAuditField buys: the field is delimited,
		// so "tok-a" cannot match inside "tok-aaa".
		{Actor: "tokenbot", Action: store.AuditActionToolCallExecuted,
			Detail: "tool:\"ssh_exec\"" + store.AgentTokenAuditField("tok-a")},
	}
	for i := range tokenRows {
		if err := st.AppendAudit(ctx, &tokenRows[i]); err != nil {
			t.Fatalf("AppendAudit(token row %d): %v", i, err)
		}
	}
	for _, tc := range []struct {
		name  string
		agent string
		jti   string
		want  int
	}{
		{"executed + resumed for one token", "tokenbot", "tok-aaa", 2},
		{"a second token has its own count", "tokenbot", "tok-bbb", 1},
		{"another agent's rows are not counted", "tokenbot2", "tok-aaa", 1},
		{"a prefix jti matches only itself", "tokenbot", "tok-a", 1},
		{"an unknown token has spent nothing", "tokenbot", "tok-zzz", 0},
		// A static agent key carries no token id. Answering 0 is correct, not a
		// fallback: its ceiling is the per-day budget on its own key row.
		{"an empty jti counts nothing", "tokenbot", "", 0},
	} {
		if n, err := st.CountAgentCallsForTokenSince(ctx, tc.agent, tc.jti, budgetSince); err != nil || n != tc.want {
			t.Errorf("CountAgentCallsForTokenSince(%s, %q): %s = %d (err %v), want %d",
				tc.agent, tc.jti, tc.name, n, err, tc.want)
		}
	}
	// The window applies here too: nothing is counted before it starts.
	if n, err := st.CountAgentCallsForTokenSince(ctx, "tokenbot", "tok-aaa", future); err != nil || n != 0 {
		t.Fatalf("CountAgentCallsForTokenSince(future) = %d (err %v), want 0", n, err)
	}
	// Per-agent, not global.
	if n, err := st.CountAgentToolCallsSince(ctx, "otherbot", past); err != nil || n != 1 {
		t.Fatalf("CountAgentToolCallsSince(otherbot) = %d (err %v), want 1", n, err)
	}
	// An agent with no history spends nothing, and the actor match is exact
	// and case-sensitive: "Budgetbot" is a different identity from "budgetbot"
	// and must not inherit its spend.
	if n, err := st.CountAgentToolCallsSince(ctx, "nosuchbot", past); err != nil || n != 0 {
		t.Fatalf("CountAgentToolCallsSince(unknown agent) = %d (err %v), want 0", n, err)
	}
	if n, err := st.CountAgentToolCallsSince(ctx, "Budgetbot", past); err != nil || n != 0 {
		t.Fatalf("CountAgentToolCallsSince is not case-sensitive on actor: got %d (err %v), want 0", n, err)
	}
	// Clean up so later sections see the same tidy set they did before.
	for _, k := range []*store.AgentKey{budgeted, created, stateNil, stateZero, stateFive} {
		if err := st.DeleteAgentKey(ctx, k.ID); err != nil {
			t.Fatalf("DeleteAgentKey(%s): %v", k.Name, err)
		}
	}

	// --- operator SSH certificates + KRL revocation (Phase 28) ---
	vb := future
	c1 := &store.SSHCert{Serial: 1001, KeyID: "pamv1:alice@web", Principal: "root", Actor: "alice", ValidBefore: &vb}
	if err := st.RecordSSHCert(ctx, c1); err != nil {
		t.Fatalf("RecordSSHCert: %v", err)
	}
	if c1.ID == 0 || c1.IssuedAt.IsZero() {
		t.Fatalf("RecordSSHCert did not populate ID/IssuedAt: %+v", c1)
	}
	if err := st.RecordSSHCert(ctx, &store.SSHCert{Serial: 1001}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate serial: want ErrConflict, got %v", err)
	}
	if err := st.RecordSSHCert(ctx, &store.SSHCert{Serial: 1002, Principal: "svc", Actor: "bob"}); err != nil {
		t.Fatalf("RecordSSHCert(2): %v", err)
	}
	// Nothing revoked yet.
	if revoked, err := st.ListRevokedSSHCertSerials(ctx); err != nil || len(revoked) != 0 {
		t.Fatalf("ListRevokedSSHCertSerials(none): %v err %v", revoked, err)
	}
	// Revoke one; it appears in the KRL serial list, and a re-revoke conflicts.
	if err := st.RevokeSSHCert(ctx, 1001, "carol", now); err != nil {
		t.Fatalf("RevokeSSHCert: %v", err)
	}
	if err := st.RevokeSSHCert(ctx, 1001, "carol", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("double revoke: want ErrConflict, got %v", err)
	}
	if err := st.RevokeSSHCert(ctx, 9999, "carol", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke unknown: want ErrNotFound, got %v", err)
	}
	if revoked, err := st.ListRevokedSSHCertSerials(ctx); err != nil || len(revoked) != 1 || revoked[0] != 1001 {
		t.Fatalf("ListRevokedSSHCertSerials(one): %v err %v", revoked, err)
	}
	if certs, err := st.ListSSHCerts(ctx, 10); err != nil || len(certs) != 2 || certs[0].Serial != 1002 {
		t.Fatalf("ListSSHCerts newest-first: %+v err %v", certs, err)
	}

	// --- vendor access gate (Phase 29) ---
	ven := &store.Vendor{Username: "acme-tech", Org: "ACME"}
	if err := st.CreateVendor(ctx, ven); err != nil {
		t.Fatalf("CreateVendor: %v", err)
	}
	if err := st.CreateVendor(ctx, &store.Vendor{Username: "acme-tech"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate vendor: want ErrConflict, got %v", err)
	}
	if v, err := st.GetVendorByUsername(ctx, "acme-tech"); err != nil || v.Org != "ACME" {
		t.Fatalf("GetVendorByUsername: %+v err %v", v, err)
	}
	if vs, err := st.ListVendors(ctx, 0, 0); err != nil || len(vs) != 1 || vs[0].Username != "acme-tech" {
		t.Fatalf("ListVendors: %+v err %v", vs, err)
	}
	if vs, err := st.ListVendors(ctx, 10, ven.ID); err != nil || len(vs) != 0 {
		t.Fatalf("ListVendors(after=last): %d err %v", len(vs), err)
	}
	if err := st.UpdateVendorOrg(ctx, ven.ID, "ACME Industries"); err != nil {
		t.Fatalf("UpdateVendorOrg: %v", err)
	}
	if v, _ := st.GetVendorByUsername(ctx, "acme-tech"); v.Org != "ACME Industries" {
		t.Fatalf("after UpdateVendorOrg: %+v", v)
	}
	if err := st.UpdateVendorOrg(ctx, 999999, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdateVendorOrg missing: want ErrNotFound, got %v", err)
	}
	if _, err := st.GetVendorByUsername(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown vendor: want ErrNotFound, got %v", err)
	}
	// A non-vendor login is unaffected by the gate.
	if isV, ok, err := st.VendorSessionAllowed(ctx, "alice", tgt.Name, "root", now); err != nil || isV || !ok {
		t.Fatalf("non-vendor gate: isVendor=%v allowed=%v err=%v (want false,true)", isV, ok, err)
	}
	// A vendor with no grant is a vendor but not allowed.
	if isV, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "root", now); !isV || ok {
		t.Fatalf("vendor no grant: isVendor=%v allowed=%v (want true,false)", isV, ok)
	}
	// A grant to a missing vendor/target is ErrNotFound.
	if err := st.CreateVendorGrant(ctx, &store.VendorGrant{VendorID: 999999, TargetID: tgt.ID, NotAfter: future}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("grant on missing vendor: want ErrNotFound, got %v", err)
	}
	grant := &store.VendorGrant{VendorID: ven.ID, TargetID: tgt.ID, Principal: "root", NotAfter: future}
	if err := st.CreateVendorGrant(ctx, grant); err != nil {
		t.Fatalf("CreateVendorGrant: %v", err)
	}
	// Pending grant does not yet allow access.
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "root", now); ok {
		t.Fatal("a pending grant must not allow access")
	}
	if err := st.ApproveVendorGrant(ctx, grant.ID, "customer-appr", now); err != nil {
		t.Fatalf("ApproveVendorGrant: %v", err)
	}
	if err := st.ApproveVendorGrant(ctx, grant.ID, "customer-appr", now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("re-approve: want ErrConflict, got %v", err)
	}
	// Approved, in-window, matching account: allowed. Past the window: not allowed.
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "root", now); !ok {
		t.Fatal("an approved in-window grant must allow access as the granted account")
	}
	// The grant is scoped to "root": a DIFFERENT account is refused, and the
	// account-agnostic query ("") still sees the grant.
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "postgres", now); ok {
		t.Fatal("a grant for root must not authorize a different account")
	}
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "", now); !ok {
		t.Fatal("an account-agnostic query must see the active grant")
	}
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "root", future.Add(time.Minute)); ok {
		t.Fatal("a grant past its window must not allow access")
	}
	// Offboard cascade: disables the vendor and revokes the grant.
	if err := st.OffboardVendor(ctx, ven.ID, now); err != nil {
		t.Fatalf("OffboardVendor: %v", err)
	}
	if v, _ := st.GetVendorByUsername(ctx, "acme-tech"); v == nil || !v.Disabled {
		t.Fatalf("offboarded vendor must be disabled: %+v", v)
	}
	if _, ok, _ := st.VendorSessionAllowed(ctx, "acme-tech", tgt.Name, "root", now); ok {
		t.Fatal("an offboarded vendor must not have access")
	}
	if grants, err := st.ListVendorGrants(ctx, ven.ID); err != nil || len(grants) != 1 || grants[0].Status != "revoked" {
		t.Fatalf("ListVendorGrants after offboard: %+v err %v", grants, err)
	}
	if err := st.OffboardVendor(ctx, 999999, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("offboard unknown vendor: want ErrNotFound, got %v", err)
	}

	// Application-secrets API (Phase 24): app keys + per-app secret grants
	// (default-deny; grants cascade on credential or app delete).
	appTarget := &store.Target{Name: "app-host", Host: "10.9.9.9", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, appTarget); err != nil {
		t.Fatalf("CreateTarget(app): %v", err)
	}
	appCred := &store.Credential{TargetID: appTarget.ID, Username: "svc", SecretType: "password", SecretEnc: "v2:enc"}
	if err := st.CreateCredential(ctx, appCred); err != nil {
		t.Fatalf("CreateCredential(app): %v", err)
	}
	app := &store.AppKey{Name: "ci-runner", Owner: "team", TokenHash: "apphash1"}
	if err := st.CreateAppKey(ctx, app); err != nil {
		t.Fatalf("CreateAppKey: %v", err)
	}
	if got, err := st.GetAppKeyByTokenHash(ctx, "apphash1"); err != nil || got.Name != "ci-runner" {
		t.Fatalf("GetAppKeyByTokenHash: %+v err %v", got, err)
	}
	if err := st.CreateAppKey(ctx, &store.AppKey{Name: "off", TokenHash: "apphash2", Disabled: true}); err != nil {
		t.Fatalf("CreateAppKey(disabled): %v", err)
	}
	if _, err := st.GetAppKeyByTokenHash(ctx, "apphash2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a disabled app key must not resolve")
	}
	// Default-deny before a grant.
	if ok, err := st.AppMayAccessCredential(ctx, app.ID, appCred.ID); err != nil || ok {
		t.Fatalf("AppMayAccessCredential before grant: ok=%v err=%v", ok, err)
	}
	ag := &store.AppSecretGrant{AppID: app.ID, CredentialID: appCred.ID}
	if err := st.GrantAppSecret(ctx, ag); err != nil {
		t.Fatalf("GrantAppSecret: %v", err)
	}
	if ok, err := st.AppMayAccessCredential(ctx, app.ID, appCred.ID); err != nil || !ok {
		t.Fatalf("AppMayAccessCredential after grant: ok=%v err=%v", ok, err)
	}
	if err := st.GrantAppSecret(ctx, &store.AppSecretGrant{AppID: app.ID, CredentialID: appCred.ID}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate grant: want ErrConflict, got %v", err)
	}
	if err := st.GrantAppSecret(ctx, &store.AppSecretGrant{AppID: app.ID, CredentialID: 999999}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("grant to a missing credential: want ErrNotFound, got %v", err)
	}
	if grants, err := st.ListAppSecretGrants(ctx, app.ID); err != nil || len(grants) != 1 {
		t.Fatalf("ListAppSecretGrants: %d err %v", len(grants), err)
	}
	// Explicit grant delete.
	if err := st.DeleteAppSecretGrant(ctx, ag.ID); err != nil {
		t.Fatalf("DeleteAppSecretGrant: %v", err)
	}
	if err := st.DeleteAppSecretGrant(ctx, ag.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteAppSecretGrant(missing): want ErrNotFound, got %v", err)
	}
	if ok, _ := st.AppMayAccessCredential(ctx, app.ID, appCred.ID); ok {
		t.Fatal("access must be denied after the grant is deleted")
	}
	// Grant cascades when the credential is deleted.
	if err := st.GrantAppSecret(ctx, &store.AppSecretGrant{AppID: app.ID, CredentialID: appCred.ID}); err != nil {
		t.Fatalf("GrantAppSecret(re): %v", err)
	}
	if err := st.DeleteCredential(ctx, appCred.ID); err != nil {
		t.Fatalf("DeleteCredential(app): %v", err)
	}
	if grants, err := st.ListAppSecretGrants(ctx, app.ID); err != nil || len(grants) != 0 {
		t.Fatalf("grant should cascade on credential delete: %d err %v", len(grants), err)
	}
	// Grant cascades when the app is deleted.
	appCred2 := &store.Credential{TargetID: appTarget.ID, Username: "svc2", SecretType: "password", SecretEnc: "v2:enc"}
	if err := st.CreateCredential(ctx, appCred2); err != nil {
		t.Fatalf("CreateCredential(app2): %v", err)
	}
	if err := st.GrantAppSecret(ctx, &store.AppSecretGrant{AppID: app.ID, CredentialID: appCred2.ID}); err != nil {
		t.Fatalf("GrantAppSecret(2): %v", err)
	}
	if err := st.DeleteAppKey(ctx, app.ID); err != nil {
		t.Fatalf("DeleteAppKey: %v", err)
	}
	if _, err := st.GetAppKeyByTokenHash(ctx, "apphash1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a deleted app key must not resolve")
	}
	if ok, _ := st.AppMayAccessCredential(ctx, app.ID, appCred2.ID); ok {
		t.Fatal("grant should cascade on app delete")
	}

	// Broker audit is append-only; the store reads the head under its append lock
	// and threads it to the linker (nil at genesis), so appends can't fork the
	// chain. Head follows the latest, list is chain order.
	if _, err := st.AppendBrokerAuditLinked(ctx, func(head *store.BrokerAuditEvent) store.BrokerAuditEvent {
		if head != nil {
			t.Fatalf("first append: want nil head at genesis, got %+v", head)
		}
		return store.BrokerAuditEvent{Actor: "bot", Action: "broker.tool_call.executed", Detail: "one", PrevHash: []byte{}, HMAC: []byte{0x01}}
	}); err != nil {
		t.Fatalf("AppendBrokerAuditLinked: %v", err)
	}
	if _, err := st.AppendBrokerAuditLinked(ctx, func(head *store.BrokerAuditEvent) store.BrokerAuditEvent {
		if head == nil || len(head.HMAC) != 1 || head.HMAC[0] != 0x01 {
			t.Fatalf("second append: want head HMAC 0x01, got %+v", head)
		}
		return store.BrokerAuditEvent{Actor: "bot", Action: "broker.tool_call.denied", Detail: "two", PrevHash: head.HMAC, HMAC: []byte{0x02}}
	}); err != nil {
		t.Fatalf("AppendBrokerAuditLinked: %v", err)
	}
	if head, err := st.GetBrokerAuditHead(ctx); err != nil || head == nil || head.Detail != "two" {
		t.Fatalf("GetBrokerAuditHead: %+v err %v", head, err)
	}
	all, err := st.ListBrokerAudit(ctx, 0)
	if err != nil || len(all) != 2 || all[0].Detail != "one" || all[1].Detail != "two" {
		t.Fatalf("ListBrokerAudit: %+v err %v", all, err)
	}
	if len(all[0].HMAC) != 1 || all[0].HMAC[0] != 0x01 {
		t.Fatalf("broker audit HMAC not round-tripped: %v", all[0].HMAC)
	}

	// --- broker single-use resume tokens (Phase 13) ---
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-1", CallID: "call_abc", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken: %v", err)
	}
	// A duplicate JTI is a conflict in both stores (not a silent overwrite).
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-1", CallID: "call_other", ExpiresAt: time.Now().Add(time.Hour).UTC()}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("CreateBrokerToken(dup): want ErrConflict, got %v", err)
	}
	// First consume wins and returns the bound call id.
	if cid, err := st.ConsumeBrokerToken(ctx, "jti-1"); err != nil || cid != "call_abc" {
		t.Fatalf("ConsumeBrokerToken: cid=%q err=%v", cid, err)
	}
	// A second consume of the same token fails — single-use.
	if _, err := st.ConsumeBrokerToken(ctx, "jti-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(reuse): want ErrNotFound, got %v", err)
	}
	// An unknown token fails.
	if _, err := st.ConsumeBrokerToken(ctx, "jti-nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(unknown): want ErrNotFound, got %v", err)
	}
	// An expired token cannot be consumed.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-exp", CallID: "call_x", ExpiresAt: time.Now().Add(-time.Minute).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(expired): %v", err)
	}
	if _, err := st.ConsumeBrokerToken(ctx, "jti-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(expired): want ErrNotFound, got %v", err)
	}

	// Peek returns the bound call id WITHOUT spending the token (repeatable), then
	// Consume spends it and Peek reports it gone.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-peek", CallID: "call_peek", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(peek): %v", err)
	}
	for i := 0; i < 2; i++ {
		if cid, err := st.PeekBrokerToken(ctx, "jti-peek"); err != nil || cid != "call_peek" {
			t.Fatalf("PeekBrokerToken (unspent): cid=%q err=%v", cid, err)
		}
	}
	if _, err := st.ConsumeBrokerToken(ctx, "jti-peek"); err != nil {
		t.Fatalf("ConsumeBrokerToken(peek): %v", err)
	}
	if _, err := st.PeekBrokerToken(ctx, "jti-peek"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("PeekBrokerToken(spent): want ErrNotFound, got %v", err)
	}

	// GC removes spent + expired tokens; an unexpired unused one survives.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-live", CallID: "call_live", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(live): %v", err)
	}
	if n, err := st.DeleteExpiredBrokerTokens(ctx); err != nil || n < 1 {
		t.Fatalf("DeleteExpiredBrokerTokens: n=%d err=%v", n, err)
	}
	if cid, err := st.PeekBrokerToken(ctx, "jti-live"); err != nil || cid != "call_live" {
		t.Fatalf("GC removed a live token: cid=%q err=%v", cid, err)
	}

	// --- leader lock ---
	// An uncontended lock runs fn and reports ran=true; fn's error propagates.
	ran, err := st.WithLeaderLock(ctx, 0x70616d5f7473, func(context.Context) error { return nil }) // "pam_ts"
	if err != nil || !ran {
		t.Fatalf("WithLeaderLock(uncontended): ran=%v err=%v", ran, err)
	}
	sentinel := errors.New("boom")
	if _, err := st.WithLeaderLock(ctx, 0x70616d5f7473, func(context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("WithLeaderLock must propagate fn's error, got %v", err)
	}

	// --- audit cursor read (Phase 35) ---
	// AuditSince returns events with id > afterID, oldest-first, capped by limit.
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "fwd", Action: "fwd.one", Detail: "a"}); err != nil {
		t.Fatal(err)
	}
	base, err := st.AuditSince(ctx, 0, 1000)
	if err != nil || len(base) == 0 {
		t.Fatalf("AuditSince(0): %d events, err %v", len(base), err)
	}
	if base[0].ID > base[len(base)-1].ID {
		t.Fatal("AuditSince must return events oldest-first (ascending id)")
	}
	lastID := base[len(base)-1].ID
	if after, err := st.AuditSince(ctx, lastID, 1000); err != nil || len(after) != 0 {
		t.Fatalf("AuditSince(lastID) must be empty, got %d (err %v)", len(after), err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "fwd", Action: "fwd.two", Detail: "b"}); err != nil {
		t.Fatal(err)
	}
	if next, err := st.AuditSince(ctx, lastID, 1000); err != nil || len(next) != 1 || next[0].Action != "fwd.two" {
		t.Fatalf("AuditSince(lastID) after a new event = %v (err %v)", next, err)
	}

	// --- audit retention prune (Phase 36) ---
	// A cutoff in the future prunes everything present; the trail is then empty.
	if _, err := st.PruneAuditBefore(ctx, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("PruneAuditBefore(future): %v", err)
	}
	if remaining, err := st.AuditSince(ctx, 0, 1000); err != nil || len(remaining) != 0 {
		t.Fatalf("after pruning everything, %d events remain (err %v)", len(remaining), err)
	}
	// A fresh event survives a cutoff in the past (ts >= cutoff).
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "ret", Action: "ret.keep", Detail: "x"}); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneAuditBefore(ctx, time.Now().Add(-24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("PruneAuditBefore(past) removed %d (err %v), want 0", n, err)
	}
	if remaining, err := st.AuditSince(ctx, 0, 1000); err != nil || len(remaining) != 1 {
		t.Fatalf("a recent event must survive a past cutoff, got %d (err %v)", len(remaining), err)
	}

	// --- ListAudit limit semantics ---
	// This exists because the two stores silently disagreed here and nothing
	// caught it: pgstore collapsed any limit above 500 back to the 100 default,
	// so a caller asking for 2000 got 2000 from memstore in tests and 100 from
	// Postgres in production. An interface with two implementations is only as
	// good as the contract test holding them together, so the limit rule is now
	// part of that contract rather than an implementation detail each side
	// invented for itself.
	//
	// The assertions below are deliberately built to FAIL against the old
	// pgstore. That takes more than 100 events and a mid-sized explicit limit:
	// with fewer events, or comparing only against the default page, the broken
	// and correct implementations return identical results and the test proves
	// nothing.
	const auditFill = store.DefaultAuditPage + 60 // 160: comfortably over the default page
	for i := 0; i < auditFill; i++ {
		if err := st.AppendAudit(ctx, &store.AuditEvent{
			Actor: "limit-contract", Action: "test.page", Detail: fmt.Sprintf("n:%d", i),
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	const midLimit = store.DefaultAuditPage + 40 // 140: above the default, below any cap
	mid, err := st.ListAudit(ctx, midLimit)
	if err != nil {
		t.Fatalf("ListAudit(%d): %v", midLimit, err)
	}
	if len(mid) != midLimit {
		t.Fatalf("ListAudit(%d) returned %d events, want exactly %d", midLimit, len(mid), midLimit)
	}
	// An oversized limit must be CAPPED, never reduced to the default: asking for
	// more must never return less. This is the assertion the old pgstore fails —
	// it answered an oversized request with the 100-event default, fewer than the
	// 140 a smaller request returned.
	big, err := st.ListAudit(ctx, store.MaxAuditPage*10)
	if err != nil {
		t.Fatalf("ListAudit(oversized): %v", err)
	}
	if len(big) < len(mid) {
		t.Fatalf("ListAudit(oversized) returned %d events but ListAudit(%d) returned %d — asking for more must never return less",
			len(big), midLimit, len(mid))
	}
	if len(big) > store.MaxAuditPage {
		t.Fatalf("ListAudit returned %d events, above the MaxAuditPage cap of %d", len(big), store.MaxAuditPage)
	}
	// A non-positive limit means the default page — not "everything", which is
	// what memstore used to do.
	zero, err := st.ListAudit(ctx, 0)
	if err != nil {
		t.Fatalf("ListAudit(0): %v", err)
	}
	if len(zero) != store.DefaultAuditPage {
		t.Fatalf("ListAudit(0) returned %d events, want the default page of %d", len(zero), store.DefaultAuditPage)
	}
	// A small explicit limit is honoured exactly, newest first.
	page, err := st.ListAudit(ctx, 5)
	if err != nil {
		t.Fatalf("ListAudit(5): %v", err)
	}
	if len(page) != 5 {
		t.Fatalf("ListAudit(5) returned %d events, want exactly 5", len(page))
	}
	for i := 1; i < len(page); i++ {
		if page[i-1].ID <= page[i].ID {
			t.Fatalf("ListAudit is not newest-first: id %d before id %d", page[i-1].ID, page[i].ID)
		}
	}

	// --- LatestAuditByAction ---
	// Retention's archiver uses this to find where the previous archive finished,
	// so both stores must agree on "most recent" and on "none" — a wrong answer
	// here re-exports history that is already archived, or (worse) skips events.
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "sys", Action: "marker.test", Detail: "n:1"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "sys", Action: "other.action", Detail: "noise"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "sys", Action: "marker.test", Detail: "n:2"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	latest, err := st.LatestAuditByAction(ctx, "marker.test")
	if err != nil {
		t.Fatalf("LatestAuditByAction: %v", err)
	}
	if latest == nil || latest.Detail != "n:2" {
		t.Fatalf("LatestAuditByAction returned %+v, want the newest marker (n:2)", latest)
	}
	// An action with no events is (nil, nil) — not an error, and not the newest
	// event of some other action.
	if missing, err := st.LatestAuditByAction(ctx, "marker.never.happened"); err != nil || missing != nil {
		t.Fatalf("LatestAuditByAction(unknown) = %+v, %v; want nil, nil", missing, err)
	}

	// --- session kill bus (Phase 34) ---
	// A selector published on the bus is delivered to a subscriber, JSON-intact
	// (Postgres LISTEN/NOTIFY for pgstore; an in-process hub for memstore).
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	kills, err := st.SubscribeSessionKills(subCtx)
	if err != nil {
		t.Fatalf("SubscribeSessionKills: %v", err)
	}
	// pgstore's LISTEN runs in a goroutine that must register before a NOTIFY is
	// seen; publish a few times until one is delivered (or time out).
	want := session.KillSelector{Actor: "mallory", Target: "db-01"}
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	if err := st.PublishSessionKill(ctx, want); err != nil {
		t.Fatalf("PublishSessionKill: %v", err)
	}
killDelivered:
	for {
		select {
		case got := <-kills:
			if got.Actor == want.Actor && got.Target == want.Target {
				break killDelivered
			}
		case <-tick.C:
			_ = st.PublishSessionKill(ctx, want) // retry until the listener is ready
		case <-deadline:
			t.Fatal("kill bus: published selector was not delivered to the subscriber")
		}
	}

	// --- cross-replica live monitoring (Phase 55) ---
	// The shared live-session inventory: rows round-trip with their replica,
	// list oldest-first, filter by freshness, and delete by id and by replica.
	started := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	rowA := session.Info{ID: "livesess-a", Actor: "alice", Target: "web-01",
		Protocol: "ssh", Remote: "10.0.0.5:50412", Replica: "replica-a", Started: started}
	rowB := session.Info{ID: "livesess-b", Actor: "bob", Target: "db-01",
		Protocol: "postgres", Replica: "replica-b", Started: started.Add(30 * time.Second)}
	if err := st.PutLiveSession(ctx, rowA); err != nil {
		t.Fatalf("PutLiveSession(a): %v", err)
	}
	if err := st.PutLiveSession(ctx, rowB); err != nil {
		t.Fatalf("PutLiveSession(b): %v", err)
	}
	// Upserting an existing id must update in place, not duplicate.
	rowA.Actor = "alice2"
	if err := st.PutLiveSession(ctx, rowA); err != nil {
		t.Fatalf("PutLiveSession(a, upsert): %v", err)
	}
	live, err := st.ListLiveSessions(ctx, time.Hour)
	if err != nil {
		t.Fatalf("ListLiveSessions: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("ListLiveSessions = %d rows, want 2 (upsert must not duplicate)", len(live))
	}
	if live[0].ID != rowA.ID || live[1].ID != rowB.ID {
		t.Fatalf("ListLiveSessions order = [%s %s], want oldest started first [%s %s]",
			live[0].ID, live[1].ID, rowA.ID, rowB.ID)
	}
	if got := live[0]; got.Actor != "alice2" || got.Target != rowA.Target || got.Protocol != rowA.Protocol ||
		got.Remote != rowA.Remote || got.Replica != rowA.Replica || !got.Started.Equal(rowA.Started) {
		t.Fatalf("live row round-trip = %+v, want %+v", got, rowA)
	}
	// Freshness filter: a negative window puts the cutoff in the future, so
	// even a just-written row is "stale" — proving the filter without having
	// to backdate seen-at stamps (which the API deliberately cannot do).
	if stale, err := st.ListLiveSessions(ctx, -time.Second); err != nil || len(stale) != 0 {
		t.Fatalf("ListLiveSessions(stale cutoff) = %d rows, %v; want 0, nil", len(stale), err)
	}
	if err := st.DeleteLiveSession(ctx, rowA.ID); err != nil {
		t.Fatalf("DeleteLiveSession: %v", err)
	}
	if err := st.DeleteLiveSession(ctx, rowA.ID); err != nil {
		t.Fatalf("DeleteLiveSession must be idempotent, got %v", err)
	}
	if err := st.DeleteReplicaLiveSessions(ctx, "replica-b"); err != nil {
		t.Fatalf("DeleteReplicaLiveSessions: %v", err)
	}
	if left, err := st.ListLiveSessions(ctx, time.Hour); err != nil || len(left) != 0 {
		t.Fatalf("after deletes ListLiveSessions = %d rows, %v; want 0, nil", len(left), err)
	}

	// --- cross-replica step-up decisions (Phase 56) ---
	// The shared pending-pause inventory: rows round-trip (the statement is an
	// opaque string here — the session layer stores it sealed), list oldest
	// requested first, upsert in place, expire by the store's own clock, and
	// delete idempotently.
	requested := time.Now().Add(-30 * time.Second).Truncate(time.Millisecond)
	suA := session.PendingStepUp{SessionID: "stepup-a", Actor: "alice",
		Statement: "sealed-blob-a", Replica: "replica-a", Requested: requested}
	suB := session.PendingStepUp{SessionID: "stepup-b", Actor: "bob",
		Statement: "sealed-blob-b", Replica: "replica-b", Requested: requested.Add(10 * time.Second)}
	if err := st.PutStepUp(ctx, suA, time.Hour); err != nil {
		t.Fatalf("PutStepUp(a): %v", err)
	}
	if err := st.PutStepUp(ctx, suB, time.Hour); err != nil {
		t.Fatalf("PutStepUp(b): %v", err)
	}
	suA.Statement = "sealed-blob-a2"
	if err := st.PutStepUp(ctx, suA, time.Hour); err != nil {
		t.Fatalf("PutStepUp(a, upsert): %v", err)
	}
	sus, err := st.ListStepUps(ctx)
	if err != nil {
		t.Fatalf("ListStepUps: %v", err)
	}
	if len(sus) != 2 {
		t.Fatalf("ListStepUps = %d rows, want 2 (upsert must not duplicate)", len(sus))
	}
	if sus[0].SessionID != suA.SessionID || sus[1].SessionID != suB.SessionID {
		t.Fatalf("ListStepUps order = [%s %s], want oldest requested first [%s %s]",
			sus[0].SessionID, sus[1].SessionID, suA.SessionID, suB.SessionID)
	}
	if got := sus[0]; got.Actor != suA.Actor || got.Statement != "sealed-blob-a2" ||
		got.Replica != suA.Replica || !got.Requested.Equal(suA.Requested) {
		t.Fatalf("step-up row round-trip = %+v, want %+v", got, suA)
	}
	if sus[0].Expires.IsZero() || !sus[0].Expires.After(sus[0].Requested) {
		t.Fatalf("listed expiry %v not after requested %v (the store must stamp it)", sus[0].Expires, sus[0].Requested)
	}
	// Expiry filter: a non-positive TTL puts the cutoff at/before now, so even a
	// just-written row is expired — proving the filter runs on the store's own
	// clock without having to wait a real TTL out.
	if err := st.PutStepUp(ctx, session.PendingStepUp{SessionID: "stepup-expired", Actor: "carol",
		Statement: "sealed-blob-c", Replica: "replica-a", Requested: requested}, -time.Second); err != nil {
		t.Fatalf("PutStepUp(expired): %v", err)
	}
	if sus, err = st.ListStepUps(ctx); err != nil || len(sus) != 2 {
		t.Fatalf("ListStepUps with an expired row = %d rows, %v; want the 2 live ones", len(sus), err)
	}
	if err := st.DeleteStepUp(ctx, suA.SessionID); err != nil {
		t.Fatalf("DeleteStepUp: %v", err)
	}
	if err := st.DeleteStepUp(ctx, suA.SessionID); err != nil {
		t.Fatalf("DeleteStepUp must be idempotent, got %v", err)
	}
	if err := st.DeleteStepUp(ctx, suB.SessionID); err != nil {
		t.Fatalf("DeleteStepUp(b): %v", err)
	}
	if left, err := st.ListStepUps(ctx); err != nil || len(left) != 0 {
		t.Fatalf("after deletes ListStepUps = %d rows, %v; want 0, nil", len(left), err)
	}

	// The decision bus: a decision published on any replica reaches a
	// subscriber, fields intact (pgstore's LISTEN registers asynchronously, so
	// publish is retried until delivery, as with the kill bus).
	decisions, err := st.SubscribeStepUpDecisions(subCtx)
	if err != nil {
		t.Fatalf("SubscribeStepUpDecisions: %v", err)
	}
	wantDec := session.StepUpDecision{SessionID: "stepup-a", Approve: true, Decider: "boss", Seal: "opaque-seal"}
	decDeadline := time.After(5 * time.Second)
	decTick := time.NewTicker(100 * time.Millisecond)
	defer decTick.Stop()
	if err := st.PublishStepUpDecision(ctx, wantDec); err != nil {
		t.Fatalf("PublishStepUpDecision: %v", err)
	}
decisionDelivered:
	for {
		select {
		case got := <-decisions:
			if got == wantDec {
				break decisionDelivered
			}
		case <-decTick.C:
			_ = st.PublishStepUpDecision(ctx, wantDec) // retry until the listener is ready
		case <-decDeadline:
			t.Fatal("step-up bus: published decision was not delivered to the subscriber")
		}
	}

	// The live bus: interest announcements and output frames are delivered to a
	// subscriber; a frame larger than one transport payload (Postgres NOTIFY
	// tops out near 8000 bytes) arrives as ordered chunks that reassemble to
	// the same bytes. Establish listener liveness with the retried interest
	// announcement FIRST, so the big frame can then be published exactly once —
	// a retry loop would double its bytes.
	frames, interest, err := st.SubscribeLive(subCtx)
	if err != nil {
		t.Fatalf("SubscribeLive: %v", err)
	}
	liveDeadline := time.After(5 * time.Second)
	liveTick := time.NewTicker(100 * time.Millisecond)
	defer liveTick.Stop()
	if err := st.PublishLiveInterest(ctx, "livesess-a"); err != nil {
		t.Fatalf("PublishLiveInterest: %v", err)
	}
interestDelivered:
	for {
		select {
		case got := <-interest:
			if got == "livesess-a" {
				break interestDelivered
			}
		case <-liveTick.C:
			_ = st.PublishLiveInterest(ctx, "livesess-a") // retry until the listener is ready
		case <-liveDeadline:
			t.Fatal("live bus: interest announcement was not delivered to the subscriber")
		}
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 640) // 10240 bytes: > one NOTIFY payload
	if err := st.PublishLiveFrame(ctx, session.LiveFrame{ID: "livesess-a", Kind: session.LiveFrameData, Data: payload}); err != nil {
		t.Fatalf("PublishLiveFrame(data): %v", err)
	}
	if err := st.PublishLiveFrame(ctx, session.LiveFrame{ID: "livesess-a", Kind: session.LiveFrameEnd}); err != nil {
		t.Fatalf("PublishLiveFrame(end): %v", err)
	}
	var reassembled []byte
	for {
		select {
		case f := <-frames:
			if f.ID != "livesess-a" {
				t.Fatalf("frame for session %q, want livesess-a", f.ID)
			}
			if f.Kind == session.LiveFrameEnd {
				// The end marker was published after the data, so every chunk
				// must have arrived — in order — by now.
				if !bytes.Equal(reassembled, payload) {
					t.Fatalf("reassembled %d bytes that do not match the %d published", len(reassembled), len(payload))
				}
				return
			}
			reassembled = append(reassembled, f.Data...)
		case <-liveDeadline:
			t.Fatalf("live bus: frames not delivered (have %d of %d bytes, no end marker)", len(reassembled), len(payload))
		}
	}
}

// appAliasFixture makes a target, two credentials, and two applications each
// granted one of them, returning the two grants. It creates everything it needs,
// so it can never quietly opt out.
func appAliasFixture(t *testing.T, st store.Store) []store.AppSecretGrant {
	t.Helper()
	ctx := context.Background()
	// Create the credentials this needs rather than reusing whatever the contract
	// happens to have left lying around. The first version asked for two existing
	// credentials and returned nil when it could not find them — and at this point
	// the contract has created exactly ONE, so the entire alias contract silently
	// never ran, on either backend. A fixture that opts itself out on a condition
	// nobody checks is worse than no fixture: the suite stayed green while
	// SetAppGrantAlias, AppCredentialByAlias and the per-app scoping went
	// completely unverified.
	tgt := &store.Target{Name: "alias-contract-host", Host: "10.7.7.7", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatalf("alias fixture CreateTarget: %v", err)
	}
	var creds []store.Credential
	for _, user := range []string{"alias-svc-a", "alias-svc-b"} {
		c := &store.Credential{TargetID: tgt.ID, Username: user, SecretType: "password", SecretEnc: "v2:placeholder"}
		if err := st.CreateCredential(ctx, c); err != nil {
			t.Fatalf("alias fixture CreateCredential(%s): %v", user, err)
		}
		creds = append(creds, *c)
	}
	var grants []store.AppSecretGrant
	for i, name := range []string{"alias-app-a", "alias-app-b"} {
		k := &store.AppKey{Name: name, Owner: "contract", TokenHash: "alias-h" + itoaTest(i)}
		if err := st.CreateAppKey(ctx, k); err != nil {
			t.Fatalf("CreateAppKey(%s): %v", name, err)
		}
		g := &store.AppSecretGrant{AppID: k.ID, CredentialID: creds[i].ID}
		if err := st.GrantAppSecret(ctx, g); err != nil {
			t.Fatalf("GrantAppSecret(%s): %v", name, err)
		}
		grants = append(grants, *g)
	}
	return grants
}

// aliasContract holds SetAppGrantAlias/AppCredentialByAlias to their promises.
func aliasContract(t *testing.T, st store.Store, grants []store.AppSecretGrant) {
	t.Helper()
	ctx := context.Background()
	a, b := grants[0], grants[1]

	if err := st.SetAppGrantAlias(ctx, a.ID, "shared-name"); err != nil {
		t.Fatalf("SetAppGrantAlias: %v", err)
	}
	got, err := st.AppCredentialByAlias(ctx, a.AppID, "shared-name")
	if err != nil || got != a.CredentialID {
		t.Fatalf("AppCredentialByAlias = %d, %v; want %d", got, err, a.CredentialID)
	}
	// Scoped to the owning app: the other app sees nothing under that name.
	if _, err := st.AppCredentialByAlias(ctx, b.AppID, "shared-name"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another app resolved an alias it was not granted: %v", err)
	}
	// And may legitimately reuse the name for its own grant.
	if err := st.SetAppGrantAlias(ctx, b.ID, "shared-name"); err != nil {
		t.Fatalf("the same alias must be reusable by a different app: %v", err)
	}
	if got, err := st.AppCredentialByAlias(ctx, b.AppID, "shared-name"); err != nil || got != b.CredentialID {
		t.Fatalf("second app's alias = %d, %v; want %d", got, err, b.CredentialID)
	}
	// The listing carries it back.
	list, err := st.ListAppSecretGrants(ctx, a.AppID)
	if err != nil || len(list) == 0 || list[0].Alias != "shared-name" {
		t.Fatalf("ListAppSecretGrants did not carry the alias: %+v, %v", list, err)
	}
	// Cleared means unaddressable, and an empty alias never resolves.
	if err := st.SetAppGrantAlias(ctx, a.ID, ""); err != nil {
		t.Fatalf("clearing an alias: %v", err)
	}
	if _, err := st.AppCredentialByAlias(ctx, a.AppID, "shared-name"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a cleared alias still resolved: %v", err)
	}
	if _, err := st.AppCredentialByAlias(ctx, a.AppID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the empty alias must never resolve: %v", err)
	}
	if err := st.SetAppGrantAlias(ctx, 0, "orphan"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("aliasing a grant that does not exist: %v, want ErrNotFound", err)
	}
}

// itoaTest is a tiny local helper so the fixture can build distinct token hashes.
func itoaTest(i int) string { return string(rune('0' + i)) }
