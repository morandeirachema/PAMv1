package store_test

import (
	"reflect"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestStoreMethodSetIsUnchanged pins the size of the composed interface. Store
// is assembled from role interfaces (one per domain) rather than written flat;
// embedding preserves the method set exactly, and this is the assertion that
// says so out loud — a role accidentally dropped from the composition would
// otherwise surface only as a distant compile error in whichever caller used it.
//
// 171, not the count you get by counting declarations in the source: the
// surface has always also carried session.LiveStore and session.StepUpStore,
// whose methods a reader skimming the file does not see. That gap between
// "what the file lists" and "what the interface is" is itself an argument for
// composing it from named roles. Was 149 through Phase 115; Phase 116 added
// VendorStore.UpdateVendorEmail (1) and the new ShareInviteStore role (6);
// Phase 118 added UserStore.UpdateUserIPAllowlist (1); Phase 120 added
// ApprovalStore.{ListDueAccessRequests,SetAccessRequestNextRun,
// StopAccessRequestRecurrence} (3), CheckoutStore.{GetCheckout,
// ExtendCheckout} (2) and the new PasswordHistoryStore role (2); Phase 124
// added MFAStore.{CreateWebAuthnCredential,ListWebAuthnCredentials,
// GetWebAuthnCredentialByCredentialID,UpdateWebAuthnSignCount,
// DeleteWebAuthnCredential,PutWebAuthnChallenge,TakeWebAuthnChallenge} (7);
// Phase 133 added UserStore.UpdateUserDeviceFingerprint (1); Phase 135 added
// CredentialStore.{SetCredentialDoubleLock,ClearCredentialDoubleLock} (2);
// Phase 137 added the new ApprovalInviteStore role (7); Phase 145 added
// CredentialStore.ListCredentialsMeta (1) — deliberately a NEW method, not a
// changed one: ListCredentials itself stays full-fidelity (SecretEnc and all)
// because real internal callers decrypt from its result, and Meta is the
// narrow, display-only sibling for the few callers that do not. Phase 149
// added UserStore.{GetUserByUsername,GetUserByExternalID,UpdateUserActive,
// UpdateUserExternalID} (4) and the new ScimStore role (4). Phase 153 added
// the new EndpointAgentStore role (6). Phase 159 added
// BrokerStore.{SetAgentKeyDisabled,TouchAgentKey,ListAgentKeysByOwner,
// QuarantineAgent,IsAgentQuarantined,ListAgentQuarantine,
// ReleaseAgentQuarantine} (7) — agent-key lifecycle: an AI-agent identity
// could previously only be created or destroyed, never suspended, expired or
// reported as dormant.
func TestStoreMethodSetIsUnchanged(t *testing.T) {
	const want = 203
	got := reflect.TypeOf((*store.Store)(nil)).Elem().NumMethod()
	if got != want {
		t.Fatalf("store.Store exposes %d methods, want %d — a role interface was dropped from or added to the composition", got, want)
	}
}
