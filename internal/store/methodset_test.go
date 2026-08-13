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
// 156, not the count you get by counting declarations in the source: the
// surface has always also carried session.LiveStore and session.StepUpStore,
// whose methods a reader skimming the file does not see. That gap between
// "what the file lists" and "what the interface is" is itself an argument for
// composing it from named roles. Was 149 through Phase 115; Phase 116 added
// VendorStore.UpdateVendorEmail (1) and the new ShareInviteStore role (6).
func TestStoreMethodSetIsUnchanged(t *testing.T) {
	const want = 156
	got := reflect.TypeOf((*store.Store)(nil)).Elem().NumMethod()
	if got != want {
		t.Fatalf("store.Store exposes %d methods, want %d — a role interface was dropped from or added to the composition", got, want)
	}
}
