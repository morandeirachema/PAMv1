package store_test

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestBudgetActionNamesMatchTheBroker guards a duplication the package layout
// forces.
//
// `internal/store` cannot import `internal/broker` — the broker imports the
// store, and Go forbids the cycle — so the two audit action names a budget is
// charged for are spelled in both places. Duplicated string constants drift
// silently, and the failure here would be invisible in the worst way: renaming
// the broker's action would leave every agent's budget reading zero used
// forever, so the gate would stop refusing anything and nothing would look
// wrong. An external test package may import both, so the copy is checked rather
// than trusted.
func TestBudgetActionNamesMatchTheBroker(t *testing.T) {
	if store.AuditActionToolCallExecuted != broker.ActionToolCallExecuted {
		t.Fatalf("store charges budget for %q but the broker now writes %q — every budget would read zero used",
			store.AuditActionToolCallExecuted, broker.ActionToolCallExecuted)
	}
	if store.AuditActionToolCallResumed != broker.ActionToolCallResumed {
		t.Fatalf("store charges budget for %q but the broker now writes %q — approved work would become free",
			store.AuditActionToolCallResumed, broker.ActionToolCallResumed)
	}
}
