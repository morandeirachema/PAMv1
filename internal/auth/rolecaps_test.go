package auth

import (
	"reflect"
	"testing"
)

// TestRoleCapabilityNames pins the capability names each built-in role exposes
// (Role.Can is matrix-tested in auth_test.go; this covers the NAME list) — the
// console builds its menu from exactly these strings via /api/me, so a rename
// or an accidental capability grant/removal must fail a test, not surface as a
// silently changed authorization surface.
func TestRoleCapabilityNames(t *testing.T) {
	auditor := RoleAuditor.Capabilities()
	want := []string{"read_inventory", "read_audit"}
	if !reflect.DeepEqual(auditor, want) {
		t.Fatalf("auditor capabilities = %v, want %v", auditor, want)
	}
	if got := RoleApprover.Capabilities(); !reflect.DeepEqual(got, []string{"read_inventory", "read_audit", "approve"}) {
		t.Fatalf("approver capabilities = %v", got)
	}
	// The admin holds every HUMAN capability but deliberately NOT call_tool —
	// a human admin key must never invoke broker tools as if it were an agent.
	admin := RoleAdmin.Capabilities()
	if len(admin) != int(capCount)-1 {
		t.Fatalf("admin holds %d capabilities, want all but call_tool (%d)", len(admin), int(capCount)-1)
	}
	for _, c := range admin {
		if c == "call_tool" {
			t.Fatal("admin must not hold call_tool — the human/agent separation")
		}
	}
	// The agent role is confined to reading the inventory (its tools list
	// targets) and calling brokered tools — never connect, reveal or manage.
	if got := RoleAgent.Capabilities(); !reflect.DeepEqual(got, []string{"read_inventory", "call_tool"}) {
		t.Fatalf("agent capabilities = %v, want [read_inventory call_tool]", got)
	}
}
