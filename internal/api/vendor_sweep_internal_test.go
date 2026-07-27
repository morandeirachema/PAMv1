package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// TestVendorSweeperCutsExpiredContracts proves the "time-boxed access, session
// ends mid-stream" guarantee: a vendor's live session survives the sweep while
// their contract grant is in-window, is killed (and audited) once the window
// closes, and a non-vendor's session is never touched.
func TestVendorSweeperCutsExpiredContracts(t *testing.T) {
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	resolver, err := auth.NewResolver(st, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	reg := session.NewRegistry()
	srv, err := New(st, v, resolver, nil, Options{Sessions: reg})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A target, a vendor, and an approved grant whose window closes in an hour.
	tgt := store.Target{Name: "ot-plc", Host: "10.4.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, &tgt); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &store.User{Username: "acme-tech", Role: "user", TokenHash: "vh"}); err != nil {
		t.Fatal(err)
	}
	ven := store.Vendor{Username: "acme-tech", Org: "ACME"}
	if err := st.CreateVendor(ctx, &ven); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	grant := store.VendorGrant{VendorID: ven.ID, TargetID: tgt.ID, Principal: "root", NotAfter: now.Add(time.Hour)}
	if err := st.CreateVendorGrant(ctx, &grant); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveVendorGrant(ctx, grant.ID, "customer", now); err != nil {
		t.Fatal(err)
	}

	// A live vendor session and a live employee session on the same target.
	vendorKilled, employeeKilled := false, false
	reg.Register(session.Info{ID: "s-vendor", Actor: "acme-tech", Target: "ot-plc", Protocol: "ssh"}, func() { vendorKilled = true })
	reg.Register(session.Info{ID: "s-employee", Actor: "erin", Target: "ot-plc", Protocol: "ssh"}, func() { employeeKilled = true })

	// In-window: nothing is cut.
	srv.sweepVendorSessions(ctx, now)
	if vendorKilled || employeeKilled || len(reg.List()) != 2 {
		t.Fatalf("in-window sweep cut something: vendor=%v employee=%v live=%d", vendorKilled, employeeKilled, len(reg.List()))
	}

	// Past the contract window: the vendor's session dies mid-stream, audited;
	// the employee is untouched.
	srv.sweepVendorSessions(ctx, now.Add(2*time.Hour))
	if !vendorKilled {
		t.Fatal("vendor session survived past its contract window")
	}
	if employeeKilled {
		t.Fatal("non-vendor session was killed by the vendor sweeper")
	}
	events, err := st.ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "vendor.session_expired" && e.Actor == "acme-tech" && strings.Contains(e.Detail, "target:ot-plc") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no vendor.session_expired audit event: %+v", events)
	}
}
