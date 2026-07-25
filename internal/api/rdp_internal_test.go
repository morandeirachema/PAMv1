package api

import (
	"encoding/hex"
	"testing"
)

// TestGuacamolePrelude locks the exact wire bytes guacamole-common-js needs before
// the render stream: the internal (empty-opcode) tunnel-UUID instruction that
// opens the tunnel, then the re-emitted `ready` that moves the client to
// CONNECTED. If either drifts, the browser viewer silently hangs.
func TestGuacamolePrelude(t *testing.T) {
	got := guacamolePrelude("abc", "$conn-1")
	if len(got) != 2 {
		t.Fatalf("prelude has %d instructions, want 2", len(got))
	}
	if string(got[0]) != "0.,3.abc;" {
		t.Fatalf("tunnel-UUID instruction = %q, want %q", got[0], "0.,3.abc;")
	}
	if string(got[1]) != "5.ready,7.$conn-1;" {
		t.Fatalf("ready instruction = %q, want %q", got[1], "5.ready,7.$conn-1;")
	}
}

// TestTunnelUUID checks the tunnel id is a fresh 16-byte hex string each call.
func TestTunnelUUID(t *testing.T) {
	a, b := tunnelUUID(), tunnelUUID()
	if a == "" || b == "" {
		t.Fatal("tunnelUUID returned empty (RNG failure?)")
	}
	if a == b {
		t.Fatal("tunnelUUID must be unique per call")
	}
	if _, err := hex.DecodeString(a); err != nil || len(a) != 32 {
		t.Fatalf("tunnelUUID = %q, want 32 hex chars", a)
	}
}

// TestRDPExtraSecureDefault verifies the default (unconfigured) RDP parameters
// neither disable certificate verification nor force an insecure security mode.
func TestRDPExtraSecureDefault(t *testing.T) {
	e := rdpExtra("", false, "allow")
	if v, ok := e["ignore-cert"]; ok && v == "true" {
		t.Fatalf("default must verify the RDP server cert, got ignore-cert=%q", v)
	}
	if _, ok := e["security"]; ok {
		t.Fatal("default must let guacd negotiate the security mode (no forced 'any')")
	}
	// Drive redirection is always disabled, regardless of clipboard policy.
	if e["enable-drive"] != "false" {
		t.Fatalf("enable-drive = %q, want false (no drive redirection)", e["enable-drive"])
	}
}

// TestRDPExtraConfigured verifies an explicit security mode and cert-ignore opt-out
// are passed through to guacd.
func TestRDPExtraConfigured(t *testing.T) {
	e := rdpExtra("nla", true, "allow")
	if e["security"] != "nla" {
		t.Fatalf("security = %q, want nla", e["security"])
	}
	if e["ignore-cert"] != "true" {
		t.Fatalf("ignore-cert = %q, want true", e["ignore-cert"])
	}
}

// TestRDPClipboardParams proves the clipboard policy maps to the right Guacamole
// disable-copy/disable-paste flags, and that drive redirection is always off.
func TestRDPClipboardParams(t *testing.T) {
	cases := map[string]struct{ copy, paste string }{
		"allow":    {"false", "false"}, // both directions on
		"readonly": {"false", "true"},  // paste INTO the target blocked; copy out on
		"deny":     {"true", "true"},   // clipboard off both ways
		"":         {"false", "false"}, // unset behaves as allow
	}
	for mode, want := range cases {
		p := rdpClipboardParams(mode)
		if p["disable-copy"] != want.copy || p["disable-paste"] != want.paste {
			t.Fatalf("mode %q: disable-copy=%q disable-paste=%q, want %q/%q",
				mode, p["disable-copy"], p["disable-paste"], want.copy, want.paste)
		}
		if p["enable-drive"] != "false" {
			t.Fatalf("mode %q: enable-drive=%q, want false", mode, p["enable-drive"])
		}
	}
}
