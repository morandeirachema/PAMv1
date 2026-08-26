package proxy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/morandeirachema/pamv1/internal/cmdguard"
)

// sftpReq builds a minimal SFTP request packet body: type || id(u32) || rest.
func sftpReq(typ byte, id uint32, rest ...byte) []byte {
	b := []byte{typ}
	var idb [4]byte
	binary.BigEndian.PutUint32(idb[:], id)
	b = append(b, idb[:]...)
	return append(b, rest...)
}

// TestSFTPReadOnlyRefusesNativeMutations is the regression for the containment
// gap where the request switch's default arm forwarded ANY unrecognised native
// request as a "read". SSH_FXP_LINK (21) creates a hard/symlink — a mutation —
// and BLOCK/UNBLOCK take server-side locks. The openssh EXTENDED twin
// (hardlink@openssh.com) was already governed by handleExtended, but the native
// ops slipped through in read-only mode against any SFTP server that speaks them
// (v6). A containment control must not depend on the target's SFTP version.
func TestSFTPReadOnlyRefusesNativeMutations(t *testing.T) {
	insp := newSFTPInspector(SFTPReadOnly, nil, nil, func(string, string) {})
	var reply bytes.Buffer

	for _, typ := range []byte{fxpLink, fxpBlock, fxpUnblock} {
		reply.Reset()
		if insp.handlePacket(sftpReq(typ, 7), &reply) {
			t.Fatalf("read-only mode FORWARDED native op %d (%s) — a mutation slipped past as a read",
				typ, sftpOpLabel(typ))
		}
		if reply.Len() == 0 {
			t.Fatalf("refused op %d left the client with no STATUS reply (it would hang)", typ)
		}
	}

	// The read family must still flow — a fail-closed default must not break
	// legitimate read-only browsing and download.
	for _, typ := range []byte{fxpStat, fxpLstat, fxpFstat, fxpReadlink, fxpRealpath, fxpOpendir, fxpReaddir} {
		reply.Reset()
		if !insp.handlePacket(sftpReq(typ, 9), &reply) {
			t.Fatalf("read-only mode REFUSED a legitimate read op %d — the allowlist is too tight", typ)
		}
	}
}

// TestSFTPAllowForwardsNativeLink confirms the fix is scoped to read-only mode:
// allow mode does not restrict, so a native LINK is forwarded as before.
func TestSFTPAllowForwardsNativeLink(t *testing.T) {
	var audited []string
	insp := newSFTPInspector(SFTPAllow, nil, nil, func(action, detail string) {
		audited = append(audited, action+" "+detail)
	})
	var reply bytes.Buffer
	if !insp.handlePacket(sftpReq(fxpLink, 7), &reply) {
		t.Fatal("allow mode should forward SSH_FXP_LINK unchanged; the fix must not restrict allow mode")
	}
	// ...but it must be audited, or an allow-mode hard/symlink is invisible in the
	// trail the guard promises records every file operation.
	found := false
	for _, a := range audited {
		if a == "sftp.modify op:link" {
			found = true
		}
	}
	if !found {
		t.Fatalf("allow-mode LINK was forwarded without an sftp.modify audit: %v", audited)
	}
}

// sftpLinkReq builds a LINK/SYMLINK-shaped body: type || id || string a || string b.
func sftpLinkReq(typ byte, id uint32, a, b string) []byte {
	body := []byte{typ}
	var idb [4]byte
	binary.BigEndian.PutUint32(idb[:], id)
	body = append(body, idb[:]...)
	for _, p := range []string{a, b} {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(p)))
		body = append(body, lb[:]...)
		body = append(body, []byte(p)...)
	}
	return body
}

// TestSFTPLinkChecksBothPathsAgainstDenylist is the regression for the
// 2026-08-26 audit's M-7. Native SSH_FXP_LINK fell to the default arm with NO
// path check on either path, and SSH_FXP_SYMLINK was read as a single-path
// mutation so its target went unchecked. Either laundered a denied path:
// `link /etc/shadow /tmp/x; get /tmp/x`. Both paths of both ops are now checked,
// in allow mode too — the admin guide's "refused in every mode, downloads
// included" now holds for links.
func TestSFTPLinkChecksBothPathsAgainstDenylist(t *testing.T) {
	deny := mustDenyMatcher(t, `(?i)/etc/shadow`)
	for _, typ := range []byte{fxpLink, fxpSymlink} {
		for _, tc := range []struct {
			name, a, b string
		}{
			{"denied as source", "/etc/shadow", "/tmp/x"},
			{"denied as target", "/tmp/x", "/etc/shadow"},
		} {
			// ALLOW mode — the mode the audit found unprotected.
			insp := newSFTPInspector(SFTPAllow, deny, nil, func(string, string) {})
			var reply bytes.Buffer
			if insp.handlePacket(sftpLinkReq(typ, 3, tc.a, tc.b), &reply) {
				t.Fatalf("op %d (%s), %s: a denied path was FORWARDED in allow mode", typ, sftpOpLabel(typ), tc.name)
			}
			if reply.Len() == 0 {
				t.Fatalf("op %d, %s: denial left no STATUS reply", typ, tc.name)
			}
		}
		// A link with two allowed paths still flows in allow mode.
		insp := newSFTPInspector(SFTPAllow, deny, nil, func(string, string) {})
		var reply bytes.Buffer
		if !insp.handlePacket(sftpLinkReq(typ, 4, "/tmp/a", "/tmp/b"), &reply) {
			t.Fatalf("op %d (%s): two allowed paths were refused", typ, sftpOpLabel(typ))
		}
	}
}

// mustDenyMatcher compiles a path denylist for the SFTP guard, failing the test
// on a bad pattern.
func mustDenyMatcher(t *testing.T, patterns ...string) *cmdguard.Guard {
	t.Helper()
	g, err := cmdguard.New(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
