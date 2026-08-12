package proxy

import "testing"

// TestMD5Password pins md5Password against vectors computed independently
// (Python hashlib, not this code) for PostgreSQL's MD5 auth construction:
// md5(md5(password+user) + salt). Nothing in the suite exercised this
// function at all — cleartext and SCRAM-SHA-256 upstream auth both have a
// dedicated test, but MD5, still common in real pg_hba.conf configs, did not.
func TestMD5Password(t *testing.T) {
	cases := []struct {
		user, password string
		salt           [4]byte
		want           string
	}{
		{"dbuser", "s3cr3t", [4]byte{0x01, 0x02, 0x03, 0x04}, "md5657f956eeee5b342f6546a7d7a3e66f1"},
		{"root", "", [4]byte{0xde, 0xad, 0xbe, 0xef}, "md552e280c55d1c620537a6ae55287cab52"},
		{"svc_account", "correct horse battery staple", [4]byte{0x00, 0x00, 0x00, 0x00}, "md5f5066651e84abe9a262a2d9be56f3b71"},
	}
	for _, c := range cases {
		if got := md5Password(c.user, c.password, c.salt); got != c.want {
			t.Fatalf("md5Password(%q, %q, %x) = %q, want %q", c.user, c.password, c.salt, got, c.want)
		}
	}

	// The salt must actually be mixed in — a build that dropped it would still
	// pass every case above with a fixed salt substituted internally as long as
	// user+password matched, so cross-check that two salts diverge.
	a := md5Password("dbuser", "s3cr3t", [4]byte{0x01, 0x02, 0x03, 0x04})
	b := md5Password("dbuser", "s3cr3t", [4]byte{0xff, 0xff, 0xff, 0xff})
	if a == b {
		t.Fatal("md5Password ignored the salt: two different salts produced the same hash")
	}
}
