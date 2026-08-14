package accountscan

import (
	"reflect"
	"testing"
)

func TestParseUnixAccounts(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash
svc_backup:x:1001:1001::/home/svc_backup:/bin/false
malformed-line-no-colons
too:few:fields
`
	got := ParseUnixAccounts(passwd)
	want := []Account{
		{Username: "root", Privileged: true},
		{Username: "deploy", Privileged: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseUnixAccountsEmpty(t *testing.T) {
	if got := ParseUnixAccounts(""); got != nil {
		t.Fatalf("empty input: got %+v, want nil", got)
	}
}

func TestParseUnixAccountsCRLF(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\r\n"
	got := ParseUnixAccounts(passwd)
	want := []Account{{Username: "root", Privileged: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseWindowsAccounts(t *testing.T) {
	netUser := `User accounts for \\WIN-01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
svc_backup               WDAGUtilityAccount
The command completed successfully.
`
	netLocalGroupAdmins := `Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
svc_backup
The command completed successfully.
`
	got := ParseWindowsAccounts(netUser, netLocalGroupAdmins)
	want := []Account{
		{Username: "Administrator", Privileged: true},
		{Username: "DefaultAccount", Privileged: false},
		{Username: "Guest", Privileged: false},
		{Username: "svc_backup", Privileged: true},
		{Username: "WDAGUtilityAccount", Privileged: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestParseWindowsAccountsNoAdminsListing proves a failed/empty admins probe
// degrades to "no account marked privileged" rather than losing the account
// list entirely — the scan should report what it could, not all-or-nothing.
func TestParseWindowsAccountsNoAdminsListing(t *testing.T) {
	netUser := `User accounts for \\WIN-01

-------------------------------------------------------------------------------
Administrator            Guest
The command completed successfully.
`
	got := ParseWindowsAccounts(netUser, "")
	want := []Account{
		{Username: "Administrator", Privileged: false},
		{Username: "Guest", Privileged: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseWindowsAccountsEmpty(t *testing.T) {
	if got := ParseWindowsAccounts("", ""); got != nil {
		t.Fatalf("empty input: got %+v, want nil", got)
	}
}
