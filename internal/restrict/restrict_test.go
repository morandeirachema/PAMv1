package restrict

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

func TestValidate(t *testing.T) {
	bad := []store.RestrictionRule{
		{Subprotocol: "*", Pattern: "rm", Action: "block"},
		{Subprotocol: "telnet", Pattern: "rm", Action: "kill"},
		{Subprotocol: "*", Pattern: "", Action: "kill"},
		{Subprotocol: "*", Pattern: "(", Action: "kill"},
		{Subprotocol: "sftp", Pattern: "$filesize:10m", Action: "kill"},
		{Subprotocol: "sftp", Pattern: "$filesize:>0", Action: "kill"},
		{Subprotocol: "ssh_exec", Pattern: "$filesize:>1m", Action: "kill"},
	}
	for _, r := range bad {
		if err := Validate(r); err == nil {
			t.Errorf("%+v: want error", r)
		}
	}
	good := []store.RestrictionRule{
		{Subprotocol: "*", Pattern: `rm\s+-rf`, Action: "kill"},
		{Subprotocol: "sql", Pattern: `(?i)^drop`, Action: "notify"},
		{Subprotocol: "sftp", Pattern: "$filesize:>10m", Action: "kill"},
		{Subprotocol: "sftp", Pattern: "$downsize:>2G", Action: "notify"},
		{Subprotocol: "kubernetes", Pattern: "delete", Action: "kill"},
	}
	for _, r := range good {
		if err := Validate(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestCompileAndCheck(t *testing.T) {
	rules := []store.RestrictionRule{
		{ID: 1, SubjectType: "user", Subject: "Alice", Subprotocol: "*", Pattern: `rm\s+-rf`, Action: "notify"},
		{ID: 2, SubjectType: "role", Subject: "user", Subprotocol: "ssh_exec", Pattern: `rm\s+-rf`, Action: "kill"},
		{ID: 3, SubjectType: "role", Subject: "user", Subprotocol: "sql", Pattern: `(?i)^drop`, Action: "kill"},
		{ID: 4, SubjectType: "user", Subject: "bob", Subprotocol: "*", Pattern: `.*`, Action: "kill"},
		{ID: 5, SubjectType: "role", Subject: "user", Subprotocol: "sftp", Pattern: "$filesize:>10m", Action: "kill"},
		{ID: 6, SubjectType: "user", Subject: "alice", Subprotocol: "sftp", Pattern: "$filesize:>1m", Action: "notify"},
		{ID: 7, SubjectType: "user", Subject: "alice", Subprotocol: "sftp", Pattern: "$downsize:>100m", Action: "kill"},
		{ID: 8, SubjectType: "user", Subject: "alice", Subprotocol: "*", Pattern: "(", Action: "kill"}, // uncompilable: skipped
	}
	alice := Compile(rules, Subject{Name: "alice", Roles: []string{"user"}})
	if alice == nil {
		t.Fatal("empty set for alice")
	}
	// Both rule 1 (notify, any) and rule 2 (kill, ssh_exec) match: kill wins.
	if m, ok := alice.Check("ssh_exec", "rm -rf /"); !ok || m.RuleID != 2 || m.Action != ActionKill {
		t.Fatalf("exec rm: %+v %v", m, ok)
	}
	// On winrm only rule 1 applies.
	if m, ok := alice.Check("winrm", "rm -rf x"); !ok || m.RuleID != 1 || m.Action != ActionNotify {
		t.Fatalf("winrm rm: %+v %v", m, ok)
	}
	if m, ok := alice.Check("sql", "DROP TABLE t"); !ok || m.RuleID != 3 {
		t.Fatalf("sql drop: %+v %v", m, ok)
	}
	if _, ok := alice.Check("sql", "select 1"); ok {
		t.Fatal("select matched")
	}
	// Size: every rule in a direction is returned, not just the tightest —
	// a small notify rule must not hide a larger kill rule (review of
	// 274-280). Alice's own 1m notify is among her upload rules; one
	// download rule, 100m.
	up := alice.SizeRules(true)
	foundNotify := false
	for _, r := range up {
		if r.Max == 1<<20 && r.Action == ActionNotify {
			foundNotify = true
		}
	}
	if !foundNotify {
		t.Fatalf("upload rules: %+v", up)
	}
	if down := alice.SizeRules(false); len(down) != 1 || down[0].Max != 100<<20 || down[0].RuleID != 7 {
		t.Fatalf("download rules: %+v", down)
	}
	// Carol (role auditor) has nothing: nil set, safe to call.
	carol := Compile(rules, Subject{Name: "carol", Roles: []string{"auditor"}})
	if carol != nil || !carol.Empty() {
		t.Fatal("carol should have an empty set")
	}
	if _, ok := carol.Check("ssh_exec", "rm -rf /"); ok {
		t.Fatal("nil set matched")
	}
	if len(carol.SizeRules(true)) != 0 {
		t.Fatal("nil set has a size rule")
	}
	// Bob: everything killed.
	bob := Compile(rules, Subject{Name: "bob"})
	if m, ok := bob.Check("kubernetes", "get pods"); !ok || m.RuleID != 4 {
		t.Fatalf("bob: %+v %v", m, ok)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{"$filesize:>10": 10, "$filesize:>10k": 10 << 10, "$downsize:>3M": 3 << 20, "$filesize:>2g": 2 << 30}
	for in, want := range cases {
		_, got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("%s: %d %v want %d", in, got, err, want)
		}
	}
}

// TestValidateReviewFixes: a regex on sftp is refused (it would never run)
// and a size that would overflow int64 is refused (it wrapped negative and
// killed every transfer).
func TestValidateReviewFixes(t *testing.T) {
	for name, r := range map[string]store.RestrictionRule{
		"sftp regex": {SubjectType: "role", Subject: "user", Subprotocol: "sftp", Pattern: "secret", Action: "kill"},
		"overflow":   {SubjectType: "role", Subject: "user", Subprotocol: "sftp", Pattern: "$filesize:>99999999999g", Action: "kill"},
	} {
		if err := Validate(r); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
