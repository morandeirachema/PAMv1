package store

import "testing"

func TestNormalizeLabels(t *testing.T) {
	got, err := NormalizeLabels(map[string]string{"tier": "db", "env": "prod"})
	if err != nil || got != "env=prod,tier=db" {
		t.Fatalf("canonical form = %q, %v", got, err)
	}
	if got, err := NormalizeLabels(nil); err != nil || got != "" {
		t.Fatalf("empty set = %q, %v", got, err)
	}
	for _, bad := range []map[string]string{
		{"env": ""}, {"": "prod"}, {"env=x": "prod"}, {"env,x": "prod"},
		{"env": "pro,d"}, {"env": "*"}, {"env": "prod ción"},
	} {
		if _, err := NormalizeLabels(bad); err == nil {
			t.Errorf("NormalizeLabels(%v) accepted", bad)
		}
	}
	tooMany := map[string]string{}
	for i := 0; i < maxLabelsPerTarget+1; i++ {
		tooMany[string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if _, err := NormalizeLabels(tooMany); err == nil {
		t.Error("an unbounded label set was accepted")
	}
}

func TestParseLabelsDropsUnreadable(t *testing.T) {
	got := ParseLabels("env=prod,broken,tier=db,=x,y=,ok=1")
	want := map[string]string{"env": "prod", "tier": "db", "ok": "1"}
	if len(got) != len(want) {
		t.Fatalf("ParseLabels = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %q = %q, want %q", k, got[k], v)
		}
	}
	if len(ParseLabels("")) != 0 {
		t.Error("an unlabelled target must parse to an empty set, not nil-panic")
	}
}

func TestParseLabelSelectorRejects(t *testing.T) {
	for _, bad := range []string{
		"", "   ", "env", "env=prod,", ",env=prod", "=prod", "env =", "env=prod,env=dev",
	} {
		if _, err := ParseLabelSelector(bad); err == nil {
			t.Errorf("ParseLabelSelector(%q) accepted", bad)
		}
	}
	// The same key twice with the SAME value is a harmless duplicate.
	if _, err := ParseLabelSelector("env=prod,env=prod"); err != nil {
		t.Errorf("a duplicate identical term is not a conflict: %v", err)
	}
}

func TestSelectorMatches(t *testing.T) {
	const labels = "env=prod,region=eu,tier=db"
	for _, c := range []struct {
		sel  string
		want bool
	}{
		{"env=prod", true},
		{"env=prod,tier=db", true},
		{"env=prod,region=eu,tier=db", true},
		{"env=*", true},
		{"env=*,tier=*", true},
		{"env=dev", false},
		{"env=prod,tier=web", false}, // every term must match
		{"owner=*", false},           // key absent
		{"env=prod,owner=*", false},
	} {
		if got := LabelSelectorMatches(c.sel, labels); got != c.want {
			t.Errorf("LabelSelectorMatches(%q, %q) = %v, want %v", c.sel, labels, got, c.want)
		}
	}
	// An unlabelled target matches no selector at all.
	if LabelSelectorMatches("env=*", "") {
		t.Error("an unlabelled target must not match a wildcard selector")
	}
	// The zero selector matches nothing, which is what an unparsable rule
	// degrades to.
	var zero LabelSelector
	if zero.Matches(map[string]string{"env": "prod"}) {
		t.Error("the zero selector must match nothing")
	}
	if LabelSelectorMatches("not a selector", labels) {
		t.Error("an unparsable selector must match nothing")
	}
}
