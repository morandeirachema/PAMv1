package inventorycsv

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	rows := [][]string{
		{"web-01", "10.0.0.5", "22", "linux", "ssh", "true", "false", "true", "env=prod", "", "", "", ""},
		{"=evil", "10.0.0.6", "", "linux", "ssh", "", "", "", "", "", "", "", ""},
	}
	if err := Write(&buf, Targets, rows); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "'=evil") {
		t.Fatalf("formula cell not neutralised:\n%s", buf.String())
	}
	got, err := Read(Targets, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Get("name") != "web-01" || got[0].Get("critical") != "true" || got[1].Get("name") != "=evil" {
		t.Fatalf("round trip = %+v", got)
	}
	if got[0].Line != 2 || got[1].Line != 3 {
		t.Errorf("lines = %d, %d; want 2, 3", got[0].Line, got[1].Line)
	}
}

func TestReadSubsetAndBlankLines(t *testing.T) {
	in := "\ufeffName, host ,os_type,protocol\nweb-01,10.0.0.5,linux,ssh\n,,,\n"
	got, err := Read(Targets, strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Get("host") != "10.0.0.5" || got[0].Get("port") != "" {
		t.Fatalf("rows = %+v", got)
	}
}

func TestReadRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":          "",
		"unknown column": "name,host,os_type,protocol,password\n",
		"duplicate":      "name,name,host,os_type,protocol\n",
		"missing":        "name,host,os_type\n",
		"ragged":         "name,host,os_type,protocol\nweb-01,10.0.0.5\n",
	} {
		if _, err := Read(Targets, strings.NewReader(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	var b strings.Builder
	b.WriteString("username,role\n")
	for i := 0; i <= MaxRows; i++ {
		b.WriteString("u,user\n")
	}
	if _, err := Read(Users, strings.NewReader(b.String())); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("row cap: %v", err)
	}
}

func TestBoolInt(t *testing.T) {
	for in, want := range map[string]bool{"": false, "No": false, "0": false, "TRUE": true, "yes": true, "1": true} {
		if got, err := Bool(in); err != nil || got != want {
			t.Errorf("Bool(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := Bool("maybe"); err == nil {
		t.Error("Bool must refuse a guess")
	}
	if n, err := Int(""); err != nil || n != 0 {
		t.Errorf("Int(\"\") = %d, %v", n, err)
	}
	if _, err := Int("22a"); err == nil {
		t.Error("Int must refuse a non-number")
	}
}

func TestEveryClassRequiresKnownColumns(t *testing.T) {
	for _, c := range All {
		known := map[string]bool{}
		for _, col := range c.Columns {
			known[col] = true
		}
		for _, r := range c.Required {
			if !known[r] {
				t.Errorf("%s requires unknown column %q", c.Name, r)
			}
		}
	}
}
