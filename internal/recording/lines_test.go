package recording

import (
	"strings"
	"testing"
)

func TestSearchLines(t *testing.T) {
	body := `{"probe":{"agent_id":9}}
{"kind":"process_started","name":"PsExec.exe","command_line":"psexec \\\\dc01 cmd"}
{"kind":"foreground_window","title":"secret.txt - Notepad"}
{"kind":"process_ended","name":"PsExec.exe"}
`
	res, err := SearchLines(strings.NewReader(body), 0, "psexec")
	if err != nil || res.Matches != 2 || !strings.Contains(res.Snippet, "process_started") || res.Truncated {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = SearchLines(strings.NewReader(body), 0, "nothing here")
	if err != nil || res.Matches != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	// The bound is honest: a match past it reports Truncated, never "not found".
	res, err = SearchLines(strings.NewReader(body), 40, "Notepad")
	if err != nil || res.Matches != 0 || !res.Truncated {
		t.Fatalf("bounded: %+v %v", res, err)
	}
}
