package api

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/guacd"
)

// TestWatchOutputDropsClipboard proves a watcher receives the display but not
// the owner's clipboard stream — neither its opening instruction nor the
// blobs and end on its index — while blobs on other streams still flow.
func TestWatchOutputDropsClipboard(t *testing.T) {
	enc := func(op string, args ...string) []byte {
		return []byte(guacd.Instruction{Opcode: op, Args: args}.Encode())
	}
	var o watchOutput
	steps := []struct {
		inst []byte
		want bool
	}{
		{enc("size", "0", "1024", "768"), true},
		{enc("clipboard", "7", "text/plain"), false},
		{enc("blob", "7", "cGFzc3dvcmQ="), false},
		{enc("blob", "3", "aW1hZ2U="), true},
		{enc("end", "7"), false},
		{enc("blob", "7", "bmV3IGltYWdl"), true}, // index 7 reused by a later, non-clipboard stream
		{enc("sync", "1000"), true},
	}
	for i, st := range steps {
		if got := o.forward(st.inst); got != st.want {
			t.Errorf("step %d %q: forward = %v, want %v", i, st.inst, got, st.want)
		}
	}
	if got := watchInput([]byte(string(enc("key", "65", "1")) + string(enc("nop")) + string(enc("", "ping", "1")))); string(got) != string(enc("nop")) {
		t.Errorf("watchInput = %q, want only nop", got)
	}
}
