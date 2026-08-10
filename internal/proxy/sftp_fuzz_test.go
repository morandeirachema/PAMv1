package proxy

import (
	"bytes"
	"testing"
)

// FuzzSFTPInspector fuzzes the SFTP request inspector, which reads the body of
// every SFTP packet an operator's client sends through the proxy — untrusted,
// attacker-influenced bytes with client-chosen length prefixes and string
// counts. The security-critical property is that the inspector never panics and
// always terminates on any input, whatever the mode: a crash or a hang here is a
// denial of service on the file-transfer path, and the inspector is a containment
// control (read-only mode must not be evadable by a malformed packet). capture
// and the path guard are nil, so there are no filesystem side effects; refusals
// are written to a throwaway buffer. The corpus is replayed on every CI run.
func FuzzSFTPInspector(f *testing.F) {
	f.Add(byte(0), []byte{fxpInit})
	f.Add(byte(0), []byte{fxpRealpath, 0, 0, 0, 7, 0, 0, 0, 1, '/'})
	f.Add(byte(0), []byte{fxpOpen, 0, 0, 0, 7, 0, 0, 0, 1, 'x', 0, 0, 0, 1})
	f.Add(byte(1), []byte{fxpLink, 0, 0, 0, 7})
	f.Add(byte(1), []byte{fxpWrite, 0, 0, 0, 7})
	f.Add(byte(0), []byte{})
	f.Fuzz(func(t *testing.T, modeSel byte, body []byte) {
		// Exercise both the read-only containment path and the allow path, which
		// take different branches (refuse-mutations vs forward-and-audit).
		mode := SFTPReadOnly
		if modeSel%2 == 1 {
			mode = SFTPAllow
		}
		insp := newSFTPInspector(mode, nil, nil, func(string, string) {})
		var reply bytes.Buffer
		_ = insp.handlePacket(body, &reply)
	})
}
