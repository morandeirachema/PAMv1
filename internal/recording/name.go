package recording

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Title builds a recording file's base name (no extension).
//
// By default it is "<unixnano>_<target>_<actor>" — greppable, but it leaks who
// accessed which system to anyone with volume, backup or snapshot access. The
// content is sealed (the rest of this package); the NAME was not, which is the
// metadata half of the same exposure.
//
// When opaque is true the name is "<unixnano>_<8 random hex>" instead, and the
// target/actor mapping lives only in the audited session.record / winrm.run
// event — reading it then requires the read_audit capability, the same gate as
// replaying the recording itself. The timestamp prefix is kept either way, so
// retention pruning and the newest-first listing keep working from the name
// alone, and two recordings started in the same nanosecond still differ.
//
// A randomness failure falls back to the descriptive name rather than minting a
// predictable one: a name collision would overwrite another session's
// recording, which is a worse outcome than the metadata this hides.
func Title(opaque bool, now time.Time, target, actor string) string {
	if opaque {
		var b [4]byte
		if _, err := rand.Read(b[:]); err == nil {
			return fmt.Sprintf("%d_%s", now.UnixNano(), hex.EncodeToString(b[:]))
		}
	}
	return fmt.Sprintf("%d_%s_%s", now.UnixNano(), target, actor)
}
