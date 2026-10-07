package proxy_test

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestCriticalTargetNotifies proves Phase 277's per-connection notification
// end to end through a real upstream sshd: a session to an ordinary target
// raises nothing; once the target is flagged critical, the next session is
// audited target.critical_connect and alerted — after session.start, and
// without being refused.
func TestCriticalTargetNotifies(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	sink := &alertSink{}
	addr := startTOFUProxy(t, st, v, proxy.HostKeyOff, sink, nil)

	if err := execThrough(t, addr); err != nil {
		t.Fatalf("ordinary target: %v", err)
	}
	if n := countAudit(t, st, "target.critical_connect"); n != 0 || sink.has("target.critical_connect", "") {
		t.Fatalf("an ordinary target must not notify: audit=%d alerts=%+v", n, sink.events)
	}

	target.Critical = true
	if err := st.UpdateTarget(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if err := execThrough(t, addr); err != nil {
		t.Fatalf("a critical target must still connect: %v", err)
	}
	waitForAuditDetail(t, st, "target.critical_connect", "target:web-01 protocol:ssh cred_user:"+upstreamUser)
	if !sink.has("target.critical_connect", "target:web-01") {
		t.Fatalf("no critical-connect alert: %+v", sink.events)
	}
}
