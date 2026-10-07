package api

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// notifyCritical is the portal's half of the critical-target notification
// (Phase 277) — the desktop viewer opens RDP/VNC sessions here rather than in
// a proxy, so it raises the same target.critical_connect row and alert the
// proxies' admit gate does. Called only after the session's own connect row
// was written; it never refuses the session.
func (s *Server) notifyCritical(ctx context.Context, target *store.Target, credUser, remote string) {
	detail := fmt.Sprintf("target:%s protocol:%s cred_user:%s", target.Name, target.Protocol, credUser)
	s.audit(ctx, "target.critical_connect", detail)
	s.alerter.Notify(ctx, alert.Event{Type: "target.critical_connect", Actor: actorFrom(ctx), Detail: detail, Remote: remote, Time: time.Now()})
}
