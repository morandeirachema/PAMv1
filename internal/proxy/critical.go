package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// notifyCritical records and announces a session opened to a critical target
// (Phase 277): an audit row target.critical_connect under the operator's
// actor, then an alert through the configured channels. It runs after the
// session-start row was durably written, so a critical connection is never
// announced for a session that did not open, and it never refuses one — the
// flag is notification, not authorization. A failed append is logged and the
// alert is still sent: losing the second row must not also lose the page.
func notifyCritical(ctx context.Context, st store.Store, log *slog.Logger, alerter alert.Notifier,
	actor string, target *store.Target, credUser, remote string) {
	detail := fmt.Sprintf("target:%s protocol:%s cred_user:%s", target.Name, target.Protocol, credUser)
	appendAudit(ctx, st, log, actor, "target.critical_connect", detail)
	if alerter == nil {
		return
	}
	alerter.Notify(ctx, alert.Event{Type: "target.critical_connect", Actor: actor, Detail: detail, Remote: remote, Time: time.Now()})
}
