package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Host-key check modes (Phase 272), the values of PAM_SSH_HOST_KEY_CHECK.
const (
	HostKeyTOFU   = "tofu"
	HostKeyStrict = "strict"
	HostKeyOff    = "off"
)

// hostKeyCallbackFor returns the callback that verifies one target's SSH host
// key on this dial. A known_hosts callback (PAM_SSH_KNOWN_HOSTS), when
// configured, is authoritative and unchanged. Otherwise the per-target pin in
// the store decides (WALLIX's "server pubkey store" with its check modes):
//
//   - a stored pin that matches: accepted, last_seen refreshed;
//   - a stored pin that does not match: REFUSED, `target.hostkey_mismatch`
//     audited under the operator's actor and alerted — a re-keyed host is
//     reset by an administrator (DELETE /api/targets/{id}/host-key), never
//     silently re-learned;
//   - no pin, mode tofu: the key is stored (`target.hostkey_saved`, alerted)
//     and accepted — the first contact is trusted, every later one checked;
//   - no pin, mode strict: refused (`target.hostkey_unknown`).
//
// A store error refuses the dial: an unverifiable key is not an accepted one.
func (p *Proxy) hostKeyCallbackFor(ctx context.Context, target *store.Target, actor string) ssh.HostKeyCallback {
	if p.upstreamHKCB != nil {
		return p.upstreamHKCB
	}
	return func(hostport string, remote net.Addr, key ssh.PublicKey) error {
		presented := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		fp := ssh.FingerprintSHA256(key)
		pin, err := p.store.GetTargetHostKey(ctx, target.ID)
		switch {
		case err == nil:
			if pin.PublicKey == presented {
				_ = p.store.PutTargetHostKey(ctx, pin) // refresh last_seen; best effort
				return nil
			}
			p.audit(ctx, actor, "target.hostkey_mismatch", fmt.Sprintf("target:%s host:%s:%d key_type:%s presented:%s pinned:%s",
				target.Name, auditField(target.Host, 255), target.Port, key.Type(), fp, pin.Fingerprint))
			p.alertHostKey(ctx, "hostkey.mismatch", actor, fmt.Sprintf("target %s (%s:%d) presented %s, pinned %s", target.Name, target.Host, target.Port, fp, pin.Fingerprint))
			return fmt.Errorf("host key mismatch for %s: presented %s, pinned %s (reset the pin if the host was re-keyed)", target.Name, fp, pin.Fingerprint)
		case errors.Is(err, store.ErrNotFound):
			if p.hostKeyCheck == HostKeyStrict {
				p.audit(ctx, actor, "target.hostkey_unknown", fmt.Sprintf("target:%s host:%s:%d key_type:%s presented:%s",
					target.Name, auditField(target.Host, 255), target.Port, key.Type(), fp))
				return fmt.Errorf("no host key pinned for %s and PAM_SSH_HOST_KEY_CHECK=strict (presented %s)", target.Name, fp)
			}
			k := &store.TargetHostKey{TargetID: target.ID, KeyType: key.Type(), Fingerprint: fp, PublicKey: presented}
			if perr := p.store.PutTargetHostKey(ctx, k); perr != nil {
				return fmt.Errorf("store host key for %s: %w", target.Name, perr)
			}
			p.audit(ctx, actor, "target.hostkey_saved", fmt.Sprintf("target:%s host:%s:%d key_type:%s fingerprint:%s",
				target.Name, auditField(target.Host, 255), target.Port, key.Type(), fp))
			p.alertHostKey(ctx, "hostkey.saved", actor, fmt.Sprintf("target %s (%s:%d) pinned on first contact: %s %s", target.Name, target.Host, target.Port, key.Type(), fp))
			return nil
		default:
			return fmt.Errorf("host key lookup for %s: %w", target.Name, err)
		}
	}
}

// alertHostKey raises a host-key event on the alerter, if one is wired.
func (p *Proxy) alertHostKey(ctx context.Context, kind, actor, detail string) {
	if p.alerter == nil {
		return
	}
	p.alerter.Notify(ctx, alert.Event{Type: kind, Actor: actor, Detail: detail, Time: time.Now()})
}
