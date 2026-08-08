package conjur

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"
)

// Secret sourcing is one-shot at boot: config.Load reads the environment once,
// and every consumer captures what it needs. That makes rotating a secret a
// restart of every replica — which for the bootstrap API key, the most widely
// shared credential in the system, is exactly the friction that stops people
// rotating it.
//
// This file adds the two halves of "config depth": a per-variable override so
// the Conjur variable id is not forced to follow one naming convention, and an
// opt-in periodic refresh of the secrets that can *honestly* be refreshed.

// refreshable lists the bootstrap secrets a running server can adopt.
//
// The list is short on purpose, and the exclusions matter more than the
// inclusions — a refresh that silently failed to take effect would be worse than
// no refresh at all:
//
//   - PAM_API_KEY and PAM_BREAK_GLASS_KEY_HASH are pure comparison values. The
//     resolver hashes a presented key and compares; replacing what it compares
//     against is complete and instant, with nothing derived from the old value.
//   - PAM_MASTER_KEY is the KEK. Every vaulted secret is sealed under it, so
//     changing it does not rotate anything — it makes the whole vault
//     undecryptable. Rotation is `pam-server -rotate-kek`, offline, re-wrapping
//     every stored secret.
//   - PAM_DATABASE_URL is bound into a live connection pool with in-flight
//     transactions.
//   - PAM_BROKER_AUDIT_KEY keys the HMAC chain. Swapping it mid-chain does not
//     re-key history, it makes every earlier event fail verification.
//   - PAM_BROKER_AUDIT_SIGN_SEED already has a rotation path that keeps the
//     retired public half trusted (PAM_BROKER_AUDIT_SIGN_PREV); a silent swap
//     would strand checkpoints signed by the old key.
var refreshable = map[string]bool{
	"PAM_API_KEY":              true,
	"PAM_BREAK_GLASS_KEY_HASH": true,
}

// RefreshableSecrets and PinnedSecrets report the split, sorted, for the startup
// log — so an operator learns which rotations will be picked up *before* they
// perform one, rather than by watching nothing happen.
func RefreshableSecrets() []string { return partition(true) }

// PinnedSecrets returns the bootstrap secrets that only a restart can change.
func PinnedSecrets() []string { return partition(false) }

// partition returns the sourced secrets on one side of the refreshable split.
func partition(want bool) []string {
	out := make([]string, 0, len(bootstrapSecrets))
	for _, s := range bootstrapSecrets {
		if refreshable[s.env] == want {
			out = append(out, s.env)
		}
	}
	sort.Strings(out)
	return out
}

// ParseVarOverrides reads PAM_CONJUR_VARS: a comma-separated list of
// `PAM_SOMETHING=conjur/variable/id` pairs that replace the default
// `<prefix>/<suffix>` convention for individual variables.
//
// It exists because the convention is a guess about someone else's Conjur
// policy. A site whose variables live at `prod/pamv1/keys/api` cannot rename
// them to suit us, and without this the whole integration is unusable there —
// the feature ships and is never turned on, which is the failure mode a
// convention-only design keeps producing.
//
// Unknown variable names are an error rather than a warning: a typo'd
// `PAM_API_KEY_` would otherwise be silently ignored and the operator would
// conclude the override does not work.
func ParseVarOverrides(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, id, ok := strings.Cut(pair, "=")
		name, id = strings.TrimSpace(name), strings.TrimSpace(id)
		if !ok || name == "" || id == "" {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %q is not NAME=variable/id", pair)
		}
		known := false
		for _, s := range bootstrapSecrets {
			if s.env == name {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %q is not a sourced bootstrap secret (%s)",
				name, strings.Join(allSecretNames(), ", "))
		}
		out[name] = id
	}
	return out, nil
}

// allSecretNames lists every sourceable secret, for error messages.
func allSecretNames() []string {
	out := make([]string, 0, len(bootstrapSecrets))
	for _, s := range bootstrapSecrets {
		out = append(out, s.env)
	}
	return out
}

// variableID resolves the Conjur variable id for one bootstrap secret: the
// per-variable override if there is one, otherwise `<prefix>/<suffix>`.
func variableID(prefix, suffix, env string, overrides map[string]string) string {
	if id, ok := overrides[env]; ok {
		return id
	}
	return prefix + "/" + suffix
}

// Applier receives a refreshed pair of bootstrap secrets. Both are always passed
// so the two can never drift apart; see auth.Resolver.SetBootstrapSecrets.
type Applier func(apiKey, breakGlassHashHex string) error

// Refresher re-reads the refreshable bootstrap secrets on a schedule and applies
// changes to a running server.
//
// It is deliberately NOT leader-locked. Every replica holds its own in-memory
// copy of these values, so every replica has to do this for itself — a
// leader-only refresh would leave the rest of the cluster authenticating against
// the old key, which is the split-brain version of the bug this closes.
type Refresher struct {
	client    *Client
	prefix    string
	overrides map[string]string
	apply     Applier
	audit     func(ctx context.Context, action, detail string)
	log       *slog.Logger

	// sourced is the set Conjur actually filled at boot. Refreshing anything
	// outside it would quietly overwrite a value the operator set explicitly,
	// breaking the "an explicit env value wins" rule one tick after startup.
	sourced map[string]bool

	// digests of the last values applied, so a change can be detected without
	// keeping the secrets themselves resident.
	digests map[string]string
}

// NewRefresher builds a Refresher over an authenticated client. audit may be nil.
func NewRefresher(c *Client, prefix string, overrides map[string]string, sourced []string,
	apply Applier, audit func(ctx context.Context, action, detail string), log *slog.Logger) *Refresher {
	if log == nil {
		log = slog.Default()
	}
	r := &Refresher{client: c, prefix: prefix, overrides: overrides, apply: apply,
		audit: audit, log: log, digests: map[string]string{}, sourced: map[string]bool{}}
	for _, env := range sourced {
		r.sourced[env] = true
	}
	// Seed from what the process is already running with, so the first tick
	// reports a change only if one really happened.
	for env := range refreshable {
		if v := os.Getenv(env); v != "" {
			r.digests[env] = digest(v)
		}
	}
	return r
}

// digest fingerprints a secret so a change can be detected without holding or
// logging the value.
func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// RefreshOnce re-reads the refreshable secrets and applies them if any changed.
// It returns the names that changed.
//
// Fail-safe on every partial outcome, because this runs unattended against a
// network service and the values it manages are the ones that let anybody in:
//
//   - a variable missing in Conjur (404) keeps the current value, rather than
//     clearing it — a policy edit must not disable break-glass;
//   - an empty value is refused for the same reason;
//   - a transport or auth failure returns an error and applies nothing;
//   - an invalid break-glass hash is rejected by the applier before anything is
//     swapped, so a bad value cannot half-apply.
func (r *Refresher) RefreshOnce(ctx context.Context) ([]string, error) {
	token, err := r.client.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("conjur refresh: authenticate: %w", err)
	}

	// Start from what is running now, so a variable Conjur does not manage keeps
	// its current value instead of being cleared.
	current := map[string]string{}
	for env := range refreshable {
		current[env] = os.Getenv(env)
	}

	var changed []string
	for _, s := range bootstrapSecrets {
		if !refreshable[s.env] {
			continue
		}
		// An explicit environment value wins here exactly as it does at boot.
		// Conjur only owns what it filled, which is why that list is recorded.
		if !r.sourced[s.env] {
			continue
		}
		val, ok, err := r.client.Get(ctx, token, variableID(r.prefix, s.suffix, s.env, r.overrides))
		if err != nil {
			return nil, fmt.Errorf("conjur refresh: reading %s: %w", s.env, err)
		}
		if !ok || val == "" {
			continue // not managed here, or empty: keep what we have
		}
		if digest(val) == r.digests[s.env] {
			continue
		}
		current[s.env] = val
		changed = append(changed, s.env)
	}
	if len(changed) == 0 {
		return nil, nil
	}

	if err := r.apply(current["PAM_API_KEY"], current["PAM_BREAK_GLASS_KEY_HASH"]); err != nil {
		return nil, fmt.Errorf("conjur refresh: applying %s: %w", strings.Join(changed, ","), err)
	}
	// Only record the new digests once the swap succeeded, so a rejected value is
	// retried on the next tick rather than remembered as applied.
	for _, env := range changed {
		r.digests[env] = digest(current[env])
		if err := os.Setenv(env, current[env]); err != nil {
			r.log.Warn("conjur refresh: could not update the process environment", "var", env, "err", err)
		}
	}
	sort.Strings(changed)
	// The values are never logged or audited — only which keys moved.
	r.log.Info("refreshed bootstrap secrets from Conjur", "keys", strings.Join(changed, ","))
	if r.audit != nil {
		r.audit(ctx, "config.secret_refreshed", "source:conjur keys:"+strings.Join(changed, ","))
	}
	return changed, nil
}

// Run refreshes every interval until ctx is cancelled. A failing tick is logged
// and the loop continues: a Conjur outage must not take the server down, and the
// values it would have refreshed are still valid.
func (r *Refresher) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.RefreshOnce(ctx); err != nil && ctx.Err() == nil {
				r.log.Warn("conjur refresh failed; keeping the current secrets", "err", err)
			}
		}
	}
}
