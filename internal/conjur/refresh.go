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
//
// Phase 80 rebuilt most of it after a review of Phase 78. What changed and why
// is worth keeping, because each was a plausible-looking design that did not
// survive being asked "and then what happens":
//
//   - The applier took BOTH secrets at once, so one malformed break-glass hash
//     blocked a perfectly good API-key rotation forever. Appliers are now
//     per-secret, and the map of them is the single definition of what is
//     refreshable — a secret with no applier cannot be reported as refreshed.
//   - The last-applied values were read back from os.Getenv, a global this
//     package does not own, and the digest was committed before the write that
//     could fail. A failed write silently reinstated the retired key on a later
//     tick. State now lives in the Refresher.
//   - The audit was best-effort and sequenced after the digest commit, so the
//     one tick that rotated a key could apply it and never record it, and never
//     retry. Audit is now fail-closed and precedes the swap, matching the
//     invariant every other secret path follows.
//   - "Conjur owns what it FILLED at boot" excluded PAM_API_KEY in every shipped
//     deployment, because they all set it explicitly — so the feature was inert
//     exactly where it was aimed, while the startup log promised otherwise.
//     Ownership is now "Conjur MANAGES it", probed at startup.

// SecretApplier hands one refreshed secret to the running server. Returning an
// error rejects the value: it is not recorded as applied, so the next tick tries
// again rather than remembering a rejection as success.
type SecretApplier func(value string) error

// Auditor records a refresh. It returns an error because this audit is
// fail-closed: a secret change that cannot be recorded is not made. Every other
// path that hands out or changes a secret in this repo follows the same rule
// (low-level doc §6.4).
type Auditor func(ctx context.Context, action, detail string) error

// Refresher re-reads refreshable bootstrap secrets on a schedule and applies
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

	// appliers is the ONE definition of what "refreshable" means: a secret is
	// refreshable exactly when something here knows how to apply it. Driving
	// detection and application from the same map is what stops a secret being
	// audited as refreshed while reaching no consumer.
	appliers map[string]SecretApplier

	// owned is the subset Conjur actually manages, probed at startup. Empty
	// means there is nothing this refresher can ever do.
	owned map[string]bool

	// applied is the last value successfully applied per secret, fingerprinted.
	// It lives here rather than being read back from os.Getenv: a process-global
	// this package does not own is not a state store, and treating it as one let
	// a failed write reinstate a retired key.
	applied map[string]string

	audit   Auditor
	onError func(ctx context.Context, err error)
	log     *slog.Logger
}

// RefreshOptions collects the wiring, which has enough parts that positional
// arguments stopped being readable.
type RefreshOptions struct {
	Prefix    string
	Overrides map[string]string
	// Appliers maps a PAM_* name to the thing that applies it. Only these are
	// ever fetched, so a secret that cannot be applied never crosses the network.
	Appliers map[string]SecretApplier
	// Audit is required. A nil Auditor would make the refresh silently
	// unrecorded, which is the failure this design exists to avoid.
	Audit Auditor
	// OnError is called for every failed pass, for metrics and alerting. A
	// refresh that has silently stopped working is a revocation control that
	// fails open.
	OnError func(ctx context.Context, err error)
	Log     *slog.Logger
}

// NewRefresher probes which refreshable secrets Conjur actually manages and
// returns a Refresher for them, or nil when there is nothing to refresh.
//
// The probe is the fix for the worst part of the first design. Ownership used to
// mean "Conjur filled this at boot", and populateEnv only fills what the
// environment left empty — while docker-compose hard-requires PAM_API_KEY, the
// Kubernetes secret ships it, and the OVA generates it. So the one secret the
// feature was built for was never refreshable in any shipped deployment, and the
// startup log said it was. Asking Conjur what it manages costs one GET per
// refreshable secret, once, and makes the answer true.
func NewRefresher(ctx context.Context, c *Client, opts RefreshOptions) (*Refresher, error) {
	if opts.Audit == nil {
		return nil, fmt.Errorf("conjur: a refresher needs an Auditor (the refresh audit is fail-closed)")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	r := &Refresher{
		client: c, prefix: opts.Prefix, overrides: opts.Overrides,
		appliers: opts.Appliers, audit: opts.Audit, onError: opts.OnError, log: log,
		owned: map[string]bool{}, applied: map[string]string{},
	}
	// An applier keyed on a name that is not sourceable would never be visited by
	// the loop below: never fetched, never applied, never audited. Silent, and
	// indistinguishable from "Conjur does not manage it". Refuse it at wiring
	// time instead.
	for name := range opts.Appliers {
		if !isBootstrapSecret(name) {
			return nil, fmt.Errorf("conjur: %q has an applier but is not a sourceable bootstrap secret (%s)",
				name, strings.Join(AllSecrets(), ", "))
		}
	}
	token, err := c.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("conjur: probing which secrets are managed: %w", err)
	}
	for _, s := range bootstrapSecrets {
		if r.appliers[s.env] == nil {
			continue
		}
		val, ok, err := c.Get(ctx, token, variableID(r.prefix, s.suffix, s.env, r.overrides))
		if err != nil {
			return nil, fmt.Errorf("conjur: probing %s: %w", s.env, err)
		}
		if !ok {
			continue
		}
		r.owned[s.env] = true
		// Seed from what the process is RUNNING with, NOT from what Conjur holds.
		//
		// Seeding from Conjur (as this first did) makes the opening tick a no-op
		// precisely when the two already differ — which is the case the startup
		// warning describes, "set in the environment AND managed in Conjur, so
		// Conjur wins". It did not win: the server kept the environment value
		// forever while the log said otherwise. That is finding BM reintroduced
		// by its own fix, one layer down.
		//
		// Reading the environment here is not the mistake finding BH was about.
		// That was using os.Getenv as the *last-applied store*, re-read every
		// tick and written back, so a failed write reinstated a retired key. This
		// is a single read at construction to learn what the process booted with,
		// which is the only authoritative answer to "what is running right now".
		// From here on `applied` belongs to the Refresher.
		_ = val
		r.applied[s.env] = digest(strings.TrimSpace(os.Getenv(s.env)))
	}
	if len(r.owned) == 0 {
		return nil, nil
	}
	return r, nil
}

// Owned reports, sorted, the secrets this refresher will actually refresh — the
// list the startup log should print. The static "what could be refreshed" list
// is a different question and was the wrong one to answer.
func (r *Refresher) Owned() []string {
	out := make([]string, 0, len(r.owned))
	for k := range r.owned {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// digest fingerprints a secret so a change can be detected without holding or
// logging the value.
func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// RefreshOnce re-reads the managed secrets and applies the ones that changed,
// returning their names.
//
// Each secret is handled independently, which is the difference between one bad
// value costing one rotation and costing all of them. Fail-safe on every partial
// outcome, because this runs unattended against a network service and the values
// it manages are the ones that let anybody in:
//
//   - a variable that disappears or reads empty keeps the current value — a
//     policy edit must not disable break-glass — but is now WARNED about, since
//     deleting a variable is a plausible way to try to revoke a key and doing
//     nothing silently is the one outcome an operator cannot detect;
//   - a value the applier rejects is not recorded, so the next tick retries;
//   - the audit is written BEFORE the swap and a failure to record skips the
//     swap, so a change can never outlive the evidence of it.
func (r *Refresher) RefreshOnce(ctx context.Context) ([]string, error) {
	token, err := r.client.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("conjur refresh: authenticate: %w", err)
	}
	var changed []string
	var errs []string
	for _, s := range bootstrapSecrets {
		if !r.owned[s.env] {
			continue
		}
		val, ok, err := r.client.Get(ctx, token, variableID(r.prefix, s.suffix, s.env, r.overrides))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s.env, err))
			continue
		}
		// Conjur returns the raw body; a trailing newline from `conjur variable
		// set` would otherwise silently become a different secret.
		val = strings.TrimSpace(val)
		if !ok || val == "" {
			r.log.Warn("conjur refresh: a managed secret is missing or empty; keeping the current value",
				"var", s.env, "note", "deleting a variable does NOT revoke the running key")
			continue
		}
		if digest(val) == r.applied[s.env] {
			continue
		}
		if err := r.applyOne(ctx, s.env, val); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		changed = append(changed, s.env)
	}
	sort.Strings(changed)
	if len(errs) > 0 {
		return changed, fmt.Errorf("conjur refresh: %s", strings.Join(errs, "; "))
	}
	return changed, nil
}

// applyOne records then applies a single secret.
//
// Order matters: the audit comes first and a failure to record aborts the swap.
// The alternative — swap, then try to record — is how the one tick that rotated
// a key ends up applied and unrecorded, and then never retried because the
// digest already moved.
func (r *Refresher) applyOne(ctx context.Context, env, val string) error {
	// The values are never logged or audited — only which key moved.
	if err := r.audit(ctx, "config.secret_refreshed", "source:conjur key:"+env); err != nil {
		return fmt.Errorf("%s: recording the refresh failed, so it was not applied: %w", env, err)
	}
	if err := r.appliers[env](val); err != nil {
		return fmt.Errorf("%s: %w", env, err)
	}
	r.applied[env] = digest(val)
	r.log.Info("refreshed a bootstrap secret from Conjur", "var", env)
	return nil
}

// Run refreshes every interval until ctx is cancelled. A failing pass is logged
// and reported through OnError, and the loop continues: a Conjur outage must not
// take the server down, and the values it would have refreshed are still valid.
func (r *Refresher) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		r.log.Error("conjur refresh: non-positive interval; refresh disabled", "interval", every)
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.RefreshOnce(ctx); err != nil && ctx.Err() == nil {
				// Error, not Warn: this is a revocation control that has stopped
				// working, and it is invisible everywhere else.
				r.log.Error("conjur refresh failed; keeping the current secrets", "err", err)
				if r.onError != nil {
					r.onError(ctx, err)
				}
			}
		}
	}
}
