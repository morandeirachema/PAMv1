// Package oncall checks whether a human operator is currently on shift before
// admitting a privileged session (Phase 232). Unlike device posture (which
// asks "is this endpoint healthy right now") or vendor employment (checked
// once, at contract-grant approval), on-call status answers a narrower
// question — "should THIS identity's standing access be usable right now" —
// the schedule-aware access HashiCorp Boundary documents under its
// context-based access control (permissions that follow an IdP-reported
// shift status). Attestation is an optional webhook the deployment's on-call
// scheduler (PagerDuty, Opsgenie, or an internal roster) answers 2xx for a
// currently on-call user; a nil Attestor accepts everyone (on-call checking
// disabled), so callers can hold one unconditionally. It mirrors
// internal/posture's Attestor shape exactly, including its
// disabled-by-default, fail-closed-when-configured posture.
package oncall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Attestor checks whether a user is currently on call against a webhook.
type Attestor struct {
	webhook string
	http    *http.Client
}

// NewAttestor builds an Attestor from a webhook URL. An empty URL returns
// (nil, nil) — on-call checking is disabled.
func NewAttestor(webhookURL string) *Attestor {
	if webhookURL == "" {
		return nil
	}
	return &Attestor{webhook: webhookURL, http: &http.Client{Timeout: 8 * time.Second}}
}

// Enabled reports whether on-call checking is configured.
func (a *Attestor) Enabled() bool { return a != nil }

// Attest returns nil if the user is currently on call, else an error. A nil
// Attestor accepts any user. The webhook receives {"user": "<username>"} and
// a 2xx response means on call.
func (a *Attestor) Attest(ctx context.Context, username string) error {
	if a == nil {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"user": username})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("on-call attestation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("user %q is not currently on call (status %d)", username, resp.StatusCode)
	}
	return nil
}
