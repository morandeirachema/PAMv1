// Package posture checks a device's live security posture — EDR/endpoint
// health — before admitting a privileged session (Phase 133). Unlike vendor
// employment attestation (checked once, at contract-grant approval), posture
// can change between one connection and the next, so it is re-checked on
// every connect: the session proxies' shared admission gate (internal/proxy
// gates.go) and the REST authz middleware both call it. Attestation is an
// optional webhook the deployment's EDR/posture system answers 2xx for a
// currently healthy device; a nil Attestor accepts everyone (posture checking
// disabled), so callers can hold one unconditionally. It mirrors
// internal/vendor's Attestor shape.
package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Attestor checks a user's live device posture against a webhook.
type Attestor struct {
	webhook string
	http    *http.Client
}

// NewAttestor builds an Attestor from a webhook URL. An empty URL returns
// (nil, nil) — posture checking is disabled.
func NewAttestor(webhookURL string) *Attestor {
	if webhookURL == "" {
		return nil
	}
	return &Attestor{webhook: webhookURL, http: &http.Client{Timeout: 8 * time.Second}}
}

// Enabled reports whether posture checking is configured.
func (a *Attestor) Enabled() bool { return a != nil }

// Attest returns nil if the user's device currently passes posture, else an
// error. A nil Attestor accepts any user. The webhook receives
// {"user": "<username>"} and a 2xx response means healthy.
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
		return fmt.Errorf("posture attestation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("user %q failed device posture check (status %d)", username, resp.StatusCode)
	}
	return nil
}
