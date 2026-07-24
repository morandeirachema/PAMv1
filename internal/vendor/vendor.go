// Package vendor validates a third-party vendor's live employment attestation
// before a contract grant is approved (Phase 29) — the "refuse access if the
// technician has been offboarded by their own employer" control. Attestation is
// an optional webhook the vendor-management system answers 2xx for a currently
// employed vendor; a nil Attestor accepts everyone (attestation disabled), so
// callers can hold one unconditionally. It mirrors the ITSM ticket.Validator.
package vendor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Attestor checks a vendor's live employment status against a webhook.
type Attestor struct {
	webhook string
	http    *http.Client
}

// NewAttestor builds an Attestor from a webhook URL. An empty URL returns
// (nil, nil) — attestation is disabled.
func NewAttestor(webhookURL string) *Attestor {
	if webhookURL == "" {
		return nil
	}
	return &Attestor{webhook: webhookURL, http: &http.Client{Timeout: 8 * time.Second}}
}

// Enabled reports whether attestation is configured.
func (a *Attestor) Enabled() bool { return a != nil }

// Attest returns nil if the vendor is currently attested (employed), else an
// error. A nil Attestor accepts any vendor. The webhook receives
// {"vendor": "<username>", "org": "<org>"} and a 2xx response means employed.
func (a *Attestor) Attest(ctx context.Context, username, org string) error {
	if a == nil {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"vendor": username, "org": org})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("vendor attestation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vendor %q is not currently attested (status %d)", username, resp.StatusCode)
	}
	return nil
}
