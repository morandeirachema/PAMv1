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
// {"user": "<username>", "kind": "user"} and a 2xx response means healthy.
func (a *Attestor) Attest(ctx context.Context, username string) error {
	return a.AttestSubject(ctx, SubjectUser, username)
}

// Subject kinds an attestation can be about (Phase 180).
const (
	// SubjectUser is a human operator's device — the original case, and what
	// "posture" normally means: an EDR agent reporting on a laptop.
	SubjectUser = "user"
	// SubjectAgent is a non-human workload identity: an AI agent's container or
	// process. Sent so a posture system can tell the two apart rather than
	// having to guess from the name — an unrecognised laptop and an
	// unrecognised workload deserve different answers, and a system that cannot
	// distinguish them tends to answer "healthy" for both.
	SubjectAgent = "agent"
)

// AttestSubject is Attest with the subject's KIND stated. The webhook receives
// {"user": "<name>", "kind": "user"|"agent"}; `user` keeps its name for
// compatibility with every webhook written before agents were attested, and
// `kind` is additive, so an existing receiver that ignores unknown fields
// behaves exactly as it did.
//
// **What this can and cannot prove.** For a laptop, an EDR system knows the
// device and answers about it. For a workload, the webhook is answering about a
// NAME PAMv1 verified cryptographically — not about the process holding the
// credential. That is a real gap and not one more infrastructure here would
// close: binding a credential to the process presenting it is workload
// attestation (SPIRE), which stays external. Treat an agent posture answer as
// "the fleet manager believes this identity's workload is healthy", never as
// proof that the caller IS that workload.
func (a *Attestor) AttestSubject(ctx context.Context, kind, name string) error {
	if a == nil {
		return nil
	}
	username := name
	body, _ := json.Marshal(map[string]string{"user": name, "kind": kind})
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
		return fmt.Errorf("%s %q failed posture check (status %d)", kind, username, resp.StatusCode)
	}
	return nil
}
