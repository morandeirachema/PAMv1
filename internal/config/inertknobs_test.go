package config_test

import (
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/config"
)

// TestInertBrokerKnobsFailStartup covers Phase 182's first half: a setting that
// is ON but cannot act fails the startup rather than serving a deployment that
// believes it is stricter than it is.
//
// This is the batch's recurring failure class one level up — not a dead field in
// the code, but a live field in the CONFIGURATION whose prerequisite is absent.
// Each of these reads to an operator as "the agents are gated", and each does
// nothing at all without the thing it gates on.
func TestInertBrokerKnobsFailStartup(t *testing.T) {
	base := map[string]string{
		"PAM_MASTER_KEY":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"PAM_API_KEY":      "k",
		"PAM_DATABASE_URL": "memory",
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			"enrollment required with no SVID verifier",
			map[string]string{"PAM_BROKER_POLICY_FILE": "/tmp/p.yaml", "PAM_BROKER_REQUIRE_ENROLLED_SVID": "true"},
			"PAM_BROKER_REQUIRE_ENROLLED_SVID needs PAM_BROKER_TRUST_DOMAIN_JWKS",
		},
		{
			"agent posture required with no posture webhook",
			map[string]string{"PAM_BROKER_POLICY_FILE": "/tmp/p.yaml", "PAM_BROKER_POSTURE_REQUIRED": "true"},
			"PAM_BROKER_POSTURE_REQUIRED needs PAM_POSTURE_ATTEST_URL",
		},
		{
			"a broker refusal with no broker",
			map[string]string{"PAM_BROKER_REQUIRE_KNOWN_OWNER": "true"},
			"PAM_BROKER_REQUIRE_KNOWN_OWNER needs the agent broker enabled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a startup error containing %q, got %v", tc.want, err)
			}
		})
	}

	// And the same knobs load fine once their prerequisite is there — the check
	// refuses an inert setting, not the feature.
	for k, v := range base {
		t.Setenv(k, v)
	}
	t.Setenv("PAM_BROKER_POLICY_FILE", "/tmp/p.yaml")
	t.Setenv("PAM_BROKER_TRUST_DOMAIN_JWKS", "/tmp/jwks.json")
	t.Setenv("PAM_BROKER_TRUST_DOMAIN", "example.org")
	t.Setenv("PAM_BROKER_AUDIENCE", "pam-broker")
	t.Setenv("PAM_POSTURE_ATTEST_URL", "https://posture.example/check")
	t.Setenv("PAM_BROKER_REQUIRE_ENROLLED_SVID", "true")
	t.Setenv("PAM_BROKER_POSTURE_REQUIRED", "true")
	t.Setenv("PAM_BROKER_REQUIRE_KNOWN_OWNER", "true")
	if _, err := config.Load(); err != nil {
		t.Fatalf("a fully configured deployment must load: %v", err)
	}
}
