package config

import (
	"strings"
	"testing"
)

// setRequired sets the three always-required vars (for the default local KEK) so
// a test can focus on the field under test.
func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("PAM_MASTER_KEY", "test-master-key")
	t.Setenv("PAM_API_KEY", "test-api-key")
	t.Setenv("PAM_DATABASE_URL", "memory")
}

// TestLoadValidation covers the fail-loud guards for negative rate limits and a
// partial email-alert config (which would otherwise silently disable controls).
func TestLoadValidation(t *testing.T) {
	t.Run("negative auth rate limit", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_AUTH_RATE_LIMIT", "-1")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_AUTH_RATE_LIMIT") {
			t.Fatalf("Load() = %v, want PAM_AUTH_RATE_LIMIT error", err)
		}
	})
	t.Run("partial email alert", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_ALERT_EMAIL_SMTP", "smtp:25")
		t.Setenv("PAM_ALERT_EMAIL_FROM", "pam@x")
		// PAM_ALERT_EMAIL_TO deliberately omitted.
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ALERT_EMAIL") {
			t.Fatalf("Load() = %v, want PAM_ALERT_EMAIL error", err)
		}
	})
	t.Run("ldap insecure not overridable", func(t *testing.T) {
		if IsOverridable("PAM_LDAP_INSECURE_SKIP_VERIFY") {
			t.Fatal("PAM_LDAP_INSECURE_SKIP_VERIFY must not be a runtime-overridable setting")
		}
	})
	t.Run("zsp cert ttl too long", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_SSH_CA_KEY", "/data/ca")
		t.Setenv("PAM_SSH_CERT_TTL_MIN", "2000") // > 24h
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_SSH_CERT_TTL_MIN") {
			t.Fatalf("Load() = %v, want PAM_SSH_CERT_TTL_MIN too-long error", err)
		}
	})
	t.Run("invalid analytics timezone", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_ANALYTICS_TIMEZONE", "Nowhere/Fake")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ANALYTICS_TIMEZONE") {
			t.Fatalf("Load() = %v, want PAM_ANALYTICS_TIMEZONE error", err)
		}
	})
	t.Run("invalid sftp capture mode", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_SSH_SFTP_CAPTURE", "everything")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_SSH_SFTP_CAPTURE") {
			t.Fatalf("Load() = %v, want PAM_SSH_SFTP_CAPTURE error", err)
		}
	})
	t.Run("negative sftp capture cap", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_SSH_SFTP_CAPTURE", "all")
		t.Setenv("PAM_SSH_SFTP_CAPTURE_MAX_MB", "-5")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_SSH_SFTP_CAPTURE_MAX_MB") {
			t.Fatalf("Load() = %v, want PAM_SSH_SFTP_CAPTURE_MAX_MB error", err)
		}
	})
}

// TestLoadRequiredVars checks each required variable is reported when missing and
// that the master key is required only for the local KEK provider.
func TestLoadRequiredVars(t *testing.T) {
	t.Run("all present", func(t *testing.T) {
		setRequired(t)
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil", err)
		}
	})
	t.Run("missing api key", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_API_KEY", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_API_KEY") {
			t.Fatalf("Load() = %v, want PAM_API_KEY error", err)
		}
	})
	t.Run("weak api key rejected on a real database", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_DATABASE_URL", "postgres://localhost/pam")
		t.Setenv("PAM_API_KEY", "short") // < 16 chars
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_API_KEY must be at least 16") {
			t.Fatalf("Load() = %v, want weak PAM_API_KEY error", err)
		}
	})
	t.Run("weak api key allowed in memory demo", func(t *testing.T) {
		setRequired(t) // PAM_DATABASE_URL=memory
		t.Setenv("PAM_API_KEY", "demo-key")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil (memory demo exempts the length floor)", err)
		}
	})
	t.Run("weak api key allowed with explicit override", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_DATABASE_URL", "postgres://localhost/pam")
		t.Setenv("PAM_API_KEY", "short")
		t.Setenv("PAM_ALLOW_WEAK_API_KEY", "true")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil with PAM_ALLOW_WEAK_API_KEY=true", err)
		}
	})
	t.Run("missing database url", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_DATABASE_URL", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_DATABASE_URL") {
			t.Fatalf("Load() = %v, want PAM_DATABASE_URL error", err)
		}
	})
	t.Run("master key not required for non-local KEK", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MASTER_KEY", "")
		t.Setenv("PAM_KEK_PROVIDER", "vault-transit")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil (KMS provider holds the key)", err)
		}
	})
	t.Run("master key required for local KEK", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MASTER_KEY", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_MASTER_KEY") {
			t.Fatalf("Load() = %v, want PAM_MASTER_KEY error", err)
		}
	})
}

// TestLoadBooleanStrict proves security toggles accept any Go bool spelling and
// reject garbage loudly rather than silently failing open.
func TestLoadBooleanStrict(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{{"true", true}, {"TRUE", true}, {"1", true}, {"t", true}, {"false", false}, {"0", false}} {
		t.Run("MFA="+tc.val, func(t *testing.T) {
			setRequired(t)
			t.Setenv("PAM_MFA_REQUIRED", tc.val)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if cfg.MFARequired != tc.want {
				t.Errorf("MFARequired = %v, want %v", cfg.MFARequired, tc.want)
			}
		})
	}
	t.Run("garbage errors, not silently off", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MFA_REQUIRED", "yes")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_MFA_REQUIRED") {
			t.Fatalf("Load() = %v, want PAM_MFA_REQUIRED invalid-boolean error", err)
		}
	})
	t.Run("WinRM HTTPS defaults true and honors false", func(t *testing.T) {
		setRequired(t)
		cfg, _ := Load()
		if !cfg.WinRMHTTPS {
			t.Error("WinRMHTTPS default = false, want true")
		}
		t.Setenv("PAM_WINRM_HTTPS", "false")
		cfg, _ = Load()
		if cfg.WinRMHTTPS {
			t.Error("WinRMHTTPS with false = true")
		}
	})
}

// TestLoadIntegerStrict proves a non-integer errors rather than silently
// disabling the worker/limit it configures.
func TestLoadIntegerStrict(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_ROTATE_INTERVAL_MIN", "1h")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ROTATE_INTERVAL_MIN") {
		t.Fatalf("Load() = %v, want PAM_ROTATE_INTERVAL_MIN invalid-integer error", err)
	}
}

// TestLoadTLSBothOrNeither proves a half-configured TLS pair is rejected instead
// of silently serving plaintext.
func TestLoadTLSBothOrNeither(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_TLS_CERT", "/tmp/cert.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_TLS") {
		t.Fatalf("Load() = %v, want TLS pairing error", err)
	}
	t.Setenv("PAM_TLS_KEY", "/tmp/key.pem")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() with both TLS vars = %v, want nil", err)
	}
}

// TestLoadBreakGlassThreshold proves an unusable quorum threshold is rejected.
func TestLoadBreakGlassThreshold(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_BREAK_GLASS_THRESHOLD") {
		t.Fatalf("Load() = %v, want threshold error for 1", err)
	}
	t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "3")
	t.Setenv("PAM_BREAK_GLASS_SHARES", "5")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() with 3-of-5 = %v, want nil", err)
	}
}

// TestLoadOffCaseInsensitive proves the proxy disable sentinel is case-insensitive.
func TestLoadOffCaseInsensitive(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_SSH_ADDR", "OFF")
	t.Setenv("PAM_DB_ADDR", "Off")
	t.Setenv("PAM_MSSQL_ADDR", "OFF")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSHAddr != "off" {
		t.Errorf("SSHAddr = %q, want normalized \"off\"", cfg.SSHAddr)
	}
	if cfg.DBAddr != "off" {
		t.Errorf("DBAddr = %q, want normalized \"off\"", cfg.DBAddr)
	}
	if cfg.MSSQLAddr != "off" {
		t.Errorf("MSSQLAddr = %q, want normalized \"off\"", cfg.MSSQLAddr)
	}
}

// TestAirGapRefusesEgressingIntegrations proves PAM_OT_AIRGAP now enforces what
// its name promises.
//
// The flag used to be consulted in exactly one place — choosing the alerter — so
// it silenced alerts and nothing else. The ITSM webhook, the vendor-attestation
// webhook, the SIEM forwarder, Conjur, a cloud KEK and a cloud identity provider
// all still egressed, while an operator who set the flag believed the opposite.
// A control that manufactures confidence is worse than no control.
func TestAirGapRefusesEgressingIntegrations(t *testing.T) {
	for _, tc := range []struct{ name, key, value, wantIn string }{
		{"ITSM webhook", "PAM_TICKET_VALIDATE_URL", "https://itsm.example/api", "PAM_TICKET_VALIDATE_URL"},
		{"vendor attestation", "PAM_VENDOR_ATTEST_URL", "https://vendor.example/attest", "PAM_VENDOR_ATTEST_URL"},
		{"SIEM forwarder", "PAM_AUDIT_FORWARD_ADDR", "siem.example:514", "PAM_AUDIT_FORWARD_ADDR"},
		{"OIDC issuer", "PAM_OIDC_ISSUER", "https://idp.example", "PAM_OIDC_ISSUER"},
		{"Conjur", "PAM_CONJUR_URL", "https://conjur.example", "PAM_CONJUR_URL"},
		{"alert webhook", "PAM_ALERT_WEBHOOK", "https://hooks.example/x", "PAM_ALERT_WEBHOOK"},
		{"cloud KEK", "PAM_KEK_PROVIDER", "aws-kms", "PAM_KEK_PROVIDER"},
		{"cloud identity", "PAM_ENTRA_TENANT_ID", "a-tenant-guid", "PAM_ENTRA_TENANT_ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setRequired(t)
			t.Setenv("PAM_OT_AIRGAP", "true")
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%s was accepted alongside PAM_OT_AIRGAP; the flag would silence alerts while this still reached the network", tc.key)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("the error does not name the offender (%s): %v", tc.wantIn, err)
			}
		})
	}
}

// TestAirGapAllowsDeclaredInternalEndpoints proves the escape hatch works, and
// that it is per-variable rather than a blanket override.
//
// "Air-gapped" rarely means "no network" — it usually means "nothing leaves this
// enclave". A local Conjur, an in-DMZ SIEM collector or a self-hosted Keycloak
// are legitimate, and refusing them outright would push operators to turn the
// flag off entirely, which is the opposite of the intent. So egress is
// impossible by accident and possible on purpose, with the exceptions written
// down in the deployment instead of living in somebody's head.
func TestAirGapAllowsDeclaredInternalEndpoints(t *testing.T) {
	t.Run("declared endpoint is accepted", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_OT_AIRGAP", "true")
		t.Setenv("PAM_AUDIT_FORWARD_ADDR", "siem.internal:514")
		t.Setenv("PAM_OT_AIRGAP_ALLOW", "PAM_AUDIT_FORWARD_ADDR")
		if _, err := Load(); err != nil {
			t.Fatalf("an endpoint declared internal was still refused: %v", err)
		}
	})

	t.Run("the allowance is per-variable, not a blanket off-switch", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_OT_AIRGAP", "true")
		t.Setenv("PAM_AUDIT_FORWARD_ADDR", "siem.internal:514")
		t.Setenv("PAM_TICKET_VALIDATE_URL", "https://itsm.example/api")
		t.Setenv("PAM_OT_AIRGAP_ALLOW", "PAM_AUDIT_FORWARD_ADDR")
		err := Load2Err(t)
		if err == nil {
			t.Fatal("allowing one endpoint allowed an undeclared one too")
		}
		if !strings.Contains(err.Error(), "PAM_TICKET_VALIDATE_URL") {
			t.Fatalf("the undeclared endpoint was not named: %v", err)
		}
		if strings.Contains(err.Error(), "PAM_AUDIT_FORWARD_ADDR") {
			t.Fatalf("the declared endpoint was still reported: %v", err)
		}
	})

	t.Run("no escape hatch for inherently external providers", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_OT_AIRGAP", "true")
		t.Setenv("PAM_KEK_PROVIDER", "aws-kms")
		t.Setenv("PAM_OT_AIRGAP_ALLOW", "PAM_KEK_PROVIDER")
		if _, err := Load(); err == nil {
			t.Fatal("AWS KMS was allowed inside an air-gapped enclave; there is no in-enclave version of somebody else's cloud")
		}
	})

	t.Run("air-gap off changes nothing", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_TICKET_VALIDATE_URL", "https://itsm.example/api")
		if _, err := Load(); err != nil {
			t.Fatalf("an ordinary deployment was refused: %v", err)
		}
	})
}

// Load2Err calls Load and returns only the error, for readability above.
func Load2Err(t *testing.T) error {
	t.Helper()
	_, err := Load()
	return err
}
