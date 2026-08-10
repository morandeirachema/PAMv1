package config

import (
	"strings"
	"testing"
)

// TestLoadRejectsBadValues pins the config validation surface: internal/config
// is the sole validator of the PAM_* environment, and a rule that silently stops
// rejecting a bad value would let a fat-fingered setting disable a security
// control (throttling off, retention deleting, an enum falling back to its
// permissive default). Each case sets the minimal valid baseline plus one bad
// variable and asserts Load reports it. It complements the individual guards in
// config_test.go by covering the rules those did not reach.
func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string // a substring the accumulated error must contain
	}{
		{"sftp mode enum", map[string]string{"PAM_SSH_SFTP": "bogus"}, "PAM_SSH_SFTP must be one of"},
		{"analytics baseline days", map[string]string{"PAM_ANALYTICS_BASELINE_DAYS": "400"}, "PAM_ANALYTICS_BASELINE_DAYS"},
		{"conjur refresh minutes", map[string]string{"PAM_CONJUR_REFRESH_MIN": "5000"}, "PAM_CONJUR_REFRESH_MIN"},
		{"cert remind days", map[string]string{"PAM_CERT_REMIND_DAYS": "400"}, "PAM_CERT_REMIND_DAYS"},
		{"rdp clipboard enum", map[string]string{"PAM_RDP_CLIPBOARD": "maybe"}, "PAM_RDP_CLIPBOARD must be one of"},
		{"rdp clipboard audit enum", map[string]string{"PAM_RDP_CLIPBOARD_AUDIT": "partial"}, "PAM_RDP_CLIPBOARD_AUDIT must be one of"},
		{"negative recording retention", map[string]string{"PAM_RECORDING_RETENTION_DAYS": "-1"}, "PAM_RECORDING_RETENTION_DAYS"},
		{"retention interval too small", map[string]string{"PAM_RETENTION_INTERVAL_HOURS": "0"}, "PAM_RETENTION_INTERVAL_HOURS"},
		{"audit forward bad proto", map[string]string{"PAM_AUDIT_FORWARD_ADDR": "siem:514", "PAM_AUDIT_FORWARD_PROTO": "sctp"}, "PAM_AUDIT_FORWARD_PROTO"},
		{"audit forward bad format", map[string]string{"PAM_AUDIT_FORWARD_ADDR": "siem:514", "PAM_AUDIT_FORWARD_PROTO": "tls", "PAM_AUDIT_FORWARD_FORMAT": "xml"}, "PAM_AUDIT_FORWARD_FORMAT"},
		{"audit forward CA without tls", map[string]string{"PAM_AUDIT_FORWARD_ADDR": "siem:514", "PAM_AUDIT_FORWARD_PROTO": "tcp", "PAM_AUDIT_FORWARD_CA": "/ca.pem"}, "PAM_AUDIT_FORWARD_CA requires"},
		{"negative max sessions", map[string]string{"PAM_MAX_SESSIONS_PER_USER": "-1"}, "PAM_MAX_SESSIONS_PER_USER"},
		{"negative broker rate", map[string]string{"PAM_BROKER_RATE_PER_MIN": "-1"}, "PAM_BROKER_RATE_PER_MIN"},
		{"token exchange without jwks", map[string]string{"PAM_BROKER_TOKEN_EXCHANGE": "true"}, "PAM_BROKER_TOKEN_EXCHANGE needs PAM_BROKER_TRUST_DOMAIN_JWKS"},
		{"jwks without domain and audience", map[string]string{"PAM_BROKER_TRUST_DOMAIN_JWKS": "/jwks.json"}, "PAM_BROKER_TRUST_DOMAIN and PAM_BROKER_AUDIENCE"},
		{"inverted business hours", map[string]string{"PAM_ANALYTICS_BUSINESS_START": "18", "PAM_ANALYTICS_BUSINESS_END": "9"}, "PAM_ANALYTICS_BUSINESS_START/_END"},
		{"zsp cert ttl too short", map[string]string{"PAM_SSH_CA_KEY": "/data/ca", "PAM_SSH_CERT_TTL_MIN": "0"}, "PAM_SSH_CERT_TTL_MIN must be >= 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setRequired(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("Load() succeeded; want an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load() error = %q; want it to contain %q", err.Error(), c.want)
			}
		})
	}
}

// TestLoadAcceptsRichValidConfig is the positive guard: a configuration that
// exercises the enums and bounds at non-default values, and turns on the
// enable-gated blocks (audit forwarding, the SVID token-exchange chain), must
// pass. It catches a validation rule that has started false-rejecting a valid
// setting — the failure mode a purely negative test cannot see.
func TestLoadAcceptsRichValidConfig(t *testing.T) {
	setRequired(t)
	for k, v := range map[string]string{
		"PAM_SSH_SFTP":                   "readonly",
		"PAM_SSH_SFTP_CAPTURE":           "all",
		"PAM_SSH_SFTP_CAPTURE_MAX_MB":    "1024",
		"PAM_RDP_CLIPBOARD":              "readonly",
		"PAM_RDP_CLIPBOARD_AUDIT":        "full",
		"PAM_ANALYTICS_BASELINE_DAYS":    "30",
		"PAM_ANALYTICS_BUSINESS_START":   "8",
		"PAM_ANALYTICS_BUSINESS_END":     "18",
		"PAM_ANALYTICS_TIMEZONE":         "Europe/Madrid",
		"PAM_CERT_REMIND_DAYS":           "14",
		"PAM_CONJUR_REFRESH_MIN":         "60",
		"PAM_RECORDING_RETENTION_DAYS":   "90",
		"PAM_AUDIT_RETENTION_DAYS":       "365",
		"PAM_RETENTION_INTERVAL_HOURS":   "24",
		"PAM_MAX_SESSIONS_PER_USER":      "5",
		"PAM_MAX_SESSIONS_TOTAL":         "50",
		"PAM_BROKER_RATE_PER_MIN":        "60",
		"PAM_AUDIT_FORWARD_ADDR":         "siem.example:6514",
		"PAM_AUDIT_FORWARD_PROTO":        "tls",
		"PAM_AUDIT_FORWARD_FORMAT":       "cef",
		"PAM_AUDIT_FORWARD_CA":           "/etc/pam/siem-ca.pem",
		"PAM_AUDIT_FORWARD_INTERVAL_SEC": "10",
		"PAM_SSH_CA_KEY":                 "/data/ca",
		"PAM_SSH_CERT_TTL_MIN":           "15",
	} {
		t.Setenv(k, v)
	}
	if _, err := Load(); err != nil {
		t.Fatalf("Load() rejected a valid rich config: %v", err)
	}
}
