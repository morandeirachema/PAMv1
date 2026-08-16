package api_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestFileAttachmentSecretRoundTrip proves the Phase 145 "file" secret type
// all the way through: created like any other secret, vaulted the same way,
// and revealed back byte-for-byte — a file-attachment secret is not a
// special case anywhere in the encrypt/decrypt path, only in what is allowed
// to hold it and how large it may be.
func TestFileAttachmentSecretRoundTrip(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{CredentialFileMaxKB: 64})

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-file", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))

	content := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nfake cert bytes\n-----END CERTIFICATE-----"))
	code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "tls-cert", "secret_type": "file", "secret": content,
	})
	if code != http.StatusCreated {
		t.Fatalf("create file credential: %d %s", code, data)
	}
	m := jsonMap(t, data)
	if m["secret_type"] != "file" {
		t.Fatalf("secret_type = %v, want file", m["secret_type"])
	}
	cid := int64(m["id"].(float64))

	code, data = do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("reveal: %d %s", code, data)
	}
	revealed := jsonMap(t, data)
	if revealed["secret"] != content {
		t.Fatalf("revealed secret does not match what was uploaded:\n got  %q\n want %q", revealed["secret"], content)
	}
	if revealed["secret_type"] != "file" {
		t.Fatalf("revealed secret_type = %v, want file", revealed["secret_type"])
	}
}

// TestFileAttachmentSecretCapRefused proves an over-cap file secret is
// refused outright — never truncated, never stored — matching the SFTP
// capture byte cap's hard-refuse posture (Phase 145).
func TestFileAttachmentSecretCapRefused(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{CredentialFileMaxKB: 1}) // 1 KB cap

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-file-big", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))

	oversized := strings.Repeat("A", 2048) // 2 KB > the 1 KB cap
	code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "too-big", "secret_type": "file", "secret": oversized,
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("over-cap file secret: got %d, want 422: %s", code, data)
	}
	if !strings.Contains(string(data), "PAM_CREDENTIAL_FILE_MAX_KB") {
		t.Fatalf("422 body should name the config knob: %s", data)
	}

	// Nothing was created — the refusal happens before any store write.
	code, data = do(t, srv, http.MethodGet, "/api/credentials?target_id="+itoa(tid), testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list credentials: %d %s", code, data)
	}
	if !strings.Contains(string(data), "[]") {
		t.Fatalf("an over-cap create must not leave a credential behind: %s", data)
	}
}
