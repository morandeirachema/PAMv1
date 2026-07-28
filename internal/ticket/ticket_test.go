package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidatorWebhook covers the webhook leg of the gate in all three
// outcomes, and above all that an UNREACHABLE ITSM denies. The control's
// promise is "no privileged access without a validated ticket"; an ITSM outage
// that silently waved requests through would invert it, so the transport-error
// branch must fail closed — the code says it does, and until now nothing
// proved it.
func TestValidatorWebhook(t *testing.T) {
	t.Run("2xx accepts", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		v, err := New("", srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Validate(context.Background(), "CHG1234"); err != nil {
			t.Fatalf("valid ticket rejected: %v", err)
		}
	})
	t.Run("non-2xx denies", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)
		v, err := New("", srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Validate(context.Background(), "CHG1234"); err == nil {
			t.Fatal("ITSM said 403 and the gate still accepted")
		}
	})
	t.Run("unreachable ITSM denies (fail closed)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // the webhook is now a dead endpoint — connection refused
		v, err := New("", url)
		if err != nil {
			t.Fatal(err)
		}
		err = v.Validate(context.Background(), "CHG1234")
		if err == nil {
			t.Fatal("unreachable ITSM and the gate still accepted — fails open")
		}
		if !strings.Contains(err.Error(), "ticket validation request failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestValidatorPatternAndDisabled covers the no-webhook paths: disabled (nil),
// fail-loud on a bad pattern, nil accepts anything, and a pattern rejects.
func TestValidatorPatternAndDisabled(t *testing.T) {
	// Neither pattern nor webhook → disabled (nil, nil).
	v, err := New("", "")
	if err != nil || v != nil {
		t.Fatalf("disabled: got %v, %v; want nil, nil", v, err)
	}
	// A nil validator accepts any ticket.
	if err := v.Validate(context.Background(), "whatever"); err != nil {
		t.Fatalf("nil validator must accept: %v", err)
	}
	if v.Enabled() {
		t.Fatal("nil validator must report Enabled()=false")
	}

	// A malformed pattern is fail-loud.
	if _, err := New("(", ""); err == nil {
		t.Fatal("bad pattern must error")
	}

	// A pattern gates the format (no webhook configured).
	pv, err := New(`^CHG[0-9]{3,}$`, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := pv.Validate(context.Background(), "CHG1234"); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}
	if err := pv.Validate(context.Background(), "nope"); err == nil {
		t.Fatal("format-mismatched ticket must be rejected")
	}
}
