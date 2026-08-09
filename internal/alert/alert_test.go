package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWebhookNotify verifies the webhook delivers the event as JSON to its URL.
func TestWebhookNotify(t *testing.T) {
	got := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &e)
		got <- e
	}))
	defer srv.Close()

	NewWebhook(srv.URL).Notify(context.Background(), Event{
		Type: "breakglass.access", Actor: "break-glass", Detail: "GET /api/targets", Time: time.Unix(1, 0),
	})

	select {
	case e := <-got:
		if e.Type != "breakglass.access" || e.Actor != "break-glass" {
			t.Fatalf("unexpected alert: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not called")
	}
}

// TestWebhookSerializesTimeInUTC proves the webhook JSON carries the timestamp
// in UTC even when the caller stamped it in another zone — so a SIEM receiving
// webhook alerts sees the same zone the syslog and email channels force, no
// matter which caller fired the alert.
func TestWebhookSerializesTimeInUTC(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- string(body)
	}))
	defer srv.Close()

	// A fixed instant in a deliberately non-UTC zone (+05:30). Marshalled raw it
	// would serialize with a "+05:30" offset; the fix must render it as "…Z".
	loc := time.FixedZone("IST", 5*3600+1800)
	NewWebhook(srv.URL).Notify(context.Background(), Event{
		Type: "breakglass.access", Actor: "x", Time: time.Unix(1, 0).In(loc),
	})

	select {
	case body := <-got:
		if !strings.Contains(body, `"time":"1970-01-01T00:00:01Z"`) {
			t.Fatalf("time not serialized in UTC: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not called")
	}
}

// TestNoop verifies the Noop notifier neither panics nor blocks.
func TestNoop(t *testing.T) {
	// Must not panic or block.
	Noop{}.Notify(context.Background(), Event{Type: "x"})
}
