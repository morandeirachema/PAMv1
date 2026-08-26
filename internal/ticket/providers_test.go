package ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These tests run against in-process fakes rather than a live ITSM, the same way
// internal/conjur does. That covers the logic that decides access — state,
// window, person — which is the part that can be wrong in a way nobody notices.
// What it cannot cover is whether a real ServiceNow instance returns the fields
// in the shape assumed here; that needs an account, and is catalogued in
// docs/EXTERNAL-INFRA-GAPS.md rather than asserted.

const testNow = "2026-08-08T12:00:00Z"

// at parses the fixed clock these tests reason against.
func at(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// fakeServiceNow serves one change record from the Table API, and asserts the
// request is authenticated — a connector that forgets its credentials would
// otherwise pass every test against a fake that does not care.
func fakeServiceNow(t *testing.T, rec map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "svc" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.Path, "/api/now/table/change_request") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query().Get("sysparm_query")
		if rec == nil || !strings.Contains(q, "number="+rec["number"]) {
			_ = json.NewEncoder(w).Encode(snResponse{Result: nil})
			return
		}
		_ = json.NewEncoder(w).Encode(snResponse{Result: []map[string]string{rec}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// snProvider builds a ServiceNow connector against the fake.
func snProvider(t *testing.T, rec map[string]string, mutate func(*ProviderConfig)) *ServiceNow {
	t.Helper()
	srv := fakeServiceNow(t, rec)
	cfg := ProviderConfig{BaseURL: srv.URL, User: "svc", Token: "secret", BindActor: true, RequireWindow: true}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewServiceNow(cfg)
}

// openChange is a change that authorises alice right now.
func openChange() map[string]string {
	return map[string]string{
		"number": "CHG0012345", "state": "Implement",
		"start_date": "2026-08-08 09:00:00", "end_date": "2026-08-08 17:00:00",
		"assigned_to": "alice", "requested_by": "bob",
	}
}

func TestServiceNowAcceptsAnOpenChangeAssignedToTheOperator(t *testing.T) {
	p := snProvider(t, openChange(), nil)
	if err := p.Check(context.Background(), "CHG0012345", "alice", at(t, testNow)); err != nil {
		t.Fatalf("a valid, in-window change assigned to the operator was refused: %v", err)
	}
}

// TestServiceNowRefusesAnotherPersonsChange is the check the generic webhook
// could not express, and the reason this connector exists: before Phase 84 a
// valid change number admitted anyone who knew it.
func TestServiceNowRefusesAnotherPersonsChange(t *testing.T) {
	p := snProvider(t, openChange(), nil)
	err := p.Check(context.Background(), "CHG0012345", "mallory", at(t, testNow))
	if err == nil {
		t.Fatal("a change naming someone else authorised mallory")
	}
	if !strings.Contains(err.Error(), "does not name") {
		t.Fatalf("unhelpful error: %v", err)
	}
	// ...and the requested_by field counts too, not only assigned_to.
	if err := p.Check(context.Background(), "CHG0012345", "bob", at(t, testNow)); err != nil {
		t.Fatalf("the requester was refused: %v", err)
	}
}

func TestServiceNowEnforcesStateAndWindow(t *testing.T) {
	cases := []struct {
		name, want string
		rec        func() map[string]string
		now        string
	}{
		{"closed change", "does not authorise", func() map[string]string {
			r := openChange()
			r["state"] = "Closed"
			return r
		}, testNow},
		{"still being assessed", "does not authorise", func() map[string]string {
			r := openChange()
			r["state"] = "Assess"
			return r
		}, testNow},
		{"before the window opens", "has not opened", openChange, "2026-08-08T08:00:00Z"},
		{"after the window closes", "window closed", openChange, "2026-08-08T18:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := snProvider(t, tc.rec(), nil)
			err := p.Check(context.Background(), "CHG0012345", "alice", at(t, tc.now))
			if err == nil {
				t.Fatal("access was authorised when it should not have been")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the refusal (want %q)", err, tc.want)
			}
		})
	}
}

// TestServiceNowWindowCanBeDisabled keeps the strict default honest: it is a
// default, not a hard rule, because a standard change may legitimately have no
// window.
func TestServiceNowWindowCanBeDisabled(t *testing.T) {
	p := snProvider(t, openChange(), func(c *ProviderConfig) { c.RequireWindow = false })
	if err := p.Check(context.Background(), "CHG0012345", "alice", at(t, "2026-08-09T23:00:00Z")); err != nil {
		t.Fatalf("window enforcement was off and the gate still refused: %v", err)
	}
}

// TestServiceNowOpenEndedWindowIsAllowed: a change with no end date is
// open-ended. Refusing it would break standard changes, so an absent bound is
// "no bound", while a bound that IS present is enforced strictly.
func TestServiceNowOpenEndedWindowIsAllowed(t *testing.T) {
	rec := openChange()
	rec["end_date"] = ""
	p := snProvider(t, rec, nil)
	if err := p.Check(context.Background(), "CHG0012345", "alice", at(t, "2026-08-09T23:00:00Z")); err != nil {
		t.Fatalf("an open-ended change was refused: %v", err)
	}
}

func TestServiceNowUnknownTicketIsRefused(t *testing.T) {
	p := snProvider(t, openChange(), nil)
	if err := p.Check(context.Background(), "CHG9999999", "alice", at(t, testNow)); err == nil {
		t.Fatal("a ticket ServiceNow does not know was accepted")
	}
}

// TestServiceNowBadCredentialsFailClosed proves the fake's auth assertion is
// load-bearing: a connector that forgot to authenticate must not pass.
func TestServiceNowBadCredentialsFailClosed(t *testing.T) {
	p := snProvider(t, openChange(), func(c *ProviderConfig) { c.User, c.Token = "svc", "wrong" })
	if err := p.Check(context.Background(), "CHG0012345", "alice", at(t, testNow)); err == nil {
		t.Fatal("an unauthenticated ITSM lookup authorised access")
	}
}

// --- Jira -------------------------------------------------------------------

// fakeJira serves one issue.
func fakeJira(t *testing.T, key, status, assignee, reporter string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/rest/api/3/issue/"+key) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var issue jiraIssue
		issue.Key = key
		issue.Fields.Status.Name = status
		if assignee != "" {
			issue.Fields.Assignee = &jiraUser{EmailAddress: assignee}
		}
		if reporter != "" {
			issue.Fields.Reporter = &jiraUser{EmailAddress: reporter}
		}
		_ = json.NewEncoder(w).Encode(issue)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestJiraAcceptsAnInProgressIssueAssignedToTheOperator(t *testing.T) {
	srv := fakeJira(t, "OPS-42", "In Progress", "alice@acme.com", "bob@acme.com")
	p := NewJira(ProviderConfig{BaseURL: srv.URL, User: "e@acme.com", Token: "t", BindActor: true})
	// The operator is `alice` in PAMv1 and alice@acme.com in Jira: matching on
	// the local part is what keeps the control usable rather than turned off.
	if err := p.Check(context.Background(), "OPS-42", "alice", at(t, testNow)); err != nil {
		t.Fatalf("an in-progress issue assigned to the operator was refused: %v", err)
	}
}

func TestJiraRefusesWrongStatusAndWrongPerson(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		srv := fakeJira(t, "OPS-42", "Done", "alice@acme.com", "")
		p := NewJira(ProviderConfig{BaseURL: srv.URL, User: "e", Token: "t", BindActor: true})
		if err := p.Check(context.Background(), "OPS-42", "alice", at(t, testNow)); err == nil {
			t.Fatal("a Done issue authorised access")
		}
	})
	t.Run("person", func(t *testing.T) {
		srv := fakeJira(t, "OPS-42", "In Progress", "alice@acme.com", "bob@acme.com")
		p := NewJira(ProviderConfig{BaseURL: srv.URL, User: "e", Token: "t", BindActor: true})
		if err := p.Check(context.Background(), "OPS-42", "mallory", at(t, testNow)); err == nil {
			t.Fatal("an issue naming someone else authorised mallory")
		}
	})
}

func TestJiraUnknownIssueIsRefused(t *testing.T) {
	srv := fakeJira(t, "OPS-42", "In Progress", "alice@acme.com", "")
	p := NewJira(ProviderConfig{BaseURL: srv.URL, User: "e", Token: "t", BindActor: true})
	if err := p.Check(context.Background(), "OPS-99", "alice", at(t, testNow)); err == nil {
		t.Fatal("an issue Jira does not know was accepted")
	}
}

// --- the webhook, which now carries the actor --------------------------------

// TestWebhookSendsTheActor pins the payload change. An endpoint that ignores the
// new field behaves exactly as before, which is what makes this backward
// compatible; one that wants to bind the person can now do so.
func TestWebhookSendsTheActor(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	if err := NewWebhook(srv.URL, nil).Check(context.Background(), "CHG1", "alice", at(t, testNow)); err != nil {
		t.Fatal(err)
	}
	if got["ticket"] != "CHG1" || got["actor"] != "alice" {
		t.Fatalf("payload = %v, want both the ticket and the actor", got)
	}
}

// TestValidatorPassesTheActorThrough proves the value reaches the provider from
// the Validator, not just from a direct Check call.
func TestValidatorPassesTheActorThrough(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = body["actor"]
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	v, err := New(`^CHG[0-9]+$`, NewWebhook(srv.URL, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Validate(context.Background(), "CHG7", "carol"); err != nil {
		t.Fatal(err)
	}
	if seen != "carol" {
		t.Fatalf("the provider saw actor %q, want carol", seen)
	}
	if v.Provider() != "webhook" {
		t.Fatalf("Provider() = %q", v.Provider())
	}
}
