package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A generic webhook can answer one question: does this ticket exist and is it
// acceptable? That is less than an ITSM gate needs, and the shortfall is not
// cosmetic — until Phase 84 the payload carried only the ticket number, so the
// gate could prove a ticket was valid but never that it was YOURS. Anyone who
// knew a colleague's change number passed it.
//
// A Provider answers the question the control is actually for: is this ticket a
// warrant for THIS person, RIGHT NOW? Three checks, and each one closes a
// standard audit finding:
//
//   - **state** — a closed, cancelled or draft change is not authorisation;
//   - **window** — access outside the approved start/end is the classic finding,
//     and a ticket that was valid last Tuesday says nothing about today;
//   - **person** — the ticket must name the operator, or the number is a
//     password that everyone in the change queue knows.

// Provider checks a ticket against a live ITSM system.
type Provider interface {
	// Check returns nil when ticket authorises actor at time now, or an error
	// describing precisely which condition failed — the operator needs to know
	// whether to wait for their window, get the change approved, or ask to be
	// added to it.
	Check(ctx context.Context, ticket, actor string, now time.Time) error
	// Name identifies the provider in errors and audit details.
	Name() string
}

// ProviderConfig is the wiring shared by the first-class connectors.
type ProviderConfig struct {
	// BaseURL is the ITSM instance root, e.g. https://acme.service-now.com or
	// https://acme.atlassian.net.
	BaseURL string
	// User and Token authenticate over HTTP basic: a ServiceNow integration user
	// and password, or a Jira account email and API token.
	User, Token string
	// AllowedStates is the set of states that authorise access. Empty means the
	// provider's default, which is deliberately narrow.
	AllowedStates []string
	// ActorFields are the ticket fields that may name the operator. Empty means
	// the provider's default.
	ActorFields []string
	// RequireWindow enforces the planned start/end window when the ticket
	// carries one.
	RequireWindow bool
	// BindActor requires the ticket to name the operator. Defaults on: a ticket
	// gate that does not bind the person is a shared password.
	BindActor bool
	// HTTP is the client to use; nil gets a sane default.
	HTTP *http.Client
}

// httpClient returns the configured client or a bounded default. The timeout is
// short on purpose: this call sits in the path of a connection an operator is
// waiting on, and an ITSM system that has stopped answering must fail the gate
// rather than hang the session.
func (c ProviderConfig) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 8 * time.Second}
}

// getJSON performs an authenticated GET and decodes the JSON body into out.
func (c ProviderConfig) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if c.User != "" || c.Token != "" {
		req.SetBasicAuth(c.User, c.Token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("ITSM request failed: %w", err)
	}
	defer resp.Body.Close()
	// Bounded read: an ITSM system is not a trusted source of unlimited bytes,
	// and this runs on the connect path.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading the ITSM response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return errTicketNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ITSM returned status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding the ITSM response: %w", err)
	}
	return nil
}

// errTicketNotFound is returned when the ITSM system does not know the ticket.
var errTicketNotFound = fmt.Errorf("no such ticket")

// matchesActor reports whether any of the named fields identifies actor.
//
// The comparison is case-insensitive and also accepts the local part of an email
// address, because the same human is `alice` in PAMv1, `alice@acme.com` in Jira
// and "Alice Smith" in a ServiceNow display value. Being strict here would make
// the control unusable and it would be turned off, which protects nobody — so
// the matching is deliberately forgiving and the *field list* is what an operator
// tightens.
func matchesActor(actor string, fields map[string]string, want []string) (matched string, ok bool) {
	a := strings.ToLower(strings.TrimSpace(actor))
	if a == "" {
		return "", false
	}
	for _, f := range want {
		v := strings.ToLower(strings.TrimSpace(fields[f]))
		if v == "" {
			continue
		}
		if v == a || strings.TrimSuffix(local(v), "") == a || local(v) == a {
			return f, true
		}
	}
	return "", false
}

// local returns the part of an email address before the @, or the string itself.
func local(s string) string {
	if i := strings.Index(s, "@"); i > 0 {
		return s[:i]
	}
	return s
}

// stateAllowed reports whether state is in allowed, case-insensitively.
func stateAllowed(state string, allowed []string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ServiceNow
// ---------------------------------------------------------------------------

// ServiceNow checks a change request through the ServiceNow Table API.
type ServiceNow struct{ cfg ProviderConfig }

// NewServiceNow builds a ServiceNow provider, applying the defaults.
//
// The default state set is `implement` and `scheduled` — a change that is
// approved and in flight. `new`, `assess` and `authorize` are deliberately out:
// a change still being reviewed is not permission to touch production, and
// `closed`/`cancelled` obviously are not either.
func NewServiceNow(cfg ProviderConfig) *ServiceNow {
	if len(cfg.AllowedStates) == 0 {
		cfg.AllowedStates = []string{"implement", "scheduled"}
	}
	if len(cfg.ActorFields) == 0 {
		cfg.ActorFields = []string{"assigned_to", "requested_by"}
	}
	return &ServiceNow{cfg: cfg}
}

// Name identifies the provider.
func (s *ServiceNow) Name() string { return "servicenow" }

// snResponse is the Table API's envelope. Requesting display values makes every
// field a string, which is what keeps this readable — the raw form returns
// reference fields as {link, value} objects holding sys_ids that mean nothing to
// an operator reading an audit line.
type snResponse struct {
	Result []map[string]string `json:"result"`
}

// Check looks the change request up by number and applies state, window and
// person.
func (s *ServiceNow) Check(ctx context.Context, ticket, actor string, now time.Time) error {
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/api/now/table/change_request?" + url.Values{
		"sysparm_query":         {"number=" + ticket},
		"sysparm_display_value": {"true"},
		"sysparm_limit":         {"1"},
		"sysparm_fields":        {"number,state,start_date,end_date,assigned_to,requested_by,short_description"},
	}.Encode()
	var out snResponse
	if err := s.cfg.getJSON(ctx, endpoint, &out); err != nil {
		return err
	}
	if len(out.Result) == 0 {
		return errTicketNotFound
	}
	rec := out.Result[0]

	if !stateAllowed(rec["state"], s.cfg.AllowedStates) {
		return fmt.Errorf("change %s is in state %q, which does not authorise access (allowed: %s)",
			ticket, rec["state"], strings.Join(s.cfg.AllowedStates, ", "))
	}
	if s.cfg.RequireWindow {
		if err := withinWindow(rec["start_date"], rec["end_date"], now); err != nil {
			return fmt.Errorf("change %s: %w", ticket, err)
		}
	}
	if s.cfg.BindActor {
		if _, ok := matchesActor(actor, rec, s.cfg.ActorFields); !ok {
			return fmt.Errorf("change %s does not name %q in %s — a ticket somebody else owns is not your authorisation",
				ticket, actor, strings.Join(s.cfg.ActorFields, "/"))
		}
	}
	return nil
}

// snTimeLayouts are the formats ServiceNow renders date-times in. The display
// value is instance-localised, so both the API form and the common display form
// are accepted.
var snTimeLayouts = []string{"2006-01-02 15:04:05", time.RFC3339, "02/01/2006 15:04:05", "2006-01-02T15:04:05"}

// withinWindow enforces a planned change window. An unparsable or absent bound
// is treated as "no bound on that side" rather than as a failure: a change with
// no end date is open-ended, and refusing it would break a legitimate standard
// change. A bound that IS present and IS parsable is enforced strictly.
func withinWindow(start, end string, now time.Time) error {
	if t, ok := parseSNTime(start); ok && now.Before(t) {
		return fmt.Errorf("its window has not opened yet (starts %s)", t.UTC().Format(time.RFC3339))
	}
	if t, ok := parseSNTime(end); ok && now.After(t) {
		return fmt.Errorf("its window closed at %s", t.UTC().Format(time.RFC3339))
	}
	return nil
}

// parseSNTime tries each known layout, in UTC.
func parseSNTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range snTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// Jira
// ---------------------------------------------------------------------------

// Jira checks an issue through the Jira Cloud REST API.
type Jira struct{ cfg ProviderConfig }

// NewJira builds a Jira provider, applying the defaults.
//
// The default state set is `in progress`, because that is the status a change
// being executed sits in. `to do` and `done` are out for the same reason
// ServiceNow's `new` and `closed` are.
func NewJira(cfg ProviderConfig) *Jira {
	if len(cfg.AllowedStates) == 0 {
		cfg.AllowedStates = []string{"in progress"}
	}
	if len(cfg.ActorFields) == 0 {
		cfg.ActorFields = []string{"assignee", "reporter"}
	}
	return &Jira{cfg: cfg}
}

// Name identifies the provider.
func (j *Jira) Name() string { return "jira" }

// jiraIssue is the subset of the issue representation this gate reads.
type jiraIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Status   struct{ Name string } `json:"status"`
		Assignee *jiraUser             `json:"assignee"`
		Reporter *jiraUser             `json:"reporter"`
		DueDate  string                `json:"duedate"`
	} `json:"fields"`
}

// jiraUser is the identity shape Jira returns for people fields.
type jiraUser struct {
	AccountID    string `json:"accountId"`
	EmailAddress string `json:"emailAddress"`
	DisplayName  string `json:"displayName"`
	Name         string `json:"name"`
}

// id returns the most useful identifier available for matching.
func (u *jiraUser) id() string {
	if u == nil {
		return ""
	}
	for _, s := range []string{u.EmailAddress, u.Name, u.DisplayName} {
		if s != "" {
			return s
		}
	}
	return ""
}

// Check looks the issue up by key and applies status and person.
//
// There is no window check: a Jira issue has no planned start/end the way a
// ServiceNow change does, and inventing one from `duedate` would be a control
// that looks like a window and is not.
func (j *Jira) Check(ctx context.Context, ticket, actor string, _ time.Time) error {
	endpoint := strings.TrimRight(j.cfg.BaseURL, "/") + "/rest/api/3/issue/" + url.PathEscape(ticket) +
		"?fields=status,assignee,reporter,duedate"
	var issue jiraIssue
	if err := j.cfg.getJSON(ctx, endpoint, &issue); err != nil {
		return err
	}
	if !stateAllowed(issue.Fields.Status.Name, j.cfg.AllowedStates) {
		return fmt.Errorf("issue %s is in status %q, which does not authorise access (allowed: %s)",
			ticket, issue.Fields.Status.Name, strings.Join(j.cfg.AllowedStates, ", "))
	}
	if j.cfg.BindActor {
		fields := map[string]string{
			"assignee": issue.Fields.Assignee.id(),
			"reporter": issue.Fields.Reporter.id(),
		}
		if _, ok := matchesActor(actor, fields, j.cfg.ActorFields); !ok {
			return fmt.Errorf("issue %s does not name %q in %s — a ticket somebody else owns is not your authorisation",
				ticket, actor, strings.Join(j.cfg.ActorFields, "/"))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

// Webhook is the provider-agnostic escape hatch: any endpoint that answers 2xx
// for an acceptable ticket. It ships for ITSM systems there is no connector for.
type Webhook struct {
	url  string
	http *http.Client
}

// NewWebhook builds the generic provider.
func NewWebhook(endpoint string, client *http.Client) *Webhook {
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	return &Webhook{url: endpoint, http: client}
}

// Name identifies the provider.
func (w *Webhook) Name() string { return "webhook" }

// Check posts the ticket AND the actor, and treats 2xx as authorisation.
//
// The actor is the Phase 84 addition and the reason the payload changed: the
// endpoint could previously only answer "is this ticket valid", never "is it
// valid FOR THIS PERSON", so a valid change number admitted anyone who knew it.
// Adding a field is backward compatible — an existing endpoint that ignores it
// behaves exactly as before, and one that wants to bind the person now can.
func (w *Webhook) Check(ctx context.Context, ticket, actor string, _ time.Time) error {
	body, err := json.Marshal(map[string]string{"ticket": ticket, "actor": actor})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("ticket validation request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ticket %q was rejected by the ITSM system (status %d)", ticket, resp.StatusCode)
	}
	return nil
}
