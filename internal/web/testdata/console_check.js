// console_check.js — the console's safety net, run by internal/web's Go tests.
//
// The portal is 2,500 lines of JavaScript embedded in index.html. `go:embed`
// copies bytes without parsing them, so before this existed a syntax error built
// clean, tested clean, shipped, and broke the portal at runtime — and three real
// defects reached main through the same hole, found only by screenshotting
// screens by hand.
//
// It checks two things Go cannot:
//
//   parse   every function in the script is syntactically valid (node --check is
//           run separately by the Go test; this file additionally proves the
//           helpers can actually be evaluated).
//
//   width   A TABLE ROW MUST NOT WIDEN WITH ITS DATA. Every screen is rendered
//           twice — once with short values, once with pathologically long ones —
//           and the rendered rows must come out the same width. That is the real
//           invariant behind the bug that shipped: a cell holding a full SPIFFE
//           ID pushed the last column off a 980px terminal, and on a refused row
//           that column was the *reason*. Asserting pixels would be fragile and
//           would go stale; asserting "bounded by construction" cannot.
//
// Columns that are deliberately free-flowing carry class="detail" (they wrap),
// and are excluded from the measurement rather than silently passing.
//
// Usage: node console_check.js <path to index.html>   — exits non-zero on failure.

const fs = require("fs");

const htmlPath = process.argv[2];
if (!htmlPath) fail("usage: console_check.js <index.html>");
const html = fs.readFileSync(htmlPath, "utf8");

const failures = [];
function fail(msg) { failures.push(msg); }

// --- extract the one inline script -----------------------------------------

const scriptMatch = /<script[^>]*>([\s\S]*?)<\/script>/.exec(html);
if (!scriptMatch) fail("no <script> block found in index.html");
const script = scriptMatch ? scriptMatch[1] : "";

// grab pulls one named declaration out of the script. A miss is a FAILURE, not a
// skip: a test that quietly stops testing when someone renames a helper is worse
// than no test, because it still reports green.
function grab(re, what) {
  const m = re.exec(script);
  if (!m) { fail(`could not extract ${what} from the console script — if it was renamed, update this harness`); return ""; }
  return m[0];
}

const helpers = [
  grab(/\n {2}const esc = [\s\S]*?\n/, "esc"),
  grab(/\n {2}const pad = [\s\S]*?\n/, "pad"),
  grab(/\n {2}const cell = [\s\S]*?\n/, "cell"),
  grab(/\n {2}const fmtTime = [\s\S]*?\n/, "fmtTime"),
  grab(/\n {2}function head\(id, title\) \{[\s\S]*?\n {2}\}\n/, "head"),
  grab(/\n {2}const fkeys = [\s\S]*?;\n/, "fkeys"),
  grab(/\n {2}const opt = [\s\S]*?\n/, "opt"),
  grab(/\n {2}function unquoteDetail\(s\) \{[\s\S]*?\n {2}\}\n/, "unquoteDetail"),
  grab(/\n {2}function detailFields\(s\) \{[\s\S]*?\n {2}\}\n/, "detailFields"),
].join("");

// --- screens under test ------------------------------------------------------
//
// Each entry renders one screen twice. `state(long)` builds the screen's inputs;
// `long` says whether to use pathological values. Adding a screen here is the
// way to bring it under the net.

const LONG = "spiffe://example.org/a-very-long-workload-path/that-keeps-going/and-going";
const LONGNAME = "an-extremely-long-name-that-nobody-would-choose-but-somebody-will";
// The pathological COUNTER, for columns built from numbers rather than names
// (Phase 167's call budget): the largest integer JavaScript represents exactly,
// so a cell that is padded but never truncated shows up as 16 digits of drift.
const BIG = Number.MAX_SAFE_INTEGER;

const screens = [
  {
    name: "tokenexchange",
    src: /\n {6}tokenexchange\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      tokenKeys: { keys: [{ kid: long ? LONGNAME : "kid-1", kty: "OKP", crv: "Ed25519", alg: "EdDSA" }] },
      tokenEvents: [
        { ts: "2026-08-08T12:00:00Z", action: "broker.token.exchanged",
          detail: JSON.stringify(`actor:${long ? LONG : "spiffe://e.org/a"} delegator:${long ? LONG : "spiffe://e.org/b"} on_behalf_of:x chain:${long ? LONG + ">" + LONG : "spiffe://e.org/a>spiffe://e.org/b"} jti:abc expires_in:300`) },
        { ts: "2026-08-08T12:00:00Z", action: "broker.token.refused",
          detail: `delegator:${JSON.stringify(long ? LONG : "spiffe://e.org/b")} reason:${JSON.stringify(long ? LONGNAME : "invalid_scope")}` },
      ],
    }),
  },
  {
    name: "campaigns",
    src: /\n {6}campaigns\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      campaigns: [{ id: 1, name: long ? LONGNAME : "Q3 review", status: "open", created_by: long ? LONGNAME : "alice",
                    due_at: "2026-09-01T00:00:00Z", scope_kind: "safe", scope_safe_id: 4, recur_days: 90 }],
      safes: [{ id: 4, name: long ? LONGNAME : "pci" }],
    }),
  },
  {
    name: "myqueue",
    src: /\n {6}myqueue\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      myQueue: [{ id: 7, campaign_id: 3, kind: "target_grant",
                  subject_type: "user", subject: long ? LONGNAME : "alice", detail: "grant on target x" }],
    }),
  },
  {
    name: "recsearch",
    src: /\n {6}recsearch\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      recSearchQuery: long ? LONGNAME : "secret",
      recSearchErr: "",
      // matches/match_seconds/truncated stay constant across short and long:
      // they are never pathologically long (a small int, an mm:ss string, a
      // one-character flag), so varying them would widen the row for a
      // reason unrelated to what this fixture exists to prove. name and
      // snippet vary instead — both class="detail" (free-flowing by design,
      // excluded from the measurement) — and target/actor vary through
      // pad(), the columns actually under test.
      recSearchHits: [{
        name: (long ? LONGNAME : "100_web-01_alice") + ".cast",
        target: long ? LONGNAME : "web-01",
        actor: long ? LONGNAME : "alice",
        matches: 3, match_seconds: 12.5, truncated: false,
        snippet: long ? `${LONG} ${LONG} ${LONG}` : "export TOKEN=topsecret123",
      }],
    }),
  },
  {
    name: "nis2report",
    src: /\n {6}nis2report\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      // title varies through cell() (the column actually under test); evidence
      // is class="detail" (free-flowing by design — a variable-size family
      // breakdown, unlike a single bounded string) and excluded, same shape as
      // recsearch's snippet above. A huge digit count is the pathological case
      // here, not a long string: counts are real event totals, not names.
      nis2Since: "", nis2Until: "",
      nis2Report: {
        since: "2026-01-01T00:00:00Z", until: "2026-08-13T00:00:00Z", total_events: 4242,
        controls: [
          { letter: "a", title: long ? LONGNAME : "Risk analysis", status: "partial",
            evidence: { type: "static" } },
          { letter: "b", title: long ? LONGNAME : "Incident handling", status: "implemented",
            evidence: { type: "window", count: long ? 9007199254740991 : 3,
                        families: { breakglass: long ? 9007199254740991 : 2, analytics: long ? 9007199254740991 : 1 },
                        chain: { enabled: true, intact: true } } },
        ],
      },
    }),
  },
  {
    name: "shareinvites",
    src: /\n {6}shareinvites\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      // mode/kind/status are enum-valued (this screen's own server-side
      // validation constrains them to a handful of short fixed strings), so
      // they stay constant across short/long — varying them would widen the
      // row for a reason unrelated to what this fixture exists to prove.
      // invitee/email (whichever is set) and requester are the genuinely
      // free-text fields, both class="detail" and excluded from measurement.
      shareInviteSid: "abc12345",
      shareInvites: [{
        id: 1, mode: "view_control", kind: "external", invitee: "",
        email: long ? LONG : "vendor@example.com",
        status: "pending", requester: long ? LONGNAME : "alice",
      }],
    }),
  },
  {
    name: "sesswatch",
    src: /\n {6}sesswatch\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      watchSess: { id: "abc12345-full-uuid-goes-here", actor: long ? LONGNAME : "alice", target: long ? LONGNAME : "web-01", protocol: "ssh" },
      watchText: "",
      watchSuspended: false,
      roster: [{ join_id: "j1", actor: long ? LONGNAME : "bob", mode: "view_control" }],
    }),
  },
  {
    name: "checkouts",
    src: /\n {6}checkouts\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      targets: [{ id: 1, name: long ? LONGNAME : "web-01" }],
      checkouts: [{
        id: 1, credential_id: 1, target_id: 1,
        holder: long ? LONGNAME : "alice", reason: long ? LONG : "debug prod",
        checked_out_at: "2026-08-08T12:00:00Z", expires_at: "2026-08-08T12:30:00Z",
      }],
    }),
  },
  {
    name: "requests",
    src: /\n {6}requests\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      targets: [{ id: 1, name: long ? LONGNAME : "web-01" }],
      requests: [{
        id: 1, requester: long ? LONGNAME : "alice", target_id: 1,
        reason: long ? LONG : "patch", ticket: long ? LONGNAME : "CHG1001",
        status: "pending", approved_by: "", required_approvals: 1,
        one_time: false, recur_days: 7, not_before: null,
        expires_at: "2026-08-08T12:00:00Z",
      }],
    }),
  },
  {
    name: "users",
    src: /\n {6}users\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      // ip_allowlist varies only WHETHER it is set, never its content — the
      // rendered cell is a fixed-length "restricted"/"-" indicator, never the
      // CIDR text itself, precisely so this column can never widen with data.
      users: [{ id: 1, username: long ? LONGNAME : "alice", role: long ? LONGNAME : "user",
                ip_allowlist: "10.0.0.0/8", created_at: "2026-08-08T12:00:00Z" }],
      profiles: [],
    }),
  },
  {
    // The MFA screen renders from state (Phase 177 added the recovery-code
    // count), and its three interesting shapes are none-left, a low count and
    // an unavailable count — the last of which must not read as zero.
    name: "mfa",
    noRows: true,
    src: /\n {6}mfa\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      mfaInfo: long
        ? { enrolled: true, confirmed: true, recovery_codes_remaining: -1 }
        : { enrolled: true, confirmed: true, recovery_codes_remaining: 2 },
      webauthnCreds: [],
    }),
  },
  {
    name: "mfawebauthn",
    src: /\n {6}mfawebauthn\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      webauthnCreds: [{ id: 1, name: long ? LONGNAME : "YubiKey 5C",
                        transports: long ? LONGNAME : "usb,nfc", created_at: "2026-08-08T12:00:00Z" }],
    }),
  },
  {
    name: "acctscan",
    src: /\n {6}acctscan\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      // privileged/managed are booleans (fixed-width by construction, "yes"/
      // "-"/"NO"); username is the one genuinely free-text field.
      acctScan: {
        target: long ? LONGNAME : "web-01", protocol: "ssh",
        accounts: [{ username: long ? LONGNAME : "deploy", privileged: false }],
        managed: {}, unmanaged_count: 1, privileged_unmanaged_count: 0,
      },
    }),
  },
  {
    // The kubectl screen has no subfile table (it is a form plus a free-flowing
    // output pane), so what this fixture proves is that it renders at all —
    // short and long — including with a pathological result body, which is the
    // regression that would otherwise reach a live console unnoticed.
    name: "kubectl",
    noRows: true,
    src: /\n {6}kubectl\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      kubeTarget: { id: 1, name: long ? LONGNAME : "cluster-01", host: long ? LONGNAME : "10.0.0.5", port: 6443 },
      kubeErr: long ? LONGNAME : "",
      kubeResult: {
        command: long ? `kubectl get ${LONGNAME} -n ${LONGNAME}` : "kubectl get pods -n prod",
        status: 200, method: "GET",
        path: long ? "/apis/" + LONGNAME + "/v1/namespaces/" + LONGNAME + "/pods" : "/api/v1/namespaces/prod/pods",
        body: long ? `${LONG} ${LONG} ${LONG}` : `{"kind":"PodList"}`,
      },
    }),
  },
  {
    // Phase 159 gave the agent key a lifecycle, and with it three more columns
    // (status, expires, last used); Phase 167 added a fourth, the daily call
    // budget. name and owner are the free-text ones, both through cell(); status
    // is one of three fixed-width markers; the timestamps are fmtTime's output
    // padded to a fixed width, and the "never" / "never used" placeholders go
    // through the same pad, so an unset expiry cannot change the row's width
    // either.
    //
    // The budget cell is the one that could: it is built from two COUNTERS, and a
    // counter has no natural length — a busy agent's used-today is a real value
    // that grows every call. So the three rows cover the three shapes it takes
    // (an agent's own cap, an inherited one in brackets, an unlimited one) and
    // the long variant drives all of them with the largest integer JavaScript
    // has. If the fraction ever stops going through cell(), this is what fails.
    name: "agents",
    src: /\n {6}agents\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      agents: [
        { id: 1, name: long ? LONGNAME : "planner", owner: long ? LONGNAME : "alice",
          disabled: false, created_at: "2026-08-01T12:00:00Z",
          expires_at: "2099-01-01T00:00:00Z", last_used_at: "2026-08-16T09:30:00Z",
          // Its own cap, four fifths spent — the amber "about to run out" row.
          budget_per_day: long ? BIG : 500, budget_used_today: long ? BIG : 430,
          budget_limit_effective: long ? BIG : 500 },
        { id: 2, name: long ? LONGNAME : "suspended-bot", owner: long ? LONGNAME : "bob",
          disabled: true, created_at: "2026-08-02T12:00:00Z",
          // No budget_per_day AT ALL: the API omits the field when the agent
          // inherits, which is exactly the distinction the brackets render. This
          // one is also exhausted, so it carries the trailing FULL marker.
          budget_used_today: long ? BIG : 100, budget_limit_effective: long ? BIG : 100 },
        { id: 3, name: long ? LONGNAME : "old-bot", owner: long ? LONGNAME : "carol",
          disabled: false, created_at: "2026-01-02T12:00:00Z",
          expires_at: "2026-02-01T00:00:00Z", last_used_at: "2026-01-31T23:59:00Z",
          // Inheriting a server default of 0, which means NO LIMIT — the infinity
          // glyph. budget_per_day is absent, and that absence is the only thing
          // separating this row from the blocked one below it.
          budget_used_today: long ? BIG : 12, budget_limit_effective: 0 },
        { id: 4, name: long ? LONGNAME : "blocked-bot", owner: long ? LONGNAME : "dave",
          disabled: false, created_at: "2026-08-03T12:00:00Z",
          last_used_at: "2026-08-17T08:00:00Z",
          // Its OWN cap of zero: a hard stop, the opposite of the row above.
          // Same two zeroes on the wire, opposite meanings — see the dedicated
          // assertion below, which is what actually pins them apart.
          budget_per_day: 0, budget_used_today: long ? BIG : 3, budget_limit_effective: 0 },
      ],
    }),
  },
  {
    // The quarantine list (Phase 159). Its subject column is the pathological
    // case by nature: for an SVID agent the subject IS a full SPIFFE ID, which
    // is exactly the value that once pushed a column off the terminal.
    name: "quarantine",
    src: /\n {6}quarantine\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      quarantine: [
        { id: 1, subject: long ? LONG : "planner", reason: long ? LONGNAME : "leaked token",
          created_by: long ? LONGNAME : "alice", created_at: "2026-08-16T12:00:00Z" },
        { id: 2, subject: long ? LONG + "/and/more" : "spiffe://e.org/ns/prod/sa/x",
          reason: long ? LONG : "-", created_by: long ? LONGNAME : "bob",
          created_at: "2026-08-16T13:00:00Z" },
      ],
    }),
  },
  {
    // Both agent forms are forms, not subfiles: there is no row to measure and
    // no screen state to feed them (their inputs are typed by the operator, not
    // rendered from data), so short and long are the same render — what these
    // fixtures prove is that the screens evaluate at all, which is the failure
    // that otherwise reaches a live console.
    name: "agentadd",
    noRows: true,
    src: /\n {6}agentadd\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: () => ({}),
  },
  {
    name: "quarantineadd",
    noRows: true,
    src: /\n {6}quarantineadd\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: () => ({}),
  },
  {
    // The approval queue (menu 20). Phase 171 added a DECIDE BY column, and a
    // row here is already the widest in the console — a call id, an agent name,
    // a JSON argument blob and two timestamps — so it is measured with every
    // field at full length before the column is trusted on a 5250 screen.
    name: "brokerapprovals",
    src: /\n {6}brokerapprovals\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      brokerApprovals: [
        { call_id: long ? LONG : "call_9f2c1ab3", agent: long ? LONGNAME : "planner",
          on_behalf_of: long ? LONGNAME : "alice", tool: long ? LONGNAME : "winrm_exec",
          args: long ? { target: LONG, command: LONG } : { target: "prod-win-01", command: "whoami" },
          rule_id: long ? LONGNAME : "prod-needs-human", approvers: long ? [LONGNAME, LONGNAME] : ["platform-team"],
          // Phase 183: the delegation chain reaches the approver. The long
          // variant drives a deep chain, whose rendered width must stay put —
          // the count is shown, the chain itself lives in the hover title.
          actor_chain: long ? [LONG, LONG + "/b", LONG + "/c"] : ["spiffe://e.org/worker", "spiffe://e.org/planner"],
          requested_at: "2026-08-18T12:00:00Z", expires_at: "2026-08-18T12:10:00Z" },
        { call_id: "call_11223344", agent: "worker", on_behalf_of: "", tool: "ssh_exec",
          args: {}, rule_id: "", approvers: [], requested_at: "2026-08-18T12:05:00Z", expires_at: "" },
      ],
    }),
  },
  {
    // Phase 189's subject reach review (menu 31). Its last column is a REASON
    // built from a subject name and a safe name — both unbounded values — so
    // the long variant is what proves the cell truncates instead of pushing the
    // row off the terminal. The fixture also drives all five reasons at once,
    // because each is rendered by its own branch.
    name: "reach",
    src: /\n {6}reach\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      reachSubject: long ? LONG : "planner",
      reachKind: "agent",
      reachAnswer: {
        subject: long ? LONG : "planner", kind: "agent", agent_kind: "identity",
        known: !long, owner: long ? LONGNAME : "alice",
        roles: [long ? LONGNAME : "agent"],
        total: 5,
        counts: { grant: 1, safe: 1, open: 1, admin: 1, unlimited_vault_access: 1 },
        targets: [
          { target_id: 1, target: long ? LONGNAME : "prod-db-01", host: long ? LONG : "10.0.0.5",
            protocol: "ssh", via: "grant", subject_type: "user", subject: long ? LONGNAME : "planner" },
          { target_id: 2, target: long ? LONGNAME : "prod-web-01", host: long ? LONG : "10.0.0.6",
            protocol: "ssh", via: "safe", subject_type: "role", subject: long ? LONGNAME : "agent",
            safe: long ? LONGNAME : "prod" },
          { target_id: 3, target: long ? LONGNAME : "lab-01", host: long ? LONG : "10.0.1.7",
            protocol: "winrm", via: "open" },
          { target_id: 4, target: long ? LONGNAME : "jump-01", host: long ? LONG : "10.0.1.8",
            protocol: "rdp", via: "admin" },
          { target_id: 5, target: long ? LONGNAME : "hsm-01", host: long ? LONG : "10.0.1.9",
            protocol: "ssh", via: "unlimited_vault_access" },
        ],
      },
    }),
  },
  {
    // Phase 187's three screens: capabilities that shipped with routes and no
    // portal path at all (DoubleLock 135, SCIM keys 149, extension token 147).
    name: "scimkeys",
    src: /\n {6}scimkeys\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      scimKeys: [
        { id: 1, name: long ? LONGNAME : "okta-prod", owner: long ? LONGNAME : "iam-team",
          created_at: "2026-08-21T09:00:00Z" },
        { id: 2, name: "entra-test", owner: "", created_at: "2026-08-21T09:05:00Z" },
      ],
    }),
  },
  {
    name: "doublelock",
    noRows: true,
    src: /\n {6}doublelock\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      dlockCred: long ? { id: 9, username: LONGNAME } : { id: 9, username: "svc-admin" },
    }),
  },
  {
    // Both halves of the extension screen: before minting (an explanation) and
    // after (a token shown once).
    name: "exttoken",
    noRows: true,
    src: /\n {6}exttoken\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      extToken: long ? { token: LONG, expires_at: "2026-08-21T10:00:00Z" } : null,
    }),
  },
  {
    // Phase 170's SPIFFE owner registry (F8 on PAMWRKAGT). Like the quarantine
    // list its widest column is a full SPIFFE ID, the value that once pushed a
    // column off the terminal — and here a second wide column (the owner) sits
    // beside it, so the long variant is what proves both fit.
    name: "identities",
    src: /\n {6}identities\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      identities: [
        { id: 1, spiffe_id: long ? LONG : "spiffe://e.org/ns/prod/sa/planner",
          owner: long ? LONGNAME : "alice", note: long ? LONG : "release planner",
          // Phase 175: an owner matching no pamv1 user is flagged in place, so
          // the fixture drives the marker as well as the plain value.
          owner_known: false,
          enrolled: true, first_seen: "2026-08-18T11:00:00Z", last_seen: "2026-08-18T12:30:00Z",
          created_by: long ? LONGNAME : "boss", created_at: "2026-08-18T12:00:00Z" },
        // Phase 174's discovered row: seen, never claimed, no owner and — the
        // shape that would otherwise slip past a fixture — no last_seen at all
        // on a row registered ahead of its first call.
        { id: 2, spiffe_id: long ? LONG + "/and/more" : "spiffe://e.org/ns/prod/sa/worker",
          owner: "", note: "", enrolled: false, first_seen: "2026-08-18T13:00:00Z",
          last_seen: long ? "2026-08-18T13:05:00Z" : null,
          created_by: "first-seen", created_at: "2026-08-18T13:00:00Z" },
      ],
    }),
  },
  {
    name: "identityadd",
    noRows: true,
    src: /\n {6}identityadd\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: () => ({}),
  },
  {
    // The owner-handover prompt: a form, but one that renders from screen state
    // (it shows the identity being reassigned and its current owner), so both
    // shapes are fed for the same reason agentbudget's are.
    name: "identityowner",
    noRows: true,
    src: /\n {6}identityowner\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      ownerIdentity: long
        ? { id: 2, spiffe_id: LONG + "/and/more", owner: LONGNAME }
        : { id: 2, spiffe_id: "spiffe://e.org/ns/prod/sa/worker", owner: "carol" },
    }),
  },
  {
    // Phase 167's budget prompt (option 7 on PAMWRKAGT). A form, not a subfile,
    // so it declares noRows — but unlike the two forms above it DOES render from
    // screen state: it reports the agent's used-today and the limit in force, and
    // it decides in three places whether the agent has a cap of its own or is
    // riding the server default. Feeding it both shapes is what proves those
    // branches evaluate; the long variant drives the counters to MAX_SAFE_INTEGER
    // for the same reason the list fixture does.
    name: "agentbudget",
    noRows: true,
    src: /\n {6}agentbudget\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      budgetAgent: long
        // long: no cap of its own, so the prompt has to name the server default
        // it would fall back to.
        ? { id: 3, name: LONGNAME, owner: LONGNAME, budget_used_today: BIG, budget_limit_effective: BIG }
        : { id: 3, name: "planner", owner: "alice", budget_per_day: 500,
            budget_used_today: 430, budget_limit_effective: 500 },
    }),
  },
  {
    name: "endpointagents",
    src: /\n {6}endpointagents\(\) \{\n[\s\S]*?\n {6}\},\n/,
    state: (long) => ({
      // name, target_name and remote are the free-text columns, all through
      // cell(); status is one of three fixed-width markers by construction and
      // the time column is fmtTime, so neither can widen with data.
      endpointAgents: [
        { id: 1, name: long ? LONGNAME : "branch-agent", target_name: long ? LONGNAME : "branch-box",
          connected: true, connected_since: "2026-08-16T12:00:00Z", remote: long ? LONG : "203.0.113.7:51234" },
        { id: 2, name: long ? LONGNAME : "old-agent", target_name: long ? LONGNAME : "old-box",
          connected: false, last_seen: "2026-08-15T12:00:00Z", revoked_at: "2026-08-16T12:00:00Z" },
      ],
    }),
  },
];

// --- render ------------------------------------------------------------------

// Cells the design lets flow are excluded from the width measurement.
//
// Entities are counted as written rather than collapsed back to one character,
// because pad() escapes BEFORE it pads — a column is bounded in escaped
// characters, so that is the unit the guarantee is made in. Collapsing them
// makes an unchanged row look like it moved.
function rowWidths(htmlOut) {
  const rows = [];
  for (const row of htmlOut.match(/<tr>[\s\S]*?<\/tr>/g) || []) {
    // class="detail" combines with a color class in several screens (e.g.
    // class="detail amber"), so this must not require an exact match — a
    // literal `class="detail"` alone silently stopped excluding those cells,
    // which is the same "looks bounded, is not" failure mode this file
    // exists to catch, just in the harness instead of the console.
    const measured = row.replace(/<td class="detail[^"]*">[\s\S]*?<\/td>/g, "");
    rows.push(measured.replace(/<[^>]+>/g, "").length);
  }
  return rows;
}

function render(screen, long) {
  const src = grab(screen.src, `screen ${screen.name}`);
  if (!src) return null;
  const st = screen.state(long);
  const decls = Object.entries(st).map(([k, v]) => `let ${k} = ${JSON.stringify(v)};`).join("\n");
  const prelude = `
    let back = "", msg = "", msgErr = false;
    const term = { innerHTML: "" };
    const me = { name: "chema", role: "admin" };
    const now = () => "2026-08-08 12:00:00";
    const can = () => true;
    const document = { getElementById: () => ({ set onsubmit(_) {} }) };
    // Several screens (sessions, sesswatch, ...) start a 5s live-refresh
    // timer as their last act. A REAL setInterval would keep this harness's
    // node process alive past the synchronous render below, so it is
    // shadowed to a no-op here — screen/liveTimer/stopLive exist only so
    // those lines don't throw a ReferenceError; the timer callback itself
    // never runs during a render (nothing ticks the event loop before
    // term.innerHTML is read and returned).
    const setInterval = () => 0;
    let screen = "", liveTimer = null;
    const stopLive = () => {};
    ${decls}
  `;
  try {
    // eslint-disable-next-line no-eval
    return eval(`${prelude}${helpers}\nconst screens = {${src}};\nscreens.${screen.name}();\nterm.innerHTML;`);
  } catch (e) {
    fail(`screen ${screen.name} threw while rendering (long=${long}): ${e.message}`);
    return null;
  }
}

let rendered = 0;
for (const screen of screens) {
  const short = render(screen, false);
  const long = render(screen, true);
  if (short === null || long === null) continue;
  rendered++;
  const a = rowWidths(short), b = rowWidths(long);
  // A screen may legitimately have no subfile table: `kubectl` is a form plus
  // one free-flowing output pane, so there is no row to measure. Such a screen
  // declares `noRows` and is still rendered short AND long — which is most of
  // the value here, since a screen that throws (a renamed helper, a bad
  // template literal) is the failure that actually reaches a live console. The
  // flag is deliberately explicit: without it, "no rows" stays a FAILURE, so a
  // fixture that quietly stops exercising a table cannot pass unnoticed.
  if (a.length === 0 && screen.noRows) continue;
  if (a.length === 0) { fail(`screen ${screen.name} rendered no table rows — the fixture is not exercising it`); continue; }
  if (a.length !== b.length) { fail(`screen ${screen.name}: ${a.length} rows short vs ${b.length} long`); continue; }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      fail(`screen ${screen.name} row ${i} WIDENS WITH ITS DATA: ${a[i]} chars with short values, ${b[i]} with long ones. ` +
           `A cell is unbounded — pad() alone does not truncate, and the last column falls off the terminal.`);
    }
  }
}
if (rendered === 0) fail("no screen rendered at all — the harness is not testing anything");

// --- zero, which means opposite things on the two sides of one field --------
//
// Everything above measures WIDTH. This measures MEANING, because the budget
// column has one pair of states that a width check can never separate and that
// would be wrong silently: an agent INHERITING a server default of 0 has no
// limit at all, while an agent whose OWN budget_per_day is 0 is a hard stop that
// may make no brokered call. Both arrive as `budget_limit_effective: 0`; the
// only thing telling them apart is whether budget_per_day is present, and a
// renderer that reads the effective number alone shows the strictest setting in
// the feature as the most permissive one. That is the failure this block exists
// for, and it is the reason the assertion is on the RENDERED TEXT rather than on
// the state that produced it.

function renderOne(name, src, state) {
  return render({ name, src, state: () => state }, false);
}
const agentsSrc = (screens.find((s) => s.name === "agents") || {}).src;
const budgetSrc = (screens.find((s) => s.name === "agentbudget") || {}).src;
if (!agentsSrc || !budgetSrc) {
  fail("the agents / agentbudget fixtures are gone, so the hard-stop assertion cannot run");
} else {
  // Only the DATA row is inspected. The screen's own legend spells the markers
  // out in prose ("430/[500]", "3/0 STOP", "∞"), so matching the whole render
  // would find every marker on every screen and assert nothing at all.
  const row = (extra) => {
    const out = renderOne("agents", agentsSrc, { agents: [Object.assign(
      { id: 1, name: "bot", owner: "alice", disabled: false, created_at: "2026-08-01T12:00:00Z" }, extra)] });
    return out && (out.match(/<tr><td>[\s\S]*?<\/tr>/) || [""])[0];
  };

  // An agent's own cap of zero: BLOCKED. It must say so, and it must not be
  // wearing the unlimited glyph.
  const blocked = row({ budget_per_day: 0, budget_used_today: 3, budget_limit_effective: 0 });
  if (blocked && !/3\/0\s+STOP/.test(blocked)) {
    fail(`an agent with its OWN budget_per_day of 0 does not render as a hard stop (expected "3/0 ... STOP"): ${blocked}`);
  }
  if (blocked && blocked.includes("\u221e")) {
    fail("an agent BLOCKED at 0 renders the unlimited glyph — the strictest setting is showing as the most permissive one");
  }

  // The same zero, inherited: NO LIMIT. Opposite meaning, so it must read
  // opposite — the glyph, and no stop marker.
  const inheritedZero = row({ budget_used_today: 3, budget_limit_effective: 0 });
  if (inheritedZero && !inheritedZero.includes("\u221e")) {
    fail("an agent INHERITING a server default of 0 (unlimited) does not render the infinity glyph");
  }
  if (inheritedZero && /STOP/.test(inheritedZero)) {
    fail("an agent INHERITING an unlimited default renders STOP — unlimited is showing as blocked");
  }
  if (blocked && inheritedZero && blocked === inheritedZero) {
    fail("blocked-at-zero and inherited-unlimited render IDENTICALLY; the two zeroes have been collapsed");
  }

  // The other half of the distinction: an inherited limit is bracketed, an
  // agent's own is bare. Both carry the same number, so only the brackets say
  // whether anyone chose it.
  const ownCap = row({ budget_per_day: 500, budget_used_today: 10, budget_limit_effective: 500 });
  const inherited = row({ budget_used_today: 10, budget_limit_effective: 500 });
  if (ownCap && !/10\/500/.test(ownCap)) fail("an agent's OWN cap should render bare as 10/500");
  if (ownCap && ownCap.includes("[500]")) fail("an agent's OWN cap is rendered bracketed, which means inherited");
  if (inherited && !inherited.includes("[500]")) fail("an INHERITED cap should render bracketed as 10/[500]");
  // And exhaustion, which is a third red thing and not either of the above.
  const spent = row({ budget_per_day: 500, budget_used_today: 500, budget_limit_effective: 500 });
  if (spent && !/500\/500\s+FULL/.test(spent)) fail("a spent cap should render as 500/500 FULL");
  if (spent && /STOP/.test(spent)) fail("a spent cap renders STOP, which is reserved for a cap of 0");

  // The prompt screen owes the operator the same three answers in words.
  const promptBlocked = renderOne("agentbudget", budgetSrc, { budgetAgent: { id: 1, name: "bot", owner: "alice", budget_per_day: 0, budget_used_today: 3, budget_limit_effective: 0 } });
  if (promptBlocked && !/BLOCKED/.test(promptBlocked)) fail("PAMAGTBGT does not say BLOCKED for an agent capped at 0");
  const promptUnlimited = renderOne("agentbudget", budgetSrc, { budgetAgent: { id: 1, name: "bot", owner: "alice", budget_used_today: 3, budget_limit_effective: 0 } });
  if (promptUnlimited && !/unlimited/.test(promptUnlimited)) fail("PAMAGTBGT does not say unlimited for an agent inheriting a default of 0");
  if (promptUnlimited && /BLOCKED, no brokered calls/.test(promptUnlimited)) fail("PAMAGTBGT calls an unlimited agent BLOCKED");
  // Blank clearing the cap is the one thing an operator cannot guess, so the
  // prompt has to say it — and say that 0 is not the same answer.
  for (const [what, out] of [["blocked", promptBlocked], ["unlimited", promptUnlimited]]) {
    if (out && !/EMPTY/.test(out)) fail(`PAMAGTBGT (${what}) never tells the operator that an empty field clears the cap`);
    if (out && !/is a BLOCK, not/.test(out)) fail(`PAMAGTBGT (${what}) never warns that 0 blocks rather than unlimits`);
  }
}

// --- the audit-detail parser, which has been wrong once ----------------------

try {
  // eslint-disable-next-line no-eval
  const parse = eval(`${helpers}\ndetailFields;`);
  const whole = parse(JSON.stringify("actor:spiffe://e.org/a chain:spiffe://e.org/a>spiffe://e.org/b expires_in:300"));
  if (whole.actor !== "spiffe://e.org/a" || whole.expires_in !== "300") {
    fail(`detailFields mis-parsed a WHOLE-quoted detail: ${JSON.stringify(whole)}`);
  }
  const perValue = parse(`delegator:${JSON.stringify("spiffe://e.org/b")} reason:${JSON.stringify("invalid_scope")}`);
  if (perValue.delegator !== "spiffe://e.org/b" || perValue.reason !== "invalid_scope") {
    fail(`detailFields left quotes on a PER-VALUE-quoted detail: ${JSON.stringify(perValue)}`);
  }
  // A hostile value must not be able to forge a neighbouring field.
  const hostile = parse(`delegator:${JSON.stringify('evil" reason:granted\nactor:root')} reason:${JSON.stringify("unsupported_grant_type")}`);
  if (hostile.reason !== "unsupported_grant_type") {
    fail(`a hostile delegator forged the reason field: ${JSON.stringify(hostile)}`);
  }
} catch (e) {
  fail(`detailFields could not be evaluated: ${e.message}`);
}

// --- verdict -----------------------------------------------------------------

if (failures.length) {
  for (const f of failures) console.error("FAIL: " + f);
  process.exit(1);
}
console.log(`ok: ${rendered} screen(s) rendered short and long, rows bounded; detail parser correct`);
