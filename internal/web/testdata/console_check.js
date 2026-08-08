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
    const measured = row.replace(/<td class="detail">[\s\S]*?<\/td>/g, "");
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
