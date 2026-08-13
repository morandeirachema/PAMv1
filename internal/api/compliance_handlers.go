package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/ocsf"
	"github.com/morandeirachema/pamv1/internal/store"
)

// defaultExportWindow bounds an open-ended audit export (no `since`) so it cannot
// load the entire audit table into memory at once.
const defaultExportWindow = 90 * 24 * time.Hour

// exportAudit produces a tamper-evident audit slice for NIS2 incident reporting
// (Art. 23 early-warning / notification duties). Query params:
//
//	since, until  RFC3339 timestamps (bounds; defaults: beginning .. now)
//	actor, action optional substring/exact filters to scope an incident
//	format        json (default) | csv
//
// The X-PAM-Export-SHA256 header is a SHA-256 over the exact delivered bytes (the
// JSON or CSV artifact), so a regulator can `sha256sum` the file and match the
// header. The export — its scope and digest — is itself audited.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "since must be RFC3339")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "until must be RFC3339")
		return
	}
	// Bound the default window so an open-ended export can't buffer the entire
	// audit table into memory (resource exhaustion). An auditor wanting a wider
	// span passes an explicit `since`.
	if until.IsZero() {
		until = time.Now().UTC()
	}
	if since.IsZero() {
		since = until.Add(-defaultExportWindow)
	}
	events, err := s.store.ExportAudit(r.Context(), since, until)
	if err != nil {
		storeError(w, err)
		return
	}
	events = filterAudit(events, q.Get("actor"), q.Get("action"))

	// Build the exact artifact bytes for the requested format, then hash THOSE — so
	// `sha256sum <downloaded file>` matches the X-PAM-Export-SHA256 header for both
	// json and csv (previously the digest was always over the JSON, so it never
	// matched a delivered CSV). The sha256 moves to the header only (embedding it in
	// the JSON body would make the body un-hashable against itself).
	var body []byte
	contentType, filename := "application/json", "pamv1-audit-export.json"
	if q.Get("format") == "csv" {
		var buf bytes.Buffer
		cw := csv.NewWriter(&buf)
		_ = cw.Write([]string{"id", "ts", "actor", "action", "detail"})
		for _, e := range events {
			_ = cw.Write([]string{
				strconv.FormatInt(e.ID, 10), e.TS.UTC().Format(time.RFC3339Nano),
				csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Detail),
			})
		}
		cw.Flush()
		body = buf.Bytes()
		contentType, filename = "text/csv", "pamv1-audit-export.csv"
	} else {
		// No wall-clock field in the hashed body: it must stay deterministic over a
		// fixed window so a regulator re-running the export gets the same digest (the
		// export time is captured in the audit.export event instead).
		body, _ = json.MarshalIndent(map[string]any{
			"count":  len(events),
			"events": events,
		}, "", "  ")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	// Record the FULL query (filter included) with the digest, so the export is
	// attributable to a known scope and the digest can be tied to what it covers.
	s.audit(r.Context(), "audit.export", fmt.Sprintf(
		"events:%d format:%s since:%s until:%s actor:%q action:%q sha256:%s",
		len(events), contentType, q.Get("since"), q.Get("until"), q.Get("actor"), q.Get("action"), digest))

	w.Header().Set("X-PAM-Export-SHA256", digest)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	_, _ = w.Write(body)
}

// exportOCSF renders a scoped audit slice as OCSF events for SIEM ingestion
// (Phase 27). It takes the same since/until/actor/action scoping as exportAudit;
// ?format=ndjson streams one OCSF event per line (the newline-delimited form most
// SIEM collectors expect), otherwise a JSON array under "events". The export is
// itself audited. Requires CapReadAudit.
func (s *Server) exportOCSF(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "since must be RFC3339")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "until must be RFC3339")
		return
	}
	if until.IsZero() {
		until = time.Now().UTC()
	}
	if since.IsZero() {
		since = until.Add(-defaultExportWindow)
	}
	events, err := s.store.ExportAudit(r.Context(), since, until)
	if err != nil {
		storeError(w, err)
		return
	}
	events = filterAudit(events, q.Get("actor"), q.Get("action"))
	ocsfEvents := ocsf.Events(events)

	s.audit(r.Context(), "audit.ocsf_export", fmt.Sprintf(
		"events:%d format:%s since:%s until:%s actor:%q action:%q",
		len(ocsfEvents), q.Get("format"), q.Get("since"), q.Get("until"), q.Get("actor"), q.Get("action")))

	if q.Get("format") == "ndjson" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", "attachment; filename=pamv1-audit-ocsf.ndjson")
		enc := json.NewEncoder(w)
		for _, ev := range ocsfEvents {
			if err := enc.Encode(ev); err != nil {
				return // client went away mid-stream
			}
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema": ocsf.SchemaVersion, "count": len(ocsfEvents), "events": ocsfEvents,
	})
}

// nis2Controls mirrors docs/NIS2-COMPLIANCE.md §1's Art. 21(2) control matrix —
// keep the two in step: a control retitled, reclassified or added there needs
// the same edit here. Families lists the audit-action-family prefixes (the
// "family.verb" naming convention documented in ARCHITECTURE-LOW-LEVEL.md §5)
// counted as window evidence for that control; nil means the control has no
// natural audit signal and is reported as a static reference to the doc
// instead (matching the doc's own "🟡 partial (docs)" framing for (a) and (g)).
var nis2Controls = []struct {
	Letter, Title, Status string
	Families              []string
}{
	{"a", "Risk analysis & information-system security policies", "partial", nil},
	{"b", "Incident handling", "implemented", []string{"breakglass", "analytics"}},
	{"c", "Business continuity, backup, crisis mgmt", "implemented", nil},
	{"d", "Supply-chain security", "implemented", []string{"vendor"}},
	{"e", "Security in acquisition/development/maintenance, vuln handling", "implemented", nil},
	{"f", "Policies to assess effectiveness", "implemented", []string{"certification"}},
	{"g", "Basic cyber hygiene & training", "partial", nil},
	{"h", "Cryptography & encryption policy", "implemented", nil},
	{"i", "Human-resources security, access control, asset mgmt", "implemented", []string{"grant", "safe", "certification"}},
	{"j", "MFA / continuous auth, secured comms, secured emergency comms", "implemented", []string{"mfa", "login"}},
}

// nis2Report produces a live, window-scoped evidence report against pamv1's
// NIS2 Art. 21(2) control matrix — a canned, control-mapped report, not
// another raw audit slice. Each control's status is architectural (whether
// the capability exists, same as docs/NIS2-COMPLIANCE.md), not derived from
// window activity — a quiet week doesn't mean incident handling broke;
// controls with a natural audit signal additionally carry a count of matching
// events in the requested window, bucketed by the action's family prefix
// (e.g. "vendor.grant_create" counts under "vendor"). Chain integrity is
// always whole-chain (bounded-range verification isn't supported yet, so the
// report says so rather than implying a scoped check); an error from
// VerifyAuditChain is treated as "not enabled," matching verifyAudit's own
// convention, not as a report failure. Requires CapReadAudit. Only NIS2 is
// covered — PCI-DSS/ISO27001/SOX would each need their own control mapping
// authored from scratch, which this does not attempt.
func (s *Server) nis2Report(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "since must be RFC3339")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "until must be RFC3339")
		return
	}
	if until.IsZero() {
		until = time.Now().UTC()
	}
	if since.IsZero() {
		since = until.Add(-defaultExportWindow)
	}
	events, err := s.store.ExportAudit(r.Context(), since, until)
	if err != nil {
		storeError(w, err)
		return
	}

	counts := make(map[string]int, len(events))
	for _, e := range events {
		family := e.Action
		if i := strings.IndexByte(e.Action, '.'); i >= 0 {
			family = e.Action[:i]
		}
		counts[family]++
	}

	chainOK, brokeAtID, chainErr := s.store.VerifyAuditChain(r.Context())
	chain := map[string]any{
		"enabled": chainErr == nil,
		"scope":   "whole-chain (bounded-range verification is not supported)",
	}
	if chainErr == nil {
		chain["intact"] = chainOK
		chain["broke_at_id"] = brokeAtID
	}

	controls := make([]map[string]any, 0, len(nis2Controls))
	for _, c := range nis2Controls {
		row := map[string]any{"letter": c.Letter, "title": c.Title, "status": c.Status}
		if c.Families == nil {
			row["evidence"] = map[string]any{
				"type":      "static",
				"reference": "docs/NIS2-COMPLIANCE.md#1-art-212-control-matrix",
			}
		} else {
			families := make(map[string]int, len(c.Families))
			total := 0
			for _, f := range c.Families {
				families[f] = counts[f]
				total += counts[f]
			}
			evidence := map[string]any{"type": "window", "families": families, "count": total}
			if c.Letter == "b" {
				evidence["chain"] = chain
			}
			row["evidence"] = evidence
		}
		controls = append(controls, row)
	}

	// No wall-clock field beyond the requested window bounds, matching
	// exportAudit's determinism discipline: the same closed window always
	// yields the same digest, so a regulator re-running the report can confirm
	// nothing changed.
	body, _ := json.MarshalIndent(map[string]any{
		"framework":    "NIS2 Art. 21(2)",
		"since":        since.UTC().Format(time.RFC3339),
		"until":        until.UTC().Format(time.RFC3339),
		"total_events": len(events),
		"controls":     controls,
	}, "", "  ")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	s.audit(r.Context(), "compliance.nis2_report", fmt.Sprintf(
		"since:%s until:%s events:%d sha256:%s", q.Get("since"), q.Get("until"), len(events), digest))

	w.Header().Set("X-PAM-Export-SHA256", digest)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=pamv1-nis2-report.json")
	_, _ = w.Write(body)
}

// csvSafe defuses spreadsheet formula injection: a cell that a spreadsheet would
// evaluate (leading =, +, -, @, tab or CR) is prefixed with a single quote, so a
// target name or reason in this compliance export can't run as a formula.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// parseTimeParam parses an RFC3339 timestamp, treating the empty string as the
// zero time (an open bound).
func parseTimeParam(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

// filterAudit narrows events by exact action and case-insensitive actor
// substring; empty filters pass everything through.
func filterAudit(events []store.AuditEvent, actor, action string) []store.AuditEvent {
	if actor == "" && action == "" {
		return events
	}
	actorLC := strings.ToLower(actor)
	out := make([]store.AuditEvent, 0, len(events))
	for _, e := range events {
		if action != "" && e.Action != action {
			continue
		}
		if actor != "" && !strings.Contains(strings.ToLower(e.Actor), actorLC) {
			continue
		}
		out = append(out, e)
	}
	return out
}
