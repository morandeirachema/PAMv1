package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/morandeirachema/pamv1/internal/report"
)

// Report windows (Phase 277). Every report reads the audit trail for its
// window into memory, so the window is bounded: a year is the longest
// question a reviewer asks of this report, and a year of rows is what the
// NIS2 export already loads.
const (
	defaultUnusedDays  = 30
	maxReportWindow    = 366 * 24 * time.Hour
	defaultStatsWindow = 7 * 24 * time.Hour
)

// reportUnused is GET /api/reports/unused?days=N: the stored users that
// neither signed in nor connected in the last N days (default 30, 1–366),
// and the targets nobody connected to. A review read, so CapReadAudit.
func (s *Server) reportUnused(w http.ResponseWriter, r *http.Request) {
	days := defaultUnusedDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 366 {
			writeError(w, http.StatusUnprocessableEntity, "days must be 1-366")
			return
		}
		days = n
	}
	until := time.Now().UTC()
	since := until.AddDate(0, 0, -days)
	ctx := r.Context()
	events, err := s.store.ExportAudit(ctx, since, until)
	if err != nil {
		storeError(w, err)
		return
	}
	users, err := s.store.ListUsers(ctx, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	out := report.FindUnused(users, targets, events, since, until)
	s.audit(ctx, "report.view", "report:unused days:"+strconv.Itoa(days)+
		" users:"+strconv.Itoa(len(out.Users))+" targets:"+strconv.Itoa(len(out.Targets)))
	writeJSON(w, http.StatusOK, out)
}

// reportConnections is GET /api/reports/connections?since=&until=&format=:
// connection statistics over the window (RFC 3339 bounds, default the last
// seven days), as JSON totals or, with format=csv, one row per connection
// for a spreadsheet.
func (s *Server) reportConnections(w http.ResponseWriter, r *http.Request) {
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
		since = until.Add(-defaultStatsWindow)
	}
	format := q.Get("format")
	switch {
	case !since.Before(until):
		writeError(w, http.StatusUnprocessableEntity, "since must be before until")
		return
	case until.Sub(since) > maxReportWindow:
		writeError(w, http.StatusUnprocessableEntity, "the window may not exceed 366 days")
		return
	case format != "" && format != "json" && format != "csv":
		writeError(w, http.StatusUnprocessableEntity, `format must be "json" or "csv"`)
		return
	}
	ctx := r.Context()
	events, err := s.store.ExportAudit(ctx, since, until)
	if err != nil {
		storeError(w, err)
		return
	}
	conns := report.Connections(events)
	if format == "" {
		format = "json"
	}
	s.audit(ctx, "report.view", "report:connections format:"+format+
		" since:"+since.UTC().Format(time.RFC3339)+" until:"+until.UTC().Format(time.RFC3339)+
		" rows:"+strconv.Itoa(len(conns)))
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="pamv1-connections.csv"`)
		if err := report.WriteConnectionsCSV(w, conns); err != nil {
			s.log.Error("connections csv", "err", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, report.Summarize(conns, since, until))
}
