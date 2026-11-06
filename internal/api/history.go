package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/history"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

// defaultStatDays and maxStatDays bound GET /stats/open?days=.
const (
	defaultStatDays = 90
	maxStatDays     = 365
)

// TimelineEntry is one line of a finding's timeline.
type TimelineEntry struct {
	At            string         `json:"at"`
	Kind          string         `json:"kind"`
	Detail        map[string]any `json:"detail"`
	Reconstructed bool           `json:"reconstructed"`
}

// TimelineView is the answer of GET /findings/{id}/timeline.
type TimelineView struct {
	Entries      []TimelineEntry `json:"entries"`
	HistoryStart string          `json:"history_start"`
}

// OpenDayView is one point of the curve of the open findings.
type OpenDayView struct {
	Date          string         `json:"date"`
	Open          map[string]int `json:"open"`
	Reconstructed bool           `json:"reconstructed"`
}

// OpenStatsView is the answer of GET /stats/open.
type OpenStatsView struct {
	Days         []OpenDayView `json:"days"`
	HistoryStart string        `json:"history_start"`
}

func (s *server) historyRoutes() {
	s.mux.HandleFunc("GET /api/v1/findings/{id}/timeline", s.timeline)
	s.mux.HandleFunc("GET /api/v1/stats/open", s.statsOpen)
	s.mux.HandleFunc("GET /api/v1/reports", s.reports)
}

// isServerKind tells a server finding apart: the timeline is for project
// findings.
func isServerKind(kind string) bool {
	return kind == scan.KindServerPackage || kind == scan.KindServerConfig || kind == scan.KindServerExposure
}

func (s *server) timeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, p, found, err := s.lookup(ctx, r.PathValue("id"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found || !p.Active || isServerKind(f.Kind) {
		s.fail(w, http.StatusNotFound, i18n.T(s.answerLang(r), "api.finding_not_found"), "")
		return
	}
	db := s.deps.Store.DB()
	start, err := history.HistoryStart(ctx, db)
	if err != nil {
		s.internal(w, r)
		return
	}
	entries, err := history.Timeline(ctx, db, f.ID)
	if err != nil {
		s.internal(w, r)
		return
	}
	v := TimelineView{Entries: []TimelineEntry{}, HistoryStart: start.UTC().Format(time.RFC3339)}
	for _, e := range entries {
		v.Entries = append(v.Entries, TimelineEntry{At: e.At.UTC().Format(time.RFC3339), Kind: e.Kind,
			Detail: e.Detail, Reconstructed: e.Reconstructed})
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) statsOpen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := defaultStatDays
	if q, set := r.URL.Query()["days"]; set {
		n, err := strconv.Atoi(q[0])
		if err != nil || n < 1 || n > maxStatDays {
			s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_days"), i18n.T(s.answerLang(r), "api.bad_days_hint", maxStatDays))
			return
		}
		days = n
	}
	list, start, err := history.OpenByDay(ctx, s.deps.Store.DB(), s.deps.Now(), time.Local, days, reportSeverity)
	if err != nil {
		s.internal(w, r)
		return
	}
	v := OpenStatsView{Days: []OpenDayView{}, HistoryStart: start.UTC().Format(time.RFC3339)}
	for _, d := range list {
		open := map[string]int{}
		for _, sev := range severities {
			open[sev] = d.Open[sev]
		}
		v.Days = append(v.Days, OpenDayView{Date: d.Date, Open: open, Reconstructed: d.Reconstructed})
	}
	writeJSON(w, http.StatusOK, v)
}

// reportSeverity is the severity of a finding in the curve and the reports:
// its effective severity of today.
func reportSeverity(row history.FindingRow) string {
	return severityOf(effective(scan.Finding{SeverityLabel: row.SeverityLabel, CVSSEnriched: row.CVSSEnriched, Malicious: row.Malicious}))
}

// withSeverities gives m every severity label, at 0 when absent.
func withSeverities(m map[string]int) map[string]int {
	out := map[string]int{}
	for _, sev := range severities {
		out[sev] = m[sev]
	}
	return out
}

func (s *server) reports(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rep, err := history.BuildReport(r.Context(), s.deps.Store.DB(), q.Get("from"), q.Get("to"), time.Local, s.deps.Now(), reportSeverity)
	if errors.Is(err, history.ErrBadPeriod) {
		s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_period"), i18n.T(s.answerLang(r), "api.bad_period_hint", history.MaxReportDays))
		return
	}
	if err != nil {
		s.internal(w, r)
		return
	}
	for _, m := range []*map[string]int{&rep.Found, &rep.GoneByMichel, &rep.GoneElsewhere, &rep.OpenStart, &rep.OpenEnd} {
		*m = withSeverities(*m)
	}
	for _, a := range []decide.Action{decide.Fix, decide.Defer, decide.Ignore} {
		if _, ok := rep.Decisions[string(a)]; !ok {
			rep.Decisions[string(a)] = 0
		}
	}
	writeJSON(w, http.StatusOK, rep)
}
