package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

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
		n, err := strconv.Atoi(strings.TrimSpace(q[0]))
		if err != nil || n < 1 || n > maxStatDays {
			s.fail(w, http.StatusBadRequest, i18n.T(s.answerLang(r), "api.bad_days"), i18n.T(s.answerLang(r), "api.bad_days_hint", maxStatDays))
			return
		}
		days = n
	}
	db := s.deps.Store.DB()
	start, err := history.HistoryStart(ctx, db)
	if err != nil {
		s.internal(w, r)
		return
	}
	list, err := history.OpenByDay(ctx, db, s.deps.Now(), time.Local, days, func(row history.FindingRow) string {
		return severityOf(effective(scan.Finding{SeverityLabel: row.SeverityLabel, CVSSEnriched: row.CVSSEnriched, Malicious: row.Malicious}))
	})
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
