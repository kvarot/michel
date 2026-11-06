package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxReportDays is the longest period a report covers.
const MaxReportDays = 62

// ErrBadPeriod means the dates of a report cannot be used: malformed, in
// the wrong order, starting after today or spanning more than
// MaxReportDays days.
var ErrBadPeriod = errors.New("bad report period")

// FixCounts are the fix attempt states reached in a period.
type FixCounts struct {
	Proposed int `json:"proposed"`
	Applied  int `json:"applied"`
	Proven   int `json:"proven"`
}

// OldestOpen is the finding open the longest at the end of a period.
type OldestOpen struct {
	FindingID   string `json:"finding_id"`
	Package     string `json:"package"`
	OSVID       string `json:"osv_id"`
	FirstSeenAt string `json:"first_seen_at"`
}

// CheckCount is how many checks of the projects ended done or failed.
type CheckCount struct {
	Done   int `json:"done"`
	Failed int `json:"failed"`
}

// ServerCheckCount is how many checks of the servers were done. Michel
// keeps the inventory of each check that succeeded but nothing of a check
// that failed, so Failed is always nil: not read.
type ServerCheckCount struct {
	Done   int  `json:"done"`
	Failed *int `json:"failed"`
}

// Checks are the checks started in a period.
type Checks struct {
	Projects CheckCount       `json:"projects"`
	Servers  ServerCheckCount `json:"servers"`
}

// ServerCounts are the server findings seen and gone in a period, counted
// apart from the project findings.
type ServerCounts struct {
	Found  int `json:"found"`
	Closed int `json:"closed"`
}

// ProjectLine is the line of one active project in a report.
type ProjectLine struct {
	Name      string `json:"name"`
	Found     int    `json:"found"`
	Gone      int    `json:"gone"`
	OpenEnd   int    `json:"open_end"`
	Decisions int    `json:"decisions"`
}

// Report is what happened in a period of local days, from From to To
// included. The severity maps hold only the severities met.
type Report struct {
	From          string         `json:"from"`
	To            string         `json:"to"`
	Found         map[string]int `json:"found"`
	GoneByMichel  map[string]int `json:"gone_by_michel"`
	GoneElsewhere map[string]int `json:"gone_elsewhere"`
	Decisions     map[string]int `json:"decisions"`
	Fixes         FixCounts      `json:"fixes"`
	OpenStart     map[string]int `json:"open_start"`
	OpenEnd       map[string]int `json:"open_end"`
	OldestOpen    *OldestOpen    `json:"oldest_open"`
	Checks        Checks         `json:"checks"`
	Servers       ServerCounts   `json:"servers"`
	Projects      []ProjectLine  `json:"projects"`
	Reconstructed bool           `json:"reconstructed"`
}

// ParsePeriod reads from and to (YYYY-MM-DD, to included) as local days in
// loc: the period runs from from 00:00 to the day after to, 00:00. It
// refuses, with ErrBadPeriod, malformed dates, to before from, from after
// the local day of now and more than MaxReportDays days.
func ParsePeriod(from, to string, loc *time.Location, now time.Time) (start, end time.Time, err error) {
	day := func(s string) (time.Time, error) {
		t, err := time.ParseInLocation("2006-01-02", s, loc)
		if err != nil || t.Format("2006-01-02") != s {
			return time.Time{}, fmt.Errorf("%w: %q is not a date", ErrBadPeriod, s)
		}
		return t, nil
	}
	if start, err = day(from); err != nil {
		return time.Time{}, time.Time{}, err
	}
	last, err := day(to)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if last.Before(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it ends before it starts", ErrBadPeriod)
	}
	y, m, d := now.In(loc).Date()
	if start.After(time.Date(y, m, d, 0, 0, 0, 0, loc)) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: it starts after today", ErrBadPeriod)
	}
	// Count the days on calendar dates, not on hours: a day lasts 23 or 25
	// hours when the clock changes.
	days := int(time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, time.UTC).
		Sub(time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)).Hours()/24) + 1
	if days > MaxReportDays {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: more than %d days", ErrBadPeriod, MaxReportDays)
	}
	return start, time.Date(last.Year(), last.Month(), last.Day()+1, 0, 0, 0, 0, loc), nil
}

// in tells whether at falls in [start, end).
func in(at, start, end time.Time) bool { return !at.Before(start) && at.Before(end) }

// BuildReport counts what happened from from to to (local days in loc, to
// included) to the findings of the active projects, by severity(row): the
// current effective severity. A finding gone after one of its fix attempts
// was applied or proven fixed is gone by Michel, otherwise gone elsewhere.
// Server findings are counted apart, in Servers. Open findings at the start
// and the end come from the replay of the curve (OpenAt).
func BuildReport(ctx context.Context, db *sql.DB, from, to string, loc *time.Location, now time.Time, severity func(FindingRow) string) (Report, error) {
	start, end, err := ParsePeriod(from, to, loc, now)
	if err != nil {
		return Report{}, err
	}
	historyStart, err := HistoryStart(ctx, db)
	if err != nil {
		return Report{}, err
	}
	tracked, err := LoadTracked(ctx, db)
	if err != nil {
		return Report{}, err
	}
	r := Report{From: from, To: to, Found: map[string]int{}, GoneByMichel: map[string]int{}, GoneElsewhere: map[string]int{},
		Decisions: map[string]int{}, OpenStart: map[string]int{}, OpenEnd: map[string]int{}, Projects: []ProjectLine{},
		Reconstructed: start.Before(historyStart)}

	projects, err := activeProjects(ctx, db)
	if err != nil {
		return Report{}, err
	}
	lines := map[string]*ProjectLine{}
	for i := range projects {
		lines[projects[i].id] = &ProjectLine{Name: projects[i].name}
	}
	line := func(projectID string) *ProjectLine {
		if l, ok := lines[projectID]; ok {
			return l
		}
		return &ProjectLine{}
	}

	byID := map[string]int{}
	for i, x := range tracked {
		byID[x.Row.ID] = i
	}
	fixed, err := r.countAttempts(ctx, db, byID, start, end)
	if err != nil {
		return Report{}, err
	}

	beforeStart, lastOfEnd := start.Add(-time.Nanosecond), end.Add(-time.Nanosecond)
	var openEnd []string
	for _, x := range tracked {
		sev := severity(x.Row)
		l := line(x.Row.ProjectID)
		for _, e := range x.Events {
			if !in(e.At, start, end) {
				continue
			}
			switch e.Kind {
			case KindSeen:
				r.Found[sev]++
				l.Found++
			case KindGone:
				l.Gone++
				if byMichel(fixed[x.Row.ID], e.At) {
					r.GoneByMichel[sev]++
				} else {
					r.GoneElsewhere[sev]++
				}
			}
		}
		if OpenAt(x.Events, x.Ignores, beforeStart) {
			r.OpenStart[sev]++
		}
		if OpenAt(x.Events, x.Ignores, lastOfEnd) {
			r.OpenEnd[sev]++
			l.OpenEnd++
			openEnd = append(openEnd, x.Row.ID)
		}
	}

	if err := r.countDecisions(ctx, db, tracked, byID, line, start, end); err != nil {
		return Report{}, err
	}
	if r.OldestOpen, err = oldestOpen(ctx, db, openEnd); err != nil {
		return Report{}, err
	}
	if err := r.countChecks(ctx, db, start, end); err != nil {
		return Report{}, err
	}
	if err := r.countServers(ctx, db, start, end); err != nil {
		return Report{}, err
	}
	for i := range projects {
		r.Projects = append(r.Projects, *lines[projects[i].id])
	}
	return r, nil
}

// byMichel tells whether a finding gone at gone had a fix attempt applied
// or proven fixed by then (fixed: the instants of those states).
func byMichel(fixed []time.Time, gone time.Time) bool {
	for _, at := range fixed {
		if !at.After(gone) {
			return true
		}
	}
	return false
}

type projectName struct{ id, name string }

func activeProjects(ctx context.Context, db *sql.DB) ([]projectName, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, name FROM project WHERE active = 1 ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the projects: %w", err)
	}
	defer rows.Close()
	var out []projectName
	for rows.Next() {
		var p projectName
		if err := rows.Scan(&p.id, &p.name); err != nil {
			return nil, fmt.Errorf("cannot read the projects: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the projects: %w", err)
	}
	return out, nil
}

// countAttempts counts the states the fix attempts of the tracked findings
// reached in the period, and returns, by finding, when its attempts were
// applied or proven fixed (at any time).
func (r *Report) countAttempts(ctx context.Context, db *sql.DB, tracked map[string]int, start, end time.Time) (map[string][]time.Time, error) {
	rows, err := db.QueryContext(ctx, `SELECT a.finding_id, e.at, e.state FROM fix_attempt_event e JOIN fix_attempt a ON a.id = e.attempt_id`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	defer rows.Close()
	fixed := map[string][]time.Time{}
	for rows.Next() {
		var id, at, state string
		if err := rows.Scan(&id, &at, &state); err != nil {
			return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
		}
		if _, ok := tracked[id]; !ok {
			continue
		}
		t, err := parseAt(at)
		if err != nil {
			return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
		}
		// The states are fix.StateProposed, fix.StateApplied and
		// fix.StateProvenFixed: history cannot import the fix package,
		// which imports it.
		if state == "applied" || state == "proven_fixed" {
			fixed[id] = append(fixed[id], t)
		}
		if !in(t, start, end) {
			continue
		}
		switch state {
		case "proposed":
			r.Fixes.Proposed++
		case "applied":
			r.Fixes.Applied++
		case "proven_fixed":
			r.Fixes.Proven++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the fix attempts: %w", err)
	}
	return fixed, nil
}

// countDecisions counts the decisions taken in the period on the tracked
// findings, by action and by project.
func (r *Report) countDecisions(ctx context.Context, db *sql.DB, tracked []Tracked, byID map[string]int, line func(string) *ProjectLine, start, end time.Time) error {
	rows, err := db.QueryContext(ctx, `SELECT finding_id, action, created_at FROM decision`)
	if err != nil {
		return fmt.Errorf("cannot read the decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, action, created string
		if err := rows.Scan(&id, &action, &created); err != nil {
			return fmt.Errorf("cannot read the decisions: %w", err)
		}
		i, ok := byID[id]
		if !ok {
			continue
		}
		t, err := parseAt(created)
		if err != nil {
			return fmt.Errorf("cannot read the decisions: %w", err)
		}
		if in(t, start, end) {
			r.Decisions[action]++
			line(tracked[i].Row.ProjectID).Decisions++
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cannot read the decisions: %w", err)
	}
	return nil
}

// oldestOpen is, among the findings ids, the one first seen the earliest.
func oldestOpen(ctx context.Context, db *sql.DB, ids []string) (*OldestOpen, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	rows, err := db.QueryContext(ctx, `SELECT f.id, f.package, f.osv_id, f.first_seen_at
		FROM finding f JOIN project p ON p.id = f.project_id WHERE p.active = 1 AND f.kind NOT IN (`+serverKinds+`)`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	defer rows.Close()
	var best *OldestOpen
	var bestAt time.Time
	for rows.Next() {
		var o OldestOpen
		if err := rows.Scan(&o.FindingID, &o.Package, &o.OSVID, &o.FirstSeenAt); err != nil {
			return nil, fmt.Errorf("cannot read the findings: %w", err)
		}
		if !want[o.FindingID] {
			continue
		}
		t, err := parseAt(o.FirstSeenAt)
		if err != nil {
			return nil, fmt.Errorf("cannot read the findings: %w", err)
		}
		if best == nil || t.Before(bestAt) || (t.Equal(bestAt) && o.FindingID < best.FindingID) {
			o.FirstSeenAt = t.UTC().Format(time.RFC3339)
			best, bestAt = &o, t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	return best, nil
}

// countChecks counts the checks started in the period. A project check is
// a scan row of an active project: ok, partial or empty is done, failed or
// interrupted is failed, one still running is neither. A server check is
// an inventory of an active server: Michel stores one for each check that
// succeeded and nothing for a check that failed, which stays not read.
func (r *Report) countChecks(ctx context.Context, db *sql.DB, start, end time.Time) error {
	rows, err := db.QueryContext(ctx, `SELECT s.status, s.started_at FROM scan s JOIN project p ON p.id = s.project_id WHERE p.active = 1`)
	if err != nil {
		return fmt.Errorf("cannot read the checks of the projects: %w", err)
	}
	for rows.Next() {
		var status, started string
		if err := rows.Scan(&status, &started); err != nil {
			rows.Close()
			return fmt.Errorf("cannot read the checks of the projects: %w", err)
		}
		t, err := parseAt(started)
		if err != nil {
			rows.Close()
			return fmt.Errorf("cannot read the checks of the projects: %w", err)
		}
		if !in(t, start, end) {
			continue
		}
		// The statuses are scan.ScanOK, scan.ScanPartial, scan.ScanEmpty,
		// scan.ScanFailed and scan.ScanInterrupted: history cannot import
		// the scan package, which imports it.
		switch status {
		case "ok", "partial", "empty":
			r.Checks.Projects.Done++
		case "failed", "interrupted":
			r.Checks.Projects.Failed++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cannot read the checks of the projects: %w", err)
	}

	rows, err = db.QueryContext(ctx, `SELECT i.at FROM target_inventory i JOIN target t ON t.id = i.target_id WHERE t.active = 1`)
	if err != nil {
		return fmt.Errorf("cannot read the checks of the servers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var at string
		if err := rows.Scan(&at); err != nil {
			return fmt.Errorf("cannot read the checks of the servers: %w", err)
		}
		t, err := parseAt(at)
		if err != nil {
			return fmt.Errorf("cannot read the checks of the servers: %w", err)
		}
		if in(t, start, end) {
			r.Checks.Servers.Done++
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cannot read the checks of the servers: %w", err)
	}
	return nil
}

// countServers counts the server findings seen and gone in the period, on
// the active servers only, like the list of the findings of a server
// (scan.Repo.ListServerFindings: source_key empty).
func (r *Report) countServers(ctx context.Context, db *sql.DB, start, end time.Time) error {
	rows, err := db.QueryContext(ctx, `SELECT e.at, e.kind FROM finding_event e JOIN finding f ON f.id = e.finding_id
		JOIN target t ON t.id = f.project_id
		WHERE t.active = 1 AND f.source_key = '' AND f.kind IN (`+serverKinds+`)`)
	if err != nil {
		return fmt.Errorf("cannot read the history of the server findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var at, kind string
		if err := rows.Scan(&at, &kind); err != nil {
			return fmt.Errorf("cannot read the history of the server findings: %w", err)
		}
		t, err := parseAt(at)
		if err != nil {
			return fmt.Errorf("cannot read the history of the server findings: %w", err)
		}
		if !in(t, start, end) {
			continue
		}
		switch kind {
		case KindSeen:
			r.Servers.Found++
		case KindGone:
			r.Servers.Closed++
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("cannot read the history of the server findings: %w", err)
	}
	return nil
}
