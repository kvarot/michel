package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// serverKinds are the finding kinds of the servers. The curve leaves them
// out, as the findings list of a project does (scan.ListFindings).
const serverKinds = `'server_package', 'server_config', 'server_exposure'`

// FindingRow is what the replay needs of a finding: who owns it and what
// its effective severity is computed from (scan.EffectiveSeverity).
type FindingRow struct {
	ID            string
	ProjectID     string
	Kind          string
	SeverityLabel string
	CVSSEnriched  float64
	Malicious     bool
}

// Event is one change of a finding, as finding_event keeps it.
type Event struct {
	At   time.Time
	Kind string
}

// Span is the time an ignore decision is in force: from From, until Until
// (excluded). A zero Until means it still is.
type Span struct {
	From, Until time.Time
}

// Tracked is a finding of an active project with its events, in order, and
// the spans of its ignore decisions.
type Tracked struct {
	Row     FindingRow
	Events  []Event
	Ignores []Span
}

// OpenAt is the rule of an open finding at instant at, once every change at
// or before at is applied: the finding was seen, is not gone, and no ignore
// decision is in force. A fix or defer decision leaves it open.
func OpenAt(events []Event, ignores []Span, at time.Time) bool {
	seen, gone := false, false
	for _, e := range events {
		if e.At.After(at) {
			continue
		}
		switch e.Kind {
		case KindSeen, KindBack:
			seen, gone = true, false
		case KindGone:
			seen, gone = true, true
		}
	}
	if !seen || gone {
		return false
	}
	for _, s := range ignores {
		if !s.From.After(at) && (s.Until.IsZero() || at.Before(s.Until)) {
			return false
		}
	}
	return true
}

// LocalDay is one calendar day in a location: from Start (00:00 local)
// to End (the next day's 00:00 local, excluded).
type LocalDay struct {
	Start, End time.Time
	Date       string // YYYY-MM-DD
}

// LocalDays returns the n local days that end with the day of now, oldest
// first. Each bound is a local midnight, so a day lasts 23 or 25 hours when
// the clock changes.
func LocalDays(now time.Time, loc *time.Location, n int) []LocalDay {
	y, m, d := now.In(loc).Date()
	out := make([]LocalDay, 0, n)
	for i := n - 1; i >= 0; i-- {
		start := time.Date(y, m, d-i, 0, 0, 0, 0, loc)
		out = append(out, LocalDay{Start: start, End: time.Date(y, m, d-i+1, 0, 0, 0, 0, loc), Date: start.Format("2006-01-02")})
	}
	return out
}

// Day is the count of the open findings at the end of one local day, by
// severity. It is Reconstructed when the day ended before the history
// began to be written.
type Day struct {
	Date          string
	Open          map[string]int
	Reconstructed bool
}

// HistoryStart is when the history began to be written (history_start).
func HistoryStart(ctx context.Context, db *sql.DB) (time.Time, error) {
	var s string
	err := db.QueryRowContext(ctx, `SELECT at FROM history_start WHERE id = 1`).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, errors.New("the start of the history is not recorded")
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read the start of the history: %w", err)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read the start of the history: %w", err)
	}
	return t, nil
}

// OpenByDay counts, for each of the days local days ending today, the
// findings open at the end of the day, by severity(row): the current
// effective severity, applied to the whole history. Server findings and
// findings of removed projects are left out.
func OpenByDay(ctx context.Context, db *sql.DB, now time.Time, loc *time.Location, days int, severity func(FindingRow) string) ([]Day, error) {
	start, err := HistoryStart(ctx, db)
	if err != nil {
		return nil, err
	}
	tracked, err := LoadTracked(ctx, db)
	if err != nil {
		return nil, err
	}
	sev := make([]string, len(tracked))
	for i, x := range tracked {
		sev[i] = severity(x.Row)
	}
	out := []Day{}
	for _, d := range LocalDays(now, loc, days) {
		day := Day{Date: d.Date, Open: map[string]int{}, Reconstructed: d.End.Before(start)}
		last := d.End.Add(-time.Nanosecond)
		for i, x := range tracked {
			if OpenAt(x.Events, x.Ignores, last) {
				day.Open[sev[i]]++
			}
		}
		out = append(out, day)
	}
	return out, nil
}

// LoadTracked reads, in three queries, the findings of the active projects
// (server findings left out), their events and their ignore decisions.
func LoadTracked(ctx context.Context, db *sql.DB) ([]Tracked, error) {
	rows, err := db.QueryContext(ctx, `SELECT f.id, f.project_id, f.kind, f.severity_label, f.cvss_enriched, f.malicious
		FROM finding f JOIN project p ON p.id = f.project_id
		WHERE p.active = 1 AND f.kind NOT IN (`+serverKinds+`) ORDER BY f.id`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	out := []Tracked{}
	index := map[string]int{}
	for rows.Next() {
		var r FindingRow
		var malicious int
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Kind, &r.SeverityLabel, &r.CVSSEnriched, &malicious); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot read the findings: %w", err)
		}
		r.Malicious = malicious != 0
		index[r.ID] = len(out)
		out = append(out, Tracked{Row: r})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}

	rows, err = db.QueryContext(ctx, `SELECT finding_id, at, kind FROM finding_event ORDER BY finding_id, seq`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the history of the findings: %w", err)
	}
	for rows.Next() {
		var id, at, kind string
		if err := rows.Scan(&id, &at, &kind); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot read the history of the findings: %w", err)
		}
		i, ok := index[id]
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot read the history of the findings: %w", err)
		}
		out[i].Events = append(out[i].Events, Event{At: t, Kind: kind})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the history of the findings: %w", err)
	}

	rows, err = db.QueryContext(ctx, `SELECT finding_id, created_at, superseded_at FROM decision WHERE action = 'ignore'`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, created, superseded string
		if err := rows.Scan(&id, &created, &superseded); err != nil {
			return nil, fmt.Errorf("cannot read the decisions: %w", err)
		}
		i, ok := index[id]
		if !ok {
			continue
		}
		var s Span
		if s.From, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, fmt.Errorf("cannot read the decisions: %w", err)
		}
		if superseded != "" {
			if s.Until, err = time.Parse(time.RFC3339, superseded); err != nil {
				return nil, fmt.Errorf("cannot read the decisions: %w", err)
			}
		}
		out[i].Ignores = append(out[i].Ignores, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the decisions: %w", err)
	}
	return out, nil
}
