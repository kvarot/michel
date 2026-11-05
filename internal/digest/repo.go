package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Run is one digest Michel sent (or tried to send). Its Until starts the
// next digest's window, whatever happened on its channels.
type Run struct {
	ID        string           `json:"id"`
	Since     time.Time        `json:"since"`
	Until     time.Time        `json:"until"`
	Lang      i18n.Lang        `json:"lang"`
	Projects  []ProjectSummary `json:"projects"`
	Summary   map[string]int   `json:"summary"`
	Channels  []ChannelResult  `json:"channels"`
	CreatedAt time.Time        `json:"created_at"`
}

// ProjectSummary is the counters of one project in a run.
type ProjectSummary struct {
	Name       string `json:"name"`
	New        int    `json:"new"`
	Gone       int    `json:"gone"`
	Superseded int    `json:"superseded"`
	Due        int    `json:"due"`
}

// ChannelResult is what happened on one channel: Result is ok, error or
// skipped; Error is in English.
type ChannelResult struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Result string `json:"result"`
	Error  string `json:"error"`
}

// RunOf is the run recording d, with a new id, created at now, with no
// channel yet.
func RunOf(d Digest, now time.Time) Run {
	r := Run{ID: ulid.Make().String(), Since: d.Since, Until: d.Until, Lang: d.Lang, Projects: []ProjectSummary{}, Channels: []ChannelResult{}, CreatedAt: now,
		Summary: map[string]int{"new_total": d.NewTotal, "attention_total": d.AttentionTotal, "failed_scans": d.FailedScans,
			"empty_projects": d.EmptyProjects, "show_empty": boolInt(d.ShowEmpty),
			"catalog_failed": len(d.Catalog.Failed) + len(d.Catalog.Unreachable)}}
	if carriesDeviation(d) {
		r.Summary[deviationKey] = 1
	}
	for _, p := range d.Projects {
		news := 0
		for _, pkg := range p.New {
			news += len(pkg.FindingIDs)
		}
		gone := 0
		for _, pkg := range p.Gone {
			gone += len(pkg.FindingIDs)
		}
		r.Projects = append(r.Projects, ProjectSummary{Name: p.Name, New: news, Gone: gone, Superseded: len(p.Superseded), Due: len(p.Due)})
	}
	return r
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Repo stores digest runs.
type Repo struct{ s *store.Store }

// NewRepo builds a Repo.
func NewRepo(s *store.Store) *Repo { return &Repo{s: s} }

func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Save inserts run with a new id when it has none.
func (r *Repo) Save(ctx context.Context, run Run) error {
	if run.ID == "" {
		run.ID = ulid.Make().String()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now()
	}
	projects, channels, summary := run.Projects, run.Channels, run.Summary
	if projects == nil {
		projects = []ProjectSummary{}
	}
	if channels == nil {
		channels = []ChannelResult{}
	}
	if summary == nil {
		summary = map[string]int{}
	}
	pj, _ := json.Marshal(projects)
	ch, _ := json.Marshal(channels)
	sm, _ := json.Marshal(summary)
	if _, err := r.s.DB().ExecContext(ctx, `INSERT INTO digest_run (id, since, until, lang, projects, summary, channels, created_at)
		VALUES (?,?,?,?,?,?,?,?)`, run.ID, timeText(run.Since), timeText(run.Until), string(run.Lang), string(pj), string(sm), string(ch),
		timeText(run.CreatedAt)); err != nil {
		return fmt.Errorf("cannot save the digest run: %w", err)
	}
	return nil
}

func (r *Repo) query(ctx context.Context, q string, args ...any) ([]Run, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, since, until, lang, projects, summary, channels, created_at FROM digest_run `+q, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the digest runs: %w", err)
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var run Run
		var since, until, lang, pj, sm, ch, created string
		if err := rows.Scan(&run.ID, &since, &until, &lang, &pj, &sm, &ch, &created); err != nil {
			return nil, err
		}
		run.Since, run.Until, run.CreatedAt, run.Lang = parseTime(since), parseTime(until), parseTime(created), i18n.Lang(lang)
		run.Projects, run.Channels, run.Summary = []ProjectSummary{}, []ChannelResult{}, map[string]int{}
		for _, c := range []struct {
			name, raw string
			into any
		}{{"projects", pj, &run.Projects}, {"channels", ch, &run.Channels}, {"summary", sm, &run.Summary}} {
			if err := json.Unmarshal([]byte(c.raw), c.into); err != nil {
				return nil, fmt.Errorf("cannot read the %s of digest run %s: %w", c.name, run.ID, err)
			}
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// Last returns the last digest sent (a pending claim is not one), whatever
// happened on its channels.
func (r *Repo) Last(ctx context.Context) (Run, bool, error) {
	list, err := r.List(ctx, 1)
	if err != nil || len(list) == 0 {
		return Run{}, false, err
	}
	return list[0], true, nil
}

// List returns the last digests sent, newest first. A pending claim is left
// out: its send is not over, and it may yet be released.
func (r *Repo) List(ctx context.Context, last int) ([]Run, error) {
	// A few more rows are read than asked for, to step over claims.
	rows, err := r.query(ctx, `ORDER BY created_at DESC, id DESC LIMIT ?`, last+pendingRoom)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, run := range rows {
		if !run.Pending() && len(out) < last {
			out = append(out, run)
		}
	}
	return out, nil
}
