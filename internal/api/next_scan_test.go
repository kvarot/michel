package api

import (
	"context"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/watch"
)

// The card says when the daily watch checks the project next, or that its
// watch is off.
func TestProjectsSayTheNextScan(t *testing.T) {
	f := newFixture(t, nil)
	v := f.viewOf("en", "demo")
	want := watch.Next(now.Add(-time.Hour), true, now, 7, 0).UTC().Format(time.RFC3339)
	if !v.AutoScan || v.NextScanAt != want {
		t.Errorf("auto_scan %v next %q, want %q", v.AutoScan, v.NextScanAt, want)
	}
	repo := project.NewRepo(f.st)
	p, err := repo.Get(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	p.AutoScan = false
	if err := repo.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if v := f.viewOf("en", "demo"); v.AutoScan || v.NextScanAt != "" {
		t.Errorf("watch off for the project: %+v", v)
	}
}

// An interrupted check does not count: the watch checks the project again
// at its next look, and the card says so rather than "tomorrow".
func TestNextScanIgnoresAnInterruptedCheck(t *testing.T) {
	later := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	f := newFixtureWith(t, nil, func(f *fixture) { f.deps.Now = func() time.Time { return later } })
	if _, err := f.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES ('s-cut', ?, ?, 'interrupted')`,
		f.proj.ID, later.Add(-10*time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 23, 7, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if v := f.viewOf("en", "demo"); v.NextScanAt != want {
		t.Errorf("next %q, want %q (today: the interrupted check does not count)", v.NextScanAt, want)
	}
}
