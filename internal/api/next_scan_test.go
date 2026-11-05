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
