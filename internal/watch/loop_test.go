package watch

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// rig is a watch loop on a real database with a fake scanner and a clock the
// test moves.
type rig struct {
	t        *testing.T
	st       *store.Store
	mu       sync.Mutex
	now      time.Time
	pol      policy.Policy
	projects []project.Project
	scans    []string // project names, in order
	sources  int
	fail     map[string]error
	ticks    atomic.Int32
	block    chan struct{} // when set, a scan waits on it (or on ctx)
	entered  chan struct{} // when set, a scan says it started
}

func newRig(t *testing.T, now time.Time, names ...string) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := &rig{t: t, st: st, now: now, pol: policy.Defaults(), fail: map[string]error{}}
	for i, n := range names {
		id := fmt.Sprintf("p%d", i)
		if _, err := st.DB().Exec(`INSERT INTO project (id, name, source_type, path, classification, created_at)
			VALUES (?,?,'local_path','/x','sensitive','2026-01-01T00:00:00Z')`, id, n); err != nil {
			t.Fatal(err)
		}
		r.projects = append(r.projects, project.Project{ID: id, Name: n, Active: true, AutoScan: true})
	}
	return r
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) set(now time.Time) {
	r.mu.Lock()
	r.now = now
	r.mu.Unlock()
}

func (r *rig) deps() Deps {
	return Deps{
		Now:    r.clock,
		Policy: func() policy.Policy { r.mu.Lock(); defer r.mu.Unlock(); return r.pol },
		Projects: func(context.Context) ([]project.Project, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]project.Project{}, r.projects...), nil
		},
		Repo:    NewRepo(r.st),
		Sources: func(context.Context) error { r.mu.Lock(); r.sources++; r.mu.Unlock(); return nil },
		Scan: func(ctx context.Context, p project.Project) error {
			if r.block != nil {
				if r.entered != nil {
					r.entered <- struct{}{}
				}
				select {
				case <-r.block:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			r.mu.Lock()
			r.scans = append(r.scans, p.Name)
			err := r.fail[p.Name]
			now := r.now
			r.mu.Unlock()
			if errors.Is(err, errNoRow) {
				return err
			}
			status := "ok"
			if err != nil {
				status = "failed"
			}
			if _, e := r.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`,
				fmt.Sprintf("s%d-%s", now.UnixNano(), p.ID), p.ID, now.UTC().Format(time.RFC3339), status); e != nil {
				r.t.Error(e)
			}
			return err
		},
		TickHook: func() { r.ticks.Add(1) },
	}
}

// errNoRow is a failure before the scan row exists (a missing database).
var errNoRow = errors.New("no database")

// look runs the loop until it has looked n more times, then stops it.
func (r *rig) look(n int) {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	start := r.ticks.Load()
	go func() { Loop(ctx, r.deps(), 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for r.ticks.Load()-start < int32(n)+1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
}

func (r *rig) scanned() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.scans...)
}

func TestLoopRestartAfterTheHourScansOnce(t *testing.T) {
	r := newRig(t, at("2026-11-05", "09:00"), "demo", "shop")
	r.look(3)
	if got := r.scanned(); len(got) != 2 || r.sources != 1 {
		t.Fatalf("first serve: scans %v, sources %d", got, r.sources)
	}
	// serve stops and starts again the same morning: nothing is done twice.
	r.set(at("2026-11-05", "09:30"))
	r.look(3)
	if got := r.scanned(); len(got) != 2 || r.sources != 1 {
		t.Errorf("after a restart: scans %v, sources %d", got, r.sources)
	}
	// The next day, one more pass.
	r.set(at("2026-11-06", "07:00"))
	r.look(3)
	if got := r.scanned(); len(got) != 4 || r.sources != 2 {
		t.Errorf("next day: scans %v, sources %d", got, r.sources)
	}
}

func TestLoopWaitsForTheHour(t *testing.T) {
	r := newRig(t, at("2026-11-05", "06:30"), "demo")
	r.look(3)
	if got := r.scanned(); len(got) != 0 || r.sources != 0 {
		t.Errorf("before the hour: scans %v, sources %d", got, r.sources)
	}
}

func TestLoopRetriesAFailedScanTwice(t *testing.T) {
	for _, cause := range []error{errors.New("folder gone"), errNoRow} {
		r := newRig(t, at("2026-11-05", "07:00"), "demo")
		r.fail["demo"] = cause
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { Loop(ctx, r.deps(), 5*time.Millisecond); close(done) }()
		wait := func(n int32) {
			start := r.ticks.Load()
			for r.ticks.Load()-start < n {
				time.Sleep(2 * time.Millisecond)
			}
		}
		wait(3)
		if got := r.scanned(); len(got) != 1 {
			t.Fatalf("%v: first try: %v", cause, got)
		}
		r.set(at("2026-11-05", "07:20")) // too early for a retry
		wait(3)
		if got := r.scanned(); len(got) != 1 {
			t.Errorf("%v: retried before 30 minutes: %v", cause, got)
		}
		for i, hm := range []string{"07:31", "08:02", "08:40", "12:00"} {
			r.set(at("2026-11-05", hm))
			wait(3)
			want := min(i+2, 3)
			if got := r.scanned(); len(got) != want {
				t.Errorf("%v at %s: %d tries, want %d", cause, hm, len(got), want)
			}
		}
		// The next day it tries again.
		r.set(at("2026-11-06", "07:05"))
		wait(3)
		if got := r.scanned(); len(got) != 4 {
			t.Errorf("%v: next day: %d tries", cause, len(got))
		}
		cancel()
		<-done
	}
}

func TestLoopSkipsInactiveAndOptedOut(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo", "gone", "manual")
	r.projects[1].Active = false
	r.projects[2].AutoScan = false
	r.look(3)
	if got := r.scanned(); len(got) != 1 || got[0] != "demo" {
		t.Errorf("scans = %v", got)
	}
	// A project deleted from the list is never scanned either.
	r.projects = r.projects[1:]
	r.set(at("2026-11-06", "08:00"))
	r.look(3)
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("scans after deletion = %v", got)
	}
}

func TestLoopWatchOffDoesNothing(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo")
	off := false
	r.pol.Watch.Enabled = &off
	r.look(3)
	if got := r.scanned(); len(got) != 0 || r.sources != 0 {
		t.Errorf("watch off: scans %v, sources %d", got, r.sources)
	}
}

func TestLoopFollowsScanAtChange(t *testing.T) {
	r := newRig(t, at("2026-11-05", "09:00"), "demo")
	r.pol.Watch.ScanAt = "10:00"
	r.look(3)
	if got := r.scanned(); len(got) != 0 {
		t.Fatalf("before 10:00: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Loop(ctx, r.deps(), 5*time.Millisecond); close(done) }()
	r.mu.Lock()
	r.pol.Watch.ScanAt = "08:30"
	r.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.scanned()) == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("after scan_at moved to 08:30: %v", got)
	}
	// Moved again later the same day, past the scan: one more pass.
	r.mu.Lock()
	r.pol.Watch.ScanAt = "09:05"
	r.mu.Unlock()
	r.set(at("2026-11-05", "09:10"))
	deadline = time.Now().Add(5 * time.Second)
	for len(r.scanned()) < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := r.scanned(); len(got) != 2 {
		t.Errorf("after scan_at moved to 09:05: %v", got)
	}
	cancel()
	<-done
}

func TestLoopClockGoesBack(t *testing.T) {
	r := newRig(t, at("2026-11-05", "07:30"), "demo")
	r.look(3)
	r.set(at("2026-11-05", "07:05"))
	r.look(3)
	r.set(at("2026-11-04", "09:00"))
	r.look(3)
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("scans = %v", got)
	}
}

func TestLoopScanRunningElsewhereIsNotAFailure(t *testing.T) {
	r := newRig(t, at("2026-11-05", "07:00"), "demo")
	r.fail["demo"] = fmt.Errorf("%w: demo", scan.ErrScanRunning)
	r.look(3)
	r.set(at("2026-11-05", "08:00"))
	r.look(3)
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("tries = %v", got)
	}
}

// The source read failing (no consent, no network) does not stop the
// offline checks.
func TestLoopScansEvenWhenSourcesFail(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo")
	d := r.deps()
	d.Sources = func(context.Context) error { return errors.New("waiting for consent") }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Loop(ctx, d, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.scanned()) == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("scans = %v", got)
	}
}

// Stopping serve stops the scan in progress, and nothing more starts.
func TestLoopStopsTheRunningScanOnCancel(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo", "shop")
	r.block, r.entered = make(chan struct{}), make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Loop(ctx, r.deps(), 5*time.Millisecond); close(done) }()
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no scan started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop with its context")
	}
	if got := r.scanned(); len(got) != 0 || len(r.entered) != 0 {
		t.Errorf("scans after a stop: %v, %d started", got, len(r.entered))
	}
}

func TestClaimSourcesOncePerDay(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"))
	repo := NewRepo(r.st)
	ctx := context.Background()
	for i, want := range []bool{true, false} {
		got, err := repo.ClaimSources(ctx, "2026-11-05", r.now)
		if err != nil || got != want {
			t.Errorf("claim %d = %v %v", i, got, err)
		}
	}
	if got, err := repo.ClaimSources(ctx, "2026-11-06", r.now); err != nil || !got {
		t.Errorf("next day = %v %v", got, err)
	}
}

// A check stopped with serve (interrupted) or left running by a crash is not
// the check of the day: after a restart the project is checked again. A
// failed check counts.
func TestLastStartsIgnoresInterruptedAndRunning(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo", "shop", "blog")
	for _, row := range [][3]string{
		{"p0", "2026-11-05T06:00:00Z", "ok"},
		{"p0", "2026-11-05T07:10:00Z", "interrupted"},
		{"p1", "2026-11-05T07:20:00Z", "running"},
		{"p2", "2026-11-05T06:30:00Z", "failed"},
	} {
		if _, err := r.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`,
			row[0]+row[1], row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	last, err := NewRepo(r.st).LastStarts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := last["p0"].UTC().Format(time.RFC3339); got != "2026-11-05T06:00:00Z" {
		t.Errorf("demo: last start %s, want the ok one", got)
	}
	if _, has := last["p1"]; has {
		t.Errorf("shop: a running row counts as a check: %v", last["p1"])
	}
	if got := last["p2"].UTC().Format(time.RFC3339); got != "2026-11-05T06:30:00Z" {
		t.Errorf("blog: last start %s, want the failed one", got)
	}
}

func TestLoopChecksAgainAfterAnInterruptedCheck(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo")
	if _, err := r.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES ('s1','p0',?,'interrupted')`,
		at("2026-11-05", "07:10").UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	r.look(3)
	if got := r.scanned(); len(got) != 1 {
		t.Errorf("after an interrupted check: scans %v", got)
	}
}
