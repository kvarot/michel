package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/workcopy"
)

// awaiting starts an attempt whose agent changed a test file, and returns
// it with its proposal, whose tests wait for a click.
func awaiting(t *testing.T, f *fixture) (Attempt, Proposal) {
	t.Helper()
	f.consent()
	evilAgent(f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok || p.TestsStatus != workcopy.TestsAwaiting {
		t.Fatalf("no awaiting proposal: %+v %+v", p, f.attempt(a.ID))
	}
	return f.attempt(a.ID), p
}

// testRuns are the runs of the project's tests the recorder saw.
func testRuns(f *fixture) []run {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	var out []run
	for _, r := range f.rec.runs {
		if r.name == "vendor/bin/phpunit" {
			out = append(out, r)
		}
	}
	return out
}

func TestRunTestsSupersedesWithResult(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	got, err := RunTests(context.Background(), f.d, a.ID, old.Hash)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	runs := testRuns(f)
	if len(runs) != 1 {
		t.Fatalf("test runs = %d, want 1", len(runs))
	}
	parent := filepath.Join(f.d.DataDir, "fix-tmp", a.ID)
	if filepath.Dir(runs[0].dir) != parent || !strings.HasPrefix(filepath.Base(runs[0].dir), "tests-") {
		t.Errorf("the tests ran in %s", runs[0].dir)
	}
	if _, err := os.Lstat(runs[0].dir); err == nil {
		t.Error("the tests folder was left behind")
	}
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if cur.ID != got.ID || got.ID == old.ID || got.TestsStatus != workcopy.TestsPassed || got.Hash == old.Hash ||
		string(got.DiffRaw) != string(old.DiffRaw) || got.Diff != old.Diff || got.CommitSHA != old.CommitSHA || got.Tree != old.Tree ||
		got.RescanClean != old.RescanClean || got.Summary != old.Summary || !slices.Equal(got.Files, old.Files) {
		t.Errorf("new proposal = %+v\nold = %+v", got, old)
	}
	if got.Hash != proposalHash(got.DiffRaw, got.CommitSHA, workcopy.TestsPassed, got.Summary) {
		t.Error("the new hash does not cover the result")
	}
	if n := len(got.Commands); n != len(old.Commands)+1 || got.Commands[n-1] != (RanCommand{What: "tests"}) {
		t.Errorf("commands = %+v", got.Commands)
	}
	if err := Approve(context.Background(), f.d, a.ID, old.Hash); !errors.Is(err, ErrStaleProposal) {
		t.Errorf("Approve with the old hash: %v, want ErrStaleProposal", err)
	}
	if err := Approve(context.Background(), f.d, a.ID, got.Hash); err != nil {
		t.Errorf("Approve with the new hash: %v", err)
	}
	if text := michelText(t, f, a.ID); !strings.Contains(text, i18n.T(i18n.EN, "fix.msg.tests_clicked")) || !strings.Contains(text, "Tests: passed") {
		t.Errorf("Michel's messages = %q", text)
	}
}

func TestRunTestsStaleHashRunsNothing(t *testing.T) {
	f := newFixture(t)
	a, _ := awaiting(t, f)
	before := len(f.rec.names())
	if _, err := RunTests(context.Background(), f.d, a.ID, strings.Repeat("0", 64)); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("RunTests with another hash: %v, want ErrStaleProposal", err)
	}
	if after := len(f.rec.names()); after != before {
		t.Errorf("commands ran: %v", f.rec.names()[before:])
	}
	if ev := f.audits("fix.tests_run"); len(ev) != 1 || ev[0].Result != "refused" {
		t.Errorf("fix.tests_run audit = %+v", ev)
	}
}

func TestRunTestsDroppedWhenAgentProposedMeanwhile(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	var newer Proposal
	inner := f.d.Work.Exec
	f.d.Work.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			// The agent proposes again while the tests run.
			p := old
			p.ID, p.Summary, p.Hash = "", "a newer proposal", strings.Repeat("c", 64)
			var err error
			if newer, err = f.d.Repo.AddProposal(context.Background(), p); err != nil {
				t.Error(err)
			}
		}
		return inner(ctx, name, args, env, dir)
	}
	if _, err := RunTests(context.Background(), f.d, a.ID, old.Hash); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("RunTests: %v, want ErrStaleProposal", err)
	}
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if cur.ID != newer.ID || cur.Summary != "a newer proposal" {
		t.Errorf("the clicked result replaced the newer proposal: %+v", cur)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("state = %s", got.State)
	}
	if text := michelText(t, f, a.ID); !strings.Contains(text, i18n.T(i18n.EN, "fix.msg.tests_dropped")) {
		t.Errorf("Michel's messages = %q", text)
	}
	if ev := f.audits("fix.tests_run"); len(ev) != 2 || ev[0].Result != "started" || ev[1].Result != "dropped" {
		t.Errorf("fix.tests_run audit = %+v", ev)
	}
}

func TestRunTestsTwoRunsOwnFolders(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	inner := f.d.Work.Exec
	var mu sync.Mutex
	dirs := map[string]bool{}
	both := make(chan struct{})
	f.d.Work.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			mu.Lock()
			dirs[dir] = true
			if len(dirs) == 2 {
				close(both)
			}
			mu.Unlock()
			select {
			case <-both:
			case <-time.After(20 * time.Second):
				t.Error("the second run never started")
			}
			// Both folders are whole while both runs go on.
			mu.Lock()
			for d := range dirs {
				if _, err := os.Lstat(filepath.Join(d, "composer.lock")); err != nil {
					t.Errorf("a folder was wiped mid-run: %s", d)
				}
			}
			mu.Unlock()
		}
		return inner(ctx, name, args, env, dir)
	}
	errs := make(chan error, 2)
	// Two processes (serve and michel fix test): each has its own Sessions.
	for range 2 {
		d := f.d
		d.Sessions = NewSessions()
		go func() {
			_, err := RunTests(context.Background(), d, a.ID, old.Hash)
			errs <- err
		}()
	}
	var ok, stale int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrStaleProposal):
			stale++
		default:
			t.Errorf("RunTests: %v", err)
		}
	}
	if ok != 1 || stale != 1 || len(dirs) != 2 {
		t.Errorf("ok=%d stale=%d folders=%v", ok, stale, dirs)
	}
}

func TestRunTestsRefusedWithoutTree(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	p := old
	p.ID, p.Tree, p.Hash = "", "", strings.Repeat("d", 64)
	if _, err := f.d.Repo.AddProposal(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if CanRunTests(p) {
		t.Error("a proposal without its tree offers the button")
	}
	if _, err := RunTests(context.Background(), f.d, a.ID, p.Hash); !errors.Is(err, ErrNoTree) || ErrorKey(err) != "fix.err.no_tree" {
		t.Fatalf("RunTests: %v, want ErrNoTree", err)
	}
	if len(testRuns(f)) != 0 {
		t.Error("the tests ran")
	}
}

func TestRunTestsTimeoutKeepsProposed(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := f.d.Work.Exec
	f.d.Work.Exec = func(c context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			// Tests that hang until their bound.
			cancel()
			<-c.Done()
			return nil, nil, c.Err()
		}
		return inner(c, name, args, env, dir)
	}
	if _, err := RunTests(ctx, f.d, a.ID, old.Hash); !errors.Is(err, ErrTestsInterrupted) {
		t.Fatalf("RunTests: %v, want ErrTestsInterrupted", err)
	}
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || cur.ID != old.ID || cur.TestsStatus != workcopy.TestsAwaiting {
		t.Errorf("state = %s, current = %+v", got.State, cur)
	}
	if ev := f.audits("fix.tests_run"); len(ev) != 2 || ev[0].Result != "started" || ev[1].Result != "interrupted" {
		t.Errorf("fix.tests_run audit = %+v", ev)
	}
}

func TestRunTestsNotAwaitingRefused(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	p := f.proj
	p.AutoFixMinor = false // Michel's own tree: tests run alone, no auto-approval
	f.update(p)
	proposeOnly(f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	prop, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok || prop.TestsStatus != workcopy.TestsPassed {
		t.Fatalf("proposal = %+v", prop)
	}
	runs := len(testRuns(f))
	if _, err := RunTests(context.Background(), f.d, a.ID, prop.Hash); !errors.Is(err, ErrNotAwaiting) {
		t.Fatalf("RunTests: %v, want ErrNotAwaiting", err)
	}
	if len(testRuns(f)) != runs {
		t.Error("the tests ran again")
	}
}

func TestRunTestsAudited(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	got, err := RunTests(context.Background(), f.d, a.ID, old.Hash)
	if err != nil {
		t.Fatal(err)
	}
	ev := f.audits("fix.tests_run")
	if len(ev) != 2 || ev[0].Result != "started" || ev[1].Result != "ok" {
		t.Fatalf("fix.tests_run audit = %+v", ev)
	}
	if e := ev[0].Evidence; e["attempt_id"] != a.ID || e["hash"] != old.Hash || e["author"] != "test" {
		t.Errorf("started evidence = %+v", e)
	}
	ev = ev[1:]
	e := ev[0].Evidence
	if e["attempt_id"] != a.ID || e["proposal_id"] != got.ID || e["hash"] != old.Hash || e["author"] != "test" ||
		e["tests"] != workcopy.TestsPassed || e["files_code"] != float64(2) {
		t.Errorf("evidence = %+v", e)
	}
}
