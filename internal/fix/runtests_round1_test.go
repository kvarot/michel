package fix

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/workcopy"
)

// TestRunTestsOwnBound: a clicked run has its own bound, apart from the
// caller's: tests that hang end at it, nothing is recorded.
func TestRunTestsOwnBound(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	f.d.TestsBound = 300 * time.Millisecond
	if f.d.TestsTimeout() != 300*time.Millisecond || (Deps{}).TestsTimeout() != DefaultTestsTimeout || DefaultTestsTimeout != 30*time.Minute {
		t.Fatalf("bounds: %v %v", f.d.TestsTimeout(), (Deps{}).TestsTimeout())
	}
	inner := f.d.Work.Exec
	f.d.Work.Exec = func(c context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			<-c.Done() // tests that hang
			return nil, nil, c.Err()
		}
		return inner(c, name, args, env, dir)
	}
	start := time.Now()
	if _, err := RunTests(context.Background(), f.d, a.ID, old.Hash); !errors.Is(err, ErrTestsInterrupted) {
		t.Fatalf("RunTests: %v, want ErrTestsInterrupted", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Error("the bound did not hold")
	}
	if cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID); cur.ID != old.ID {
		t.Errorf("a result was recorded: %+v", cur)
	}
}

// TestRunTestsSecondClickRefusedWhileRunning: in one process, a second click
// while the tests run is refused at once; the tests run once.
func TestRunTestsSecondClickRefusedWhileRunning(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	inner := f.d.Work.Exec
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.d.Work.Exec = func(c context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			once.Do(func() { close(started) })
			<-release
		}
		return inner(c, name, args, env, dir)
	}
	done := make(chan error, 1)
	go func() {
		_, err := RunTests(context.Background(), f.d, a.ID, old.Hash)
		done <- err
	}()
	<-started
	_, err := RunTests(context.Background(), f.d, a.ID, old.Hash)
	close(release)
	if !errors.Is(err, ErrTestsRunning) || ErrorKey(err) != "fix.err.tests_running" {
		t.Errorf("second click: %v, want ErrTestsRunning", err)
	}
	if err := <-done; err != nil {
		t.Errorf("first click: %v", err)
	}
	if n := len(testRuns(f)); n != 1 {
		t.Errorf("test runs = %d, want 1", n)
	}
	// Once over, the attempt is free again (the new proposal's tests no longer wait).
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if _, err := RunTests(context.Background(), f.d, a.ID, cur.Hash); !errors.Is(err, ErrNotAwaiting) {
		t.Errorf("after the run: %v, want ErrNotAwaiting", err)
	}
}

// TestRunTestsRechecksBeforeInstall: the agent proposes while Michel writes
// the files: nothing is installed nor run.
func TestRunTestsRechecksBeforeInstall(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	inner := f.d.Work.Exec
	var once sync.Once
	f.d.Work.Exec = func(c context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "git" && len(args) > 0 && strings.Contains(strings.Join(args, " "), "archive") {
			once.Do(func() {
				p := old
				p.ID, p.Hash = "", strings.Repeat("e", 64)
				if _, err := f.d.Repo.AddProposal(context.Background(), p); err != nil {
					t.Error(err)
				}
			})
		}
		return inner(c, name, args, env, dir)
	}
	before := len(f.rec.names())
	if _, err := RunTests(context.Background(), f.d, a.ID, old.Hash); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("RunTests: %v, want ErrStaleProposal", err)
	}
	if names := f.rec.names()[before:]; len(names) != 0 {
		t.Errorf("commands ran: %v", names)
	}
	for _, e := range f.audits("fix.tests_run") {
		if e.Result == "started" {
			t.Error("recorded as started")
		}
	}
}

// TestRunTestsErrorAuditedAndSaid: a failure past the checks is recorded as
// error and said in the conversation; nothing is stored.
func TestRunTestsErrorAuditedAndSaid(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	p := old
	p.ID, p.Tree, p.Hash = "", strings.Repeat("a", 40), strings.Repeat("f", 64) // a tree the copy does not hold
	if _, err := f.d.Repo.AddProposal(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := RunTests(context.Background(), f.d, a.ID, p.Hash); err == nil {
		t.Fatal("RunTests on a missing tree succeeded")
	}
	ev := f.audits("fix.tests_run")
	if len(ev) != 1 || ev[0].Result != "error" {
		t.Errorf("fix.tests_run audit = %+v", ev)
	}
	if text := michelText(t, f, a.ID); !strings.Contains(text, strings.SplitN(i18n.T(i18n.EN, "fix.msg.tests_error", ""), "(", 2)[0]) {
		t.Errorf("Michel's messages = %q", text)
	}
	if cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID); cur.Hash != p.Hash || cur.TestsStatus != workcopy.TestsAwaiting {
		t.Errorf("current = %+v", cur)
	}
}

// TestRunTestsAuditFailureAfterInsertStillSucceeds: the new proposal is
// stored; a failed write of the ok audit does not turn the click into an
// error.
func TestRunTestsAuditFailureAfterInsertStillSucceeds(t *testing.T) {
	f := newFixture(t)
	a, old := awaiting(t, f)
	inner := f.d.Work.Exec
	f.d.Work.Exec = func(c context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name == "vendor/bin/phpunit" {
			if _, err := f.st.DB().Exec(`ALTER TABLE audit_event RENAME TO audit_event_gone`); err != nil {
				t.Error(err)
			}
		}
		return inner(c, name, args, env, dir)
	}
	got, err := RunTests(context.Background(), f.d, a.ID, old.Hash)
	if err != nil {
		t.Fatalf("RunTests: %v", err)
	}
	if cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID); cur.ID != got.ID || got.TestsStatus != workcopy.TestsPassed {
		t.Errorf("current = %+v, got %+v", cur, got)
	}
}
