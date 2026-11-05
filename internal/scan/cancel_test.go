package scan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// fakeScanner replaces osv-scanner for the test.
func fakeScanner(t *testing.T, f func(root string) (models.VulnerabilityResults, error)) {
	t.Helper()
	saved := scanFunc
	scanFunc = func(_ Deps, root string, _ []string, _ func(string) bool, _, _ string) (models.VulnerabilityResults, error) {
		return f(root)
	}
	t.Cleanup(func() { scanFunc = saved })
}

// osv-scanner's logger is a global: Run and ScanDir never run the scanner
// at the same time. (No -race on this machine; the fake counts overlaps.)
func TestScannerCallsAreSerialized(t *testing.T) {
	var inFlight, most atomic.Int32
	fakeScanner(t, func(string) (models.VulnerabilityResults, error) {
		n := inFlight.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inFlight.Add(-1)
		return models.VulnerabilityResults{}, nil
	})
	envs := []env{newEnv(t, "project-a"), newEnv(t, "project-a")}
	var wg sync.WaitGroup
	for _, e := range envs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot}); err != nil {
				t.Errorf("Run: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = ScanDir(context.Background(), e.deps, e.proj.Path, nil, Options{OSVRoot: osvRoot})
		}()
	}
	wg.Wait()
	if m := most.Load(); m != 1 {
		t.Errorf("%d scanner calls ran at once, want 1", m)
	}
}

// A scan waiting for another one to end returns as soon as it is cancelled
// and never runs the scanner.
func TestScanCancelledWhileWaitingNeverScans(t *testing.T) {
	first, second := newEnv(t, "project-a"), newEnv(t, "project-a")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fakeScanner(t, func(root string) (models.VulnerabilityResults, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return models.VulnerabilityResults{}, nil
	})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = Run(context.Background(), first.deps, first.proj, Options{OSVRoot: osvRoot})
	}()
	<-started
	defer func() { close(release); <-firstDone }()
	for _, which := range []string{"Run", "ScanDir"} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			var err error
			if which == "Run" {
				_, err = Run(ctx, second.deps, second.proj, Options{OSVRoot: osvRoot})
			} else {
				_, err = ScanDir(ctx, second.deps, second.proj.Path, nil, Options{OSVRoot: osvRoot})
			}
			done <- err
		}()
		time.Sleep(50 * time.Millisecond) // it is waiting for the first scan
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s = %v, want context.Canceled", which, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not return within 1 s of the cancel", which)
		}
	}
	var status string
	if err := second.st.DB().QueryRow(`SELECT status FROM scan`).Scan(&status); err != nil || status != ScanInterrupted {
		t.Errorf("waiting scan status %q (%v), want %s", status, err, ScanInterrupted)
	}
	close(release)
	<-firstDone
	release = make(chan struct{}) // the deferred close has nothing left to free
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("the scanner ran %d times, want 1 (the cancelled scans never ran it)", n)
	}
}

// A cancel once the scanner has returned does not lose what follows: the
// findings, the manifests and the audit rows are all stored.
func TestCancelAfterTheScannerKeepsEveryRow(t *testing.T) {
	e := newEnv(t, "project-a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lookup := func([]string) (map[string]Enrichment, error) {
		cancel() // after the scanner, before the transaction
		return map[string]Enrichment{}, nil
	}
	r, err := Run(ctx, e.deps, e.proj, Options{OSVRoot: osvRoot, Lookup: lookup})
	if err != nil || r.Status != ScanOK || len(r.Errors) != 0 {
		t.Fatalf("Run = %s %v %v", r.Status, r.Errors, err)
	}
	count := func(q string) int {
		var n int
		if err := e.st.DB().QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM finding`); n != 3 {
		t.Errorf("findings = %d, want 3", n)
	}
	if n := count(`SELECT COUNT(*) FROM scan_manifest`); n != 2 {
		t.Errorf("manifests = %d, want 2", n)
	}
	if n := count(`SELECT COUNT(*) FROM audit_event WHERE action = 'scan.manifest'`); n != 2 {
		t.Errorf("scan.manifest rows = %d, want 2", n)
	}
	if n := count(`SELECT COUNT(*) FROM audit_event WHERE action = 'scan.finish' AND result = 'ok'`); n != 1 {
		t.Errorf("scan.finish ok rows = %d, want 1", n)
	}
}

func TestRunReturnsOnCancel(t *testing.T) {
	e := newEnv(t, "project-a")
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fakeScanner(t, func(string) (models.VulnerabilityResults, error) {
		close(started)
		<-release
		defer close(finished)
		return models.VulnerabilityResults{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, e.deps, e.proj, Options{OSVRoot: osvRoot})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Run did not return within 1 s of the cancel")
	}
	var status string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan`).Scan(&status); err != nil || status != ScanInterrupted {
		t.Errorf("scan status %q (%v), want %s", status, err, ScanInterrupted)
	}
	// The scanner ends later: its result is dropped, nothing is stored.
	close(release)
	<-finished
	time.Sleep(50 * time.Millisecond)
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM finding`).Scan(&n); err != nil || n != 0 {
		t.Errorf("findings after the cancel = %d (%v), want 0", n, err)
	}
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM scan_manifest`).Scan(&n); err != nil || n != 0 {
		t.Errorf("manifests after the cancel = %d (%v), want 0", n, err)
	}
	if err := e.st.DB().QueryRow(`SELECT status FROM scan`).Scan(&status); err != nil || status != ScanInterrupted {
		t.Errorf("scan status after the scanner ended %q (%v)", status, err)
	}
}
