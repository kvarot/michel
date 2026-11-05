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
