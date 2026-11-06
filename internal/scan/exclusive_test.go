package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// insertRunning adds a scan of the project left running since started, as
// another process scanning it would.
func insertRunning(t *testing.T, e env, id string, started time.Time) {
	t.Helper()
	if _, err := e.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, osv_db_fetched_at, scanner_version, status)
		VALUES (?,?,?,'','other','running')`, id, e.proj.ID, started.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func scanCount(t *testing.T, e env) int {
	t.Helper()
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM scan WHERE project_id = ?`, e.proj.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRunRefusesWhileTheProjectIsScanned(t *testing.T) {
	e := newEnv(t, "project-a")
	insertRunning(t, e, "other-scan", time.Now().Add(-5*time.Minute))
	_, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	if !errors.Is(err, ErrScanRunning) {
		t.Fatalf("err = %v, want ErrScanRunning", err)
	}
	if n := scanCount(t, e); n != 1 {
		t.Errorf("%d scan rows, want only the running one", n)
	}
	var status string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan WHERE id = 'other-scan'`).Scan(&status); err != nil || status != "running" {
		t.Errorf("the other scan = %q %v", status, err)
	}
}

func TestRunIgnoresAStaleRunningScan(t *testing.T) {
	e := newEnv(t, "project-a")
	insertRunning(t, e, "dead-scan", time.Now().Add(-2*StaleScanAfter))
	if r := e.run(t); r.Status != ScanOK {
		t.Fatalf("status = %s", r.Status)
	}
	var status string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan WHERE id = 'dead-scan'`).Scan(&status); err != nil || status != ScanInterrupted {
		t.Errorf("the dead scan = %q %v", status, err)
	}
}

// Another process marked this scan interrupted while it ran: the end of the
// scan does not turn it into a success, and its findings are not written.
func TestRunDoesNotRewriteAnInterruptedScan(t *testing.T) {
	e := newEnv(t, "project-a")
	saved := afterScanHook
	afterScanHook = func() {
		if _, err := e.st.DB().Exec(`UPDATE scan SET status = 'interrupted', error = 'swept' WHERE status = 'running'`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterScanHook = saved })
	r, err := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	if err == nil || r.Status != ScanInterrupted {
		t.Fatalf("status = %s, err = %v", r.Status, err)
	}
	var status, msg string
	if err := e.st.DB().QueryRow(`SELECT status, error FROM scan WHERE id = ?`, r.ScanID).Scan(&status, &msg); err != nil ||
		status != ScanInterrupted || msg != "swept" {
		t.Errorf("row = %q %q %v", status, msg, err)
	}
	var findings int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM finding WHERE project_id = ?`, e.proj.ID).Scan(&findings); err != nil || findings != 0 {
		t.Errorf("%d findings written, %v", findings, err)
	}
}

// The same holds for a failure stored after the other process marked the
// scan interrupted.
func TestFailureDoesNotRewriteAnInterruptedScan(t *testing.T) {
	e := newEnv(t, "project-a")
	fakeScanner(t, func(string) (models.VulnerabilityResults, error) {
		if _, err := e.st.DB().Exec(`UPDATE scan SET status = 'interrupted', error = 'swept' WHERE status = 'running'`); err != nil {
			t.Error(err)
		}
		return models.VulnerabilityResults{}, errors.New("boom")
	})
	r, _ := Run(context.Background(), e.deps, e.proj, Options{OSVRoot: osvRoot})
	var status string
	if err := e.st.DB().QueryRow(`SELECT status FROM scan WHERE id = ?`, r.ScanID).Scan(&status); err != nil || status != ScanInterrupted {
		t.Errorf("row = %q %v", status, err)
	}
}
