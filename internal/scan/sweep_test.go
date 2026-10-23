package scan

import (
	"context"
	"testing"
	"time"
)

func insertRunningScan(t *testing.T, e env, id string, started time.Time) {
	t.Helper()
	if _, err := e.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`,
		id, e.proj.ID, started.UTC().Format(time.RFC3339), "running"); err != nil {
		t.Fatal(err)
	}
}

func scanRow(t *testing.T, e env, id string) (status, errText, finished string) {
	t.Helper()
	if err := e.st.DB().QueryRow(`SELECT status, error, finished_at FROM scan WHERE id=?`, id).Scan(&status, &errText, &finished); err != nil {
		t.Fatal(err)
	}
	return status, errText, finished
}

func TestSweepStaleMarksOldRunning(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	insertRunningScan(t, e, "old", now.Add(-2*time.Hour))
	n, err := SweepStale(context.Background(), e.st.DB(), now, StaleScanAfter)
	if err != nil || n != 1 {
		t.Fatalf("swept %d, err %v", n, err)
	}
	status, errText, finished := scanRow(t, e, "old")
	if status != ScanInterrupted || errText != "Michel stopped before this scan finished" || finished != now.Format(time.RFC3339) {
		t.Errorf("row = %q %q %q", status, errText, finished)
	}
	if n, err := SweepStale(context.Background(), e.st.DB(), now, StaleScanAfter); err != nil || n != 0 {
		t.Errorf("second sweep: %d %v", n, err)
	}
}

func TestSweepStaleLeavesRecentRunning(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	insertRunningScan(t, e, "recent", now.Add(-10*time.Minute))
	n, err := SweepStale(context.Background(), e.st.DB(), now, StaleScanAfter)
	if err != nil || n != 0 {
		t.Fatalf("swept %d, err %v", n, err)
	}
	if status, errText, _ := scanRow(t, e, "recent"); status != "running" || errText != "" {
		t.Errorf("row = %q %q", status, errText)
	}
}

func TestScanSweepsStaleScansFirst(t *testing.T) {
	e := newEnv(t, "project-a")
	insertRunningScan(t, e, "old", time.Now().Add(-2*time.Hour))
	r := e.run(t)
	if r.Swept != 1 {
		t.Errorf("swept = %d", r.Swept)
	}
	if status, _, _ := scanRow(t, e, "old"); status != ScanInterrupted {
		t.Errorf("old scan status = %q", status)
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action='scan.sweep'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("scan.sweep events = %d err %v", n, err)
	}
	if r := e.run(t); r.Swept != 0 {
		t.Errorf("second run swept %d", r.Swept)
	}
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action='scan.sweep'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("scan.sweep events after a clean run = %d err %v", n, err)
	}
}
