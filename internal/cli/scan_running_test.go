package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// insertRunningScan leaves a scan of the project running, as another Michel
// scanning it would.
func insertRunningScan(t *testing.T, dir, name string, started time.Time) {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().Exec(`INSERT INTO scan (id, project_id, started_at, osv_db_fetched_at, scanner_version, status)
		SELECT 'other-'||id, id, ?, '', 'other', 'running' FROM project WHERE name = ?`, started.UTC().Format(time.RFC3339), name); err != nil {
		t.Fatal(err)
	}
}

func TestScanSaysAnotherScanRuns(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	insertRunningScan(t, dir, "demo", time.Now().Add(-time.Minute))
	_, _, errOut, err := run(t, dir, "--lang", "fr", "scan", "--project", "demo", "--osv-db", db)
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut, "un contrôle de demo est déjà en cours") {
		t.Errorf("stderr = %q", errOut)
	}
}
