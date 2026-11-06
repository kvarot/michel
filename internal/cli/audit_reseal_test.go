package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

// michel.db made again while the secrets folder is kept: verify fails on the
// seals until michel audit reseal --yes, which says what it does first and
// leaves its trace in the log.
func TestAuditResealAfterANewDatabase(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"michel.db", "michel.db-wal", "michel.db-shm", "audit.head"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "audit", "verify"); ExitCode(err) != ExitCodeAuditBroken {
		t.Fatalf("verify before the reseal: %v", err)
	}
	_, out, _, err := run(t, dir, "--lang", "fr", "audit", "reseal")
	if err != nil || !strings.Contains(out, "Avec --yes") {
		t.Fatalf("reseal without --yes: %v\n%s", err, out)
	}
	if _, _, _, err := run(t, dir, "audit", "verify"); ExitCode(err) != ExitCodeAuditBroken {
		t.Fatalf("reseal without --yes changed the log: %v", err)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "audit", "reseal", "--yes")
	if err != nil || !strings.Contains(out, "seals start again") {
		t.Fatalf("reseal --yes: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "audit", "verify")
	if err != nil || !strings.Contains(out, "before the seals") {
		t.Fatalf("verify after the reseal: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "audit", "list")
	if err != nil || !strings.Contains(out, "audit.reseal") {
		t.Errorf("no trace of the reseal: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "audit", "reseal")
	if err != nil || !strings.Contains(out, "nothing to reseal") {
		t.Errorf("second reseal: %v\n%s", err, out)
	}
}

// Removed events are evidence: reseal refuses, with or without --yes.
func TestAuditResealRefusesRemovedEvents(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		if _, _, _, err := run(t, dir, "noop"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`DELETE FROM audit_event WHERE seq = (SELECT MAX(seq) FROM audit_event)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, args := range [][]string{{"audit", "reseal"}, {"audit", "reseal", "--yes"}} {
		_, out, _, err := run(t, dir, append([]string{"--lang", "fr"}, args...)...)
		if ExitCode(err) != ExitCodeAuditBroken || !strings.Contains(out, "ce sont des preuves") {
			t.Errorf("%v: %v\n%s", args, err, out)
		}
	}
}
