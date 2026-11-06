package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/store"
)

func TestAuditVerifyChecksSeals(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "audit-key")); err != nil {
		t.Fatalf("no seal key after the first start: %v", err)
	}
	_, out, _, err := run(t, dir, "--lang", "fr", "audit", "verify")
	if err != nil || !strings.Contains(out, "1 sceau vérifié") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	// A seal changed by hand is caught.
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE audit_event SET hmac = 'ab' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, out, _, err = run(t, dir, "audit", "verify")
	if ExitCode(err) != ExitCodeAuditBroken || !strings.Contains(out, audit.ReasonSealMismatch) {
		t.Errorf("changed seal: %v\n%s", err, out)
	}
}

func TestAuditVerifyFailsWithoutTheAnchor(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "audit.head")); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "audit", "verify")
	if ExitCode(err) != ExitCodeAuditBroken || !strings.Contains(out, "BROKEN") {
		t.Errorf("required: %v\n%s", err, out)
	}
	// integrity_protection: none keeps the old answer: a warning.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("sovereignty:\n  audit:\n    integrity_protection: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _, err = run(t, dir, "audit", "verify")
	if err != nil || !strings.Contains(out, "head anchor absent") {
		t.Errorf("none: %v\n%s", err, out)
	}
}

func TestSecretSetRefusesTheAuditKey(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"secret", "set", "audit-key"}, {"secret", "delete", "audit-key"}} {
		_, _, _, err := run(t, dir, args...)
		if err == nil || !strings.Contains(err.Error(), "audit-key") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// Without the key, stripping every seal and blanking the sealed anchor is
// still caught.
func TestAuditVerifyCatchesABlankedSealedAnchor(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := run(t, dir, "noop"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE audit_event SET hmac = ''`,
		`UPDATE audit_anchor SET sealed_from = 0, sealed_seq = 0, sealed_head = '', sealed_mac = ''`} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	_, out, _, err := run(t, dir, "--lang", "fr", "audit", "verify")
	if ExitCode(err) != ExitCodeAuditBroken || !strings.Contains(out, "marque scellée") {
		t.Errorf("blanked anchor: %v\n%s", err, out)
	}
}
