package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

func TestFindingsMarkKEV(t *testing.T) {
	dir, list := scannedDemo(t, false)
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE finding SET kev = 1, kev_added = '2026-03-12' WHERE id = ?`, list[0].ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, out, _, err := run(t, dir, "findings", "--project", "demo")
	if err != nil || !strings.Contains(out, "[KEV]") || strings.Count(out, "[KEV]") != 1 {
		t.Errorf("findings: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "finding", list[0].ID)
	if err != nil || !strings.Contains(out, "kev: yes, exploited in the wild (CISA KEV list since 2026-03-12)") {
		t.Errorf("finding: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "finding", list[0].ID, "--lang", "fr")
	if err != nil || !strings.Contains(out, "KEV : oui, exploitée dans la nature (liste KEV de la CISA depuis le 12/03/2026)") {
		t.Errorf("finding fr: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "finding", list[0].ID, "--json")
	if err != nil || !strings.Contains(out, `"kev":true`) || !strings.Contains(out, `"kev_added":"2026-03-12"`) {
		t.Errorf("json: %v\n%s", err, out)
	}
}
