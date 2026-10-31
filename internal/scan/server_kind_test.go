package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/store"
)

func TestProjectListIgnoresServerFindings(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, k := range []struct{ id, kind string }{
		{"f-dep", KindDependency}, {"f-pkg", KindServerPackage}, {"f-cfg", KindServerConfig},
	} {
		if _, err := st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
			installed_version, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, kind)
			VALUES (?, 'P1', '', 'Debian', 'openssl', 'CVE-2099-0001', 'high', '1', 'new', 's', 's', '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z', ?)`,
			k.id, k.kind); err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []string{"", "all", "actionable", "new"} {
		got, err := NewRepo(st).ListFindings(context.Background(), "P1", status)
		if err != nil || len(got) != 1 || got[0].ID != "f-dep" {
			t.Fatalf("status %q: %+v, %v", status, got, err)
		}
	}
}
