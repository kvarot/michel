package vulnmatch

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func TestEcosystemFromOSRelease(t *testing.T) {
	cases := []struct {
		id, ver, want string
		ok            bool
	}{
		{"debian", "12", "Debian:12", true},
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS", true},
		{"ubuntu", "23.10", "Ubuntu:23.10", true},
		{"alpine", "3.19.1", "Alpine:v3.19", true},
		{"almalinux", "9.3", "AlmaLinux:9", true},
		{"rocky", "9.2", "Rocky Linux:9", true},
		{"arch", "", "", false},
		{"debian", "", "", false},
		{"fedora", "39", "", false},
	}
	for _, c := range cases {
		got, ok := Ecosystem(target.OSInfo{ID: c.id, VersionID: c.ver})
		if got != c.want || ok != c.ok {
			t.Errorf("%s %s: got %q,%v want %q,%v", c.id, c.ver, got, ok, c.want, c.ok)
		}
	}
	if k := CatalogKey("Debian:12"); k != "osv.debian" {
		t.Errorf("key %q", k)
	}
	if k := CatalogKey("Rocky Linux:9"); k != "osv.rocky-linux" {
		t.Errorf("key %q", k)
	}
}

const dsa = `{"id":"DSA-0000-1","aliases":["CVE-0000-0001"],"database_specific":{"severity":"High"},
"affected":[{"package":{"ecosystem":"Debian:12","name":"php8.2"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.2.20-1"}]}]}]}`

const dsaEpoch = `{"id":"DSA-0000-2","aliases":["CVE-0000-0002"],
"affected":[{"package":{"ecosystem":"Debian:12","name":"epochpkg"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:8.2.20-1"}]}]}]}`

const dsaOther = `{"id":"DSA-0000-3","affected":[{"package":{"ecosystem":"Debian:11","name":"php8.2"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}]}`

// fixtureRoot builds a fabricated Debian archive in a temp dir.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	p := osvdb.ZipPath(root, "Debian")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range map[string]string{"DSA-0000-1.json": dsa, "DSA-0000-2.json": dsaEpoch, "DSA-0000-3.json": dsaOther} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestMatchDebianSourcePackage(t *testing.T) {
	pkgs := []target.Package{
		{Name: "php8.2-fpm", Source: "php8.2", Version: "8.2.7-1", Arch: "amd64"},
		{Name: "curl", Source: "curl", Version: "7.0", Arch: "amd64"},
	}
	hits, err := Match(context.Background(), fixtureRoot(t), "Debian:12", pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits %+v", hits)
	}
	h := hits[0]
	if h.Package.Name != "php8.2-fpm" || h.OSVID != "DSA-0000-1" || h.Fixed != "8.2.20-1" || h.Severity != "high" {
		t.Errorf("hit %+v", h)
	}
	if len(h.Aliases) != 1 || h.Aliases[0] != "CVE-0000-0001" {
		t.Errorf("aliases %v", h.Aliases)
	}
}

func TestMatchFixedVersionNotReported(t *testing.T) {
	for _, v := range []string{"8.2.20-1", "8.2.20-1+deb12u1", "8.3.0-1"} {
		hits, err := Match(context.Background(), fixtureRoot(t), "Debian:12", []target.Package{{Name: "php8.2", Version: v}})
		if err != nil || len(hits) != 0 {
			t.Errorf("%s: hits %v err %v", v, hits, err)
		}
	}
}

func TestDebianEpochComparison(t *testing.T) {
	// 8.2.99 < 1:8.2.20-1 because of the epoch: affected.
	hits, err := Match(context.Background(), fixtureRoot(t), "Debian:12", []target.Package{{Name: "epochpkg", Version: "8.2.99"}})
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits %v err %v", hits, err)
	}
	// 1:8.2.20-1 is the fix itself.
	hits, err = Match(context.Background(), fixtureRoot(t), "Debian:12", []target.Package{{Name: "epochpkg", Version: "1:8.2.20-1"}})
	if err != nil || len(hits) != 0 {
		t.Fatalf("fixed: hits %v err %v", hits, err)
	}
}

func TestMissingDatabaseIsSourceDisabled(t *testing.T) {
	_, err := Match(context.Background(), t.TempDir(), "Debian:12", nil)
	var sd ErrSourceDisabled
	if !errors.As(err, &sd) || sd.Key != "osv.debian" {
		t.Fatalf("err %v", err)
	}
}

func TestFindingsAreServerPackage(t *testing.T) {
	hits := []Hit{{Package: target.Package{Name: "php8.2-fpm", Version: "8.2.7-1"}, OSVID: "DSA-0000-1", Aliases: []string{"CVE-0000-0001"}, Severity: "high", Fixed: "8.2.20-1"}}
	fs := Findings(target.Target{ID: "srv-demo"}, hits)
	if len(fs) != 1 {
		t.Fatalf("findings %v", fs)
	}
	f := fs[0]
	if f.Kind != scan.KindServerPackage || f.ProjectID != "srv-demo" || f.OSVID != "DSA-0000-1" || f.InstalledVersion != "8.2.7-1" || len(f.FixedVersions) != 1 || f.Aliases[0] != "CVE-0000-0001" || f.ID == "" {
		t.Errorf("finding %+v", f)
	}
}
