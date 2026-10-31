package vulnmatch

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func rng(fixed string) string {
	return `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]`
}

func aff(eco, name, ranges string) string {
	return `{"package":{"ecosystem":"` + eco + `","name":"` + name + `"},` + ranges + `}`
}

func adv(id string, extra string, affected ...string) string {
	return `{"id":"` + id + `",` + extra + `"affected":[` + strings.Join(affected, ",") + `]}`
}

// buildRoot writes a fabricated archive of the base ecosystem into a temp dir.
func buildRoot(t *testing.T, baseEco string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	p := osvdb.ZipPath(root, baseEco)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
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

func fixtureRoot(t *testing.T) string {
	return buildRoot(t, "Debian", map[string]string{"DSA-0000-1.json": dsa, "DSA-0000-2.json": dsaEpoch, "DSA-0000-3.json": dsaOther})
}

func run(t *testing.T, root, eco string, pkgs []target.Package) Result {
	t.Helper()
	res, err := Match(context.Background(), root, eco, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestMatchDebianSourcePackage(t *testing.T) {
	pkgs := []target.Package{
		{Name: "php8.2-fpm", Source: "php8.2", Version: "8.2.7-1", Arch: "amd64"},
		{Name: "curl", Source: "curl", Version: "7.0", Arch: "amd64"},
	}
	res := run(t, fixtureRoot(t), "Debian:12", pkgs)
	if len(res.Hits) != 1 || !res.ReleaseKnown {
		t.Fatalf("res %+v", res)
	}
	h := res.Hits[0]
	if h.Package.Name != "php8.2-fpm" || h.OSVID != "DSA-0000-1" || h.Fixed != "8.2.20-1" || h.Severity != "high" || h.Uncertain {
		t.Errorf("hit %+v", h)
	}
	if len(h.Aliases) != 1 || h.Aliases[0] != "CVE-0000-0001" {
		t.Errorf("aliases %v", h.Aliases)
	}
}

func TestMatchFixedVersionNotReported(t *testing.T) {
	for _, v := range []string{"8.2.20-1", "8.2.20-1+deb12u1", "8.3.0-1"} {
		res := run(t, fixtureRoot(t), "Debian:12", []target.Package{{Name: "php8.2", Version: v}})
		if len(res.Hits) != 0 || len(res.Unjudged) != 0 {
			t.Errorf("%s: %+v", v, res)
		}
	}
}

func TestDebianEpochComparison(t *testing.T) {
	// 8.2.99 < 1:8.2.20-1 because of the epoch: affected.
	res := run(t, fixtureRoot(t), "Debian:12", []target.Package{{Name: "epochpkg", Version: "8.2.99"}})
	if len(res.Hits) != 1 {
		t.Fatalf("%+v", res)
	}
	res = run(t, fixtureRoot(t), "Debian:12", []target.Package{{Name: "epochpkg", Version: "1:8.2.20-1"}})
	if len(res.Hits) != 0 {
		t.Fatalf("fixed: %+v", res)
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
	res := Result{Hits: []Hit{{Package: target.Package{Name: "php8.2-fpm", Version: "8.2.7-1"}, Source: "php8.2", Binaries: []string{"php8.2-cli", "php8.2-fpm"}, OSVID: "DSA-0000-1", Aliases: []string{"CVE-0000-0001"}, Severity: "high", Fixed: "8.2.20-1"}}}
	fs := Findings(target.Target{ID: "srv-demo"}, res)
	if len(fs) != 1 {
		t.Fatalf("findings %v", fs)
	}
	f := fs[0]
	if f.Kind != scan.KindServerPackage || f.ProjectID != "srv-demo" || f.Package != "php8.2" || f.OSVID != "DSA-0000-1" || f.InstalledVersion != "8.2.7-1" || len(f.FixedVersions) != 1 || f.Aliases[0] != "CVE-0000-0001" || f.ID == "" {
		t.Errorf("finding %+v", f)
	}
	if !strings.Contains(f.Summary, "php8.2-cli, php8.2-fpm") {
		t.Errorf("summary %q", f.Summary)
	}
}

// I1: what cannot be compared is reported as affected and as unjudged.
func TestUnparseableVersionIsUncertainAndUnjudged(t *testing.T) {
	res := run(t, fixtureRoot(t), "Debian:12", []target.Package{{Name: "php8.2", Version: "x:1"}})
	if len(res.Hits) != 1 || !res.Hits[0].Uncertain || len(res.Unjudged) != 1 || res.Unjudged[0].OSVID != "DSA-0000-1" || res.Unjudged[0].Reason == "" {
		t.Fatalf("%+v", res)
	}
}

func TestUnparseableBoundIsAffected(t *testing.T) {
	root := buildRoot(t, "Debian", map[string]string{"a.json": adv("DSA-0000-9", "", aff("Debian:12", "foo", rng("x:1")))})
	res := run(t, root, "Debian:12", []target.Package{{Name: "foo", Version: "1.0"}})
	if len(res.Hits) != 1 || !res.Hits[0].Uncertain || len(res.Unjudged) != 1 {
		t.Fatalf("%+v", res)
	}
}

// I2: a release the database does not know is not "clean".
func TestUnknownReleaseNotKnown(t *testing.T) {
	res := run(t, fixtureRoot(t), "Debian:99", []target.Package{{Name: "php8.2", Version: "1"}})
	if res.ReleaseKnown || len(res.Hits) != 0 {
		t.Fatalf("%+v", res)
	}
}

// I3: CVSS vectors are scored.
func TestVectorSeverity(t *testing.T) {
	cases := []struct {
		vec, label string
		min        float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical", 9.8},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical", 9.8},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", "high", 7.5},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "low", 0.1},
		{"7.5", "high", 7.5},
		{"garbage", "unknown", 0},
	}
	for _, c := range cases {
		a := advisory{Severity: []struct {
			Score string `json:"score"`
		}{{Score: c.vec}}}
		l, sc := severity(a)
		if l != c.label || sc < c.min {
			t.Errorf("%s: %s %v", c.vec, l, sc)
		}
	}
}

// I4: one hit per advisory and source, however many binaries and architectures.
func TestCollapsePerSource(t *testing.T) {
	pkgs := []target.Package{
		{Name: "php8.2-fpm", Source: "php8.2", Version: "8.2.7-1", Arch: "amd64"},
		{Name: "php8.2-cli", Source: "php8.2", Version: "8.2.7-1", Arch: "amd64"},
		{Name: "php8.2-common", Source: "php8.2", Version: "8.2.7-1", Arch: "amd64"},
		{Name: "php8.2-common", Source: "php8.2", Version: "8.2.7-1", Arch: "i386"},
	}
	res := run(t, fixtureRoot(t), "Debian:12", pkgs)
	if len(res.Hits) != 1 {
		t.Fatalf("%+v", res.Hits)
	}
	if got := strings.Join(res.Hits[0].Binaries, ","); got != "php8.2-cli,php8.2-common,php8.2-fpm" {
		t.Errorf("binaries %s", got)
	}
	if fs := Findings(target.Target{ID: "srv-demo"}, res); len(fs) != 1 {
		t.Fatalf("findings %d", len(fs))
	}
}

func TestSecondAffectedEntryKeepsFixed(t *testing.T) {
	root := buildRoot(t, "Debian", map[string]string{"a.json": adv("DSA-0000-8", "",
		aff("Debian:12", "foo", `"versions":["1.0"]`),
		aff("Debian:12", "foo", rng("2.0")))})
	for i := 0; i < 5; i++ {
		res := run(t, root, "Debian:12", []target.Package{{Name: "foo", Version: "1.0"}})
		if len(res.Hits) != 1 || res.Hits[0].Fixed != "2.0" {
			t.Fatalf("%+v", res.Hits)
		}
	}
}

// I5: Alpine and RPM ecosystems.
func TestMatchAlpine(t *testing.T) {
	root := buildRoot(t, "Alpine", map[string]string{"a.json": adv("ALPINE-0000-1", `"aliases":["CVE-0000-0003"],`, aff("Alpine:v3.19", "php82", rng("8.2.20-r1")))})
	res := run(t, root, "Alpine:v3.19", []target.Package{
		{Name: "php82-fpm", Source: "php82", Version: "8.2.20-r0"},
		{Name: "php82", Version: "8.2.20-r1"},
	})
	if len(res.Hits) != 1 || res.Hits[0].Fixed != "8.2.20-r1" {
		t.Fatalf("%+v", res)
	}
}

func TestMatchRockyBinaryOrSourceName(t *testing.T) {
	root := buildRoot(t, "Rocky Linux", map[string]string{
		"a.json": adv("RLSA-0000:1", "", aff("Rocky Linux:9", "php-fpm", rng("0:8.2.20-1.el9"))),
		"b.json": adv("RLSA-0000:2", "", aff("Rocky Linux:9", "php", rng("0:8.2.20-1.el9"))),
	})
	res := run(t, root, "Rocky Linux:9", []target.Package{{Name: "php-fpm", Source: "php", Version: "0:8.2.7-1.el9", Arch: "x86_64"}})
	if len(res.Hits) != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestMatchSkipsBadAndOddEntries(t *testing.T) {
	root := buildRoot(t, "Debian", map[string]string{
		"bad.json":       "{not json",
		"note.txt":       "ignored",
		"withdrawn.json": adv("DSA-0000-5", `"withdrawn":"2024-01-01T00:00:00Z",`, aff("Debian:12", "foo", rng("9"))),
		"last.json":      adv("DSA-0000-6", "", aff("Debian:12", "foo", `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.5"}]}]`)),
	})
	res := run(t, root, "Debian:12", []target.Package{{Name: "foo", Version: "1.0"}, {Name: "bar", Version: "1.0"}})
	if res.Skipped != 1 || len(res.Hits) != 1 || res.Hits[0].OSVID != "DSA-0000-6" {
		t.Fatalf("%+v", res)
	}
}
