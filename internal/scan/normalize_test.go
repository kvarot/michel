package scan

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestFindingIDStable(t *testing.T) {
	a := FindingID("p1", "composer.lock", "Packagist", "acme/vuln", "ACME-1")
	if len(a) != 16 {
		t.Fatalf("id %q is not 16 hex chars", a)
	}
	if b := FindingID("p1", "composer.lock", "Packagist", "acme/vuln", "ACME-1"); a != b {
		t.Errorf("same input gave %q and %q", a, b)
	}
	if b := FindingID("p1", "web/composer.lock", "Packagist", "acme/vuln", "ACME-1"); a == b {
		t.Error("a different manifest must give a different id")
	}
}

func TestSeverityLabel(t *testing.T) {
	for _, c := range []struct {
		in    string
		label string
		score float64
	}{{"", "unknown", 0}, {"9.8", "critical", 9.8}, {"7.5", "high", 7.5}, {"5.3", "medium", 5.3}, {"2.1", "low", 2.1}, {"n/a", "unknown", 0}} {
		l, s := SeverityLabel(c.in)
		if l != c.label || s != c.score {
			t.Errorf("SeverityLabel(%q) = %s,%v want %s,%v", c.in, l, s, c.label, c.score)
		}
	}
}

func loadAdvisory(t *testing.T, doc string) *osvschema.Vulnerability {
	t.Helper()
	v := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal([]byte(doc), v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFixedVersions(t *testing.T) {
	v := loadAdvisory(t, `{"id":"X-1","modified":"2026-10-01T00:00:00Z","affected":[
	 {"package":{"ecosystem":"Packagist","name":"acme/vuln"},"ranges":[
	   {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.1"}]},
	   {"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.0.5"},{"fixed":"1.0.1"}]},
	   {"type":"GIT","repo":"https://x/y","events":[{"introduced":"0"},{"fixed":"deadbeef"}]}]},
	 {"package":{"ecosystem":"Packagist","name":"acme/other"},"ranges":[
	   {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}]}`)
	got := FixedVersions(v, "Packagist", "acme/vuln")
	if want := []string{"1.0.1", "2.0.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if got := FixedVersions(v, "Packagist", "nobody"); len(got) != 0 {
		t.Errorf("unknown package gave %v", got)
	}
}

func TestNormalizeRelPathSlash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	src := filepath.Join(root, "web", "sub", "package-lock.json")
	v := loadAdvisory(t, `{"id":"X-1","modified":"2026-10-01T00:00:00Z","summary":"s","aliases":["CVE-1"],"affected":[
	 {"package":{"ecosystem":"npm","name":"vuln-pkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}`)
	r := models.VulnerabilityResults{Results: []models.PackageSource{{
		Source: models.SourceInfo{Path: src},
		Packages: []models.PackageVulns{{
			Package:         models.PackageInfo{Name: "vuln-pkg", Version: "1.0.0", Ecosystem: "npm"},
			DepGroups:       []string{"dev"},
			Vulnerabilities: []*osvschema.Vulnerability{v, v},
			Groups:          []models.GroupInfo{{IDs: []string{"X-1"}, MaxSeverity: "7.5"}},
		}},
	}}}
	fs, ms := Normalize("p1", root, r)
	if len(ms) != 1 || ms[0].RelPath != "web/sub/package-lock.json" || ms[0].Packages != 1 || ms[0].Ecosystem != "npm" {
		t.Fatalf("manifests = %+v", ms)
	}
	if len(fs) != 1 {
		t.Fatalf("duplicate vulnerability not collapsed: %d findings", len(fs))
	}
	f := fs[0]
	if f.ManifestRelPath != "web/sub/package-lock.json" || f.SeverityLabel != "high" || f.CVSS != 7.5 ||
		f.InstalledVersion != "1.0.0" || !reflect.DeepEqual(f.FixedVersions, []string{"1.0.1"}) ||
		!reflect.DeepEqual(f.Aliases, []string{"CVE-1"}) || !reflect.DeepEqual(f.DepGroups, []string{"dev"}) {
		t.Errorf("finding = %+v", f)
	}
	if f.ID != FindingID("p1", "web/sub/package-lock.json", "npm", "vuln-pkg", "X-1") {
		t.Error("id does not follow FindingID")
	}
}

func TestNormalizeFlagsMaliciousAsCritical(t *testing.T) {
	root := filepath.Join(t.TempDir(), "proj")
	mal := loadAdvisory(t, `{"id":"MAL-2024-0001","modified":"2026-10-01T00:00:00Z","summary":"Malicious code in vuln-pkg","affected":[
	 {"package":{"ecosystem":"npm","name":"vuln-pkg"},"versions":["1.0.0"]}]}`)
	plain := loadAdvisory(t, `{"id":"X-2","modified":"2026-10-01T00:00:00Z","affected":[
	 {"package":{"ecosystem":"npm","name":"vuln-pkg"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}`)
	r := models.VulnerabilityResults{Results: []models.PackageSource{{
		Source: models.SourceInfo{Path: filepath.Join(root, "package-lock.json")},
		Packages: []models.PackageVulns{{
			Package:         models.PackageInfo{Name: "vuln-pkg", Version: "1.0.0", Ecosystem: "npm"},
			Vulnerabilities: []*osvschema.Vulnerability{mal, plain},
			Groups:          []models.GroupInfo{{IDs: []string{"MAL-2024-0001"}}, {IDs: []string{"X-2"}, MaxSeverity: "5.0"}},
		}},
	}}}
	fs, _ := Normalize("p1", root, r)
	if len(fs) != 2 {
		t.Fatalf("findings = %+v", fs)
	}
	for _, f := range fs {
		if f.Kind != KindDependency {
			t.Errorf("%s kind %q", f.OSVID, f.Kind)
		}
		mal := f.OSVID == "MAL-2024-0001"
		if f.Malicious != mal || (mal && f.SeverityLabel != "critical") || (!mal && f.SeverityLabel != "medium") {
			t.Errorf("finding = %+v", f)
		}
	}
}
