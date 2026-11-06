package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPURL(t *testing.T) {
	for _, c := range []struct{ eco, name, version, want string }{
		{"Packagist", "monolog/monolog", "2.0.0", "pkg:composer/monolog/monolog@2.0.0"},
		{"npm", "lodash", "4.17.0", "pkg:npm/lodash@4.17.0"},
		{"npm", "@scope/name", "1.0.0", "pkg:npm/%40scope/name@1.0.0"},
		{"Go", "golang.org/x/net", "0.1.0", "pkg:golang/golang.org/x/net@0.1.0"},
		{"Foo", "x", "1", ""},
	} {
		if got := PURL(c.eco, c.name, c.version); got != c.want {
			t.Errorf("PURL(%s, %s, %s) = %q, want %q", c.eco, c.name, c.version, got, c.want)
		}
	}
}

func TestRunStoresComponentsOnOK(t *testing.T) {
	e := newEnv(t)
	lock := `{"content-hash":"x","packages":[{"name":"acme/vuln","version":"1.0.0"},{"name":"acme/safe","version":"2.0.0"}],"packages-dev":[{"name":"acme/tool","version":"3.0.0"}]}`
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	r := e.run(t)
	if r.Status != ScanOK {
		t.Fatalf("status %s errors %v", r.Status, r.Errors)
	}
	id, cs, err := e.repo.ListComponents(context.Background(), e.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if id != r.ScanID || len(cs) != 3 {
		t.Fatalf("scan %q (want %q), components %+v", id, r.ScanID, cs)
	}
	want := []Component{
		{"composer.lock", "Packagist", "acme/safe", "2.0.0", "pkg:composer/acme/safe@2.0.0", ""},
		{"composer.lock", "Packagist", "acme/tool", "3.0.0", "pkg:composer/acme/tool@3.0.0", "dev"},
		{"composer.lock", "Packagist", "acme/vuln", "1.0.0", "pkg:composer/acme/vuln@1.0.0", ""},
	}
	for i := range want {
		if cs[i] != want[i] {
			t.Errorf("component %d = %+v, want %+v", i, cs[i], want[i])
		}
	}
}

func TestPartialScanKeepsComponents(t *testing.T) {
	e := newEnv(t, "project-a")
	first := e.run(t)
	if first.Status != ScanOK {
		t.Fatalf("scan 1: %s %v", first.Status, first.Errors)
	}
	_, before, err := e.repo.ListComponents(context.Background(), e.proj.ID)
	if err != nil || len(before) == 0 {
		t.Fatalf("components %+v, err %v", before, err)
	}
	if err := os.WriteFile(filepath.Join(e.proj.Path, "composer.lock"), []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	second := e.run(t)
	if second.Status != ScanPartial {
		t.Fatalf("scan 2 status %s", second.Status)
	}
	id, after, err := e.repo.ListComponents(context.Background(), e.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if id != first.ScanID || len(after) != len(before) {
		t.Fatalf("scan %q (want %q), components %+v, before %+v", id, first.ScanID, after, before)
	}
	for i := range before {
		if after[i] != before[i] {
			t.Errorf("component %d changed: %+v -> %+v", i, before[i], after[i])
		}
	}
}
