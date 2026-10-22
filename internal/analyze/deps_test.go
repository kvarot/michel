package analyze

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func load(t *testing.T, dir, eco string) *DepGraph {
	t.Helper()
	g, err := LoadDepGraph(filepath.Join("testdata", "deps", dir), eco)
	if err != nil {
		t.Fatalf("LoadDepGraph: %v", err)
	}
	return g
}

func TestComposerDirectAndTransitive(t *testing.T) {
	g := load(t, "composer", "Packagist")
	if !g.HasRootManifest {
		t.Fatal("expected root manifest")
	}
	p := g.PathTo("acme/vuln")
	if p.Directness != "transitive" || !reflect.DeepEqual(p.Via, []string{"acme/app", "acme/lib"}) {
		t.Fatalf("unexpected path %+v", p)
	}
	d := g.PathTo("acme/app")
	if d.Directness != "direct" || d.Constraint != "^1.0" || len(d.Via) != 0 {
		t.Fatalf("unexpected direct %+v", d)
	}
	if got := g.PathTo("Acme/VULN"); got.Directness != "transitive" {
		t.Fatalf("names must be case-insensitive: %+v", got)
	}
	if dev := g.PathTo("acme/devtool"); dev.Directness != "direct" || dev.Constraint != "^2.0" {
		t.Fatalf("require-dev must be a root: %+v", dev)
	}
}

func TestNpmDirectAndTransitive(t *testing.T) {
	g := load(t, "npm", "npm")
	p := g.PathTo("vuln-pkg")
	if p.Directness != "transitive" || !reflect.DeepEqual(p.Via, []string{"app-pkg"}) {
		t.Fatalf("unexpected path %+v", p)
	}
	if d := g.PathTo("app-pkg"); d.Directness != "direct" || d.Constraint != "^1.0.0" {
		t.Fatalf("unexpected direct %+v", d)
	}
	if d := g.PathTo("dev-pkg"); d.Directness != "direct" {
		t.Fatalf("devDependencies must be roots: %+v", d)
	}
	if o := g.PathTo("opt-pkg"); o.Directness != "transitive" {
		t.Fatalf("optionalDependencies must be edges: %+v", o)
	}
	if n := g.PathTo("nested-pkg"); n.Directness != "unknown" {
		t.Fatalf("nested-pkg is unreachable in this model: %+v", n)
	}
}

func TestNpmRootFallsBackToPackageJSON(t *testing.T) {
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`
	pj := `{"dependencies":{"a":"^1.0.0"}}`
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(pj), 0o644)
	g, err := LoadDepGraph(dir, "npm")
	if err != nil || !g.HasRootManifest {
		t.Fatalf("err=%v g=%+v", err, g)
	}
	if d := g.PathTo("a"); d.Directness != "direct" || d.Constraint != "^1.0.0" {
		t.Fatalf("unexpected %+v", d)
	}
}

func TestNpmUnsupportedLockfileVersion(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":1,"dependencies":{}}`), 0o644)
	_, err := LoadDepGraph(dir, "npm")
	if err == nil || err.Error() != "unsupported package-lock.json lockfileVersion 1" {
		t.Fatalf("got %v", err)
	}
}

func TestComposerWithoutRootManifestIsUnknown(t *testing.T) {
	g := load(t, "composer-nolockroot", "Packagist")
	if g.HasRootManifest {
		t.Fatal("expected no root manifest")
	}
	p := g.PathTo("acme/vuln")
	if p.Directness != "unknown" || len(p.Via) != 0 {
		t.Fatalf("unexpected %+v", p)
	}
}

func TestComposerIgnoresPlatformRequires(t *testing.T) {
	g := load(t, "composer", "Packagist")
	for _, dep := range g.Requires["acme/app"] {
		if dep == "php" || dep == "ext-json" || dep == "lib-pcre" || dep == "composer-plugin-api" {
			t.Fatalf("platform require leaked: %v", g.Requires["acme/app"])
		}
	}
	if _, ok := g.Root["php"]; ok {
		t.Fatal("php leaked into Root")
	}
}

func TestUnknownPackageIsUnknown(t *testing.T) {
	g := load(t, "composer", "Packagist")
	if p := g.PathTo("nobody/nothing"); p.Directness != "unknown" {
		t.Fatalf("unexpected %+v", p)
	}
}

func TestMissingLockfileIsError(t *testing.T) {
	for _, eco := range []string{"Packagist", "npm"} {
		if _, err := LoadDepGraph(t.TempDir(), eco); err == nil {
			t.Fatalf("%s: expected error", eco)
		}
	}
	if _, err := LoadDepGraph(t.TempDir(), "PyPI"); err == nil {
		t.Fatal("expected unsupported ecosystem error")
	}
}
