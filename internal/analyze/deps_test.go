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

func writeNpm(t *testing.T, lock string) *DepGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadDepGraph(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestNpmHoistedCopyWinsForRequires(t *testing.T) {
	g := writeNpm(t, `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"1"}},
"node_modules/a":{"version":"1.0.0"},
"node_modules/a/node_modules/x":{"version":"1.0.0","dependencies":{"nested-only":"1"}},
"node_modules/x":{"version":"2.0.0","dependencies":{"top-only":"1"}}}}`)
	if got := g.Requires["x"]; !reflect.DeepEqual(got, []string{"top-only"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNpmRootOptionalAndPeerAreDirect(t *testing.T) {
	g := writeNpm(t, `{"lockfileVersion":3,"packages":{
"":{"optionalDependencies":{"opt":"^1"},"peerDependencies":{"peer":"^2"}},
"node_modules/opt":{"version":"1.0.0"},"node_modules/peer":{"version":"2.0.0"}}}`)
	if p := g.PathTo("opt"); p.Directness != "direct" || p.Constraint != "^1" {
		t.Fatalf("%+v", p)
	}
	if p := g.PathTo("peer"); p.Directness != "direct" {
		t.Fatalf("%+v", p)
	}
}

func TestPathToCycleTerminates(t *testing.T) {
	g := &DepGraph{Ecosystem: "npm", HasRootManifest: true, Root: map[string]string{"a": ""},
		Requires: map[string][]string{"a": {"b"}, "b": {"a", "c"}}}
	if p := g.PathTo("c"); !reflect.DeepEqual(p.Via, []string{"a", "b"}) {
		t.Fatalf("%+v", p)
	}
	if p := g.PathTo("zzz"); p.Directness != "unknown" {
		t.Fatalf("%+v", p)
	}
}

func TestPathToDirectWinsOverTransitive(t *testing.T) {
	g := &DepGraph{Ecosystem: "npm", HasRootManifest: true, Root: map[string]string{"a": "", "b": "^1"},
		Requires: map[string][]string{"a": {"b"}}}
	if p := g.PathTo("b"); p.Directness != "direct" || len(p.Via) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestPathToTieBrokenLexically(t *testing.T) {
	g := &DepGraph{Ecosystem: "npm", HasRootManifest: true, Root: map[string]string{"z": "", "m": ""},
		Requires: map[string][]string{"z": {"t"}, "m": {"t"}}}
	for i := 0; i < 20; i++ {
		if p := g.PathTo("t"); !reflect.DeepEqual(p.Via, []string{"m"}) {
			t.Fatalf("%+v", p)
		}
	}
}

func TestComposerDevOnlyTransitiveReachable(t *testing.T) {
	g := &DepGraph{Ecosystem: "Packagist", HasRootManifest: true, Root: map[string]string{"acme/devtool": "^2"},
		Requires: map[string][]string{"acme/devtool": {"acme/devdep"}}}
	if p := g.PathTo("acme/devdep"); p.Directness != "transitive" || !reflect.DeepEqual(p.Via, []string{"acme/devtool"}) {
		t.Fatalf("%+v", p)
	}
}

func TestNpmNamesAreCaseSensitive(t *testing.T) {
	g := load(t, "npm", "npm")
	if p := g.PathTo("App-Pkg"); p.Directness != "unknown" {
		t.Fatalf("%+v", p)
	}
}
