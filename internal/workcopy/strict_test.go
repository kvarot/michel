package workcopy

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/project"
)

func TestComposerLockIsReadStrictly(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	for i, lock := range []string{
		// Case variants: Go's struct decoding would keep Type/URL, PHP the lower-case ones.
		`{"packages":[{"name":"a/b","dist":{"type":"path","url":"../outside","Type":"zip","URL":"https://x"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"path","url":"../outside"}}],"Packages":[]}`,
		`{"packages":[],"packages":[{"name":"a/b","dist":{"type":"path","url":"../outside"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"zip","url":"https://x"},"dist":{"type":"path","url":"../outside"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"artifact","url":"https://x"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"zip","url":"http://x"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"zip"}}]}`,
		`{"packages":[{"name":"a/b","dist":{"type":"zip","url":["https://x"]}}]}`,
		`{"packages":[{"name":"a/b","source":{"type":"path","url":"../x","Type":"git","Url":"https://x"}}]}`,
		`{"packages":[{"name":"a/b","source":{"type":"git","url":"file:///x"}}]}`,
		`{"packages":[{"name":"a/b","Dist":{"type":"path","url":"../outside"}}]}`,
		`{"Packages-Dev":[{"name":"a/b","dist":{"type":"path","url":"../outside"}}]}`,
		`{"packages":"x"}`,
		`{"packages":[1]}`,
		`[]`,
		`{"packages":[]} {}`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"composer.lock": lock}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.lock %s: %v, want ErrUnsafeInstall", lock, err)
		}
	}
	// preferred-install must stay "dist": a source install runs git, hg or
	// svn against the lockfile's source URLs.
	for i, cj := range []string{`{"config":{"preferred-install":"source"}}`, `{"config":{"preferred-install":{"*":"source"}}}`, `{"config":{"preferred-install":"auto"}}`} {
		if err := installCase(t, d, c, fmt.Sprintf("j%d", i), map[string]string{"composer.lock": "{}", "composer.json": cj}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.json %s: %v, want ErrUnsafeInstall", cj, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	lock := `{"packages":[{"name":"a/b","dist":{"type":"zip","url":"https://api.github.com/repos/a/b/zipball/x","reference":"x","shasum":""},"source":{"type":"git","url":"git@github.com:a/b.git","reference":"x"}}],` +
		`"packages-dev":[{"name":"c/d","dist":{"type":"tar","url":"https://r.example/d.tar"}}],"platform":{"php":">=8.2"}}`
	if err := installCase(t, d, c, "ok", map[string]string{"composer.lock": lock, "composer.json": `{"config":{"preferred-install":"dist"}}`}); err != nil {
		t.Errorf("a plain composer.lock refused: %v", err)
	}
}

func TestPackageLockIsReadStrictly(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	entry := func(fields string) string {
		return `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{` + fields + `}}}`
	}
	registry := `"version":"1.0.0","integrity":"sha512-x","resolved":"https://r.example/a.tgz"`
	for i, lock := range []string{
		entry(`"version":"1.0.0","integrity":"sha512-x","resolved":"file:../../outside","Resolved":"https://r.example/a.tgz"`),
		entry(`"version":"file:../../outside"`),
		entry(`"version":"1.0.0","resolved":"https://r.example/a.tgz"`), // no integrity
		entry(`"version":"1.0.0","integrity":"sha512-x"`),               // no resolved
		entry(`"version":"1.0.0","integrity":"sha512-x","resolved":"http://r.example/a.tgz"`),
		entry(`"version":"https://evil.example/a.tgz","integrity":"sha512-x","resolved":"https://r.example/a.tgz"`),
		entry(`"version":"git+ssh://git@evil.example/x.git","integrity":"sha512-x","resolved":"https://r.example/a.tgz"`),
		entry(`"link":true,"resolved":"../outside"`),
		entry(`"link":true,"resolved":"C:/outside"`),
		entry(`"link":true`),
		entry(`"link":"true","resolved":"https://r.example/a.tgz"`),
		entry(registry + `,"inBundle":"yes"`),
		`{"lockfileVersion":1,"dependencies":{"a":{"version":"file:../../outside"}}}`,
		`{"packages":{"":{}}}`,
		`{"lockfileVersion":"3","packages":{"":{}}}`,
		`{"lockfileVersion":3,"packages":[]}`,
		`{"lockfileVersion":3,"packages":{"../../../outside":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":3,"packages":{"/abs":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":3,"packages":{"C:/x":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules\\a":{` + registry + `}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/.git/x":{` + registry + `}}}`,
		`{"lockfileVersion":3,"packages":{"packages/w":{"version":"1.0.0","resolved":"file:../x"}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/a":1}}`,
		`{"lockfileVersion":3,"packages":{"":{}},"Packages":{"node_modules/a":{"version":"file:../x"}}}`,
		`{"LockfileVersion":3,"packages":{"":{}}}`,
		entry(`"Link":true,"resolved":"../outside"`),
		`{"lockfileVersion":3,"packages":{"":{}},"packages":{"node_modules/a":{"version":"file:../x"}}}`,
		`{"lockfileVersion":3,"packages":{"":{}}} x`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"package-lock.json": lock}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("package-lock.json %s: %v, want ErrUnsafeInstall", lock, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	for i, lock := range []string{
		`{"name":"demo","lockfileVersion":3,"requires":true,"packages":{` +
			`"":{"name":"demo","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"a":"^1.2.3"}},` +
			`"node_modules/a":{"version":"1.2.3","resolved":"https://registry.npmjs.org/a/-/a-1.2.3.tgz","integrity":"sha512-abc","dependencies":{"b":"^2.0.0"},"bundleDependencies":["c"],"engines":{"node":">=18"}},` +
			`"node_modules/a/node_modules/b":{"version":"2.0.0-beta.1+build.5","resolved":"https://registry.npmjs.org/b/-/b-2.0.0-beta.1.tgz","integrity":"sha512-def","dev":true},` +
			`"node_modules/a/node_modules/c":{"version":"1.0.0","inBundle":true},` +
			`"node_modules/w":{"resolved":"packages/w","link":true},` +
			`"packages/w":{"name":"w","version":"0.1.0","dependencies":{"a":"^1.2.3"}}}}`,
		`{"lockfileVersion":2,"packages":{"":{},"node_modules/a":{` + registry + `}},"dependencies":{"a":{"version":"1.0.0","resolved":"https://r.example/a.tgz","integrity":"sha512-x"}}}`,
	} {
		rec.runs = nil
		if err := installCase(t, d, c, fmt.Sprintf("ok%d", i), map[string]string{"package-lock.json": lock}); err != nil {
			t.Errorf("a plain package-lock.json refused: %v", err)
		} else if len(rec.runs) != 1 {
			t.Errorf("the install ran %d commands, want 1", len(rec.runs))
		}
	}
}

func TestStrictJSONRefusesAmbiguousDocuments(t *testing.T) {
	parallel(t)
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"x":{"a":1,"a":2}}`, `{"x":[{"a":1,"A":2}]}`, `{} {}`, `{"a":1} x`, `{"a":`, `x`, ``, `{"a":1}}`} {
		if _, err := strictJSON([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	v, err := strictJSON([]byte(` {"a":{"b":[1,"x",true,null,{"c":1.5}]},"B":"y"} `))
	if err != nil {
		t.Fatalf("a plain document refused: %v", err)
	}
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 2 {
		t.Fatalf("got %#v", v)
	}
	if _, err := strictObject([]byte(`[1]`)); err == nil {
		t.Error("an array was accepted as an object")
	}
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	if _, err := strictJSON([]byte(deep)); err == nil {
		t.Error("a 200-level document was accepted")
	}
}

func TestInstallRefusesJunctionedLockfileDir(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	outside := t.TempDir()
	writeFile(t, outside, "composer.lock", "{}")
	writeFile(t, outside, "vendor/keep.txt", "keep\n")
	writeFile(t, outside, "app/composer.lock", "{}")
	writeFile(t, outside, "app/vendor/keep.txt", "keep\n")
	writeFile(t, outside, "app/package-lock.json", minLock)
	writeFile(t, outside, "app/node_modules/keep.txt", "keep\n")
	writeFile(t, outside, "app/package.json", `{"packageManager":"yarn@https://evil.example/x.tgz"}`)
	// A junction at the folder of the lockfile, and one at a parent of it.
	if !junction(t, filepath.Join(c.Dir, "j"), outside) {
		t.Skip("no junction or symbolic link available")
	}
	writeFile(t, c.Dir, "p/.keep", "")
	if !junction(t, filepath.Join(c.Dir, "p", "link"), outside) {
		t.Fatal("second junction")
	}
	for _, tc := range []struct{ eco, rel string }{
		{"Packagist", "j/composer.lock"}, {"Packagist", "j/app/composer.lock"},
		{"npm", "j/app/package-lock.json"}, {"Packagist", "p/link/app/composer.lock"}, {"npm", "p/link/app/package-lock.json"},
	} {
		if err := Install(context.Background(), d, c, tc.eco, tc.rel); !errors.Is(err, ErrOutsideCopy) {
			t.Errorf("Install(%s) through a junction: %v, want ErrOutsideCopy", tc.rel, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("an install through a junction ran %d commands", len(rec.runs))
	}
	for _, rel := range []string{"vendor/keep.txt", "app/vendor/keep.txt", "app/node_modules/keep.txt"} {
		if b, err := os.ReadFile(filepath.Join(outside, filepath.FromSlash(rel))); err != nil || string(b) != "keep\n" {
			t.Errorf("%s outside the copy was touched: %v", rel, err)
		}
	}
	// node_modules itself a junction to an outside folder: the junction goes,
	// its target is not emptied.
	writeFile(t, c.Dir, "q/package-lock.json", minLock)
	if junction(t, filepath.Join(c.Dir, "q", "node_modules"), filepath.Join(outside, "app", "node_modules")) {
		if err := Install(context.Background(), d, c, "npm", "q/package-lock.json"); err != nil {
			t.Errorf("Install with a junctioned node_modules: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outside, "app", "node_modules", "keep.txt")); err != nil {
			t.Error("the target of the node_modules junction was emptied")
		}
	}
}

func TestArchiveHoldsNoExcludedFiles(t *testing.T) {
	parallel(t)
	f := newFixture(t)
	var names []string
	f.deps.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		out, errOut, err := defaultExec(ctx, name, args, env, dir)
		if name == "git" && gitSubcommand(args) == "archive" {
			i := slices.Index(args, "-o")
			if i < 0 || i+1 >= len(args) {
				t.Fatalf("archive without -o: %v", args)
			}
			p := args[i+1]
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			a, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			tr := tar.NewReader(a)
			for {
				hdr, err := tr.Next()
				if err != nil {
					break
				}
				names = append(names, hdr.Name)
			}
		}
		return out, errOut, err
	}
	c := prepare(t, f)
	if len(names) == 0 {
		t.Fatal("no archive seen")
	}
	for _, n := range names {
		rel := strings.TrimSuffix(n, "/")
		if isExcluded(rel, f.proj.Exclude) || strings.HasPrefix(rel, "private") {
			t.Errorf("the archive holds the excluded %s", n)
		}
	}
	if !slices.Contains(names, "README.md") || !slices.Contains(names, "src/app.php") {
		t.Errorf("the archive misses plain files: %v", names)
	}
	want := []string{".env", "config/.env.local", "config/server.key", "private/notes.txt"}
	if !slices.Equal(c.Excluded, want) {
		t.Errorf("Excluded %v, want %v", c.Excluded, want)
	}
}

func TestComposerPackageNamesAreChecked(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	dist := `"dist":{"type":"zip","url":"https://r.example/x.zip","reference":"abc","shasum":""}`
	for i, lock := range []string{
		// The reproduced probe: composer installs into vendor/<name>.
		`{"packages":[{"name":"c/x/../../../../../outside/victim",` + dist + `}]}`,
		`{"packages":[{"name":"../outside",` + dist + `}]}`,
		`{"packages":[{"name":"Acme/Lib",` + dist + `}]}`,
		`{"packages":[{"name":"acme",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib/x",` + dist + `}]}`,
		`{"packages":[{"name":"acme/.lib",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib---x",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib ",` + dist + `}]}`,
		`{"packages":[{` + dist + `}]}`,
		`{"packages":[{"name":1,` + dist + `}]}`,
		`{"packages-dev":[{"name":"acme/lib","target-dir":"../../x",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib","type":"wordpress-plugin",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib","type":"custom-installer",` + dist + `}]}`,
		`{"packages":[{"name":"acme/lib","Type":"library",` + dist + `}]}`,
		// dist and source members: only type, url, reference, shasum.
		`{"packages":[{"name":"acme/lib","dist":{"type":"zip","url":"https://r.example/x.zip","mirrors":[{"url":"file:///outside/secret.zip","preferred":true}]}}]}`,
		`{"packages":[{"name":"acme/lib","dist":{"type":"zip","url":"https://r.example/x.zip","transport-options":{"ssl":{"verify_peer":false}}}}]}`,
		`{"packages":[{"name":"acme/lib","source":{"type":"git","url":"https://r.example/x.git","mirrors":[{"url":"/outside/%package%","preferred":true}]}}]}`,
		`{"packages":[{"name":"acme/lib","dist":{"type":"zip","url":"https://r.example/x.zip","Mirrors":[]}}]}`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"composer.lock": lock}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.lock %s: %v, want ErrUnsafeInstall", lock, err)
		}
	}
	for i, cj := range []string{
		`{"require":{"../outside":"*"}}`,
		`{"require":{"c/x/../../../../../outside/victim":"*"}}`,
		`{"require-dev":{"Acme/Lib":"^1"}}`,
		`{"require":"acme/lib"}`,
		`{"target-dir":"../x"}`,
		`{"type":"wordpress-plugin"}`,
		`{"Type":"library"}`,
		`{"Require":{"../x":"*"}}`,
	} {
		if err := installCase(t, d, c, fmt.Sprintf("j%d", i), map[string]string{"composer.lock": "{}", "composer.json": cj}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("composer.json %s: %v, want ErrUnsafeInstall", cj, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	lock := `{"packages":[{"name":"acme/lib-x",` + dist + `,"type":"library"},{"name":"a1/b_c.d","type":"metapackage"},{"name":"acme/plug","type":"composer-plugin",` + dist + `}],` +
		`"packages-dev":[{"name":"acme/tpl","type":"project","source":{"type":"git","url":"https://r.example/x.git","reference":"abc"}}]}`
	cj := `{"name":"acme/app","type":"project","require":{"php":">=8.2","ext-json":"*","ext-pdo_mysql":"*","lib-curl":"*","composer-runtime-api":"^2","acme/lib-x":"^1"},"require-dev":{"a1/b_c.d":"*"}}`
	if err := installCase(t, d, c, "ok", map[string]string{"composer.lock": lock, "composer.json": cj}); err != nil {
		t.Errorf("a plain composer project refused: %v", err)
	}
}

func TestNpmWorkspaceFoldersStayInTheCopy(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	outside := t.TempDir()
	writeFile(t, outside, "node_modules/keep.txt", "keep\n")
	reg := `"version":"1.0.0","integrity":"sha512-x","resolved":"https://r.example/x.tgz"`
	// The reproduced probe: a lock key under src, src being a junction.
	writeFile(t, c.Dir, "a/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"src/node_modules/x":{`+reg+`}}}`)
	if !junction(t, filepath.Join(c.Dir, "a", "src"), outside) {
		t.Skip("no junction or symbolic link available")
	}
	if err := Install(context.Background(), d, c, "npm", "a/package-lock.json"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("lock key through a junction: %v, want ErrOutsideCopy", err)
	}
	// A deeper junction, and a workspace folder of package.json.
	writeFile(t, c.Dir, "b/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"packages/w/node_modules/x":{`+reg+`}}}`)
	writeFile(t, c.Dir, "b/packages/.keep", "")
	if !junction(t, filepath.Join(c.Dir, "b", "packages", "w"), outside) {
		t.Fatal("junction")
	}
	if err := Install(context.Background(), d, c, "npm", "b/package-lock.json"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("lock key through a deeper junction: %v, want ErrOutsideCopy", err)
	}
	writeFile(t, c.Dir, "w/package-lock.json", minLock)
	writeFile(t, c.Dir, "w/package.json", `{"workspaces":["apps/web","packages/*"]}`)
	writeFile(t, c.Dir, "w/apps/.keep", "")
	if !junction(t, filepath.Join(c.Dir, "w", "apps", "web"), outside) {
		t.Fatal("junction")
	}
	if err := Install(context.Background(), d, c, "npm", "w/package-lock.json"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("workspace folder through a junction: %v, want ErrOutsideCopy", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("an install ran %d commands", len(rec.runs))
	}
	if b, err := os.ReadFile(filepath.Join(outside, "node_modules", "keep.txt")); err != nil || string(b) != "keep\n" {
		t.Errorf("the outside folder was touched: %v", err)
	}
	// Every node_modules named by the lock starts fresh, not only the top one.
	writeFile(t, c.Dir, "e/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/w":{"link":true,"resolved":"packages/w"},"packages/w":{"version":"1.0.0"},"packages/w/node_modules/x":{`+reg+`}}}`)
	writeFile(t, c.Dir, "e/node_modules/old/index.js", "x\n")
	writeFile(t, c.Dir, "e/packages/w/node_modules/evil/index.js", "x\n")
	writeFile(t, c.Dir, "e/packages/w/package.json", `{"name":"w"}`)
	if junction(t, filepath.Join(c.Dir, "e", "packages", "w", "node_modules", "link"), outside) {
		t.Log("junction planted inside the workspace's node_modules")
	}
	if err := Install(context.Background(), d, c, "npm", "e/package-lock.json"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, rel := range []string{"e/node_modules", "e/packages/w/node_modules"} {
		if _, err := os.Lstat(filepath.Join(c.Dir, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was not reset", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "e", "packages", "w", "package.json")); err != nil {
		t.Error("the workspace itself was deleted")
	}
	if b, err := os.ReadFile(filepath.Join(outside, "node_modules", "keep.txt")); err != nil || string(b) != "keep\n" {
		t.Errorf("the outside folder was touched by the reset: %v", err)
	}
}

func TestBundledEntriesNeedABundlingParent(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	reg := `"version":"1.0.0","integrity":"sha512-x","resolved":"https://r.example/a.tgz"`
	lock := func(entries string) string { return `{"lockfileVersion":3,"packages":{"":{},` + entries + `}}` }
	for i, l := range []string{
		lock(`"node_modules/a":{` + reg + `,"inBundle":true,"resolved":"file:../x"}`),
		lock(`"node_modules/a":{"version":"1.0.0","inBundle":true,"resolved":"file:../../outside"}`),
		lock(`"node_modules/a":{"version":"1.0.0","inBundle":true,"resolved":"git+ssh://git@evil.example/x.git"}`),
		lock(`"node_modules/a":{"version":"1.0.0","inBundle":true}`),                                               // no parent
		lock(`"node_modules/a":{` + reg + `},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true}`), // parent does not bundle b
		lock(`"node_modules/a":{` + reg + `,"bundleDependencies":["c"]},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true}`),
		lock(`"node_modules/a":{` + reg + `,"bundleDependencies":"b"},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true}`),
		lock(`"node_modules/a":{` + reg + `,"BundleDependencies":["b"]},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true}`),
		lock(`"node_modules/a":{` + reg + `,"bundleDependencies":["b"]},"node_modules/a/node_modules/b":{"inBundle":true}`), // no version
	} {
		if err := installCase(t, d, c, fmt.Sprintf("l%d", i), map[string]string{"package-lock.json": l}); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("package-lock.json %s: %v, want ErrUnsafeInstall", l, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused install ran %d commands", len(rec.runs))
	}
	for i, l := range []string{
		lock(`"node_modules/a":{` + reg + `,"bundleDependencies":["b","@s/c"]},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true},"node_modules/a/node_modules/@s/c":{"version":"2.0.0","inBundle":true}`),
		lock(`"node_modules/a":{` + reg + `,"bundleDependencies":true},"node_modules/a/node_modules/b":{"version":"1.0.0","inBundle":true,"resolved":"https://r.example/b.tgz"}`),
	} {
		if err := installCase(t, d, c, fmt.Sprintf("ok%d", i), map[string]string{"package-lock.json": l}); err != nil {
			t.Errorf("bundled dependencies refused: %v", err)
		}
	}
}

func TestPrepareOfTreeWithOnlyExcludedFiles(t *testing.T) {
	parallel(t)
	needGit(t)
	env := testGitEnv(t)
	for name, files := range map[string][]string{"only-excluded": {".env", "private/notes.txt"}, "empty": nil} {
		root := t.TempDir()
		gitT(t, env, root, "init", "-q", "-b", "main")
		for _, f := range files {
			writeFile(t, root, f, "x\n")
		}
		gitT(t, env, root, "add", "-A")
		gitT(t, env, root, "commit", "-q", "--allow-empty", "-m", "init")
		p := project.Project{ID: "01JDEMO0000000000000000000", Name: "demo", Path: root, Exclude: []string{"private"}}
		d := Deps{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:1"}
		c, err := Prepare(context.Background(), d, p, "01JATTEMPT0000000000000000")
		if err != nil {
			t.Errorf("%s: Prepare: %v", name, err)
			continue
		}
		entries, _ := os.ReadDir(c.Dir)
		if len(entries) != 1 || entries[0].Name() != ".git" {
			t.Errorf("%s: the copy holds %d entries, want only .git", name, len(entries))
		}
		want := []string{}
		if files != nil {
			want = []string{".env", "private/notes.txt"}
		}
		if !slices.Equal(c.Excluded, want) {
			t.Errorf("%s: Excluded %v, want %v", name, c.Excluded, want)
		}
		writeFile(t, c.Dir, "README.md", "new\n")
		sha, err := Commit(context.Background(), d, c, "fix")
		if err != nil {
			t.Errorf("%s: Commit: %v", name, err)
			continue
		}
		if got := gitT(t, env, c.Mirror, "diff", "--name-only", c.Base, sha); got != "README.md" {
			t.Errorf("%s: the fix commit changes %q", name, got)
		}
		if err := Remove(d, c); err != nil {
			t.Error(err)
		}
	}
}

func TestCheckBinaryRefusesUnreadableFiles(t *testing.T) {
	parallel(t)
	dir := t.TempDir()
	writeFile(t, dir, "b.bin", "\x00\x01\x02")
	// A changed file that is not on disk and not deleted.
	if err := checkBinary(dir, []string{"missing.bin"}, nil); err == nil {
		t.Error("a missing file was skipped")
	}
	old := maxCopyFile
	maxCopyFile = 2
	if err := checkBinary(dir, []string{"b.bin"}, nil); !errors.Is(err, ErrDiffTooLarge) {
		t.Errorf("a file over the cap: %v, want ErrDiffTooLarge", err)
	}
	maxCopyFile = old
	outside := t.TempDir()
	writeFile(t, outside, "x.bin", "\x00\x01")
	if junction(t, filepath.Join(dir, "j"), outside) {
		if err := checkBinary(dir, []string{"j/x.bin"}, nil); !errors.Is(err, ErrOutsideCopy) {
			t.Errorf("a file through a junction: %v, want ErrOutsideCopy", err)
		}
	}
	if err := checkBinary(dir, []string{"b.bin"}, nil); err != nil {
		t.Errorf("a real binary refused: %v", err)
	}
}

func TestTreeListingCapIsReachable(t *testing.T) {
	parallel(t)
	if listingCap() >= maxGitOutput {
		t.Errorf("the listing cap %d is not below the git output cap %d: it can never refuse a listing", listingCap(), maxGitOutput)
	}
}

// Ruling 29: a lock key is a literal folder path. Glob characters are
// refused, and its folder prefixes are never cut at a wildcard (a key
// "src*/node_modules/x" must not stop the junction check before src*).
func TestLockKeysAreLiteral(t *testing.T) {
	parallel(t)
	for _, k := range []string{"node_modules/a*", "src?/node_modules/x", "node_modules/[a]", "node_modules/{a,b}", "node_modules/!a", "a]/node_modules/x", "a}/node_modules/x"} {
		if validLockKey(k) {
			t.Errorf("validLockKey(%q) = true, want false", k)
		}
	}
	for _, k := range []string{"node_modules/a", "node_modules/@s/b", "packages/w/node_modules/x"} {
		if !validLockKey(k) {
			t.Errorf("validLockKey(%q) = false, want true", k)
		}
	}
	if got := lockPrefixes("a/b*/c"); !slices.Equal(got, []string{"a", "a/b*", "a/b*/c"}) {
		t.Errorf("lockPrefixes = %v, want literal prefixes", got)
	}
	if got := workspacePrefixes("apps/*/web"); !slices.Equal(got, []string{"apps"}) {
		t.Errorf("workspacePrefixes = %v, want [apps]", got)
	}
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	reg := `"version":"1.0.0","integrity":"sha512-x","resolved":"https://r.example/x.tgz"`
	writeFile(t, c.Dir, "g/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"src*/node_modules/x":{`+reg+`}}}`)
	if err := Install(context.Background(), d, c, "npm", "g/package-lock.json"); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("glob lock key: %v, want ErrUnsafeInstall", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("an install ran %d commands", len(rec.runs))
	}
}

// Ruling 29: the target of a linked package is checked like a key: a
// link or junction at any of its folders refuses the install.
func TestLinkTargetsAreChecked(t *testing.T) {
	parallel(t)
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	outside := t.TempDir()
	writeFile(t, outside, "keep.txt", "keep\n")
	for _, bad := range []string{"pack*s/w", "packages/../w", "packages/.git/w"} {
		writeFile(t, c.Dir, "b/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/w":{"link":true,"resolved":"`+bad+`"}}}`)
		if err := Install(context.Background(), d, c, "npm", "b/package-lock.json"); !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("link target %q: %v, want ErrUnsafeInstall", bad, err)
		}
	}
	writeFile(t, c.Dir, "a/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/w":{"link":true,"resolved":"libs/w"}}}`)
	writeFile(t, c.Dir, "a/libs/.keep", "")
	if !junction(t, filepath.Join(c.Dir, "a", "libs", "w"), outside) {
		t.Skip("no junction or symbolic link available")
	}
	if err := Install(context.Background(), d, c, "npm", "a/package-lock.json"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("link target through a junction: %v, want ErrOutsideCopy", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("an install ran %d commands", len(rec.runs))
	}
	if b, err := os.ReadFile(filepath.Join(outside, "keep.txt")); err != nil || string(b) != "keep\n" {
		t.Errorf("the outside folder was touched: %v", err)
	}
}

// Ruling 29: checkPackageJSON returns the workspaces it collected together
// with the error of the walk, whatever the evaluation order.
func TestCheckPackageJSONReturnsWorkspaces(t *testing.T) {
	parallel(t)
	dir := t.TempDir()
	writeFile(t, dir, "p/package.json", `{"workspaces":["apps/web","packages/*"]}`)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ws, err := checkPackageJSON(root, "p")
	if err != nil || !slices.Equal(ws, []string{"apps/web", "packages/*"}) {
		t.Errorf("checkPackageJSON = %v, %v; want the two workspaces", ws, err)
	}
}
