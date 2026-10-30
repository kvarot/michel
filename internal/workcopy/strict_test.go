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
)

func TestComposerLockIsReadStrictly(t *testing.T) {
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
			`"node_modules/a":{"version":"1.2.3","resolved":"https://registry.npmjs.org/a/-/a-1.2.3.tgz","integrity":"sha512-abc","dependencies":{"b":"^2.0.0"},"engines":{"node":">=18"}},` +
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

func TestTreeListingCapIsReachable(t *testing.T) {
	if listingCap() >= maxGitOutput {
		t.Errorf("the listing cap %d is not below the git output cap %d: it can never refuse a listing", listingCap(), maxGitOutput)
	}
}
