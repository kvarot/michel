package workcopy

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestUpdateUsesInstallChecks(t *testing.T) {
	rec := &recorder{}
	d := Deps{DataDir: t.TempDir(), Exec: rec.exec}
	c := fakeCopy(t, d)
	composer := []string{"composer", "update", "acme/lib:^1.2.5", "--with-all-dependencies", "--no-scripts", "--no-plugins", "--no-interaction"}
	npm := []string{"npm", "install", "left-pad@1.0.1", "--save-exact", "--ignore-scripts", "--no-audit", "--no-fund"}

	// A plain project: the command runs in the lockfile's folder with the
	// fix environment, npm with Michel's empty npmrc.
	writeFile(t, c.Dir, "composer.lock", "{}")
	writeFile(t, c.Dir, "web/package-lock.json", minLock)
	if err := Update(context.Background(), d, c, "Packagist", "composer.lock", composer); err != nil {
		t.Fatalf("composer update: %v", err)
	}
	if err := Update(context.Background(), d, c, "npm", "web/package-lock.json", npm); err != nil {
		t.Fatalf("npm install: %v", err)
	}
	if len(rec.runs) != 2 || rec.runs[0].name != "composer" || !slices.Equal(rec.runs[0].args, composer[1:]) || rec.runs[0].dir != c.Dir {
		t.Errorf("composer run = %+v", rec.runs[0])
	}
	npmrc := filepath.Join(d.DataDir, "fix-home", "npmrc")
	if r := rec.runs[1]; r.name != "npm" || !slices.Equal(r.args, append(append([]string{}, npm[1:]...), "--userconfig", npmrc)) || r.dir != filepath.Join(c.Dir, "web") {
		t.Errorf("npm run = %+v", r)
	}
	for _, r := range rec.runs {
		if home := envValue(r.env, "HOME"); home != filepath.Join(d.DataDir, "fix-home") {
			t.Errorf("%s ran with HOME=%q", r.name, home)
		}
	}

	// Hostile settings in the copy: refused before anything runs, like an
	// install.
	rec.runs = nil
	writeFile(t, c.Dir, "composer.json", `{"config":{"bin-dir":"../outside"}}`)
	if err := Update(context.Background(), d, c, "Packagist", "composer.lock", composer); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("hostile composer.json config: %v, want ErrUnsafeInstall", err)
	}
	writeFile(t, c.Dir, "web/.npmrc", "script-shell=/bin/sh\n")
	if err := Update(context.Background(), d, c, "npm", "web/package-lock.json", npm); !errors.Is(err, ErrUnsafeInstall) {
		t.Errorf("hostile .npmrc: %v, want ErrUnsafeInstall", err)
	}
	writeFile(t, c.Dir, "y/yarn.lock", "# yarn lockfile v1\n")
	if err := Update(context.Background(), d, c, "npm", "y/yarn.lock", npm); !errors.Is(err, ErrInstallUnsupported) {
		t.Errorf("yarn: %v, want ErrInstallUnsupported", err)
	}
	if len(rec.runs) != 0 {
		t.Errorf("a refused update ran %d commands", len(rec.runs))
	}

	// Argv outside the closed forms.
	writeFile(t, c.Dir, "composer.json", `{"name":"acme/app"}`)
	for name, argv := range map[string][]string{
		"shell":          {"sh", "-c", "composer update"},
		"wrong program":  {"npm", "update", "acme/lib", "--no-scripts", "--no-plugins", "--no-interaction"},
		"missing flag":   {"composer", "update", "acme/lib", "--with-all-dependencies", "--no-scripts", "--no-plugins"},
		"extra flag":     {"composer", "update", "acme/lib", "--no-scripts", "--no-plugins", "--no-interaction", "--ignore-platform-reqs"},
		"two packages":   {"composer", "update", "acme/lib", "acme/other", "--no-scripts", "--no-plugins", "--no-interaction"},
		"path package":   {"composer", "require", "../x", "--no-scripts", "--no-plugins", "--no-interaction"},
		"url constraint": {"composer", "require", "acme/lib:https://evil/x.zip", "--no-scripts", "--no-plugins", "--no-interaction"},
		"other sub":      {"composer", "run-script", "acme/lib", "--no-scripts", "--no-plugins", "--no-interaction"},
	} {
		if err := Update(context.Background(), d, c, "Packagist", "composer.lock", argv); !errors.Is(err, ErrInvalidUpdate) {
			t.Errorf("%s: %v, want ErrInvalidUpdate", name, err)
		}
	}
	for name, argv := range map[string][]string{
		"npm alias": {"npm", "install", "left-pad@npm:evil@1.0.0", "--ignore-scripts", "--no-audit", "--no-fund"},
		"npm git":   {"npm", "install", "git+https://x/y", "--ignore-scripts", "--no-audit", "--no-fund"},
		"npm run":   {"npm", "run", "build", "--ignore-scripts", "--no-audit", "--no-fund"},
	} {
		if err := Update(context.Background(), d, c, "npm", "web/package-lock.json", argv); !errors.Is(err, ErrInvalidUpdate) && !errors.Is(err, ErrUnsafeInstall) {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	if len(rec.runs) != 0 {
		t.Errorf("an invalid update ran %d commands", len(rec.runs))
	}
	if err := Update(context.Background(), d, Copy{Dir: t.TempDir()}, "Packagist", "composer.lock", composer); !errors.Is(err, ErrNotACopy) {
		t.Errorf("update outside a copy: %v", err)
	}
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return kv[len(key)+1:]
		}
	}
	return ""
}

func TestTreeHashAndCommitFile(t *testing.T) {
	f := newFixture(t)
	c := prepare(t, f)
	t0, err := TreeHash(context.Background(), f.deps, c)
	if err != nil || len(t0) != 40 {
		t.Fatalf("TreeHash: %q %v", t0, err)
	}
	again, _ := TreeHash(context.Background(), f.deps, c)
	if again != t0 {
		t.Errorf("TreeHash is not stable: %s then %s", t0, again)
	}
	writeFile(t, c.Dir, "composer.lock", `{"packages":[{"name":"acme/lib"}]}`+"\n")
	t1, _ := TreeHash(context.Background(), f.deps, c)
	if t1 == t0 {
		t.Error("a changed file keeps the tree hash")
	}
	// An excluded file never counts.
	writeFile(t, c.Dir, ".env", "X=1\n")
	if t2, _ := TreeHash(context.Background(), f.deps, c); t2 != t1 {
		t.Error("an excluded file changes the tree hash")
	}
	sha, err := Commit(context.Background(), f.deps, c, "fix")
	if err != nil {
		t.Fatal(err)
	}
	// The working tree moves on; the commit does not.
	writeFile(t, c.Dir, "composer.lock", "changed after the commit\n")
	b, ok, err := CommitFile(context.Background(), f.deps, c, sha, "composer.lock")
	if err != nil || !ok || !strings.Contains(string(b), "acme/lib") || strings.Contains(string(b), "after") {
		t.Errorf("CommitFile = %q %v %v", b, ok, err)
	}
	if _, ok, err := CommitFile(context.Background(), f.deps, c, sha, "missing.txt"); ok || err != nil {
		t.Errorf("missing file: %v %v", ok, err)
	}
	if _, _, err := CommitFile(context.Background(), f.deps, c, sha, "../x"); !errors.Is(err, ErrOutsideCopy) {
		t.Errorf("path outside: %v", err)
	}
}
