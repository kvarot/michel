package workcopy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestInstallDirsSkipsTrackedFolders(t *testing.T) {
	got := installDirs([]string{
		"composer.json", "composer.lock", "README.md",
		"web/package.json", "web/package-lock.json",
		"tools/composer.json", "tools/vendor/acme/x.php", // a committed vendor stays the user's
		"libs/a/package.json",
		"bad[x]/package.json", // not a plain pathspec
	})
	want := []string{"libs/a/node_modules", "vendor", "web/node_modules"}
	if !slices.Equal(got, want) {
		t.Errorf("installDirs = %v, want %v", got, want)
	}
}

// TestUpdateOutputNeverJoinsTheChange: Michel's own update writes vendor/
// in the copy (untracked in Base, not gitignored); it is removed after the
// update and left out of the tree, so the change holds only the manifest
// and the lockfile, and the tree equals the snapshot when the agent did
// nothing.
func TestUpdateOutputNeverJoinsTheChange(t *testing.T) {
	f := newFixture(t)
	f.deps.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
		if name != "composer" {
			return defaultExec(ctx, name, args, env, dir)
		}
		writeFile(t, dir, "composer.json", `{"name":"acme/lib","require":{"acme/dep":"^1.2.5"}}`+"\n")
		writeFile(t, dir, "composer.lock", `{"packages":[{"name":"acme/dep","version":"1.2.5"}]}`+"\n")
		writeFile(t, dir, "vendor/acme/dep/src/Config.php", "<?php\nreturn ['password' => 'hunter2hunter2'];\n")
		writeFile(t, dir, "vendor/autoload.php", "<?php\n")
		return nil, nil, &exec.ExitError{} // a failed update leaves its output too
	}
	c := prepare(t, f)
	if !slices.Equal(c.InstallDirs, []string{"vendor"}) {
		t.Fatalf("InstallDirs = %v", c.InstallDirs)
	}
	argv := []string{"composer", "update", "acme/dep:^1.2.5", "--with-all-dependencies", "--no-scripts", "--no-plugins", "--no-interaction"}
	err := Update(context.Background(), f.deps, c, "Packagist", "composer.lock", argv)
	if _, ok := err.(*CmdError); !ok {
		t.Fatalf("Update: %v, want a *CmdError", err)
	}
	if _, err := os.Lstat(filepath.Join(c.Dir, "vendor")); err == nil {
		t.Error("vendor/ is still in the copy after Michel's update")
	}
	tree0, err := TreeHash(context.Background(), f.deps, c)
	if err != nil {
		t.Fatal(err)
	}
	// Something re-creates vendor/ later: still not part of the change.
	writeFile(t, c.Dir, "vendor/late.php", "<?php\n")
	writeFile(t, c.Dir, "VENDOR/case.php", "<?php\n")
	snap, err := Freeze(context.Background(), f.deps, c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(snap.Change.Files, []string{"composer.json", "composer.lock"}) {
		t.Errorf("change files = %v", snap.Change.Files)
	}
	if snap.Tree != tree0 {
		t.Errorf("snapshot tree %s != tree after the update %s", snap.Tree, tree0)
	}
	run, cleanup, err := Materialize(context.Background(), f.deps, c, snap.Tree)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Lstat(filepath.Join(run.Dir, "vendor")); err == nil {
		t.Error("vendor/ reached the scratch worktree")
	}
}
