package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

// The words the fake tool looks for in src/app.php of the project it is
// pointed at (internal/plugin/testdata/faketool).
const (
	fakeToolFixed = "FAKE-FLAW-FIXED"
	fakeToolFails = "FAKE-TOOL-FAILS"
)

// proveGit runs git in the project of a test, with no setting of this PC.
func proveGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.autocrlf=false", "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeApp(t *testing.T, path, content string) {
	t.Helper()
	file := filepath.Join(path, "src", "app.php")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// provableProject is a Git project named demo, with the fake tool as the
// plugin trivy, turned on. withLockfile false gives a folder with code only.
func provableProject(t *testing.T, withLockfile bool) (dir, db, path string) {
	t.Helper()
	buildFakeTool(t, "trivy")
	dir, db = t.TempDir(), buildTestOSVDB(t)
	if withLockfile {
		path = copyProject(t, "project-a")
	} else {
		path = t.TempDir()
	}
	writeApp(t, path, "<?php // a flaw\n")
	proveGit(t, path, "init", "-q", "-b", "main")
	proveGit(t, path, "add", "-A")
	proveGit(t, path, "commit", "-q", "-m", "start")
	if _, _, _, err := run(t, dir, "project", "add", path, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "source", "enable", "plugin.trivy"); err != nil {
		t.Fatal(err)
	}
	return dir, db, path
}

// appliedFix records an attempt in state applied on a finding of the wanted
// source ("" for a dependency flaw), with its branch in the project: change
// makes the commit of the branch. It returns the attempt and the finding.
func appliedFix(t *testing.T, dir, path, sourceKey string, change func()) (string, string) {
	t.Helper()
	ctx := context.Background()
	proveGit(t, path, "checkout", "-q", "-b", "michel/fix-test")
	change()
	proveGit(t, path, "add", "-A")
	proveGit(t, path, "commit", "-q", "-m", "the fix")
	sha := proveGit(t, path, "rev-parse", "HEAD")
	proveGit(t, path, "checkout", "-q", "main")
	var attempt, finding string
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(ctx, "demo")
		if err != nil {
			t.Fatal(err)
		}
		list, err := scan.NewRepo(st).ListFindings(ctx, p.ID, "all")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range list {
			if f.SourceKey == sourceKey {
				finding = f.ID
				break
			}
		}
		if finding == "" {
			t.Fatalf("no finding of source %q in %d findings", sourceKey, len(list))
		}
		repo := fix.NewRepo(st)
		a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: finding, ProjectID: p.ID, Origin: fix.OriginAgent})
		if err != nil {
			t.Fatal(err)
		}
		attempt = a.ID
		if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "The fix.", Files: []string{"src/app.php"}, TestsStatus: "passed", Hash: "h", CommitSHA: sha}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateApplied, ""); err != nil {
			t.Fatal(err)
		}
	})
	return attempt, finding
}

func attemptOf(t *testing.T, dir, id string) fix.Attempt {
	t.Helper()
	var a fix.Attempt
	withStore(t, dir, func(st *store.Store) {
		var err error
		if a, err = fix.NewRepo(st).GetAttempt(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	})
	return a
}

func statusOf(t *testing.T, dir, findingID string) string {
	t.Helper()
	var s string
	withStore(t, dir, func(st *store.Store) {
		if err := st.DB().QueryRow(`SELECT status FROM finding WHERE id = ?`, findingID).Scan(&s); err != nil {
			t.Fatal(err)
		}
	})
	return s
}

// A code flaw found by a plugin: one michel scan after the merge is enough,
// the tool runs first and no longer sees it.
func TestScanProvesAMergedFixOfACodeFlaw(t *testing.T) {
	dir, db, path := provableProject(t, true)
	if _, out, errOut, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db); err != nil {
		t.Fatalf("scan: %v\n%s\n%s", err, out, errOut)
	}
	id, finding := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	if _, out, errOut, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db); err != nil {
		t.Fatalf("scan: %v\n%s\n%s", err, out, errOut)
	}
	if got := statusOf(t, dir, finding); got != scan.StatusGone {
		t.Errorf("finding = %s, want gone", got)
	}
	if a := attemptOf(t, dir, id); a.State != fix.StateProvenFixed {
		t.Errorf("attempt = %s (%s), want proven_fixed", a.State, a.Cause)
	}
}

// The same in a folder with no lockfile: the scan has nothing to read, the
// tool still looks at the code. (Nothing to scan is an exit code with
// --project, so the error of run is not checked here.)
func TestScanProvesACodeFlawWithoutALockfile(t *testing.T) {
	dir, db, path := provableProject(t, false)
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	id, _ := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if a := attemptOf(t, dir, id); a.State != fix.StateProvenFixed {
		t.Errorf("attempt = %s (%s), want proven_fixed", a.State, a.Cause)
	}
}

// Merged, and the tool that looked still sees the flaw: this verdict is true.
func TestScanSaysAMergedCodeFlawIsStillSeen(t *testing.T) {
	dir, db, path := provableProject(t, true)
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	id, finding := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // still a flaw\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if got := statusOf(t, dir, finding); got == scan.StatusGone {
		t.Errorf("finding = %s", got)
	}
	if a := attemptOf(t, dir, id); a.State != fix.StateInconclusive {
		t.Errorf("attempt = %s, want inconclusive", a.State)
	}
}

// A source that did not look proves nothing, either way: neither a flaw still
// open (a false "still seen") nor a flaw closed by an earlier reading.
func TestScanLeavesTheFixAppliedWhenTheToolDidNotLook(t *testing.T) {
	off := func(t *testing.T, dir, path string) {
		if _, _, _, err := run(t, dir, "source", "disable", "plugin.trivy"); err != nil {
			t.Fatal(err)
		}
	}
	fails := func(t *testing.T, dir, path string) {
		writeApp(t, path, "<?php // "+fakeToolFails+"\n")
	}
	for _, tc := range []struct {
		name   string
		gone   bool
		before func(t *testing.T, dir, path string)
	}{
		{"turned off, flaw open", false, off},
		{"turned off, flaw closed earlier", true, off},
		{"failed, flaw open", false, fails},
		{"failed, flaw closed earlier", true, fails},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, db, path := provableProject(t, true)
			run(t, dir, "scan", "--project", "demo", "--osv-db", db)
			id, finding := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
			proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
			if tc.gone {
				withStore(t, dir, func(st *store.Store) {
					if _, err := st.DB().Exec(`UPDATE finding SET status = ? WHERE id = ?`, scan.StatusGone, finding); err != nil {
						t.Fatal(err)
					}
				})
			}
			tc.before(t, dir, path)
			run(t, dir, "scan", "--project", "demo", "--osv-db", db)
			if a := attemptOf(t, dir, id); a.State != fix.StateApplied {
				t.Errorf("attempt = %s (%s), want applied", a.State, a.Cause)
			}
		})
	}
}

// A dependency flaw keeps its verdict in a real scan...
func TestScanSaysAMergedDependencyFlawIsStillSeen(t *testing.T) {
	dir, db, path := provableProject(t, true)
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	id, _ := appliedFix(t, dir, path, "", func() { writeApp(t, path, "<?php // the lockfile did not change\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if a := attemptOf(t, dir, id); a.State != fix.StateInconclusive {
		t.Errorf("attempt = %s, want inconclusive", a.State)
	}
}

// ...and a scan that found no lockfile did not look at it: the flaw keeps its
// status, the fix stays applied, even once merged.
func TestScanWithoutALockfileProvesNoDependencyFlaw(t *testing.T) {
	dir, db, path := provableProject(t, true)
	run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	id, _ := appliedFix(t, dir, path, "", func() {
		for _, name := range []string{"composer.lock", "web/package-lock.json"} {
			if err := os.Remove(filepath.Join(path, name)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	})
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	_, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db)
	if err == nil {
		t.Fatal("the scan found something to read: this test needs a folder with no lockfile")
	}
	if a := attemptOf(t, dir, id); a.State != fix.StateApplied {
		t.Errorf("attempt = %s (%s), want applied", a.State, a.Cause)
	}
}
