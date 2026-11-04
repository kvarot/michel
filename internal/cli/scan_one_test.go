package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
	"github.com/spf13/cobra"
)

// scanOneDirectly runs the real scanOneProject on a project of the data
// folder dir, the way michel serve calls it, from a command with the flags of
// michel serve.
func scanOneDirectly(t *testing.T, dir, db, name string, queue bool) (scan.Result, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	var r scan.Result
	var summary string
	var runErr error
	root := NewRootCmd(deps)
	sub := &cobra.Command{Use: "one", RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := projectRepo(deps).Get(cmd.Context(), name)
		if err != nil {
			return err
		}
		r, summary, runErr = scanOneProject(cmd.Context(), cmd, deps, p, queue)
		return nil
	}}
	sub.Flags().String("osv-db", db, "")
	root.AddCommand(sub)
	root.SetArgs([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "one"})
	if err := root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, errOut.String())
	}
	deps.Close()
	if out.Len() != 0 {
		t.Errorf("scanOneProject printed on the output: %s", out.String())
	}
	return r, summary, runErr
}

// Against the real extraction and a really merged branch: the API only holds
// Deps.ScanProject, a fake there would prove nothing.
func TestScanProvesAMergedFix(t *testing.T) {
	dir, db, path := provableProject(t, true)
	if r, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil || r.Status != scan.ScanOK {
		t.Fatalf("first scan: %+v %v", r, err)
	}
	id, finding := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	if r, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil || r.Status != scan.ScanOK {
		t.Fatalf("scan after the merge: %+v %v", r, err)
	}
	if got := statusOf(t, dir, finding); got != scan.StatusGone {
		t.Errorf("finding = %s, want gone", got)
	}
	a := attemptOf(t, dir, id)
	if a.State != fix.StateProvenFixed || string(a.State) != "proven_fixed" {
		t.Errorf("attempt in the database = %q (%s), want proven_fixed", a.State, a.Cause)
	}
}

// The plugins run before the proof in a folder with no lockfile as well: the
// other branch of the extraction.
func TestScanProvesAMergedFixWithoutALockfile(t *testing.T) {
	dir, db, path := provableProject(t, false)
	if _, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil {
		t.Fatal(err)
	}
	id, _ := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	if r, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil || r.Status != scan.ScanEmpty {
		t.Fatalf("scan: %+v %v", r, err)
	}
	if a := attemptOf(t, dir, id); a.State != fix.StateProvenFixed {
		t.Errorf("attempt = %s (%s), want proven_fixed", a.State, a.Cause)
	}
}

// A merge the plugin still sees proves nothing: the sequence is the one of
// michel scan, not a shortcut.
func TestScanOneDoesNotProveWithoutTheMerge(t *testing.T) {
	dir, db, path := provableProject(t, true)
	if _, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil {
		t.Fatal(err)
	}
	id, _ := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	if _, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil {
		t.Fatal(err)
	}
	if a := attemptOf(t, dir, id); a.State == fix.StateProvenFixed {
		t.Errorf("attempt proven with no merge: %+v", a)
	}
}

// treeContent is every entry of a folder with its bytes, its mode and its
// time: nothing may change, .git included.
func treeContent(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		v := fmt.Sprintf("%v %d", info.Mode(), info.ModTime().UnixNano())
		if !info.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScanWritesNothingInTheProject(t *testing.T) {
	dir, db, path := provableProject(t, true)
	before := treeContent(t, path)
	if r, _, err := scanOneDirectly(t, dir, db, "demo", true); err != nil || r.Status != scan.ScanOK {
		t.Fatalf("scan: %+v %v", r, err)
	}
	compareTrees(t, before, treeContent(t, path))
	// With an applied fix too, so that the proof reads the repository.
	id, _ := appliedFix(t, dir, path, "plugin.trivy", func() { writeApp(t, path, "<?php // "+fakeToolFixed+"\n") })
	proveGit(t, path, "merge", "-q", "--no-ff", "--no-edit", "michel/fix-test")
	before = treeContent(t, path)
	if r, _, err := scanOneDirectly(t, dir, db, "demo", true); err != nil || r.Status != scan.ScanOK {
		t.Fatalf("scan: %+v %v", r, err)
	}
	if a := attemptOf(t, dir, id); a.State != fix.StateProvenFixed {
		t.Errorf("attempt = %s (%s): the proof did not run", a.State, a.Cause)
	}
	compareTrees(t, before, treeContent(t, path))
}

func compareTrees(t *testing.T, before, after map[string]string) {
	t.Helper()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s changed", k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s appeared", k)
		}
	}
}

// queuedAttempts counts the attempts waiting for the worker of michel serve.
func queuedAttempts(t *testing.T, dir string) int {
	t.Helper()
	var n int
	withStore(t, dir, func(st *store.Store) {
		if err := st.DB().QueryRow(`SELECT COUNT(*) FROM fix_queue`).Scan(&n); err != nil {
			t.Fatal(err)
		}
	})
	return n
}

// Without the level and the consent nothing is queued, even when asked.
func TestScanOneQueuesOnlyWithTheLevel(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scanOneDirectly(t, dir, db, "demo", true); err != nil {
		t.Fatal(err)
	}
	if n := queuedAttempts(t, dir); n != 0 {
		t.Errorf("level 1 queued %d", n)
	}
}

// consentingProject is a project at level 2, with the AI consent, not scanned.
func consentingProject(t *testing.T) (dir, db string) {
	t.Helper()
	dir, db = t.TempDir(), buildTestOSVDB(t)
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("sovereignty:\n  mode: standard\n  data_classification: sensitive\n  network:\n    default_egress: deny\n    allow: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--fix-level", "2"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "fix", "consent", "demo", "--yes"); err != nil {
		t.Fatal(err)
	}
	return dir, db
}

// With the level and the consent, what was asked decides.
func TestScanOneQueuesAtLevelTwoWithConsent(t *testing.T) {
	dir, db := consentingProject(t)
	if _, _, err := scanOneDirectly(t, dir, db, "demo", false); err != nil {
		t.Fatal(err)
	}
	if n := queuedAttempts(t, dir); n != 0 {
		t.Errorf("queue=false queued %d", n)
	}
	if _, _, err := scanOneDirectly(t, dir, db, "demo", true); err != nil {
		t.Fatal(err)
	}
	if n := queuedAttempts(t, dir); n == 0 {
		t.Error("queue=true queued nothing")
	}
}

// What michel serve hands to the API queues, as a server check from the page
// does. It is called directly: through a running serve, the worker would take
// the queue and start a real agent.
func TestServeScanProjectQueuesAtLevelTwo(t *testing.T) {
	dir, db := consentingProject(t)
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	var scanErr error
	root := NewRootCmd(deps)
	sub := &cobra.Command{Use: "one", RunE: func(cmd *cobra.Command, _ []string) error {
		p, err := projectRepo(deps).Get(cmd.Context(), "demo")
		if err != nil {
			return err
		}
		scanErr = serveScanProject(cmd, deps)(cmd.Context(), p)
		return nil
	}}
	sub.Flags().String("osv-db", db, "")
	root.AddCommand(sub)
	root.SetArgs([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "one"})
	if err := root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, errOut.String())
	}
	deps.Close()
	if scanErr != nil {
		t.Fatalf("%v\n%s", scanErr, errOut.String())
	}
	if n := queuedAttempts(t, dir); n == 0 {
		t.Error("the scan of michel serve queued nothing")
	}
}
