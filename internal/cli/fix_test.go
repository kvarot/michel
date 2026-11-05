package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/workcopy"
)

// withStore opens the store of the data folder dir for f, then closes it
// (the commands open it themselves).
func withStore(t *testing.T, dir string, f func(st *store.Store)) {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f(st)
}

func TestFixApproveRefusesChangedProposal(t *testing.T) {
	dir, list := scannedDemo(t, false)
	ctx := context.Background()
	var id string
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(ctx, "demo")
		if err != nil {
			t.Fatal(err)
		}
		repo := fix.NewRepo(st)
		a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: list[0].ID, ProjectID: p.ID, Origin: fix.OriginAgent})
		if err != nil {
			t.Fatal(err)
		}
		id = a.ID
		if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: id, Summary: "First proposal.", Files: []string{"composer.lock"},
			TestsStatus: "passed", Hash: "hash-one"}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetState(ctx, id, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
			t.Fatal(err)
		}
	})
	// Nothing shown yet: approve asks for status first.
	if _, _, _, err := run(t, dir, "fix", "approve", id); err == nil || !strings.Contains(err.Error(), "michel fix status") {
		t.Fatalf("approve before status: %v", err)
	}
	_, out, _, err := run(t, dir, "fix", "status", id[:10])
	if err != nil || !strings.Contains(out, "hash-one") || !strings.Contains(out, "First proposal.") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "fix", "status")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "proposed") {
		t.Fatalf("status list: %v\n%s", err, out)
	}
	// The agent replaces its proposal after status showed the first one.
	withStore(t, dir, func(st *store.Store) {
		if _, err := fix.NewRepo(st).AddProposal(ctx, fix.Proposal{AttemptID: id, Summary: "Second proposal.", Files: []string{"composer.lock"},
			TestsStatus: "passed", Hash: "hash-two"}); err != nil {
			t.Fatal(err)
		}
	})
	_, _, _, err = run(t, dir, "fix", "approve", id, "--lang", "fr")
	if err == nil || !strings.Contains(err.Error(), i18n.T(i18n.FR, "fix.err.stale_proposal")) {
		t.Fatalf("approve of a changed proposal: %v", err)
	}
	withStore(t, dir, func(st *store.Store) {
		a, err := fix.NewRepo(st).GetAttempt(ctx, id)
		if err != nil || a.State != fix.StateProposed || a.ApprovedBy != "" {
			t.Errorf("attempt after a stale approve = %+v %v", a, err)
		}
	})
	// Status shows the new one; approve then records it (the branch cannot
	// be made here: the attempt has no copy).
	if _, out, _, err = run(t, dir, "fix", "status", id); err != nil || !strings.Contains(out, "hash-two") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	_, _, _, err = run(t, dir, "fix", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "branch") {
		t.Errorf("approve: %v", err)
	}
	withStore(t, dir, func(st *store.Store) {
		a, err := fix.NewRepo(st).GetAttempt(ctx, id)
		if err != nil || a.State != fix.StateApproved || a.ApprovedHash != "hash-two" || a.ApprovedBy != "cli" {
			t.Errorf("attempt after approve = %+v %v", a, err)
		}
	})
	// Refusing works on an approved attempt too.
	if _, out, _, err = run(t, dir, "fix", "refuse", id, "--reason", "not now"); err != nil || !strings.Contains(out, id) {
		t.Errorf("refuse: %v\n%s", err, out)
	}
	if _, _, _, err := run(t, dir, "fix", "status", "zz"); err == nil {
		t.Error("status of an unknown attempt succeeded")
	}
}

// runTyped is run with a terminal where a person types answer.
func runTyped(t *testing.T, dir, answer string, args ...string) (*Deps, string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now, TypedLine: func() (string, bool) { return answer, true }}
	t.Cleanup(func() { deps.Close() })
	cmd := NewRootCmd(deps)
	cmd.SetArgs(append([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "--lang", "en"}, args...))
	err := cmd.Execute()
	deps.Close()
	return deps, out.String(), errOut.String(), err
}

func TestFixStatusMasksAFileNamedLikeAKey(t *testing.T) {
	dir, list := scannedDemo(t, false)
	ctx := context.Background()
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	var id string
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(ctx, "demo")
		if err != nil {
			t.Fatal(err)
		}
		repo := fix.NewRepo(st)
		a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: list[0].ID, ProjectID: p.ID, Origin: fix.OriginAgent})
		if err != nil {
			t.Fatal(err)
		}
		id = a.ID
		w := fix.Work{HoldSum: "sum", Copy: workcopy.Copy{SecretHits: []mask.Hit{{File: "src/" + key + ".php", Line: 2, Kind: mask.KindAWSKey, Strong: true}}}}
		if err := repo.SetWork(ctx, id, w); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetState(ctx, id, []fix.State{fix.StatePreparing}, fix.StateHeld, ""); err != nil {
			t.Fatal(err)
		}
	})
	for _, args := range [][]string{{"fix", "status", id}, {"fix", "status", id, "--json"}} {
		_, out, _, err := run(t, dir, args...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, key) {
			t.Errorf("%v shows the name:\n%s", args, out)
		}
	}
	_, out, _, _ := runTyped(t, dir, "no", "fix", "continue", id)
	if strings.Contains(out, key) {
		t.Errorf("continue shows the name:\n%s", out)
	}
}

func TestFixHeldAttemptIsAnsweredByItsCommands(t *testing.T) {
	dir, list := scannedDemo(t, false)
	ctx := context.Background()
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	var id string
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(ctx, "demo")
		if err != nil {
			t.Fatal(err)
		}
		repo := fix.NewRepo(st)
		a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: list[0].ID, ProjectID: p.ID, Origin: fix.OriginAgent})
		if err != nil {
			t.Fatal(err)
		}
		id = a.ID
		w := fix.Work{HoldSum: "sum", Copy: workcopy.Copy{SecretHits: []mask.Hit{{File: "src/config.php", Line: 2, Kind: mask.KindAWSKey, Strong: true}}}}
		if err := repo.SetWork(ctx, id, w); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetState(ctx, id, []fix.State{fix.StatePreparing}, fix.StateHeld, ""); err != nil {
			t.Fatal(err)
		}
	})
	// No terminal: refused whatever was shown, and the attempt waits.
	if _, _, _, err := run(t, dir, "fix", "continue", id); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("continue without a terminal: %v", err)
	}
	// Nothing shown yet: continue asks for status first.
	if _, _, _, err := runTyped(t, dir, "yes", "fix", "continue", id); err == nil || !strings.Contains(err.Error(), "michel fix status") {
		t.Fatalf("continue before status: %v", err)
	}
	_, out, _, err := run(t, dir, "fix", "status", id)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"src/config.php", "michel fix continue " + id, "michel fix withdraw " + id} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, key) {
		t.Errorf("status shows the value:\n%s", out)
	}
	// Another word is not a yes; the list is shown again first.
	_, out, _, err = runTyped(t, dir, "ok", "fix", "continue", id)
	if err == nil || !strings.Contains(err.Error(), "yes") {
		t.Fatalf("continue with another word: %v", err)
	}
	if !strings.Contains(out, "src/config.php") {
		t.Errorf("the list is not shown again:\n%s", out)
	}
	// The project has no consent: the yes is refused and the attempt waits.
	if _, _, _, err := runTyped(t, dir, "yes", "fix", "continue", id); err == nil {
		t.Error("continue without consent succeeded")
	}
	withStore(t, dir, func(st *store.Store) {
		if a, err := fix.NewRepo(st).GetAttempt(ctx, id); err != nil || a.State != fix.StateHeld {
			t.Errorf("attempt = %+v %v", a, err)
		}
	})
	if _, out, _, err = run(t, dir, "fix", "withdraw", id); err != nil || !strings.Contains(out, id) {
		t.Errorf("withdraw: %v\n%s", err, out)
	}
	withStore(t, dir, func(st *store.Store) {
		if a, err := fix.NewRepo(st).GetAttempt(ctx, id); err != nil || a.State != fix.StateWithdrawn {
			t.Errorf("attempt = %+v %v", a, err)
		}
	})
}

func TestFixConsentYes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("sovereignty:\n  mode: standard\n  data_classification: sensitive\n  network:\n    default_egress: deny\n    allow: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	// Without --yes: the lines are shown, nothing changes.
	_, out, _, err := run(t, dir, "fix", "consent", "demo", "--lang", "fr")
	if err != nil || !strings.Contains(out, i18n.T(i18n.FR, "fix.consent.runs_code")) || !strings.Contains(out, "api.anthropic.com") ||
		!strings.Contains(out, "--yes") {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(cfg); strings.Contains(string(b), "api.anthropic.com") {
		t.Fatalf("the policy changed without --yes:\n%s", b)
	}
	_, out, _, err = run(t, dir, "fix", "consent", "demo", "--yes")
	if err != nil || !strings.Contains(out, "demo") {
		t.Fatalf("consent --yes: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "api.anthropic.com") || !strings.Contains(string(b), "registry.npmjs.org") {
		t.Errorf("the policy lacks the rules:\n%s", b)
	}
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(context.Background(), "demo")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := fix.NewRepo(st).Consent(context.Background(), p.ID); err != nil || !ok {
			t.Errorf("no consent recorded: %v", err)
		}
	})
	_, out, _, err = run(t, dir, "fix", "consent", "demo")
	if err != nil || !strings.Contains(out, i18n.T(i18n.EN, "cli.fix.consent.already", "demo")) {
		t.Errorf("second consent: %v\n%s", err, out)
	}
	if _, _, _, err := run(t, dir, "fix", "consent", "nowhere"); err == nil {
		t.Error("consent of an unknown project succeeded")
	}
	// A strict_local policy is refused, in clear.
	if err := os.WriteFile(cfg, []byte("sovereignty:\n  mode: strict_local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "fix", "consent", "demo", "--yes"); err == nil || !strings.Contains(err.Error(), "strict_local") {
		t.Errorf("strict_local consent: %v", err)
	}
}

func TestFixTestNeedsYes(t *testing.T) {
	dir, list := scannedDemo(t, false)
	ctx := context.Background()
	var id string
	files := []string{"composer.lock"}
	for i := range 12 {
		files = append(files, "src/F"+string(rune('a'+i))+".php")
	}
	files = append(files, "tests/AppTest.php", "composer.json")
	withStore(t, dir, func(st *store.Store) {
		p, err := project.NewRepo(st).Get(ctx, "demo")
		if err != nil {
			t.Fatal(err)
		}
		repo := fix.NewRepo(st)
		a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: list[0].ID, ProjectID: p.ID, Origin: fix.OriginAgent,
			Work: fix.Work{Plan: fix.Plan{Ecosystem: "Packagist", ManifestRel: "composer.lock"}}})
		if err != nil {
			t.Fatal(err)
		}
		id = a.ID
		if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: id, Summary: "A proposal.", Files: files,
			TestsStatus: workcopy.TestsAwaiting, Hash: "hash-one", Tree: strings.Repeat("a", 40)}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetState(ctx, id, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
			t.Fatal(err)
		}
	})
	// Without --yes: the code files, the warning, and nothing runs.
	_, out, _, err := run(t, dir, "fix", "test", id, "--lang", "fr")
	if err != nil {
		t.Fatalf("fix test: %v", err)
	}
	// Every file the person must read: the list of software first, the
	// tests next, then at most 10 other files.
	manifest := i18n.T(i18n.FR, "cli.fix.test.file_manifest", "composer.json")
	lock := i18n.T(i18n.FR, "cli.fix.test.file_lockfile", "composer.lock")
	iM, iL, iT, iA := strings.Index(out, manifest), strings.Index(out, lock), strings.Index(out, "tests/AppTest.php"), strings.Index(out, "src/Fa.php")
	if !strings.Contains(out, i18n.T(i18n.FR, "cli.fix.test.warning", id)) || iM < 0 || iL < iM || iT < iL || iA < iT ||
		!strings.Contains(out, "src/Fj.php") || strings.Contains(out, "src/Fk.php") || !strings.Contains(out, i18n.N(i18n.FR, "cli.fix.test.more", 2)) ||
		!strings.Contains(out, i18n.T(i18n.FR, "cli.fix.test.confirm")) {
		t.Errorf("fix test without --yes:\n%s", out)
	}
	withStore(t, dir, func(st *store.Store) {
		if cur, _, _ := fix.NewRepo(st).CurrentProposal(ctx, id); cur.Hash != "hash-one" {
			t.Errorf("the proposal changed: %+v", cur)
		}
	})
	// With --yes but nothing shown: status first.
	if _, _, _, err := run(t, dir, "fix", "test", id, "--yes"); err == nil || !strings.Contains(err.Error(), "michel fix status") {
		t.Errorf("fix test --yes before status: %v", err)
	}
	// Status says how to run them.
	if _, out, _, err := run(t, dir, "fix", "status", id); err != nil || !strings.Contains(out, "michel fix test "+id) ||
		!strings.Contains(out, i18n.T(i18n.EN, "cli.fix.tests.awaiting")) {
		t.Errorf("status: %v\n%s", err, out)
	}
	// The agent replaces its proposal after status: --yes is refused.
	withStore(t, dir, func(st *store.Store) {
		if _, err := fix.NewRepo(st).AddProposal(ctx, fix.Proposal{AttemptID: id, Summary: "Second.", Files: files,
			TestsStatus: workcopy.TestsAwaiting, Hash: "hash-two", Tree: strings.Repeat("b", 40)}); err != nil {
			t.Fatal(err)
		}
	})
	if _, _, _, err := run(t, dir, "fix", "test", id, "--yes", "--lang", "fr"); err == nil || !strings.Contains(err.Error(), i18n.T(i18n.FR, "fix.err.stale_proposal")) {
		t.Errorf("fix test --yes on a changed proposal: %v", err)
	}
}
