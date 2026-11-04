package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/brief"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/secret"
)

// committedFiles lists the files the fix commit sha changes against its
// parent, in the user's repository.
func committedFiles(t *testing.T, f *fixture, sha string) []string {
	t.Helper()
	out := gitT(t, f.env, f.proj.Path, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
	files := strings.Fields(out)
	slices.Sort(files)
	return files
}

// vendorComposer is a fake composer whose update writes, like the real
// one, the manifest, the lockfile and vendor/ (untracked in Base, not
// gitignored), vendor holding a library file with a password-like line.
func vendorComposer(t *testing.T, f *fixture) {
	t.Helper()
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "update" {
			writeFile(t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.2.5"}}`+"\n")
			writeFile(t, dir, "composer.lock", michelLock)
			writeFile(t, dir, "vendor/acme/lib/src/Db.php", "<?php\nreturn ['password' => 'hunter2hunter2', 'host' => 'db'];\n")
			writeFile(t, dir, "vendor/autoload.php", "<?php\n// [secret-key] in a comment of a library\n")
		}
	}
}

// TestApplyKeepsSecretLikeCode: the agent's own change holds a
// password-like assignment; the proposal shows it masked, and the branch
// is still created from the raw patch (final review C1).
func TestApplyKeepsSecretLikeCode(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		writeFile(f.t, dir, "src/app.php", "<?php\n$password = \"hunter2hunter2\";\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Upgrade acme/lib."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, p := approved(t, f)
	if !mask.HasToken(p.Diff) || strings.Contains(p.Diff, "hunter2hunter2") {
		t.Errorf("the displayed diff is not masked:\n%s", p.Diff)
	}
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	sha := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/heads/"+Branch(a.ID))
	if shown := gitT(t, f.env, f.proj.Path, "show", sha+":src/app.php"); !strings.Contains(shown, "hunter2hunter2") {
		t.Errorf("the branch does not hold the agent's code as written: %s", shown)
	}
	if got := f.attempt(a.ID); got.State != StateApplied {
		t.Errorf("state = %s (%s)", got.State, got.Cause)
	}
}

// TestMichelsUpdateOutputStaysOutOfTheProposal: Michel's own update writes
// vendor/ in the copy; the proposal holds only the manifest and the
// lockfile, and the tree after the update is the snapshot when the agent
// changed nothing (final review C2).
func TestMichelsUpdateOutputStaysOutOfTheProposal(t *testing.T) {
	f := newFixture(t)
	f.consent()
	vendorComposer(t, f)
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		if _, err := os.Lstat(filepath.Join(dir, "vendor")); err == nil {
			f.t.Error("vendor/ of Michel's update is in the agent's copy")
		}
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Michel's update looks fine."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	if !slices.Equal(got.Work.Copy.InstallDirs, []string{"vendor"}) {
		t.Errorf("InstallDirs = %v (not kept with the attempt)", got.Work.Copy.InstallDirs)
	}
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatalf("no proposal: %+v", got)
	}
	if !slices.Equal(p.Files, []string{"composer.json", "composer.lock"}) {
		t.Errorf("proposal files = %v", p.Files)
	}
	ev := f.audits("fix.propose")
	if len(ev) != 1 || ev[0].Evidence["tree_unchanged"] != true {
		t.Errorf("fix.propose audit = %+v, want tree_unchanged", ev)
	}
}

// TestEndToEndVendorProposalIsApplied is the real run's path with fakes:
// the fake agent leaves Michel's update as it is, the fake composer writes
// vendor/ with a password-like line and a "[secret-…]"-like text; the
// proposal is approved and applied, and the branch holds only the
// manifest and the lockfile (final review, recommendation).
func TestEndToEndVendorProposalIsApplied(t *testing.T) {
	f := newFixture(t)
	f.consent()
	vendorComposer(t, f)
	proposeOnly(f)
	a, p := approved(t, f)
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v (%s)", err, f.attempt(a.ID).Cause)
	}
	sha := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/heads/"+Branch(a.ID))
	if sha != p.CommitSHA {
		t.Errorf("branch = %s, want %s", sha, p.CommitSHA)
	}
	if files := committedFiles(t, f, sha); !slices.Equal(files, []string{"composer.json", "composer.lock"}) {
		t.Errorf("the branch commits %v", files)
	}
	if got := f.attempt(a.ID); got.State != StateApplied {
		t.Errorf("state = %s (%s)", got.State, got.Cause)
	}
}

func TestPromptAsksUserLanguage(t *testing.T) {
	for lang, want := range map[i18n.Lang]string{i18n.FR: "French", i18n.EN: "English"} {
		p := Prompt(brief.Brief{}, lang)
		rule := "write every message to the user, and the summary and notes of propose_fix, in " + want
		if !strings.Contains(p, rule) {
			t.Errorf("%s prompt lacks the language rule %q:\n%s", lang, rule, p)
		}
		// The rule is Michel's, before the untrusted data.
		if strings.Index(p, rule) > strings.Index(p, "Untrusted data follows") {
			t.Errorf("%s: the language rule is inside or after the data block", lang)
		}
	}
}

// TestSessionHasTurnCap: a session is bounded by turns too, not only by
// time (final review I9).
func TestSessionHasTurnCap(t *testing.T) {
	f := newFixture(t)
	f.consent()
	turns := -1
	inner := f.d.Agent
	f.d.Agent = func(ctx context.Context, ad agent.Deps, s agent.Spec) (Session, error) {
		turns = s.MaxTurns
		return inner(ctx, ad, s)
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if turns != DefaultMaxTurns || DefaultMaxTurns <= 0 {
		t.Errorf("MaxTurns = %d, want %d", turns, DefaultMaxTurns)
	}
	f.d.MaxTurns = 7
	if f.d.maxTurns() != 7 {
		t.Errorf("an explicit MaxTurns is not kept")
	}
}

// TestSweepLeavesAnotherProcessesAgent: michel serve starts while michel
// fix prepare runs an agent (its token set, recent): the attempt, its
// copy and its agent files stay; without its token it ends failed (final
// review I5).
func TestSweepLeavesAnotherProcessesAgent(t *testing.T) {
	f := newFixture(t)
	f.consent()
	release := make(chan struct{})
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) { <-release }
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); f.wait(a.ID) }()
	writeFile(t, f.d.DataDir, "agent/"+a.ID+"/settings.json", "{}")
	writeFile(t, f.d.DataDir, "agent/01STALE00000000000000000000/settings.json", "{}")
	serve := f.d
	serve.Sessions = NewSessions() // another process: the session is not its own
	if err := Sweep(context.Background(), serve); err != nil {
		t.Fatal(err)
	}
	got := f.attempt(a.ID)
	if got.State != StatePreparing {
		t.Fatalf("state = %s (%s): the other process's attempt was failed", got.State, got.Cause)
	}
	if _, err := os.Lstat(got.Work.Copy.Dir); err != nil {
		t.Errorf("the live copy was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.d.DataDir, "agent", a.ID, "settings.json")); err != nil {
		t.Errorf("the live agent's files were removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.d.DataDir, "agent", "01STALE00000000000000000000")); err == nil {
		t.Error("the files of an unknown agent survived")
	}
	if !tokenStillSet(f.d.Secrets, a.ID) {
		t.Error("the live attempt's token was removed")
	}
	// Its token gone, the attempt is abandoned.
	if err := DeleteAttemptToken(f.d.Secrets, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := Sweep(context.Background(), serve); err != nil {
		t.Fatal(err)
	}
	if got := f.attempt(a.ID); got.State != StateFailed {
		t.Errorf("state = %s, want failed once the token is gone", got.State)
	}
	if _, err := os.Lstat(filepath.Join(f.d.DataDir, "agent", a.ID)); err == nil {
		t.Error("the agent files of the failed attempt survived")
	}
}

// failingMaskStore refuses to save mask tables.
type failingMaskStore struct{ secret.Store }

func (s failingMaskStore) Set(name string, v []byte) error {
	if strings.HasPrefix(name, "mask-") {
		return errors.New("disk full")
	}
	return s.Store.Set(name, v)
}

// TestStartFailureRemovesTheCopy: Start fails after Prepare and before the
// copy is recorded in the attempt: the copy and the mirror go (final
// review I6).
func TestStartFailureRemovesTheCopy(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.d.Secrets = failingMaskStore{f.d.Secrets}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err == nil {
		t.Fatal("Start succeeded without its mask table")
	}
	if a.State != StateFailed {
		t.Errorf("state = %s", a.State)
	}
	for _, tree := range []string{"worktrees", "fix-mirrors"} {
		entries, _ := os.ReadDir(filepath.Join(f.d.DataDir, tree, f.proj.ID))
		if len(entries) != 0 {
			t.Errorf("%s left after a failed start: %d entries", tree, len(entries))
		}
	}
}

// TestMaskTableStaysOneMeaning: a value first masked in the session's
// process is saved at once; michel mcp's Propose masks with its own nonce
// and never touches the saved table, so one token never stands for two
// values (final review I8).
func TestMaskTableStaysOneMeaning(t *testing.T) {
	f := newFixture(t)
	f.consent()
	release := make(chan struct{})
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) { <-release }
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); f.wait(a.ID) }()
	if err := SendMessage(context.Background(), f.d, a.ID, "my db: password=hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	saved, err := mask.Load(f.d.Secrets, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(mapValues(saved.Table()), "hunter2hunter2") {
		t.Fatalf("the value masked in the session is not in the saved table: %d entries", saved.Len())
	}
	before := saved.Table()
	copyDir := f.attempt(a.ID).Work.Copy.Dir
	writeFile(t, copyDir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
	other := "AKIA" + "QRSTUVWXYZ234567"
	p, err := Propose(context.Background(), f.d, a.ID, ProposeInput{Summary: "the key " + other + " was in the logs"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Summary, other) || !mask.HasToken(p.Summary) {
		t.Fatalf("summary not masked: %q", p.Summary)
	}
	after, err := mask.Load(f.d.Secrets, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Table()) != len(before) {
		t.Errorf("Propose changed the saved table: %d entries, then %d", len(before), len(after.Table()))
	}
	for tok := range after.Table() {
		if strings.Contains(p.Summary, tok) {
			t.Errorf("Propose reused the session's token %s for another value", tok)
		}
	}
}

func mapValues(t mask.Table) []string {
	out := []string{}
	for _, v := range t {
		out = append(out, v)
	}
	return out
}

func TestSecretHitsNameTheFolder(t *testing.T) {
	text := secretHitsMessage(i18n.EN, []mask.Hit{{File: "config/db.php", Line: 3}, {File: "config/db.php", Line: 4}, {File: "app.php", Line: 1}})
	if !strings.Contains(text, "exclude the folder or folders concerned: config") || !strings.Contains(text, "take them out of these files") {
		t.Errorf("message = %q", text)
	}
	text = secretHitsMessage(i18n.FR, []mask.Hit{{File: "app.php", Line: 1}})
	if strings.Contains(text, "exclus") || !strings.Contains(text, "enlève-la de ce fichier") || !strings.Contains(text, "n'a pas démarré") {
		t.Errorf("a root file has no folder to exclude: %q", text)
	}
	if secretHitsMessage(i18n.EN, nil) != "" {
		t.Error("a message without hits")
	}
}
