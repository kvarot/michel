package fix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/workcopy"
)

// evilAgent is an agent that writes a test file next to its lockfile change
// and proposes: the "test" is the project's own test runner, faked by the
// recorder, which writes marker (outside every copy) when it runs.
func evilAgent(f *fixture) {
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		writeFile(f.t, dir, "tests/EvilTest.php", "<?php\n// writes a file outside the copy\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Upgrade acme/lib to 1.2.5."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
}

// markerRunner makes the fake test runner write marker when it runs, the
// way a test the agent wrote would.
func markerRunner(f *fixture, marker string) {
	base := f.rec.onRun
	f.rec.onRun = func(name string, args []string, dir string) {
		if base != nil {
			base(name, args, dir)
		}
		if name == "vendor/bin/phpunit" {
			_ = os.WriteFile(marker, []byte("ran\n"), 0o600)
		}
	}
}

// michelsUpdate makes the fake composer update write the very lockfile the
// fixture's default agent writes: the agent's write then leaves Michel's own
// tree as it was, and Michel runs the tests alone. It wraps the recorder's
// onRun set before it.
func michelsUpdate(t *testing.T, f *fixture) {
	base := f.rec.onRun
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && len(args) > 0 && args[0] == "update" {
			writeFile(t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		}
		if base != nil {
			base(name, args, dir)
		}
	}
}

func michelText(t *testing.T, f *fixture, id string) string {
	t.Helper()
	msgs, err := f.d.Repo.ListMessages(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range msgs {
		if m.Role == RoleMichel {
			out = append(out, m.Text)
		}
	}
	return strings.Join(out, "\n")
}

func TestProposeChangedTreeAwaitsTests(t *testing.T) {
	f := newFixture(t)
	f.consent()
	evilAgent(f)
	marker := filepath.Join(t.TempDir(), "marker")
	markerRunner(f, marker)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, err := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if err != nil || !ok {
		t.Fatalf("no proposal: %v (attempt %+v)", err, f.attempt(a.ID))
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the agent's test ran before any click")
	}
	if slices.Contains(f.rec.names(), "vendor/bin/phpunit") {
		t.Errorf("the tests ran: %v", f.rec.names())
	}
	if !slices.Contains(f.rec.names(), "composer") {
		t.Errorf("the install did not run: %v", f.rec.names())
	}
	if p.TestsStatus != workcopy.TestsAwaiting || p.Tree == "" || !p.RescanClean {
		t.Errorf("proposal = %+v", p)
	}
	for _, c := range p.Commands {
		if c.What == "tests" {
			t.Errorf("commands list the tests: %+v", p.Commands)
		}
	}
	if p.Hash != proposalHash(p.DiffRaw, p.CommitSHA, workcopy.TestsAwaiting, p.Summary) {
		t.Error("the hash does not cover the awaiting status")
	}
	if text := michelText(t, f, a.ID); !strings.Contains(text, "tests/EvilTest.php") || strings.Contains(text, "Tests: passed") {
		t.Errorf("Michel's message = %q", text)
	}
	if ev := f.audits("fix.propose"); len(ev) != 1 || ev[0].Evidence["tests"] != workcopy.TestsAwaiting || ev[0].Evidence["tests_awaiting"] != true {
		t.Errorf("fix.propose audit = %+v", ev)
	}
}

func TestProposeUnchangedTreeStillRunsTests(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	proposeOnly(f)
	marker := filepath.Join(t.TempDir(), "marker")
	markerRunner(f, marker)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatalf("no proposal: %+v", f.attempt(a.ID))
	}
	if p.TestsStatus != workcopy.TestsPassed || p.Tree == "" {
		t.Errorf("proposal = %+v", p)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the tests did not run on Michel's own tree")
	}
	// Level 3 unchanged: Michel's own tree, tests passed, rules met: approved.
	if got := f.attempt(a.ID); got.ApprovedBy != ActorAuto {
		t.Errorf("not approved alone: %+v", got)
	}
	if ev := f.audits("fix.propose"); len(ev) != 1 || ev[0].Evidence["tests_awaiting"] == true {
		t.Errorf("fix.propose audit = %+v", ev)
	}
}

func TestProposeChangedTreeInstallFailsStaysFailed(t *testing.T) {
	f := newFixture(t)
	f.consent()
	evilAgent(f)
	f.rec.fail = "composer"
	f.rec.failOutput = "the lockfile does not resolve"
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatalf("no proposal: %+v", f.attempt(a.ID))
	}
	if p.TestsStatus != workcopy.TestsFailed {
		t.Errorf("tests status = %q, want failed", p.TestsStatus)
	}
}

func TestProposeChangedTreeNoTestCmdStaysNotRun(t *testing.T) {
	for _, cmd := range []string{"", "phpunit | tee out"} {
		f := newFixture(t)
		f.consent()
		p := f.proj
		p.TestCmd = cmd
		f.update(p)
		evilAgent(f)
		a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
		if err != nil {
			t.Fatal(err)
		}
		f.wait(a.ID)
		prop, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
		if !ok {
			t.Fatalf("no proposal: %+v", f.attempt(a.ID))
		}
		if prop.TestsStatus != workcopy.TestsNotRun {
			t.Errorf("test command %q: tests status = %q, want not_run", cmd, prop.TestsStatus)
		}
	}
}

func TestReviewFilesOrder(t *testing.T) {
	files := []string{"src/b.php", "app/composer.lock", "src/a.php", "tests/AppTest.php", "app/composer.json", "phpunit.xml.dist",
		"package.json", "config/app.php", "bin/script.sh", "yarn.lock"}
	got := reviewFiles(files)
	want := []ReviewFile{
		{"app/composer.json", FileManifest}, {"package.json", FileManifest},
		{"app/composer.lock", FileLockfile}, {"yarn.lock", FileLockfile},
		{"tests/AppTest.php", FileTests}, {"phpunit.xml.dist", FileTests}, {"config/app.php", FileTests}, {"bin/script.sh", FileTests},
		{"src/b.php", FileCode}, {"src/a.php", FileCode},
	}
	if !slices.Equal(got, want) {
		t.Errorf("reviewFiles =\n%v\nwant\n%v", got, want)
	}
}

func TestShownReviewFilesNeverHidesARiskyFile(t *testing.T) {
	var files []string
	for i := range 14 {
		files = append(files, fmt.Sprintf("src/F%02d.php", i))
	}
	files = append(files, "composer.json", "composer.lock", "tests/ZTest.php")
	shown, more := ShownReviewFiles(reviewFiles(files))
	if more != 4 || len(shown) != 13 {
		t.Fatalf("shown %d, more %d", len(shown), more)
	}
	for _, f := range []string{"composer.json", "composer.lock", "tests/ZTest.php"} {
		if !slices.ContainsFunc(shown, func(r ReviewFile) bool { return r.Path == f }) {
			t.Errorf("%s fell into and N more", f)
		}
	}
}

// TestProposeManifestOnlyChangeAwaitsAndListsIt: an agent that only edits
// composer.json (its scripts can hold a command) still waits for the click,
// and Michel names the manifest as the list of software, which can hold
// commands.
func TestProposeManifestOnlyChangeAwaitsAndListsIt(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.2.5"},"scripts":{"test":"curl evil"}}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Upgrade acme/lib."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok || p.TestsStatus != workcopy.TestsAwaiting {
		t.Fatalf("proposal = %+v", p)
	}
	if got := ReviewFiles(p); len(got) != 1 || got[0] != (ReviewFile{"composer.json", FileManifest}) {
		t.Errorf("review files = %v", got)
	}
	if text := michelText(t, f, a.ID); !strings.Contains(text, i18n.T(i18n.EN, "fix.msg.file_manifest", "composer.json")) {
		t.Errorf("Michel's message = %q", text)
	}
}
