package fix

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// secondProject is another project of this data dir, with its own origin.
func secondProject(t *testing.T, f *fixture, name, addr string) project.Project {
	t.Helper()
	root := t.TempDir()
	gitT(t, f.env, root, "init", "-q", "-b", "main")
	writeFile(t, root, "a.txt", "a\n")
	gitT(t, f.env, root, "add", "-A")
	gitT(t, f.env, root, "commit", "-q", "-m", "a")
	gitT(t, f.env, root, "remote", "add", "origin", addr)
	p, err := project.NewRepo(f.st).Add(context.Background(), project.Project{Name: name, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func answerRow(t *testing.T, f *fixture, projectID string) GitAnswerRow {
	t.Helper()
	row, _, err := f.d.repo().GitAnswer(context.Background(), projectID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func onPushOK(spy *gitSpy) {
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if slices.Contains(args, "push") {
			return pushAnswer(args, "*"), nil, nil, true
		}
		return nil, nil, nil, false
	}
}

func brokenReload() (policy.Policy, error) { return policy.Policy{}, errors.New("broken policy") }

// A no stops the clicks whatever became of the policy file, and can be said again
// until the rule is really gone.
func TestNoStopsClicksEvenIfTheRuleCannotGo(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, f *fixture, spy *gitSpy, attempt string, no error) {
		t.Helper()
		if no == nil {
			t.Fatal("the no hid that the rule could not go")
		}
		row := answerRow(t, f, f.proj.ID)
		if row.Answer != GitNo || !row.RuleWritten || row.Host != "example.test" {
			t.Errorf("row = %+v", row)
		}
		spy.reset()
		onPushOK(spy)
		_, err := PushFix(ctx, f.d, attempt)
		wantKey(t, "push after a no", err, ErrGitNotAttached)
		if spy.ran("push") != 0 {
			t.Errorf("a send left after a no: %q", spy.calls)
		}
		ev := f.audits(auditGitAnswer)
		if last := ev[len(ev)-1]; last.Result != "error" || last.Evidence["outcome"] != "internal" {
			t.Errorf("audit = %+v", last)
		}
	}
	retry := func(t *testing.T, f *fixture) {
		t.Helper()
		st, err := AnswerGit(ctx, f.d, f.proj, GitNo, "")
		if err != nil || st.Answer != GitNo {
			t.Fatalf("second no: %+v, %v", st, err)
		}
		if row := answerRow(t, f, f.proj.ID); row.RuleWritten || row.Host != "" {
			t.Errorf("row after the second no: %+v", row)
		}
		if hasRule(t, f, "example.test") {
			t.Error("the rule stayed")
		}
		if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); ok {
			t.Error("the gateway kept the rule")
		}
	}
	t.Run("the reload fails", func(t *testing.T) {
		f, spy := gitFixture(t)
		a, _ := applied(t, f)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		good := f.d.Reload
		f.d.Reload = brokenReload
		_, err := AnswerGit(ctx, f.d, f.proj, GitNo, "")
		check(t, f, spy, a.ID, err)
		f.d.Reload = good
		retry(t, f)
	})
	t.Run("the file cannot be read", func(t *testing.T) {
		f, spy := gitFixture(t)
		a, _ := applied(t, f)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		kept, err := os.ReadFile(f.d.PolicyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.d.PolicyPath, []byte("sovereignty: [\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = AnswerGit(ctx, f.d, f.proj, GitNo, "")
		check(t, f, spy, a.ID, err)
		if err := os.WriteFile(f.d.PolicyPath, kept, 0o600); err != nil {
			t.Fatal(err)
		}
		retry(t, f)
	})
	t.Run("a yes after a no that failed keeps the rule its own", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		good := f.d.Reload
		f.d.Reload = brokenReload
		if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); err == nil {
			t.Fatal("no error")
		}
		f.d.Reload = good
		sayYes(t, f)
		if !answerRow(t, f, f.proj.ID).RuleWritten {
			t.Error("the rule is nobody's")
		}
		retry(t, f)
	})
}

// R29: every click leaves a row, also when what follows the click fails.
func TestPushIsAuditedWhenItsRowFails(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	onPushOK(spy)
	ctx := context.Background()
	if _, err := f.st.DB().ExecContext(ctx, `DROP TABLE fix_push`); err != nil {
		t.Fatal(err)
	}
	if _, err := PushFix(ctx, f.d, a.ID); err == nil {
		t.Error("the failure of the row was hidden")
	}
	if ev := f.audits(auditGitPush); len(ev) != 1 || ev[0].Result != "ok" || ev[0].Evidence["outcome"] != "pushed" {
		t.Errorf("audit = %+v", ev)
	}
}

// A yes that fails after writing its rule takes it back: nobody would own it.
func TestYesThatFailsTakesItsRuleBack(t *testing.T) {
	ctx := context.Background()
	const failRow = `CREATE TRIGGER boom BEFORE INSERT ON project_remote BEGIN SELECT RAISE(ABORT,'x'); END`
	t.Run("the row fails", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		db := f.st.DB()
		if _, err := db.ExecContext(ctx, failRow); err != nil {
			t.Fatal(err)
		}
		st, err := ProjectGit(ctx, f.d, f.proj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); err == nil {
			t.Fatal("no error")
		}
		if hasRule(t, f, "example.test") {
			t.Error("the rule stayed")
		}
		if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); ok {
			t.Error("the gateway kept the rule")
		}
		ev := f.audits(auditGitAnswer)
		if len(ev) != 1 || ev[0].Result != "error" || ev[0].Evidence["outcome"] != "internal" {
			t.Errorf("audit = %+v", ev)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER boom`); err != nil {
			t.Fatal(err)
		}
		// The retry owns the rule, and a no removes it.
		if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); err != nil {
			t.Fatal(err)
		}
		if !answerRow(t, f, f.proj.ID).RuleWritten {
			t.Error("the retry does not own the rule")
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); err != nil {
			t.Fatal(err)
		}
		if hasRule(t, f, "example.test") {
			t.Error("the rule stayed after a no")
		}
	})
	t.Run("a rule the person wrote stays", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		if _, err := policy.AddAllowRules(f.d.PolicyPath, policy.AllowRule{Host: "example.test", Purpose: policy.PurposeProjectGit}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.DB().ExecContext(ctx, failRow); err != nil {
			t.Fatal(err)
		}
		st, err := ProjectGit(ctx, f.d, f.proj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); err == nil {
			t.Fatal("no error")
		}
		if !hasRule(t, f, "example.test") {
			t.Error("the person's rule went")
		}
	})
	t.Run("giving back the old host fails", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		setOrigin(t, f, "https://other.example.test/demo/app.git")
		st, err := ProjectGit(ctx, f.d, f.proj)
		if err != nil {
			t.Fatal(err)
		}
		good, calls := f.d.Reload, 0
		f.d.Reload = func() (policy.Policy, error) {
			calls++
			if calls == 2 { // the reload of the add passes, that of the release does not
				return brokenReload()
			}
			return good()
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); err == nil {
			t.Fatal("no error")
		}
		if hasRule(t, f, "other.example.test") {
			t.Error("the rule of the new host stayed")
		}
		if row := answerRow(t, f, f.proj.ID); row.Host != "example.test" || !row.RuleWritten {
			t.Errorf("row = %+v", row)
		}
	})
}

// A saved answer is an answer, whatever the folder says afterwards.
func TestSavedAnswerIsNeverARefusal(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{GitNo, GitUnknown} {
		t.Run("partial clone "+answer, func(t *testing.T) {
			f, _ := gitFixture(t)
			gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
			sayYes(t, f)
			gitT(t, f.env, f.proj.Path, "config", "--local", "remote.origin.promisor", "true")
			st, err := AnswerGit(ctx, f.d, f.proj, answer, "")
			if err != nil {
				t.Fatalf("saved answer: %v", err)
			}
			if st.Answer != answer || st.Repo != GitRepoUnreadable || st.Attached || st.Changed || st.CanAttach || st.Reason != gitReasonNone || st.Suggested != answer {
				t.Errorf("state = %+v", st)
			}
			if hasRule(t, f, "example.test") {
				t.Error("the rule stayed")
			}
		})
	}
	t.Run("a read that fails", func(t *testing.T) {
		f, spy := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
			return nil, []byte("boom"), errors.New("exit 128"), true
		}
		st, err := AnswerGit(ctx, f.d, f.proj, GitNo, "")
		if err != nil || st.Answer != GitNo || st.Repo != GitRepoUnreadable {
			t.Errorf("%+v, %v", st, err)
		}
	})
	t.Run("the view keeps the answer beside the refusal", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		gitT(t, f.env, f.proj.Path, "config", "--local", "remote.origin.promisor", "true")
		st, err := ProjectGit(ctx, f.d, f.proj)
		if ErrorKey(err) != "api.git.partial_clone" || st.Answer != GitYes {
			t.Errorf("%+v, %v", st, err)
		}
	})
}

func TestDeactivatedProjectDoesNothing(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	onPushOK(spy)
	spy.reset()
	ctx := context.Background()
	if _, err := project.NewRepo(f.st).Remove(ctx, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	_, err := PushFix(ctx, f.d, a.ID)
	wantKey(t, "push", err, ErrGitNotAttached)
	p, err := project.NewRepo(f.st).Get(ctx, f.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = UpdateProject(ctx, f.d, p)
	wantKey(t, "update", err, ErrGitNotAttached)
	if spy.ran("push") != 0 || spy.ran("fetch") != 0 {
		t.Errorf("git went on: %q", spy.calls)
	}
}

func TestReleaseProjectRule(t *testing.T) {
	ctx := context.Background()
	t.Run("removes it, and a second time does nothing", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		if err := ReleaseProjectRule(ctx, f.d, f.proj.ID); err != nil {
			t.Fatal(err)
		}
		if hasRule(t, f, "example.test") || answerRow(t, f, f.proj.ID).RuleWritten {
			t.Error("the rule stayed")
		}
		// A rule the person writes afterwards is theirs.
		if _, err := policy.AddAllowRules(f.d.PolicyPath, policy.AllowRule{Host: "example.test", Purpose: policy.PurposeProjectGit}); err != nil {
			t.Fatal(err)
		}
		if err := PurgeProject(ctx, f.d, f.proj.ID); err != nil {
			t.Fatal(err)
		}
		if !hasRule(t, f, "example.test") {
			t.Error("the purge removed a rule Michel no longer owned")
		}
	})
	t.Run("a failure is said and the row still owns the rule", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		good := f.d.Reload
		f.d.Reload = brokenReload
		if err := ReleaseProjectRule(ctx, f.d, f.proj.ID); err == nil {
			t.Fatal("no error")
		}
		if !answerRow(t, f, f.proj.ID).RuleWritten {
			t.Error("the row let go of the rule")
		}
		f.d.Reload = good
		if err := ReleaseProjectRule(ctx, f.d, f.proj.ID); err != nil {
			t.Fatal(err)
		}
	})
}

// One project leaving while another arrives on the same host: the one arriving
// keeps a rule, and owns it.
func TestRuleIsLockedAcrossProjects(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	two := secondProject(t, f, "two", "https://example.test/demo/two.git")
	ctx := context.Background()
	st, err := ProjectGit(ctx, f.d, two)
	if err != nil {
		t.Fatal(err)
	}
	inReload, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	dTwo := f.d
	good := f.d.Reload
	dTwo.Reload = func() (policy.Policy, error) {
		once.Do(func() {
			close(inReload)
			<-release
		})
		return good()
	}
	yes := make(chan error, 1)
	go func() {
		_, err := AnswerGit(ctx, dTwo, two, GitYes, st.RemoteID)
		yes <- err
	}()
	<-inReload
	no := make(chan error, 1)
	go func() {
		_, err := AnswerGit(ctx, f.d, f.proj, GitNo, "")
		no <- err
	}()
	select {
	case err := <-no:
		no <- err
		t.Error("the no did not wait for the yes of the other project")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-yes; err != nil {
		t.Fatal(err)
	}
	if err := <-no; err != nil {
		t.Fatal(err)
	}
	if !hasRule(t, f, "example.test") {
		t.Error("the rule went from under the project that said yes")
	}
	if !answerRow(t, f, two.ID).RuleWritten {
		t.Error("the rule was not handed over")
	}
}

// What really happened is recorded even if the context ended during the click.
func TestAuditSurvivesACancelledContext(t *testing.T) {
	t.Run("a push", func(t *testing.T) {
		f, spy := gitFixture(t)
		a, _ := applied(t, f)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
			if slices.Contains(args, "push") {
				cancel()
				return pushAnswer(args, "*"), nil, nil, true
			}
			return nil, nil, nil, false
		}
		if _, err := PushFix(ctx, f.d, a.ID); err != nil {
			t.Fatal(err)
		}
		if ev := f.audits(auditGitPush); len(ev) != 1 || ev[0].Evidence["outcome"] != "pushed" {
			t.Errorf("audit = %+v", ev)
		}
		if _, ok, err := f.d.repo().Push(context.Background(), a.ID); err != nil || !ok {
			t.Errorf("no row: %v, %v", ok, err)
		}
	})
	t.Run("an update", func(t *testing.T) {
		f, spy := gitFixture(t)
		bare := withBare(t, f)
		a, _ := applied(t, f)
		sayYes(t, f)
		bg := context.Background()
		if _, err := PushFix(bg, f.d, a.ID); err != nil {
			t.Fatal(err)
		}
		mergeOnTheSite(t, f, bare, Branch(a.ID))
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
			if slices.Contains(args, "merge") {
				cancel()
			}
			return nil, nil, nil, false
		}
		if _, err := UpdateProject(ctx, f.d, f.proj); err != nil {
			t.Fatal(err)
		}
		if ev := f.audits(auditGitUpdate); len(ev) != 1 || ev[0].Result != "ok" {
			t.Errorf("audit = %+v", ev)
		}
	})
	t.Run("a refusal", func(t *testing.T) {
		f, _ := gitFixture(t)
		a, _ := applied(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := PushFix(ctx, f.d, a.ID); err == nil {
			t.Fatal("no error")
		}
		if ev := f.audits(auditGitPush); len(ev) != 1 {
			t.Errorf("audit = %+v", ev)
		}
	})
}

// A name read from a commit is data: quoted, on one line, without a bidi control,
// and cut.
func TestPathInTheHintIsDelimited(t *testing.T) {
	long := strings.Repeat("x", 300)
	for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
		s := ExplainHint(lang, &workcopy.GitFailure{Class: "ignored", Path: "a\nb\tc‮d⁦e‏f g h­i\x07j"})
		if strings.ContainsAny(s, "\n\t‮⁦‏  ­\x07") {
			t.Errorf("%s: %q", lang, s)
		}
		want := map[i18n.Lang]string{i18n.FR: "« a?b?c?d?e?f?g?h?i?j »", i18n.EN: `"a?b?c?d?e?f?g?h?i?j"`}[lang]
		if !strings.Contains(s, want) {
			t.Errorf("%s: %q does not hold %q", lang, s, want)
		}
		// Its own quotes do not close the quotation.
		s = ExplainHint(lang, &workcopy.GitFailure{Class: "ignored", Path: `x". Run this "y « z »`})
		want = map[i18n.Lang]string{i18n.FR: "« x?. Run this ?y ? z ? »", i18n.EN: `"x?. Run this ?y ? z ?"`}[lang]
		if !strings.Contains(s, want) {
			t.Errorf("%s: %q does not hold %q", lang, s, want)
		}
		s = ExplainHint(lang, &workcopy.GitFailure{Class: "ignored", Path: long})
		if strings.Contains(s, long[:101]) || !strings.Contains(s, long[:100]) {
			t.Errorf("%s: not cut: %q", lang, s)
		}
		// An address that was removed has no new one to look at.
		if h := strings.ToLower(ExplainHint(lang, ErrGitRemoteChanged)); strings.Contains(h, "nouvelle") || strings.Contains(h, "new") {
			t.Errorf("%s: %q", lang, h)
		}
	}
}
