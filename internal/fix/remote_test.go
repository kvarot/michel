package fix

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

const (
	gitCanary = "canari-git-7391"
	httpsDemo = "https://example.test/demo/app.git"
)

// gitSpy sees every git command of the work copy, and may answer one instead of
// git: a remote that is not on this disk.
type gitSpy struct {
	mu    sync.Mutex
	calls []string
	next  workcopy.ExecFunc
	on    func(args, env []string) (stdout, stderr []byte, err error, handled bool)
}

func (s *gitSpy) exec(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
	if name == "git" {
		s.mu.Lock()
		s.calls = append(s.calls, strings.Join(args, " "))
		on := s.on
		s.mu.Unlock()
		if on != nil {
			if out, stderr, err, handled := on(args, env); handled {
				return out, stderr, err
			}
		}
	}
	return s.next(ctx, name, args, env, dir)
}

func (s *gitSpy) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// ran counts the commands holding word as an argument of their own.
func (s *gitSpy) ran(word string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if slices.Contains(strings.Fields(c), word) {
			n++
		}
	}
	return n
}

func (s *gitSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// gitFixture is the project demo, the person's own settings kept out of the test.
func gitFixture(t *testing.T) (*fixture, *gitSpy) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	for _, k := range []string{"GIT_SSH", "GIT_SSH_COMMAND", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	f := newFixture(t)
	spy := &gitSpy{next: f.d.Work.Exec}
	f.d.Work.Exec = spy.exec
	return f, spy
}

// withBare gives the project a bare repository as origin, reached through the test
// seam (R33): no network.
func withBare(t *testing.T, f *fixture) string {
	t.Helper()
	f.d.AllowLocalRemote = true
	bare := filepath.ToSlash(filepath.Join(t.TempDir(), "remote.git"))
	gitT(t, f.env, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", bare)
	gitT(t, f.env, f.proj.Path, "push", "-q", "origin", "main")
	return bare
}

func setOrigin(t *testing.T, f *fixture, addr string) {
	t.Helper()
	cfg := filepath.Join(f.proj.Path, ".git", "config")
	if _, err := os.Stat(cfg); err != nil {
		t.Fatal(err)
	}
	gitT(t, f.env, f.proj.Path, "config", "--local", "remote.origin.url", addr)
}

func sayYes(t *testing.T, f *fixture) GitState {
	t.Helper()
	ctx := context.Background()
	st, err := ProjectGit(ctx, f.d, f.proj)
	if err != nil {
		t.Fatalf("ProjectGit: %v", err)
	}
	st, err = AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID)
	if err != nil {
		t.Fatalf("AnswerGit yes: %v", err)
	}
	if !st.Attached || st.Answer != GitYes {
		t.Fatalf("after yes: %+v", st)
	}
	return st
}

// applied brings a fix of demo to state applied: the local branch exists.
func applied(t *testing.T, f *fixture) (Attempt, Proposal) {
	t.Helper()
	ctx := context.Background()
	f.consent()
	a, err := Start(ctx, f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, err := f.d.Repo.CurrentProposal(ctx, a.ID)
	if err != nil || !ok {
		t.Fatalf("proposal: %v, %v", ok, err)
	}
	if err := Approve(ctx, f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	return f.attempt(a.ID), p
}

// pushAnswer is git's answer to a push of the fix branch.
func pushAnswer(args []string, flag string) []byte {
	for _, a := range args {
		if strings.HasPrefix(a, "refs/heads/michel/") {
			return fmt.Appendf(nil, "To somewhere\n%s\t%s\t[new branch]\nDone\n", flag, a)
		}
	}
	return nil
}

func hasRule(t *testing.T, f *fixture, host string) bool {
	t.Helper()
	pol, _, err := policy.Load(f.policy, f.d.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	return allowed(pol.Sovereignty.Network.Allow, host, policy.PurposeProjectGit)
}

func wantKey(t *testing.T, what string, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Errorf("%s: %v, want %v", what, err, target)
	}
}

func TestNothingAttachedWithoutYes(t *testing.T) {
	f, spy := gitFixture(t)
	withBare(t, f)
	a, _ := applied(t, f)
	ctx := context.Background()
	for _, answer := range []string{"", GitNo, GitUnknown} {
		if answer != "" {
			if _, err := AnswerGit(ctx, f.d, f.proj, answer, ""); err != nil {
				t.Fatal(err)
			}
		}
		spy.reset()
		_, err := PushFix(ctx, f.d, a.ID)
		wantKey(t, "push after "+answer, err, ErrGitNotAttached)
		_, err = UpdateProject(ctx, f.d, f.proj)
		wantKey(t, "update after "+answer, err, ErrGitNotAttached)
		if n := spy.count(); n != 0 {
			t.Errorf("answer %q: git ran %d times: %q", answer, n, spy.calls)
		}
		st, err := ProjectGit(ctx, f.d, f.proj)
		if err != nil || st.Attached {
			t.Errorf("answer %q: state %+v, %v", answer, st, err)
		}
	}
}

func TestSuggestionIsNeverAnAnswer(t *testing.T) {
	f, _ := gitFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		addr, reason, suggested, provider string
		can                               bool
	}{
		{"https://github.com/demo/app.git", "known", GitYes, "github", true},
		{"git@gitlab.com:demo/app.git", "known", GitYes, "gitlab", true},
		{httpsDemo, "other", GitYes, "other", true},
		{"", "none", GitNo, "", false},
		{"http://example.test/demo/app.git", "unsupported", GitUnknown, "", false},
	} {
		if c.addr == "" {
			gitT(t, f.env, f.proj.Path, "remote", "remove", "origin")
		} else if strings.Contains(gitT(t, f.env, f.proj.Path, "remote"), "origin") {
			setOrigin(t, f, c.addr)
		} else {
			gitT(t, f.env, f.proj.Path, "remote", "add", "origin", c.addr)
		}
		st, err := ProjectGit(ctx, f.d, f.proj)
		if err != nil {
			t.Fatalf("%s: %v", c.addr, err)
		}
		if st.Repo != workcopy.RepoOK || st.Reason != c.reason || st.Suggested != c.suggested || st.Provider != c.provider || st.CanAttach != c.can {
			t.Errorf("%s: %+v", c.addr, st)
		}
		if st.Answer != "" || st.Attached {
			t.Errorf("%s: a suggestion became an answer: %+v", c.addr, st)
		}
		if st.Update != nil {
			t.Errorf("%s: an update state for a project not attached: %+v", c.addr, st.Update)
		}
	}
	gitT(t, f.env, f.proj.Path, "remote", "remove", "origin")
	gitT(t, f.env, f.proj.Path, "remote", "add", "one", httpsDemo)
	gitT(t, f.env, f.proj.Path, "remote", "add", "two", httpsDemo)
	st, err := ProjectGit(ctx, f.d, f.proj)
	if err != nil || st.Reason != "several" || st.Suggested != GitUnknown || st.CanAttach {
		t.Errorf("several: %+v, %v", st, err)
	}
}

func TestProjectGitOnFoldersWithoutARemoteToAsk(t *testing.T) {
	f, _ := gitFixture(t)
	ctx := context.Background()
	st, err := ProjectGit(ctx, f.d, project.Project{ID: "pnone", Name: "plain", Path: t.TempDir()})
	if err != nil || st.Repo != workcopy.RepoNone || st.CanAttach {
		t.Errorf("no repository: %+v, %v", st, err)
	}
	empty := t.TempDir()
	gitT(t, f.env, empty, "init", "-q")
	gitT(t, f.env, empty, "remote", "add", "origin", httpsDemo)
	pe := project.Project{ID: "pempty", Name: "empty", Path: empty}
	st, err = ProjectGit(ctx, f.d, pe)
	if err != nil || st.Repo != workcopy.RepoEmpty || st.CanAttach {
		t.Errorf("no commit: %+v, %v", st, err)
	}
	_, err = AnswerGit(ctx, f.d, pe, GitYes, st.RemoteID)
	wantKey(t, "yes without a commit", err, ErrGitEmptyRepo)
	_, err = AnswerGit(ctx, f.d, project.Project{ID: "pnone", Name: "plain", Path: t.TempDir()}, GitYes, "x")
	wantKey(t, "yes without a repository", err, ErrGitNoRepo)
}

func TestYesWritesOneRuleAndReloads(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); ok {
		t.Fatal("allowed before any yes")
	}
	sayYes(t, f)
	if !hasRule(t, f, "example.test") {
		t.Error("no rule in the policy file")
	}
	if _, err := os.Stat(f.policy + ".bak"); err != nil {
		t.Errorf("no backup of the policy: %v", err)
	}
	if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); !ok {
		t.Error("the gateway did not learn the rule")
	}
	row, ok, err := f.d.Repo.GitAnswer(context.Background(), f.proj.ID)
	if err != nil || !ok || !row.RuleWritten || row.Host != "example.test" || row.URL != httpsDemo || row.Answer != GitYes {
		t.Errorf("row = %+v, %v, %v", row, ok, err)
	}
	sayYes(t, f)
	b, _ := os.ReadFile(f.policy)
	if strings.Count(string(b), policy.PurposeProjectGit) != 1 {
		t.Errorf("rule written twice:\n%s", b)
	}
	row, _, _ = f.d.Repo.GitAnswer(context.Background(), f.proj.ID)
	if !row.RuleWritten {
		t.Error("a second yes forgot that Michel wrote the rule")
	}
}

func TestYesOnStrictLocalKeepsTheMode(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	if err := os.WriteFile(f.policy, []byte(strings.Replace(standardPolicy, "mode: standard", "mode: strict_local", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Reload(); err != nil {
		t.Fatal(err)
	}
	sayYes(t, f)
	pol, _, err := policy.Load(f.policy, f.d.DataDir)
	if err != nil || pol.Sovereignty.Mode != policy.ModeStrictLocal {
		t.Errorf("mode = %s, %v", pol.Sovereignty.Mode, err)
	}
	if !hasRule(t, f, "example.test") {
		t.Error("no rule")
	}
}

func TestYesNeedsTheAddressShown(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	ctx := context.Background()
	st, _ := ProjectGit(ctx, f.d, f.proj)
	setOrigin(t, f, "https://other.example.test/demo/app.git")
	_, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID)
	wantKey(t, "stale remote_id", err, ErrGitRemoteChanged)
	_, err = AnswerGit(ctx, f.d, f.proj, GitYes, "")
	wantKey(t, "no remote_id", err, ErrGitRemoteChanged)
	if _, ok, _ := f.d.Repo.GitAnswer(ctx, f.proj.ID); ok {
		t.Error("a row was written")
	}
	if hasRule(t, f, "example.test") || hasRule(t, f, "other.example.test") {
		t.Error("a rule was written")
	}
	gitT(t, f.env, f.proj.Path, "remote", "remove", "origin")
	_, err = AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID)
	wantKey(t, "no address", err, ErrGitNoRemote)
}

func TestYesSurvivesAnotherUserAndPassword(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", "ssh://git@example.test/demo/app.git")
	sayYes(t, f)
	ctx := context.Background()
	// The same address with another SSH user is the same address (R54).
	setOrigin(t, f, "ssh://deploy@example.test/demo/app.git")
	if st, err := ProjectGit(ctx, f.d, f.proj); err != nil || !st.Attached || st.Changed {
		t.Errorf("another SSH user: %+v, %v", st, err)
	}
	setOrigin(t, f, "ssh://git@example.test/demo/other.git")
	if st, err := ProjectGit(ctx, f.d, f.proj); err != nil || st.Attached || !st.Changed || st.Update != nil {
		t.Errorf("another project: %+v, %v", st, err)
	}
}

func TestAnswerCanChange(t *testing.T) {
	ctx := context.Background()
	t.Run("yes then no removes the rule Michel wrote", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		for _, answer := range []string{GitNo, GitUnknown} {
			st, err := AnswerGit(ctx, f.d, f.proj, answer, "")
			if err != nil || st.Attached || st.Answer != answer {
				t.Fatalf("%s: %+v, %v", answer, st, err)
			}
			if hasRule(t, f, "example.test") {
				t.Errorf("%s: the rule stayed", answer)
			}
			if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); ok {
				t.Errorf("%s: the gateway kept the rule", answer)
			}
			sayYes(t, f)
		}
	})
	t.Run("a rule another project uses stays until the last one", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		root := t.TempDir()
		gitT(t, f.env, root, "init", "-q", "-b", "main")
		writeFile(t, root, "a.txt", "a\n")
		gitT(t, f.env, root, "add", "-A")
		gitT(t, f.env, root, "commit", "-q", "-m", "a")
		gitT(t, f.env, root, "remote", "add", "origin", "https://example.test/demo/two.git")
		two, err := project.NewRepo(f.st).Add(ctx, project.Project{Name: "two", Path: root})
		if err != nil {
			t.Fatal(err)
		}
		st, _ := ProjectGit(ctx, f.d, two)
		if _, err := AnswerGit(ctx, f.d, two, GitYes, st.RemoteID); err != nil {
			t.Fatal(err)
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); err != nil {
			t.Fatal(err)
		}
		if !hasRule(t, f, "example.test") {
			t.Fatal("the rule two uses was removed")
		}
		if _, err := AnswerGit(ctx, f.d, two, GitNo, ""); err != nil {
			t.Fatal(err)
		}
		if hasRule(t, f, "example.test") {
			t.Error("the last project left and the rule Michel wrote stayed")
		}
	})
	t.Run("a rule Michel did not write stays", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		if _, err := policy.AddAllowRules(f.policy, policy.AllowRule{Host: "example.test", Purpose: policy.PurposeProjectGit}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.d.Reload(); err != nil {
			t.Fatal(err)
		}
		f.d.Gateway.SetRules(f.d.Policy.Sovereignty.Network.Allow)
		sayYes(t, f)
		if row, _, _ := f.d.Repo.GitAnswer(ctx, f.proj.ID); row.RuleWritten {
			t.Error("rule_written is true for the person's rule")
		}
		if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); err != nil {
			t.Fatal(err)
		}
		if !hasRule(t, f, "example.test") {
			t.Error("the person's rule was removed")
		}
	})
	t.Run("a new address gives back the rule of the old host", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		sayYes(t, f)
		setOrigin(t, f, "https://other.example.test/demo/app.git")
		sayYes(t, f)
		if hasRule(t, f, "example.test") || !hasRule(t, f, "other.example.test") {
			t.Errorf("rules: old %v, new %v", hasRule(t, f, "example.test"), hasRule(t, f, "other.example.test"))
		}
	})
	t.Run("a policy that does not load is put back", func(t *testing.T) {
		f, _ := gitFixture(t)
		gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
		st, _ := ProjectGit(ctx, f.d, f.proj)
		f.d.Reload = func() (policy.Policy, error) { return policy.Policy{}, errors.New("no") }
		if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); err == nil {
			t.Fatal("no error")
		}
		if hasRule(t, f, "example.test") {
			t.Error("the rule stayed though the policy could not be reloaded")
		}
		if _, ok, _ := f.d.Repo.GitAnswer(ctx, f.proj.ID); ok {
			t.Error("a row was written")
		}
	})
}

func TestStoredRowHasNoSecret(t *testing.T) {
	f, _ := gitFixture(t)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", "https://demo:"+gitCanary+"@example.test/demo/app.git")
	st := sayYes(t, f)
	if !st.HadCredential {
		t.Error("the presence of a secret is not told")
	}
	for _, field := range []string{st.Display, st.Host, st.RemoteID, st.Provider} {
		if strings.Contains(field, gitCanary) {
			t.Errorf("secret in the state: %+v", st)
		}
	}
	var name, url, host, provider string
	if err := f.st.DB().QueryRow(`SELECT remote_name, url, host, provider FROM project_remote`).Scan(&name, &url, &host, &provider); err != nil {
		t.Fatal(err)
	}
	if url != httpsDemo || strings.Contains(name+url+host+provider, gitCanary) {
		t.Errorf("row: %q %q %q %q", name, url, host, provider)
	}
	f.noCanary(t)
}

// noCanary reads every place a click could leave text in.
func (f *fixture) noCanary(t *testing.T) {
	t.Helper()
	for _, q := range []string{
		`SELECT coalesce(action,'') || ' ' || coalesce(target,'') || ' ' || coalesce(result,'') || ' ' || coalesce(evidence,'') FROM audit_event`,
		`SELECT text FROM fix_message`,
		`SELECT cause || ' ' || cause_detail FROM fix_attempt`,
		`SELECT url || ' ' || host FROM project_remote`,
		`SELECT commit_sha || ' ' || host FROM fix_push`,
	} {
		rows, err := f.st.DB().Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(s, gitCanary) {
				t.Errorf("the canary is stored: %s", s)
			}
		}
		rows.Close()
	}
}

func TestPushNeedsApplied(t *testing.T) {
	f, spy := gitFixture(t)
	withBare(t, f)
	a, _ := applied(t, f)
	sayYes(t, f)
	spy.reset()
	for _, state := range []State{StatePreparing, StateProposed, StateApproved, StateRefused, StateProvenFixed, StateInconclusive, StateFailed, StateSuperseded, StateHeld, StateWithdrawn} {
		if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(state), a.ID); err != nil {
			t.Fatal(err)
		}
		_, err := PushFix(context.Background(), f.d, a.ID)
		wantKey(t, string(state), err, ErrGitNotApplied)
	}
	if n := spy.count(); n != 0 {
		t.Errorf("git ran: %q", spy.calls)
	}
}

func TestServerAttemptCannotPush(t *testing.T) {
	f, spy := gitFixture(t)
	withBare(t, f)
	sayYes(t, f)
	ctx := context.Background()
	a, err := f.d.Repo.CreateAttempt(ctx, Attempt{FindingID: f.finding.ID, ProjectID: f.proj.ID, Origin: OriginServer,
		Work: Work{Server: &ServerWork{TargetID: f.proj.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = 'applied' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	spy.reset()
	_, err = PushFix(ctx, f.d, a.ID)
	wantKey(t, "server attempt", err, ErrGitNotApplied)
	if spy.count() != 0 {
		t.Errorf("git ran: %q", spy.calls)
	}
}

func TestChangedAddressStopsPushAndUpdate(t *testing.T) {
	f, spy := gitFixture(t)
	withBare(t, f)
	a, _ := applied(t, f)
	sayYes(t, f)
	other := filepath.ToSlash(filepath.Join(t.TempDir(), "other.git"))
	gitT(t, f.env, filepath.Dir(other), "init", "-q", "--bare", "-b", "main", other)
	setOrigin(t, f, other)
	spy.reset()
	ctx := context.Background()
	_, err := PushFix(ctx, f.d, a.ID)
	wantKey(t, "push", err, ErrGitRemoteChanged)
	_, err = UpdateProject(ctx, f.d, f.proj)
	wantKey(t, "update", err, ErrGitRemoteChanged)
	if spy.ran("push") != 0 || spy.ran("fetch") != 0 || spy.ran("merge") != 0 {
		t.Errorf("git went on: %q", spy.calls)
	}
	if refs := gitT(t, f.env, other, "for-each-ref"); refs != "" {
		t.Errorf("the new address received something: %s", refs)
	}
	st, err := ProjectGit(ctx, f.d, f.proj)
	if err != nil || !st.Changed || st.Attached || st.Answer != GitYes {
		t.Errorf("state: %+v, %v", st, err)
	}
	// The fix asks again: no remote at all is the same refusal.
	gitT(t, f.env, f.proj.Path, "remote", "remove", "origin")
	_, err = PushFix(ctx, f.d, a.ID)
	wantKey(t, "no remote", err, ErrGitRemoteChanged)
}

func TestNoRuleStopsPush(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	if _, err := policy.RemoveAllowRules(f.policy, policy.AllowRule{Host: "example.test", Purpose: policy.PurposeProjectGit}); err != nil {
		t.Fatal(err)
	}
	f.d.Gateway.SetRules(nil)
	spy.reset()
	ctx := context.Background()
	_, err := PushFix(ctx, f.d, a.ID)
	wantKey(t, "push", err, ErrGitNoRule)
	_, err = UpdateProject(ctx, f.d, f.proj)
	wantKey(t, "update", err, ErrGitNoRule)
	if spy.ran("push") != 0 || spy.ran("fetch") != 0 {
		t.Errorf("git went on: %q", spy.calls)
	}
	st, err := ProjectGit(ctx, f.d, f.proj)
	if err != nil || st.Update == nil || st.Update.Ready || st.Update.Code != "api.git.no_rule" {
		t.Errorf("state: %+v, %+v, %v", st, st.Update, err)
	}
}

type failSink struct{}

func (failSink) Record(egress.Attempt) error { return errors.New("the audit log is down") }

func TestPushChecksGatewayFirst(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	gw := f.d.Gateway
	seen := 0
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if !slices.Contains(args, "push") {
			return nil, nil, nil, false
		}
		for _, at := range gw.Attempts() {
			if at.Purpose == policy.PurposeProjectGit && at.Host == "example.test" && at.Allowed {
				seen++
			}
		}
		return pushAnswer(args, "*"), nil, nil, true
	}
	ctx := context.Background()
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Error("no egress attempt before git started")
	}
	// Audit down: nothing is sent.
	pol := f.d.Policy
	f.d.Gateway = egress.New(pol, failSink{})
	spy.reset()
	if _, err := PushFix(ctx, f.d, a.ID); err == nil {
		t.Error("a push without an audit trace")
	} else if ErrorKey(err) == "api.git.no_rule" {
		t.Errorf("audit down reads as a removed rule: %v", err)
	}
	if spy.ran("push") != 0 {
		t.Errorf("git pushed without an audit trace: %q", spy.calls)
	}
}

func TestHttpsUsesTheAllowProxy(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	var proxy string
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if !slices.Contains(args, "push") {
			return nil, nil, nil, false
		}
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "HTTPS_PROXY="); ok {
				proxy = v
			}
		}
		if !slices.Contains(args, httpsDemo) {
			t.Errorf("address: %q", args)
		}
		return pushAnswer(args, "*"), nil, nil, true
	}
	if _, err := PushFix(context.Background(), f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(proxy, "http://michel:") || !strings.Contains(proxy, "@127.0.0.1:") {
		t.Fatalf("proxy = %q", proxy)
	}
	_, addr, _ := strings.Cut(proxy, "@")
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("the proxy is still listening after the click")
	}
}

// R54: what is stored has no SSH user, what git receives has the one the config
// holds now, and never what else the raw address carried.
func TestPushGetsTheUserFromTheConfig(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", "ssh://git:"+gitCanary+"@example.test/demo/app.git")
	sayYes(t, f)
	ctx := context.Background()
	row, _, _ := f.d.Repo.GitAnswer(ctx, f.proj.ID)
	if row.URL != "ssh://example.test/demo/app.git" {
		t.Errorf("stored address = %q", row.URL)
	}
	setOrigin(t, f, "ssh://deploy@example.test/demo/app.git")
	var argv []string
	var noProxy = true
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if !slices.Contains(args, "push") {
			return nil, nil, nil, false
		}
		argv = args
		for _, kv := range env {
			noProxy = noProxy && !strings.HasPrefix(kv, "HTTPS_PROXY=")
		}
		return pushAnswer(args, "*"), nil, nil, true
	}
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(argv, "ssh://deploy@example.test/demo/app.git") {
		t.Errorf("argv = %q", argv)
	}
	if strings.Contains(strings.Join(argv, " "), gitCanary) {
		t.Errorf("a secret in the argv: %q", argv)
	}
	if !noProxy {
		t.Error("an SSH push was given the proxy")
	}
	f.noCanary(t)
}

func TestSecondClickIsAlreadyAndAudited(t *testing.T) {
	f, _ := gitFixture(t)
	bare := withBare(t, f)
	a, p := applied(t, f)
	sayYes(t, f)
	ctx := context.Background()
	first, err := PushFix(ctx, f.d, a.ID)
	if err != nil || first.Outcome != workcopy.PushPushed || first.Branch != Branch(a.ID) || first.Provider != "local" || first.MergeURL != "" {
		t.Fatalf("first click: %+v, %v", first, err)
	}
	if got := gitT(t, f.env, bare, "rev-parse", "refs/heads/"+Branch(a.ID)); got != p.CommitSHA {
		t.Errorf("remote branch = %s, want %s", got, p.CommitSHA)
	}
	f.d.Repo.Now = func() time.Time { return first.At.Add(time.Hour) }
	second, err := PushFix(ctx, f.d, a.ID)
	if err != nil || second.Outcome != workcopy.PushAlready {
		t.Fatalf("second click: %+v, %v", second, err)
	}
	if !second.At.Equal(first.At) {
		t.Errorf("the date moved: %v, %v", first.At, second.At)
	}
	stored, ok, err := f.d.Repo.Push(ctx, a.ID)
	if err != nil || !ok || stored.CommitSHA != p.CommitSHA {
		t.Errorf("row: %+v, %v, %v", stored, ok, err)
	}
	ev := f.audits("project.git.push")
	if len(ev) != 2 || ev[0].Evidence["outcome"] != "pushed" || ev[1].Evidence["outcome"] != "already" {
		t.Errorf("audit = %+v", ev)
	}
}

// blockedPush makes the fake remote hold a push until the test lets it go.
func blockedPush(t *testing.T, f *fixture, spy *gitSpy) (started, release chan struct{}) {
	t.Helper()
	started, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if !slices.Contains(args, "push") {
			return nil, nil, nil, false
		}
		once.Do(func() { close(started) })
		<-release
		return pushAnswer(args, "*"), nil, nil, true
	}
	return started, release
}

func TestConcurrentClickIsBusy(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	st := sayYes(t, f)
	started, release := blockedPush(t, f, spy)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		_, err := PushFix(ctx, f.d, a.ID)
		done <- err
	}()
	<-started
	if !GitBusy(f.d, f.proj.ID) {
		t.Error("GitBusy is false during a click")
	}
	_, err := PushFix(ctx, f.d, a.ID)
	wantKey(t, "second push", err, ErrGitBusy)
	_, err = UpdateProject(ctx, f.d, f.proj)
	wantKey(t, "update", err, ErrGitBusy)
	_, err = AnswerGit(ctx, f.d, f.proj, GitNo, "")
	wantKey(t, "answer", err, ErrGitBusy)
	if unlock, ok := TryGitLock(f.d, f.proj.ID); ok {
		unlock()
		t.Error("TryGitLock took the lock of a running click")
	}
	if got, err := ProjectGit(ctx, f.d, f.proj); err != nil || got.Update == nil || got.Update.Code != "api.git.busy" || got.Update.Ready {
		t.Errorf("the page during a click: %+v, %v", got, err)
	}
	_ = st
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if GitBusy(f.d, f.proj.ID) {
		t.Error("GitBusy is true after the click")
	}
	unlock, ok := TryGitLock(f.d, f.proj.ID)
	if !ok {
		t.Fatal("the lock is not free")
	}
	_, err = UpdateProject(ctx, f.d, f.proj)
	wantKey(t, "update while a scan holds the lock", err, ErrGitBusy)
	unlock()
}

func TestGitBusyDuringAClick(t *testing.T) {
	f, _ := gitFixture(t)
	if GitBusy(f.d, f.proj.ID) {
		t.Fatal("busy with nothing running")
	}
	lock := f.d.sessions().gitLock(f.proj.ID)
	lock.Lock()
	if !GitBusy(f.d, f.proj.ID) {
		t.Error("not busy with the lock taken")
	}
	lock.Unlock()
	if GitBusy(f.d, "another") {
		t.Error("the lock of another project")
	}
}

func TestAutoApplyNeverPushes(t *testing.T) {
	f, spy := gitFixture(t)
	bare := withBare(t, f)
	sayYes(t, f)
	f.consent()
	level3(t, f)
	proposeOnly(f)
	spy.reset()
	ctx := context.Background()
	a, err := Start(ctx, f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateApplied {
		t.Fatalf("state = %s (%s)", got.State, got.Cause)
	}
	if err := Sweep(ctx, f.d); err != nil {
		t.Fatal(err)
	}
	f.setFindingStatus(f.finding.ID, scan.StatusGone)
	if _, err := Prove(ctx, f.d, f.proj.ID, Pass{Scanned: true}); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	wd := f.d
	wd.WorkerInterval = 20 * time.Millisecond
	Worker(wctx, wd)
	if n := spy.ran("push"); n != 0 {
		t.Errorf("git push ran alone: %q", spy.calls)
	}
	if n := spy.ran("merge"); n != 0 {
		t.Errorf("git merge ran alone: %q", spy.calls)
	}
	if got := gitT(t, f.env, bare, "for-each-ref", "--format=%(refname)"); got != "refs/heads/main" {
		t.Errorf("the remote holds: %s", got)
	}
}

// R29: nothing but the two routes of a click starts these, no command line.
func TestOnlyTheRoutesCallTheClicks(t *testing.T) {
	root := filepath.Join("..")
	calls := regexp.MustCompile(`fix\.(PushFix|UpdateProject)\(`)
	var found []string
	err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if calls.Match(b) {
			found = append(found, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !strings.HasSuffix(found[0], "api/projects_git.go") {
		t.Errorf("callers: %q", found)
	}
	here, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	inner := regexp.MustCompile(`(?m)^\t.*\b(PushFix|UpdateProject)\(ctx`)
	for _, name := range here {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(name)
		if inner.Match(b) {
			t.Errorf("%s calls a click", name)
		}
	}
}

func TestPushRecordsNoOutput(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	for _, c := range []struct{ said, class string }{
		{"remote: " + gitCanary + "\nfatal: Authentication failed for 'https://demo:" + gitCanary + "@example.test/'", "auth"},
		{"Host key verification failed. " + gitCanary, "host_key"},
		{"remote: Repository not found " + gitCanary, "not_found"},
		{"Could not resolve host " + gitCanary, "network"},
		{"something else " + gitCanary, "failed"},
	} {
		spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
			if !slices.Contains(args, "push") {
				return nil, nil, nil, false
			}
			return nil, []byte(c.said), errors.New(c.said), true
		}
		_, err := PushFix(context.Background(), f.d, a.ID)
		var gf *workcopy.GitFailure
		if !errors.As(err, &gf) || gf.Class != c.class {
			t.Errorf("%s: %v", c.class, err)
		}
		if ErrorKey(err) != "api.git."+c.class {
			t.Errorf("key = %s", ErrorKey(err))
		}
		for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
			if strings.Contains(Explain(lang, err)+ExplainHint(lang, err), gitCanary) {
				t.Errorf("the canary reached a sentence: %q", Explain(lang, err))
			}
		}
	}
	f.noCanary(t)
	if _, ok, _ := f.d.Repo.Push(context.Background(), a.ID); ok {
		t.Error("a failed push wrote a fix_push row")
	}
}

func TestAuditEvents(t *testing.T) {
	f, spy := gitFixture(t)
	a, p := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", "https://demo:"+gitCanary+"@example.test/demo/app.git")
	ctx := context.Background()
	sayYes(t, f)
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		switch {
		case slices.Contains(args, "push"):
			return pushAnswer(args, "*"), nil, nil, true
		case slices.Contains(args, "fetch") && slices.Contains(args, httpsDemo):
			return nil, []byte("fatal: Authentication failed"), errors.New("exit 128"), true
		}
		return nil, nil, nil, false
	}
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateProject(ctx, f.d, f.proj); ErrorKey(err) != "api.git.auth" {
		t.Fatalf("update: %v", err)
	}
	if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := PushFix(ctx, f.d, a.ID); !errors.Is(err, ErrGitNotAttached) {
		t.Fatal(err)
	}
	if _, err := UpdateProject(ctx, f.d, f.proj); !errors.Is(err, ErrGitNotAttached) {
		t.Fatal(err)
	}
	if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, "stale"); !errors.Is(err, ErrGitRemoteChanged) {
		t.Fatal(err)
	}

	want := func(ev audit.Event, result, outcome string, keys ...string) {
		t.Helper()
		if ev.Result != result || ev.Evidence["outcome"] != outcome || ev.Actor != "test" {
			t.Errorf("event = %+v, want %s %s", ev, result, outcome)
		}
		for _, k := range append(keys, "project_id", "host", "provider", "author") {
			if _, ok := ev.Evidence[k]; !ok {
				t.Errorf("no %s in %+v", k, ev.Evidence)
			}
		}
		if ev.Evidence["project_id"] != f.proj.ID {
			t.Errorf("project_id: %+v", ev.Evidence)
		}
	}
	answers := f.audits("project.git.answer")
	if len(answers) != 3 {
		t.Fatalf("answers = %+v", answers)
	}
	want(answers[0], "ok", GitYes)
	want(answers[1], "ok", GitNo)
	want(answers[2], "refused", "remote_changed")
	if answers[0].Evidence["host"] != "example.test" || answers[0].Evidence["provider"] != "other" || answers[0].Evidence["rule_written"] != true {
		t.Errorf("yes: %+v", answers[0].Evidence)
	}
	pushes := f.audits("project.git.push")
	if len(pushes) != 2 {
		t.Fatalf("pushes = %+v", pushes)
	}
	want(pushes[0], "ok", "pushed", "attempt_id", "branch", "commit")
	want(pushes[1], "refused", "not_attached", "attempt_id", "branch", "commit")
	if pushes[0].Evidence["commit"] != p.CommitSHA || pushes[0].Evidence["branch"] != Branch(a.ID) || pushes[0].Evidence["attempt_id"] != a.ID {
		t.Errorf("push: %+v", pushes[0].Evidence)
	}
	updates := f.audits("project.git.update")
	if len(updates) != 2 {
		t.Fatalf("updates = %+v", updates)
	}
	want(updates[0], "error", "auth")
	want(updates[1], "refused", "not_attached")
	rows, err := f.st.DB().Query(`SELECT evidence FROM audit_event WHERE action LIKE 'project.git.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s, "demo/app") || strings.Contains(s, "https:") || strings.Contains(s, f.proj.Path) {
			t.Errorf("a full address in the audit: %s", s)
		}
	}
	f.noCanary(t)
}

// mergeOnTheSite stands for the site: a separate clone merges the branch into main
// its own way and pushes main.
func mergeOnTheSite(t *testing.T, f *fixture, bare, branch string, how ...string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "site")
	gitT(t, f.env, filepath.Dir(dir), "clone", "-q", bare, dir)
	gitT(t, f.env, dir, "fetch", "-q", "origin", branch)
	gitT(t, f.env, dir, append([]string{"merge", "-q"}, append(how, "FETCH_HEAD")...)...)
	if slices.Contains(how, "--squash") {
		gitT(t, f.env, dir, "commit", "-q", "-m", "squashed")
	}
	gitT(t, f.env, dir, "push", "-q", "origin", "main")
}

func TestProveAfterUpdateIsProvenFixed(t *testing.T) {
	testProveAfterUpdate(t, "--no-ff", "-m", "merged")
}

func TestProveAfterSquashIsProvenFixed(t *testing.T) {
	testProveAfterUpdate(t, "--squash")
}

func testProveAfterUpdate(t *testing.T, how ...string) {
	t.Helper()
	f, _ := gitFixture(t)
	bare := withBare(t, f)
	a, _ := applied(t, f)
	sayYes(t, f)
	ctx := context.Background()
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	mergeOnTheSite(t, f, bare, Branch(a.ID), how...)
	res, err := UpdateProject(ctx, f.d, f.proj)
	if err != nil || res.Outcome != workcopy.FolderUpdated {
		t.Fatalf("update: %+v, %v", res, err)
	}
	again, err := UpdateProject(ctx, f.d, f.proj)
	if err != nil || again.Outcome != workcopy.FolderUpToDate {
		t.Fatalf("second click: %+v, %v", again, err)
	}
	if ev := f.audits("project.git.update"); len(ev) != 2 || ev[0].Evidence["outcome"] != "updated" || ev[1].Evidence["outcome"] != "up_to_date" {
		t.Errorf("audit = %+v", ev)
	}
	f.setFindingStatus(f.finding.ID, scan.StatusGone)
	if n, err := Prove(ctx, f.d, f.proj.ID, Pass{Scanned: true}); err != nil || n != 1 {
		t.Fatalf("Prove: %d, %v", n, err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state = %s (%s)", got.State, got.Cause)
	}
	_, err = PushFix(ctx, f.d, a.ID)
	wantKey(t, "push of a finished fix", err, ErrGitNotApplied)
}

func TestPurgeForgetsRemoteAndPush(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	spy.on = func(args, env []string) ([]byte, []byte, error, bool) {
		if slices.Contains(args, "push") {
			return pushAnswer(args, "*"), nil, nil, true
		}
		return nil, nil, nil, false
	}
	ctx := context.Background()
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := PurgeProject(ctx, f.d, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	if hasRule(t, f, "example.test") {
		t.Error("the rule stayed")
	}
	if ok, _ := f.d.Gateway.Allowed("example.test", policy.PurposeProjectGit); ok {
		t.Error("the gateway kept the rule")
	}
	if _, err := project.NewRepo(f.st).Purge(ctx, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"project_remote", "fix_push"} {
		var n int
		if err := f.st.DB().QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows, %v", table, n, err)
		}
	}
}

func TestLocalNeedsNoRuleAndAllowLocal(t *testing.T) {
	f, _ := gitFixture(t)
	withBare(t, f)
	ctx := context.Background()
	f.d.AllowLocalRemote = false
	st, err := ProjectGit(ctx, f.d, f.proj)
	if err != nil || st.CanAttach || st.Reason != "unsupported" || st.Suggested != GitUnknown {
		t.Fatalf("not allowed: %+v, %v", st, err)
	}
	if _, err := AnswerGit(ctx, f.d, f.proj, GitYes, st.RemoteID); !errors.Is(err, ErrGitNoRemote) {
		t.Errorf("yes on a local remote: %v", err)
	}
	f.d.AllowLocalRemote = true
	a, _ := applied(t, f)
	st = sayYes(t, f)
	if st.Reason != "other" || st.Provider != "local" || st.Display == "" || st.Host != st.Display || !st.CanAttach {
		t.Errorf("state = %+v", st)
	}
	if strings.Contains(st.Display, filepath.ToSlash(f.proj.Path)) {
		t.Errorf("a path in the state: %+v", st)
	}
	row, _, _ := f.d.Repo.GitAnswer(ctx, f.proj.ID)
	if row.RuleWritten {
		t.Error("rule_written for a local remote")
	}
	b, _ := os.ReadFile(f.policy)
	if strings.Contains(string(b), policy.PurposeProjectGit) {
		t.Errorf("a rule for a local remote:\n%s", b)
	}
	if st.Update == nil || !st.Update.Ready {
		t.Errorf("update state: %+v", st.Update)
	}
	if _, err := PushFix(ctx, f.d, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateProject(ctx, f.d, f.proj); err != nil {
		t.Fatal(err)
	}
	for _, at := range f.d.Gateway.Attempts() {
		if at.Purpose == policy.PurposeProjectGit {
			t.Errorf("an egress attempt for a local remote: %+v", at)
		}
	}
	f.d.AllowLocalRemote = false
	_, err = PushFix(ctx, f.d, a.ID)
	wantKey(t, "local, no longer allowed", err, ErrGitRemoteChanged)
}

// A partial clone reaches the page with no click: what it reads must be true.
func TestPartialCloneIsNamed(t *testing.T) {
	f, spy := gitFixture(t)
	a, _ := applied(t, f)
	gitT(t, f.env, f.proj.Path, "remote", "add", "origin", httpsDemo)
	sayYes(t, f)
	gitT(t, f.env, f.proj.Path, "config", "--local", "remote.origin.promisor", "true")
	ctx := context.Background()
	_, err := ProjectGit(ctx, f.d, f.proj)
	if ErrorKey(err) != "api.git.partial_clone" {
		t.Fatalf("ProjectGit: %v, key %q", err, ErrorKey(err))
	}
	for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
		if s := Explain(lang, err); s == i18n.T(lang, "api.git.failed") || strings.HasPrefix(s, "!") {
			t.Errorf("sentence = %q", s)
		}
	}
	spy.reset()
	_, err = PushFix(ctx, f.d, a.ID)
	if ErrorKey(err) != "api.git.partial_clone" {
		t.Errorf("push: %v", err)
	}
	_, err = UpdateProject(ctx, f.d, f.proj)
	if ErrorKey(err) != "api.git.partial_clone" {
		t.Errorf("update: %v", err)
	}
	if spy.ran("push") != 0 || spy.ran("fetch") != 0 {
		t.Errorf("git went on: %q", spy.calls)
	}
	// Taking the agreement back stays possible.
	if _, err := AnswerGit(ctx, f.d, f.proj, GitNo, ""); ErrorKey(err) != "api.git.partial_clone" {
		t.Errorf("no: %v", err)
	}
	if hasRule(t, f, "example.test") {
		t.Error("the rule stayed after a no")
	}
}

func TestSweepRemovesOldTemporaryRepos(t *testing.T) {
	f, _ := gitFixture(t)
	net := filepath.Join(f.d.DataDir, "fix-net")
	at := f.d.now()
	id := func(ago time.Duration) string {
		return ulid.MustNew(ulid.Timestamp(at.Add(-ago)), ulid.DefaultEntropy()).String() + ".git"
	}
	old, recent := id(2*time.Hour), id(time.Minute)
	for _, name := range []string{old, recent, "notes"} {
		if err := os.MkdirAll(filepath.Join(net, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(net, old)); !os.IsNotExist(err) {
		t.Errorf("the leftover stayed: %v", err)
	}
	for _, name := range []string{recent, "notes"} {
		if _, err := os.Stat(filepath.Join(net, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGitTexts(t *testing.T) {
	classes := []string{"auth", "host_key", "not_found", "rejected", "network", "timeout", "failed", "branch_moved",
		"detached", "default_unknown", "dirty", "in_progress", "filter", "diverged", "untracked", "update_failed",
		"ignored", "update_partial", "submodule", "partial_clone"}
	sentinels := map[string]error{"no_repo": ErrGitNoRepo, "empty_repo": ErrGitEmptyRepo, "not_attached": ErrGitNotAttached,
		"no_remote": ErrGitNoRemote, "remote_changed": ErrGitRemoteChanged, "no_rule": ErrGitNoRule,
		"branch_moved": ErrGitBranchMoved, "busy": ErrGitBusy, "not_applied": ErrGitNotApplied}
	for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
		for _, c := range classes {
			err := &workcopy.GitFailure{Class: c}
			if ErrorKey(err) != "api.git."+c {
				t.Errorf("%s: key %s", c, ErrorKey(err))
			}
			if s := Explain(lang, err); s == "" || strings.HasPrefix(s, "!") {
				t.Errorf("%s %s: %q", lang, c, s)
			}
			if s := ExplainHint(lang, err); s == "" || strings.HasPrefix(s, "!") {
				t.Errorf("%s %s hint: %q", lang, c, s)
			}
		}
		for k, err := range sentinels {
			if ErrorKey(err) != "api.git."+k {
				t.Errorf("%s: key %s", k, ErrorKey(err))
			}
			if s := Explain(lang, err); strings.HasPrefix(s, "!") || s == "" {
				t.Errorf("%s: %q", k, s)
			}
			if s := ExplainHint(lang, err); strings.HasPrefix(s, "!") || s == "" {
				t.Errorf("%s hint: %q", k, s)
			}
		}
		// A class no sentence was written for is not shown as a raw key.
		if ErrorKey(&workcopy.GitFailure{Class: "nope"}) != "api.git.failed" {
			t.Error("unknown class")
		}
		nd := &workcopy.GitFailure{Class: "not_default", Current: "feature", Default: "main"}
		if s := Explain(lang, nd); !strings.Contains(s, "feature") || !strings.Contains(s, "main") {
			t.Errorf("not_default: %q", s)
		}
		// What is in the way is named, in the hint.
		for _, c := range []string{"ignored", "untracked", "submodule"} {
			with := &workcopy.GitFailure{Class: c, Path: ".env"}
			if s := ExplainHint(lang, with); !strings.Contains(s, ".env") {
				t.Errorf("%s: no path in %q", c, s)
			}
			if s := ExplainHint(lang, &workcopy.GitFailure{Class: c}); strings.Contains(s, "%") {
				t.Errorf("%s: a verb in %q", c, s)
			}
		}
		// A path is data: it never reaches the format.
		if s := ExplainHint(lang, &workcopy.GitFailure{Class: "ignored", Path: "a%sb"}); !strings.Contains(s, "a%sb") {
			t.Errorf("path as a format: %q", s)
		}
		// A plain git would overwrite an ignored file and a submodule's content:
		// the advice never sends there first. An untracked file may be ignored too
		// when the second reading failed.
		for _, c := range []string{"ignored", "submodule"} {
			s := strings.ToLower(ExplainHint(lang, &workcopy.GitFailure{Class: c}))
			if !strings.Contains(s, "attention") && !strings.Contains(s, "careful") {
				t.Errorf("%s: no warning in %q", c, s)
			}
		}
		if s := strings.ToLower(ExplainHint(lang, &workcopy.GitFailure{Class: "untracked"})); strings.Contains(s, "git") {
			t.Errorf("untracked sends to a tool that may overwrite: %q", s)
		}
		// A submodule that holds no change: not "changes not saved".
		if s := Explain(lang, &workcopy.GitFailure{Class: "submodule"}); s == Explain(lang, &workcopy.GitFailure{Class: "dirty"}) {
			t.Errorf("submodule reads like dirty: %q", s)
		}
	}
}
