package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

const gitCanary = "canari-git-7391"

// gitFixture is the fix fixture with the person's own settings kept out, and a
// fake git push when push is set: no network.
type gitFixture struct {
	*fixFixture
	env []string

	mu   sync.Mutex
	push func(args []string) ([]byte, []byte, error)
	gits []string
}

func newGitFixture(t *testing.T, opts ...func(ff *fixFixture)) *gitFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	for _, k := range []string{"GIT_SSH", "GIT_SSH_COMMAND"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	gf := &gitFixture{}
	gf.fixFixture = newFixFixture(t, append(opts, func(ff *fixFixture) {
		next := ff.fd.Work.Exec
		ff.fd.Work.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
			if name == "git" {
				gf.mu.Lock()
				gf.gits = append(gf.gits, strings.Join(args, " "))
				push := gf.push
				gf.mu.Unlock()
				if push != nil && slices.Contains(args, "push") {
					return push(args)
				}
			}
			return next(ctx, name, args, env, dir)
		}
	})...)
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gf.env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+cfg,
		"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test", "GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
	return gf
}

func (gf *gitFixture) setPush(p func(args []string) ([]byte, []byte, error)) {
	gf.mu.Lock()
	defer gf.mu.Unlock()
	gf.push = p
}

func (gf *gitFixture) origin(addr string) {
	gf.t.Helper()
	gitRun(gf.t, gf.env, gf.proj.Path, "remote", "add", "origin", addr)
}

func (gf *gitFixture) view() GitView {
	gf.t.Helper()
	code, body := gf.send("GET", "/api/v1/projects/demo/git", "")
	if code != http.StatusOK {
		gf.t.Fatalf("git view = %d %s", code, body)
	}
	var v GitView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		gf.t.Fatal(err)
	}
	return v
}

func (gf *gitFixture) yes() GitView {
	gf.t.Helper()
	body, _ := json.Marshal(GitAnswerRequest{Answer: fix.GitYes, RemoteID: gf.view().RemoteID})
	code, out := gf.send("POST", "/api/v1/projects/demo/git/answer", string(body))
	if code != http.StatusOK {
		gf.t.Fatalf("yes = %d %s", code, out)
	}
	var v GitView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		gf.t.Fatal(err)
	}
	return v
}

// appliedAttempt stores an attempt of demo in state applied, with its local branch
// at the fix commit, without any agent.
func (gf *gitFixture) appliedAttempt() (string, string) {
	gf.t.Helper()
	ctx := context.Background()
	repo := fix.NewRepo(gf.st)
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: gf.ids["ACME-2026-0001"], ProjectID: gf.proj.ID, Origin: fix.OriginAgent})
	if err != nil {
		gf.t.Fatal(err)
	}
	root := gf.proj.Path
	branch := fix.Branch(a.ID)
	gitRun(gf.t, gf.env, root, "branch", branch)
	cmd := []string{"-C", root, "rev-parse", "refs/heads/" + branch}
	out, _, err := workcopy.DefaultExec(ctx, "git", cmd, gf.env, root)
	if err != nil {
		gf.t.Fatal(err)
	}
	sha := strings.TrimSpace(string(out))
	if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "s", Hash: "h", CommitSHA: sha}); err != nil {
		gf.t.Fatal(err)
	}
	if _, err := gf.st.DB().Exec(`UPDATE fix_attempt SET state = 'applied' WHERE id = ?`, a.ID); err != nil {
		gf.t.Fatal(err)
	}
	return a.ID, branch
}

func pushedAnswer(args []string, flag string) []byte {
	for _, a := range args {
		if strings.HasPrefix(a, "refs/heads/michel/") {
			return []byte(flag + "\t" + a + "\t[new branch]\n")
		}
	}
	return nil
}

func TestGitViewNeedsNoNetworkAndHasNoAbsolutePath(t *testing.T) {
	gf := newGitFixture(t)
	bare := filepath.ToSlash(filepath.Join(t.TempDir(), "remote.git"))
	gitRun(t, gf.env, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	gf.fd.AllowLocalRemote = true
	gf.origin(bare)
	gf.yes()
	gf.mu.Lock()
	gf.gits = nil
	gf.mu.Unlock()
	code, body := gf.send("GET", "/api/v1/projects/demo/git", "")
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	for _, leak := range []string{bare, filepath.ToSlash(gf.proj.Path), gf.proj.Path, filepath.ToSlash(filepath.Dir(bare))} {
		if strings.Contains(body, leak) || strings.Contains(body, strings.ReplaceAll(leak, `\`, `\\`)) {
			t.Errorf("a path in the view: %s", body)
		}
	}
	for _, c := range gf.gits {
		f := strings.Fields(c)
		for _, sub := range []string{"push", "fetch", "merge", "clone", "commit"} {
			if slices.Contains(f, sub) {
				t.Errorf("the view ran git %s: %s", sub, c)
			}
		}
	}
}

func TestGitViewHasNoSecret(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://demo:" + gitCanary + "@github.com/demo/app.git")
	code, body := gf.send("GET", "/api/v1/projects/demo/git", "")
	if code != http.StatusOK || strings.Contains(body, gitCanary) {
		t.Fatalf("%d %s", code, body)
	}
	v := gf.view()
	if !v.HadCredential || v.Display != "github.com/demo/app" {
		t.Errorf("%+v", v)
	}
	body2, _ := json.Marshal(gf.yes())
	if strings.Contains(string(body2), gitCanary) {
		t.Errorf("secret in the answer: %s", body2)
	}
}

func TestGitViewSuggests(t *testing.T) {
	gf := newGitFixture(t)
	check := func(reason, suggested string, can bool) {
		t.Helper()
		v := gf.view()
		if v.Reason != reason || v.Suggested != suggested || v.CanAttach != can || v.Answer != "" || v.Attached {
			t.Errorf("%s: %+v", reason, v)
		}
	}
	check("none", fix.GitNo, false)
	gf.origin("https://github.com/demo/app.git")
	check("known", fix.GitYes, true)
	gitRun(t, gf.env, gf.proj.Path, "remote", "set-url", "origin", "https://example.test/demo/app.git")
	check("other", fix.GitYes, true)
	gitRun(t, gf.env, gf.proj.Path, "remote", "set-url", "origin", "ftp://example.test/demo/app.git")
	check("unsupported", fix.GitUnknown, false)
	gitRun(t, gf.env, gf.proj.Path, "remote", "remove", "origin")
	gitRun(t, gf.env, gf.proj.Path, "remote", "add", "one", "https://example.test/a/b.git")
	gitRun(t, gf.env, gf.proj.Path, "remote", "add", "two", "https://example.test/a/c.git")
	check("several", fix.GitUnknown, false)
}

func TestPartialCloneViewSaysSo(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	gitRun(t, gf.env, gf.proj.Path, "config", "--local", "remote.origin.promisor", "true")
	code, body := gf.send("GET", "/api/v1/projects/demo/git?lang=fr", "")
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "api.git.partial_clone" || !strings.Contains(eb.Error, "copie partielle") || eb.Hint == "" {
		t.Errorf("%d %s", code, body)
	}
}

func TestAnswerRefusesUnknownFieldAndBadValue(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://example.test/demo/app.git")
	for _, body := range []string{
		`{"answer":"yes","remote_id":"x","url":"https://evil.example"}`,
		`{"answer":"maybe"}`,
		`{"answer":""}`,
		`{"answer":"yes"}`,
		`{"answer":"yes","remote_id":"  "}`,
		`not json`,
	} {
		if code, out := gf.send("POST", "/api/v1/projects/demo/git/answer", body); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", body, code, out)
		}
	}
	if code, out := gf.send("POST", "/api/v1/projects/demo/git/answer", `{"answer":"yes","remote_id":"stale"}`); code != http.StatusConflict || !strings.Contains(out, "api.git.remote_changed") {
		t.Errorf("stale id = %d %s", code, out)
	}
	if v := gf.view(); v.Answer != "" {
		t.Errorf("an answer was stored: %+v", v)
	}
	if rows := gf.auditRows("project.git.answer"); len(rows) != 1 {
		t.Errorf("audit = %+v", rows)
	}
}

func TestPushReturnsMergeURL(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, branch := gf.appliedAttempt()
	gf.yes()
	gf.setPush(func(args []string) ([]byte, []byte, error) { return pushedAnswer(args, "*"), nil, nil })
	code, body := gf.send("POST", "/api/v1/fix/"+id+"/push", "")
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var out GitPushResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Outcome != "pushed" || out.Provider != "github" || out.Branch != branch || out.PushedAt == "" ||
		out.MergeURL != "https://github.com/demo/app/pull/new/"+branch {
		t.Errorf("%+v", out)
	}
	gf.setPush(func(args []string) ([]byte, []byte, error) { return pushedAnswer(args, "="), nil, nil })
	code, body = gf.send("POST", "/api/v1/fix/"+id+"/push", "")
	if code != http.StatusOK || !strings.Contains(body, `"outcome":"already"`) {
		t.Errorf("second click = %d %s", code, body)
	}
	if code, body := gf.send("POST", "/api/v1/fix/nope/push", ""); code != http.StatusNotFound {
		t.Errorf("unknown attempt = %d %s", code, body)
	}
}

func TestCraftedRemoteGivesNoLink(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com.example.test/demo/app.git")
	id, _ := gf.appliedAttempt()
	v := gf.yes()
	if v.Provider != "other" || v.Reason != "other" {
		t.Errorf("%+v", v)
	}
	gf.setPush(func(args []string) ([]byte, []byte, error) { return pushedAnswer(args, "*"), nil, nil })
	code, body := gf.send("POST", "/api/v1/fix/"+id+"/push", "")
	if code != http.StatusOK || !strings.Contains(body, `"merge_url":""`) {
		t.Errorf("%d %s", code, body)
	}
}

func TestFailureIsNeverUnauthorized(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()
	gf.setPush(func(args []string) ([]byte, []byte, error) {
		return nil, []byte("fatal: Authentication failed " + gitCanary), errors.New("exit 128")
	})
	code, body := gf.send("POST", "/api/v1/fix/"+id+"/push", "")
	if code != http.StatusBadGateway || !strings.Contains(body, "api.git.auth") || strings.Contains(body, gitCanary) {
		t.Errorf("%d %s", code, body)
	}
}

// One case per key: the status, and a real sentence in each language.
func TestFailureCodesAndTexts(t *testing.T) {
	conflict := []error{fix.ErrGitNoRepo, fix.ErrGitEmptyRepo, fix.ErrGitNotAttached, fix.ErrGitNoRemote, fix.ErrGitRemoteChanged, fix.ErrGitNoRule, fix.ErrGitNotApplied, fix.ErrGitBranchMoved, fix.ErrGitBusy}
	for _, class := range []string{"branch_moved", "detached", "not_default", "default_unknown", "dirty", "in_progress", "filter", "diverged",
		"untracked", "ignored", "submodule", "update_failed", "update_partial", "partial_clone"} {
		conflict = append(conflict, &workcopy.GitFailure{Class: class, Current: "a", Default: "b"})
	}
	var service []error
	for _, class := range []string{"auth", "host_key", "not_found", "rejected", "network", "timeout", "failed"} {
		service = append(service, &workcopy.GitFailure{Class: class})
	}
	for want, list := range map[int][]error{http.StatusConflict: conflict, http.StatusBadGateway: service} {
		for _, err := range list {
			for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
				rec := &recordingWriter{header: http.Header{}}
				(&server{}).gitRefused(rec, nil, lang, err)
				var eb FixErrorBody
				if jerr := json.Unmarshal(rec.body, &eb); jerr != nil {
					t.Fatalf("%v: %v", err, jerr)
				}
				if rec.status != want {
					t.Errorf("%v: %d, want %d", err, rec.status, want)
				}
				if !strings.HasPrefix(eb.Code, "api.git.") || eb.Error == "" || strings.HasPrefix(eb.Error, "!") || eb.Hint == "" || strings.HasPrefix(eb.Hint, "!") {
					t.Errorf("%v %s: %+v", err, lang, eb)
				}
			}
		}
	}
}

type recordingWriter struct {
	header http.Header
	status int
	body   []byte
}

func (w *recordingWriter) Header() http.Header { return w.header }
func (w *recordingWriter) WriteHeader(s int)   { w.status = s }
func (w *recordingWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

// A scan that waits for the test holds the project's lock, and a click that waits
// holds it the other way.
func TestUpdateRefusedWhileScanning(t *testing.T) {
	release := make(chan struct{})
	gf := newGitFixture(t, func(ff *fixFixture) {
		ff.deps.ScanProject = func(ctx context.Context, p project.Project) error {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		}
	})
	gf.origin("https://example.test/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()
	if code, body := gf.send("POST", "/api/v1/projects/demo/scan", ""); code != http.StatusAccepted {
		t.Fatalf("scan = %d %s", code, body)
	}
	for _, path := range []string{"/api/v1/projects/demo/git/update", "/api/v1/fix/" + id + "/push"} {
		code, body := gf.send("POST", path, "")
		if code != http.StatusConflict || !strings.Contains(body, "api.git.busy") {
			t.Errorf("%s during a scan = %d %s", path, code, body)
		}
	}
	// A second click on the check keeps its own sentence.
	if code, body := gf.send("POST", "/api/v1/projects/demo/scan", ""); code != http.StatusConflict || !strings.Contains(body, "scan_running") {
		t.Errorf("second scan = %d %s", code, body)
	}
	close(release)
	gf.waitEnd("en", "demo")
	deadline := time.Now().Add(5 * time.Second)
	for fix.GitBusy(*gf.fd, gf.proj.ID) {
		if time.Now().After(deadline) {
			t.Fatal("the scan kept the lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestScanRefusedWhileAClickRuns(t *testing.T) {
	scanned := make(chan struct{}, 1)
	gf := newGitFixture(t, func(ff *fixFixture) {
		ff.deps.ScanProject = func(ctx context.Context, p project.Project) error {
			scanned <- struct{}{}
			return nil
		}
	})
	gf.origin("https://example.test/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	gf.setPush(func(args []string) ([]byte, []byte, error) {
		once.Do(func() { close(started) })
		<-release
		return pushedAnswer(args, "*"), nil, nil
	})
	done := make(chan int, 1)
	go func() {
		code, _ := gf.send("POST", "/api/v1/fix/"+id+"/push", "")
		done <- code
	}()
	<-started
	code, body := gf.send("POST", "/api/v1/projects/demo/scan?lang=fr", "")
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "api.git.busy" || eb.Error != i18n.T(i18n.FR, "api.git.busy") {
		t.Errorf("scan during a click = %d %s", code, body)
	}
	if v := gf.viewOf("en", "demo"); v.Scanning || v.LastFailure != nil {
		t.Errorf("a refused check left a state: %+v", v)
	}
	if v := gf.view(); v.Update == nil || v.Update.Code != "api.git.busy" {
		t.Errorf("view during a click: %+v", v)
	}
	close(release)
	if c := <-done; c != http.StatusOK {
		t.Errorf("push = %d", c)
	}
	if code, body := gf.send("POST", "/api/v1/projects/demo/scan", ""); code != http.StatusAccepted {
		t.Errorf("scan after = %d %s", code, body)
	}
	<-scanned
	gf.waitEnd("en", "demo")
}

func TestGitRoutesNeedTheToken(t *testing.T) {
	gf := newGitFixture(t)
	for _, c := range [][2]string{{"GET", "/api/v1/projects/demo/git"}, {"POST", "/api/v1/projects/demo/git/answer"},
		{"POST", "/api/v1/projects/demo/git/update"}, {"POST", "/api/v1/fix/nope/push"}} {
		for _, tok := range []string{"", "wrong"} {
			resp, _ := gf.do(c[0], c[1], tok, "")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s token %q = %d", c[0], c[1], tok, resp.StatusCode)
			}
		}
	}
}

func TestGitPostsRefuseCrossOrigin(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://example.test/demo/app.git")
	for _, path := range []string{"/api/v1/projects/demo/git/answer", "/api/v1/projects/demo/git/update", "/api/v1/fix/nope/push"} {
		resp, body := gf.do("POST", path, testToken, `{"answer":"no"}`, "Origin", "http://evil.example", "Content-Type", "application/json")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s = %d %s", path, resp.StatusCode, body)
		}
	}
	if v := gf.view(); v.Answer != "" {
		t.Errorf("a cross-origin answer was stored: %+v", v)
	}
}

// Through the routes, with a bare repository and the test seam: answer, send, then
// the update after the merge on the site.
func TestUpdateRouteOnALocalRemote(t *testing.T) {
	gf := newGitFixture(t)
	gf.fd.AllowLocalRemote = true
	bare := filepath.ToSlash(filepath.Join(t.TempDir(), "remote.git"))
	gitRun(t, gf.env, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	gf.origin(bare)
	gitRun(t, gf.env, gf.proj.Path, "push", "-q", "origin", "main")
	if v := gf.yes(); v.Provider != "local" || !v.Attached || v.Update == nil || !v.Update.Ready {
		t.Fatalf("%+v %+v", v, v.Update)
	}
	code, body := gf.send("POST", "/api/v1/projects/demo/git/update", "")
	if code != http.StatusOK || !strings.Contains(body, `"outcome":"up_to_date"`) {
		t.Fatalf("%d %s", code, body)
	}
	site := filepath.Join(t.TempDir(), "site")
	gitRun(t, gf.env, filepath.Dir(site), "clone", "-q", bare, site)
	if err := os.WriteFile(filepath.Join(site, "merged.txt"), []byte("merged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, gf.env, site, "add", "-A")
	gitRun(t, gf.env, site, "commit", "-q", "-m", "merged")
	gitRun(t, gf.env, site, "push", "-q", "origin", "main")
	code, body = gf.send("POST", "/api/v1/projects/demo/git/update", "")
	if code != http.StatusOK || !strings.Contains(body, `"outcome":"updated"`) {
		t.Fatalf("%d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(gf.proj.Path, "merged.txt")); err != nil {
		t.Error(err)
	}
	// A refusal of the folder is a 409, with what stands in the way.
	if err := os.WriteFile(filepath.Join(gf.proj.Path, "merged.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body = gf.send("POST", "/api/v1/projects/demo/git/update", "")
	if code != http.StatusConflict || !strings.Contains(body, "api.git.dirty") {
		t.Errorf("%d %s", code, body)
	}
	if rows := gf.auditRows("project.git.update"); len(rows) != 3 {
		t.Errorf("audit = %+v", rows)
	}
}
