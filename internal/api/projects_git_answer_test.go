package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/project"
)

// A saved no answers 200 on a folder Michel cannot read, and the view of that
// folder still says what was answered.
func TestPartialCloneKeepsTheAnswer(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	gf.yes()
	gitRun(t, gf.env, gf.proj.Path, "config", "--local", "remote.origin.promisor", "true")
	refused := func(want string) {
		t.Helper()
		code, body := gf.send("GET", "/api/v1/projects/demo/git", "")
		var got struct{ Code, Answer string }
		_ = json.Unmarshal([]byte(body), &got)
		if code != http.StatusConflict || got.Code != "api.git.partial_clone" || got.Answer != want {
			t.Errorf("view: %d %s", code, body)
		}
	}
	refused(fix.GitYes)
	code, body := gf.send("POST", "/api/v1/projects/demo/git/answer", `{"answer":"no"}`)
	var v GitView
	_ = json.Unmarshal([]byte(body), &v)
	if code != http.StatusOK || v.Answer != fix.GitNo || v.Repo != fix.GitRepoUnreadable || v.Attached || v.CanAttach {
		t.Errorf("no: %d %s", code, body)
	}
	refused(fix.GitNo)
}

// The answer is written to the end even if the page goes away during the request.
func TestAnswerGoesOnWhenThePageGoesAway(t *testing.T) {
	var mu sync.Mutex
	var onGit func()
	gf := newGitFixture(t, func(ff *fixFixture) {
		next := ff.fd.Work.Exec
		ff.fd.Work.Exec = func(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
			mu.Lock()
			hook := onGit
			mu.Unlock()
			if hook != nil {
				hook()
			}
			return next(ctx, name, args, env, dir)
		}
	})
	gf.origin("https://github.com/demo/app.git")
	id := gf.view().RemoteID
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mu.Lock()
	onGit = cancel
	mu.Unlock()
	body, _ := json.Marshal(GitAnswerRequest{Answer: fix.GitYes, RemoteID: id})
	req := httptest.NewRequest("POST", gf.srv.URL+"/api/v1/projects/demo/git/answer", strings.NewReader(string(body))).WithContext(ctx)
	req.Host = strings.TrimPrefix(gf.srv.URL, "http://")
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gf.srv.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	mu.Lock()
	onGit = nil
	mu.Unlock()
	if v := gf.view(); v.Answer != fix.GitYes || !v.Attached {
		t.Errorf("view = %+v", v)
	}
}

func TestDeactivatedProjectCannotSend(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()
	pushes := 0
	gf.setPush(func(args []string) ([]byte, []byte, error) {
		pushes++
		return pushedAnswer(args, "*"), nil, nil
	})
	if _, err := project.NewRepo(gf.st).Remove(context.Background(), gf.proj.ID); err != nil {
		t.Fatal(err)
	}
	code, body := gf.send("POST", "/api/v1/fix/"+id+"/push", "")
	if code != http.StatusConflict || !strings.Contains(body, "api.git.not_attached") || pushes != 0 {
		t.Errorf("%d %s, %d pushes", code, body, pushes)
	}
}
