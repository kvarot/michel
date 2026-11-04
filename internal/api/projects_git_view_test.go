package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
)

func (gf *gitFixture) attemptPush(id string) *AttemptPushView {
	gf.t.Helper()
	code, body := gf.send("GET", "/api/v1/fix/"+id, "")
	if code != http.StatusOK {
		gf.t.Fatalf("attempt = %d %s", code, body)
	}
	if !strings.Contains(body, `"push":`) {
		gf.t.Errorf("the key push is missing: %s", body)
	}
	var v AttemptView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		gf.t.Fatal(err)
	}
	return v.Push
}

func (gf *gitFixture) forgetGits() {
	gf.mu.Lock()
	defer gf.mu.Unlock()
	gf.gits = nil
}

func (gf *gitFixture) ranGit() []string {
	gf.mu.Lock()
	defer gf.mu.Unlock()
	return gf.gits
}

// The attempt says how its branch stands with the attached service, and nothing
// for a project that is not attached.
func TestAttemptViewCarriesPush(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, branch := gf.appliedAttempt()
	if p := gf.attemptPush(id); p != nil {
		t.Errorf("not answered: %+v", p)
	}
	gf.yes()
	p := gf.attemptPush(id)
	if p == nil {
		t.Fatal("attached: no push view")
	}
	if p.Provider != "github" || p.Display != gf.view().Display || p.Branch != branch || !p.CanPush || p.Pushed || p.PushedAt != "" || p.MergeURL != "" {
		t.Errorf("before the click: %+v", p)
	}

	gf.setPush(func(args []string) ([]byte, []byte, error) { return pushedAnswer(args, "*"), nil, nil })
	if code, body := gf.send("POST", "/api/v1/fix/"+id+"/push", ""); code != http.StatusOK {
		t.Fatalf("push = %d %s", code, body)
	}
	p = gf.attemptPush(id)
	if p == nil || !p.Pushed || p.PushedAt == "" || p.MergeURL != "https://github.com/demo/app/pull/new/"+branch {
		t.Fatalf("after the click: %+v", p)
	}
	if !p.CanPush {
		t.Errorf("a second click stays possible, it answers already: %+v", p)
	}

	unlock, ok := fix.TryGitLock(*gf.fd, gf.proj.ID)
	if !ok {
		t.Fatal("no lock")
	}
	if p := gf.attemptPush(id); p == nil || p.CanPush {
		t.Errorf("during a click: %+v", p)
	}
	unlock()

	if _, err := gf.st.DB().Exec(`UPDATE fix_attempt SET state = 'proven_fixed' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if p := gf.attemptPush(id); p == nil || p.CanPush || !p.Pushed || p.MergeURL == "" {
		t.Errorf("finished: the view stays, the button goes: %+v", p)
	}
	if _, err := gf.st.DB().Exec(`UPDATE fix_attempt SET state = 'applied' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}

	// The address the person agreed to is gone: nothing can leave.
	gitRun(t, gf.env, gf.proj.Path, "remote", "set-url", "origin", "https://gitlab.com/demo/app.git")
	if p := gf.attemptPush(id); p != nil {
		t.Errorf("address changed: %+v", p)
	}
	gitRun(t, gf.env, gf.proj.Path, "remote", "set-url", "origin", "https://github.com/demo/app.git")
	if p := gf.attemptPush(id); p == nil {
		t.Error("the same address again is attached again")
	}

	if code, body := gf.send("POST", "/api/v1/projects/demo/git/answer", `{"answer":"no"}`); code != http.StatusOK {
		t.Fatalf("no = %d %s", code, body)
	}
	if p := gf.attemptPush(id); p != nil {
		t.Errorf("answered no: %+v", p)
	}
}

// Without its network rule a click would be refused: the view says it first.
func TestAttemptViewNeedsTheRule(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()
	if p := gf.attemptPush(id); p == nil || !p.CanPush {
		t.Fatalf("with its rule: %+v", p)
	}
	gf.fd.Gateway.SetRules(nil)
	if p := gf.attemptPush(id); p == nil || p.CanPush {
		t.Errorf("without its rule: %+v", p)
	}
}

// A server's fix has no branch to send, and a list runs no git per attempt.
func TestAttemptPushIsNotForServersNorLists(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	id, _ := gf.appliedAttempt()
	gf.yes()

	gf.forgetGits()
	code, body := gf.send("GET", "/api/v1/fixes", "")
	if code != http.StatusOK {
		t.Fatalf("list = %d %s", code, body)
	}
	var list []AttemptView
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 || list[0].ID != id || list[0].Push != nil {
		t.Errorf("list: %+v", list)
	}
	if got := gf.ranGit(); len(got) != 0 {
		t.Errorf("the list ran git: %v", got)
	}
	a := fix.Attempt{ID: id, ProjectID: gf.proj.ID, State: fix.StateApplied, Work: fix.Work{Server: &fix.ServerWork{}}}
	state, err := fix.AttemptPush(context.Background(), *gf.fd, a, gf.proj)
	if err != nil || state != nil {
		t.Errorf("server: %+v %v", state, err)
	}
}

// The list of projects says what was answered from the database alone: looking at
// it starts no git, whatever the project holds.
func TestProjectsListRunsNoGit(t *testing.T) {
	gf := newGitFixture(t)
	gf.origin("https://github.com/demo/app.git")
	list := func() ProjectView {
		t.Helper()
		gf.forgetGits()
		code, body := gf.send("GET", "/api/v1/projects", "")
		if code != http.StatusOK {
			t.Fatalf("%d %s", code, body)
		}
		for _, key := range []string{`"git_answer":`, `"git_attached":`} {
			if !strings.Contains(body, key) {
				t.Errorf("missing %s: %s", key, body)
			}
		}
		var out []ProjectView
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		if got := gf.ranGit(); len(got) != 0 {
			t.Errorf("the list ran git: %v", got)
		}
		for _, v := range out {
			if v.Name == "demo" {
				return v
			}
		}
		t.Fatalf("no demo: %s", body)
		return ProjectView{}
	}
	if v := list(); v.GitAnswer != "" || v.GitAttached {
		t.Errorf("never answered: %+v", v)
	}
	gf.yes()
	if v := list(); v.GitAnswer != "yes" || !v.GitAttached {
		t.Errorf("yes: %+v", v)
	}
	if code, body := gf.send("POST", "/api/v1/projects/demo/git/answer", `{"answer":"unknown"}`); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if v := list(); v.GitAnswer != "unknown" || v.GitAttached {
		t.Errorf("unknown: %+v", v)
	}
}
