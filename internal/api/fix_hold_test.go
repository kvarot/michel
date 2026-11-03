package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
)

// plantKey commits a key in the project of the fixture.
func (ff *fixFixture) plantKey() {
	ff.t.Helper()
	gc := filepath.Join(ff.t.TempDir(), "gitconfig")
	if err := os.WriteFile(gc, nil, 0o600); err != nil {
		ff.t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gc,
		"GIT_AUTHOR_NAME=demo", "GIT_AUTHOR_EMAIL=demo@example.test", "GIT_COMMITTER_NAME=demo", "GIT_COMMITTER_EMAIL=demo@example.test")
	root := ff.proj.Path
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		ff.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "config.php"), []byte("<?php\n$aws = '"+fakeAWS()+"';\n"), 0o644); err != nil {
		ff.t.Fatal(err)
	}
	gitRun(ff.t, env, root, "add", "-A")
	gitRun(ff.t, env, root, "commit", "-q", "-m", "a key")
}

// heldStart starts a fix on a project with a key: 202, state held, no agent.
func (ff *fixFixture) heldStart() AttemptView {
	ff.t.Helper()
	code, body := ff.send("POST", "/api/v1/findings/"+ff.ids["ACME-2026-0001"]+"/fix", "")
	if code != http.StatusAccepted {
		ff.t.Fatalf("start = %d %s", code, body)
	}
	if strings.Contains(body, fakeAWS()) {
		ff.t.Errorf("the answer holds the value: %s", body)
	}
	var v struct {
		Attempt AttemptView `json:"attempt"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		ff.t.Fatal(err)
	}
	if v.Attempt.State != string(fix.StateHeld) || v.Attempt.Hold == nil {
		ff.t.Fatalf("attempt = %s", body)
	}
	ff.noAgent()
	return v.Attempt
}

func (ff *fixFixture) noAgent() {
	ff.t.Helper()
	select {
	case <-ff.agents:
		ff.t.Fatal("an agent started")
	default:
	}
}

func TestHoldIsAnsweredWithFilesAndLinesOnly(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	h := a.Hold
	if h.Count != 1 || len(h.Files) != 1 || h.Files[0].File != "src/config.php" || len(h.Files[0].Lines) != 1 || h.Files[0].Lines[0] != 2 || h.Hash == "" {
		t.Errorf("hold = %+v", h)
	}
	for _, path := range []string{"/api/v1/fix/" + a.ID, "/api/v1/fixes", "/api/v1/fixes?state=held"} {
		code, body := ff.send("GET", path, "")
		if code != http.StatusOK || !strings.Contains(body, `"hold":{`) || strings.Contains(body, fakeAWS()) {
			t.Errorf("GET %s = %d %s", path, code, body)
		}
	}
	// A second start finds the project taken.
	if code, body := ff.send("POST", "/api/v1/findings/"+ff.ids["ACME-2026-0001"]+"/fix", ""); code != http.StatusConflict || !strings.Contains(body, "fix.err.busy") {
		t.Errorf("second start = %d %s", code, body)
	}
}

func TestHoldRoutesNeedTheToken(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	for _, r := range []struct{ path, body string }{{"/continue", `{"hash":"` + a.Hold.Hash + `"}`}, {"/withdraw", ""}} {
		for _, tok := range []string{"", "wrong"} {
			resp, _ := ff.do("POST", "/api/v1/fix/"+a.ID+r.path, tok, r.body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s token %q = %d", r.path, tok, resp.StatusCode)
			}
		}
	}
	ff.noAgent()
}

func TestContinueStartsTheAgentForTheListShown(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	// No hash: nothing starts.
	if code, _ := ff.send("POST", "/api/v1/fix/"+a.ID+"/continue", `{}`); code != http.StatusBadRequest {
		t.Errorf("no hash = %d", code)
	}
	// Another list than the one shown: nothing starts and it still waits.
	code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/continue", `{"hash":"other"}`)
	if code != http.StatusConflict || !strings.Contains(body, "fix.err.hold_stale") {
		t.Errorf("other hash = %d %s", code, body)
	}
	ff.noAgent()
	code, body = ff.send("POST", "/api/v1/fix/"+a.ID+"/continue", `{"hash":"`+a.Hold.Hash+`"}`)
	if code != http.StatusAccepted {
		t.Fatalf("continue = %d %s", code, body)
	}
	var v AttemptView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if v.State != string(fix.StatePreparing) || v.Hold != nil {
		t.Errorf("after the yes: %s", body)
	}
	if strings.Contains(body, fakeAWS()) {
		t.Errorf("the answer holds the value: %s", body)
	}
	select {
	case ag := <-ff.agents:
		ag.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the agent was not started")
	}
	ff.fd.Sessions.Wait(a.ID, 10*time.Second)
	// The same answer again finds nothing to answer.
	if code, _ := ff.send("POST", "/api/v1/fix/"+a.ID+"/continue", `{"hash":"`+a.Hold.Hash+`"}`); code != http.StatusConflict {
		t.Errorf("second yes = %d", code)
	}
}

func TestContinueRefusedWhenTheCopyChanged(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	got, err := fix.NewRepo(ff.st).GetAttempt(t.Context(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(got.Work.Copy.Dir, "README.md"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/continue", `{"hash":"`+a.Hold.Hash+`"}`)
	if code != http.StatusConflict || !strings.Contains(body, "fix.err.hold_stale") {
		t.Errorf("continue = %d %s", code, body)
	}
	ff.noAgent()
	if code, body := ff.send("GET", "/api/v1/fix/"+a.ID, ""); code != http.StatusOK || !strings.Contains(body, `"state":"failed"`) {
		t.Errorf("attempt = %d %s", code, body)
	}
}

func TestWithdrawEndsTheAttemptWithoutAnAgent(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/withdraw", "")
	if code != http.StatusOK || !strings.Contains(body, `"state":"withdrawn"`) || strings.Contains(body, `"hold"`) {
		t.Errorf("withdraw = %d %s", code, body)
	}
	ff.noAgent()
	if code, _ := ff.send("POST", "/api/v1/fix/"+a.ID+"/withdraw", ""); code != http.StatusConflict {
		t.Errorf("second withdraw = %d", code)
	}
	// Nothing was removed from the code: Michel asks again.
	b := ff.heldStart()
	if b.ID == a.ID {
		t.Error("the same attempt")
	}
	code, body = ff.send("GET", "/api/v1/fixes?state=withdrawn", "")
	if code != http.StatusOK || !strings.Contains(body, a.ID) {
		t.Errorf("list = %d %s", code, body)
	}
}

func TestHoldRefusalsAreTranslated(t *testing.T) {
	ff := newFixFixture(t)
	ff.consent()
	ff.plantKey()
	a := ff.heldStart()
	code, body := ff.send("POST", "/api/v1/fix/"+a.ID+"/continue?lang=fr", `{"hash":"other"}`)
	if code != http.StatusConflict || !strings.Contains(body, "Ton projet a chang") {
		t.Errorf("refusal = %d %s", code, body)
	}
}
