package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// awaitingAttempt starts a fix of demo whose agent writes a test file and
// proposes: the proposal's tests wait for a click.
func (ff *fixFixture) awaitingAttempt() (string, ProposalView) {
	ff.t.Helper()
	ctx := context.Background()
	p, err := project.NewRepo(ff.st).Get(ctx, "demo")
	if err != nil {
		ff.t.Fatal(err)
	}
	p.TestCmd = "vendor/bin/phpunit"
	if err := project.NewRepo(ff.st).Update(ctx, p); err != nil {
		ff.t.Fatal(err)
	}
	ff.consent()
	v, _ := ff.start()
	a, err := fix.NewRepo(ff.st).GetAttempt(ctx, v.ID)
	if err != nil {
		ff.t.Fatal(err)
	}
	for name, body := range map[string]string{
		"composer.lock":      `{"packages":[{"name":"acme/vuln","version":"1.2.5"}]}` + "\n",
		"tests/EvilTest.php": "<?php\n",
	} {
		path := filepath.Join(a.Work.Copy.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			ff.t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			ff.t.Fatal(err)
		}
	}
	if _, err := fix.Propose(ctx, *ff.fd, a.ID, fix.ProposeInput{Summary: "Upgrade acme/vuln."}); err != nil {
		ff.t.Fatalf("Propose: %v", err)
	}
	code, body := ff.send("GET", "/api/v1/fix/"+a.ID, "")
	var got AttemptView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || got.Proposal == nil {
		ff.t.Fatalf("attempt = %d %s", code, body)
	}
	return a.ID, *got.Proposal
}

func TestRunTestsRoute(t *testing.T) {
	ff := newFixFixture(t)
	id, prop := ff.awaitingAttempt()
	if prop.TestsStatus != workcopy.TestsAwaiting || !prop.CanRunTests || len(prop.CodeFiles) != 2 ||
		prop.CodeFiles[0] != (ReviewFileView{Path: "composer.lock", Kind: "lockfile"}) || prop.CodeFiles[1] != (ReviewFileView{Path: "tests/EvilTest.php", Kind: "tests"}) {
		t.Fatalf("awaiting proposal = %+v", prop)
	}
	// A stale hash: 409, nothing ran.
	code, body := ff.send("POST", "/api/v1/fix/"+id+"/run-tests", `{"hash":"`+prop.Hash+`-old"}`)
	var eb FixErrorBody
	if code != http.StatusConflict || json.Unmarshal([]byte(body), &eb) != nil || eb.Code != "fix.err.stale_proposal" {
		t.Fatalf("stale run-tests = %d %s", code, body)
	}
	if code, body := ff.send("POST", "/api/v1/fix/"+id+"/run-tests", `{}`); code != http.StatusBadRequest {
		t.Errorf("run-tests without hash = %d %s", code, body)
	}
	// The right hash: 200 with the new proposal and its result.
	code, body = ff.send("POST", "/api/v1/fix/"+id+"/run-tests", `{"hash":"`+prop.Hash+`"}`)
	var v AttemptView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil || v.Proposal == nil {
		t.Fatalf("run-tests = %d %s", code, body)
	}
	if v.Proposal.TestsStatus != workcopy.TestsPassed || v.Proposal.Hash == prop.Hash || v.Proposal.CanRunTests || len(v.Proposal.CodeFiles) != 0 {
		t.Errorf("after the run: %+v", v.Proposal)
	}
	// Not awaiting any more: 409.
	code, body = ff.send("POST", "/api/v1/fix/"+id+"/run-tests", `{"hash":"`+v.Proposal.Hash+`"}`)
	if code != http.StatusConflict || json.Unmarshal([]byte(body), &eb) != nil || eb.Code != "fix.err.not_awaiting" {
		t.Errorf("second run-tests = %d %s", code, body)
	}
	// The old hash no longer approves.
	if code, _ := ff.send("POST", "/api/v1/fix/"+id+"/approve", `{"hash":"`+prop.Hash+`"}`); code != http.StatusConflict {
		t.Errorf("approve with the old hash = %d", code)
	}
}
