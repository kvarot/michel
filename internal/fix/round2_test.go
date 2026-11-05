package fix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/workcopy"
)

func TestProposeUsesOneSnapshot(t *testing.T) {
	f := newFixture(t)
	f.consent()
	var copyDir string
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		copyDir = dir
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	// Something writes in the agent's copy while Michel installs (after the
	// snapshot): a late tool call, a process left behind.
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "install" {
			writeFile(t, copyDir, "late.txt", "written after the snapshot\n")
			writeFile(t, copyDir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"9.9.9"}]}`+"\n")
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatalf("no proposal: %+v", got)
	}
	if len(p.Files) != 1 || p.Files[0] != "composer.lock" || strings.Contains(string(p.DiffRaw), "late") || strings.Contains(string(p.DiffRaw), "9.9.9") {
		t.Errorf("the late write reached the proposal: %v\n%s", p.Files, p.DiffRaw)
	}
	wd := f.d.work()
	if _, ok, _ := workcopy.CommitFile(context.Background(), wd, got.Work.Copy, p.CommitSHA, "late.txt"); ok {
		t.Error("the late file is in the commit")
	}
	lock, _, _ := workcopy.CommitFile(context.Background(), wd, got.Work.Copy, p.CommitSHA, "composer.lock")
	if !strings.Contains(string(lock), "1.2.5") || strings.Contains(string(lock), "9.9.9") {
		t.Errorf("committed lockfile = %s", lock)
	}
	if p.Hash != proposalHash(p.DiffRaw, p.CommitSHA, p.TestsStatus, p.Summary) {
		t.Error("the hash does not cover the committed content")
	}
	if _, err := os.Stat(filepath.Join(copyDir, "late.txt")); err != nil {
		t.Error("the late write itself was lost from the copy")
	}
}

func TestTestsRunOutsideAgentCopy(t *testing.T) {
	f := newFixture(t)
	f.consent()
	var copyDir string
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		copyDir = dir
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "install" {
			writeFile(t, dir, "vendor/marker.php", "installed\n")
		}
	}
	michelsUpdate(t, f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	scratch := filepath.Join(f.d.DataDir, "fix-tmp", a.ID, "run")
	seen := 0
	for _, r := range f.rec.runs {
		if r.name == "composer" && r.args[0] == "update" {
			continue // Michel's update at Start, in the pristine copy
		}
		seen++
		if r.dir != scratch && !strings.HasPrefix(r.dir, scratch+string(filepath.Separator)) {
			t.Errorf("%s %v ran in %s, want the scratch worktree", r.name, r.args, r.dir)
		}
		if strings.HasPrefix(r.dir, copyDir) {
			t.Errorf("%s ran in the agent's copy", r.name)
		}
	}
	if seen != 2 {
		t.Errorf("%d commands ran at Propose, want the install and the tests", seen)
	}
	if _, err := os.Stat(filepath.Join(copyDir, "vendor", "marker.php")); err == nil {
		t.Error("the install wrote in the agent's copy")
	}
	if _, err := os.Stat(filepath.Join(copyDir, "composer.lock")); err != nil {
		t.Error("the copy lost its files")
	}
}

func TestAutoDecidedBeforeTests(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	var copyDir string
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		copyDir = dir
		// The agent rewrites Michel's lockfile, then a test "restores" it.
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"},{"name":"evil/pkg","version":"1.0.0","dist":{"type":"zip","url":"https://evil/x.zip"}}]}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "GARBAGE then restore"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	base := f.rec.onRun
	f.rec.onRun = func(name string, args []string, dir string) {
		base(name, args, dir)
		if name == "vendor/bin/phpunit" {
			writeFile(t, dir, "composer.lock", michelLock)
			writeFile(t, copyDir, "composer.lock", michelLock)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("a tree the agent changed was applied alone: %+v", got)
	}
	p, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !strings.Contains(string(p.DiffRaw), "evil/pkg") {
		t.Errorf("the proposal is not the snapshot the agent made:\n%s", p.DiffRaw)
	}
	if ev := f.audits("fix.auto"); len(ev) != 1 || ev[0].Result != "skipped" {
		t.Errorf("fix.auto audit = %+v", ev)
	}
}

func TestScratchWorktreeRemoved(t *testing.T) {
	f := newFixture(t)
	f.consent()
	existed := false
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "vendor/bin/phpunit" {
			_, err := os.Stat(filepath.Join(dir, ".git"))
			existed = err == nil
		}
	}
	michelsUpdate(t, f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if !existed {
		t.Error("the tests did not run in a scratch worktree")
	}
	if _, err := os.Lstat(filepath.Join(f.d.DataDir, "fix-tmp", a.ID)); err == nil {
		t.Error("the scratch folder survived the proposal")
	}
	// A folder left by a crash goes with the sweep.
	writeFile(t, f.d.DataDir, "fix-tmp/"+a.ID+"/run/x.txt", "x")
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.d.DataDir, "fix-tmp")); err == nil {
		t.Error("the scratch folder survived the sweep")
	}
}

func TestNoAutoWhenMichelsUpdateFailed(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	f.rec.fail = "composer" // every composer command fails, the update first
	proposeOnly(f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	if got.Work.Tree0 != "" {
		t.Errorf("Tree0 recorded although Michel's update failed: %+v", got.Work)
	}
	if got.ApprovedBy != "" || got.State == StateApplied || got.State == StateApproved {
		t.Errorf("applied alone after a failed update: %+v", got)
	}
}

func TestConcurrentProposeIsSerialized(t *testing.T) {
	f := newFixture(t)
	f.consent()
	var inFlight, maxInFlight int32
	var mu sync.Mutex
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "update" {
			return
		}
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
	}
	var errs [2]error
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`+"\n")
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = Propose(ctx, d, id, ProposeInput{Summary: "proposal " + string(rune('A'+i))})
			}(i)
		}
		wg.Wait()
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	for i, err := range errs {
		if err != nil {
			t.Errorf("Propose #%d: %v", i, err)
		}
	}
	if maxInFlight != 1 {
		t.Errorf("%d installs or tests ran at the same time for one attempt", maxInFlight)
	}
	props, _ := f.d.Repo.Proposals(context.Background(), a.ID)
	if len(props) != 2 || !props[0].Superseded || props[1].Superseded {
		t.Errorf("proposals = %+v", props)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("state = %s", got.State)
	}
}
