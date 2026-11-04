package fix

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
)

// plantWeak commits lines that talk about a password without holding one.
func (f *fixture) plantWeak() {
	f.t.Helper()
	writeFile(f.t, f.proj.Path, "src/login.php", "<?php\n$password = $request->input('password');\n$rules = ['password' => 'required|min:8'];\n")
	gitT(f.t, f.env, f.proj.Path, "add", "-A")
	gitT(f.t, f.env, f.proj.Path, "commit", "-q", "-m", "login")
}

func (f *fixture) messagesOf(id string) string {
	f.t.Helper()
	msgs, err := f.d.Repo.ListMessages(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	var all strings.Builder
	for _, m := range msgs {
		all.WriteString(m.Text + "\n")
	}
	return all.String()
}

func TestWeakHitsDoNotHoldAndStayAWarning(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantWeak()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if a.State == StateHeld {
		t.Fatalf("ordinary code held the attempt")
	}
	if n := f.startedCount(); n != 1 {
		t.Errorf("%d agents started", n)
	}
	if evs := f.audits("fix.hold"); len(evs) != 0 {
		t.Errorf("fix.hold audited: %+v", evs)
	}
	f.wait(a.ID)
	text := f.messagesOf(a.ID)
	if !strings.Contains(text, "src/login.php") || !strings.Contains(text, "can read") {
		t.Errorf("no warning in the messages:\n%s", text)
	}
	if strings.Contains(text, "has not started") {
		t.Errorf("the warning says the agent did not start:\n%s", text)
	}
}

func TestHoldAsksAboutStrongHitsOnly(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantWeak()
	f.plantKey()
	a := f.held()
	h, ok := HoldOf(f.attempt(a.ID))
	if !ok || h.Count != 1 || len(h.Files) != 1 || h.Files[0].File != "src/config.php" {
		t.Fatalf("hold = %+v", h)
	}
	evs := f.audits("fix.hold")
	if len(evs) != 1 {
		t.Fatalf("fix.hold = %+v", evs)
	}
	if n, _ := evs[0].Evidence["secret_hits"].(float64); n != 1 {
		t.Errorf("secret_hits in %+v", evs[0].Evidence)
	}
	if n, _ := evs[0].Evidence["weak_hits"].(float64); n != 2 {
		t.Errorf("weak_hits in %+v", evs[0].Evidence)
	}
	// After a yes, the weak lines are still told.
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, h.Hash); err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if text := f.messagesOf(a.ID); !strings.Contains(text, "src/login.php") {
		t.Errorf("the weak lines are not told after the yes:\n%s", text)
	}
}

func TestANoIsNotAskedAgainOnTheSameCommit(t *testing.T) {
	f := newFixture(t)
	f.d.Repo.Now = f.d.Now
	f.consent()
	p := f.proj
	p.FixLevel = 2
	f.update(p)
	f.plantKey()
	ctx := context.Background()
	if n, err := QueueEligible(ctx, f.d, f.proj.ID); err != nil || n != 1 {
		t.Fatalf("QueueEligible = %d, %v", n, err)
	}
	if ok, err := WorkOnce(ctx, f.d); err != nil || !ok {
		t.Fatalf("WorkOnce = %v, %v", ok, err)
	}
	list, _ := f.d.Repo.ListAttempts(ctx, f.proj.ID, string(StateHeld))
	if len(list) != 1 {
		t.Fatalf("held = %+v", list)
	}
	if err := WithdrawHeld(ctx, f.d, list[0].ID); err != nil {
		t.Fatal(err)
	}
	// Same commit, same exclusions: nothing can have changed.
	if n, err := QueueEligible(ctx, f.d, f.proj.ID); err != nil || n != 0 {
		t.Errorf("same commit: QueueEligible = %d, %v", n, err)
	}
	// Another flaw of the project already queued would ask the same question.
	second := f.seed("acme/other", "GHSA-aaaa-bbbb-cccc", "1.0.0", "1.2.5", "composer.lock", "Packagist")
	if err := f.d.Repo.Enqueue(ctx, second.ID, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := WorkOnce(ctx, f.d); err != nil || ok {
		t.Errorf("same commit: WorkOnce = %v, %v", ok, err)
	}
	if list, _ := f.d.Repo.ListAttempts(ctx, f.proj.ID, string(StateHeld)); len(list) != 0 {
		t.Errorf("asked again: %+v", list)
	}
	// Other exclusions: the question may have another answer.
	p, err := project.NewRepo(f.st).Get(ctx, f.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.Exclude = []string{"legacy"}
	f.update(p)
	if tried, err := f.d.alreadyTried(ctx, f.finding); err != nil || tried {
		t.Errorf("other exclusions: alreadyTried = %v, %v", tried, err)
	}
	p.Exclude = nil
	f.update(p)
	if tried, err := f.d.alreadyTried(ctx, f.finding); err != nil || !tried {
		t.Errorf("same exclusions: alreadyTried = %v, %v", tried, err)
	}
	// A new commit: the queue may try again.
	f.removeKey()
	if tried, err := f.d.alreadyTried(ctx, f.finding); err != nil || tried {
		t.Errorf("new commit: alreadyTried = %v, %v", tried, err)
	}
	if n, err := QueueEligible(ctx, f.d, f.proj.ID); err != nil || n == 0 {
		t.Errorf("new commit: QueueEligible = %d, %v", n, err)
	}
}

func TestAutomaticHoldSaysAYesIsAwaited(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	var waiting, held []int
	f.d.Notify = func(_ context.Context, n int) { waiting = append(waiting, n) }
	f.d.NotifyHeld = func(_ context.Context, n int) { held = append(held, n) }
	if _, err := Start(context.Background(), f.d, f.finding.ID, OriginAgentAuto); err != nil {
		t.Fatal(err)
	}
	if len(waiting) != 0 || len(held) != 1 || held[0] != 1 {
		t.Errorf("Notify %v, NotifyHeld %v", waiting, held)
	}
}

func TestAnUnansweredHoldEndsAsANo(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	got := f.attempt(a.ID)
	dir := got.Work.Copy.Dir
	ctx := context.Background()
	at := func(after time.Duration) Deps {
		d := f.d
		d.Now = func() time.Time { return got.UpdatedAt.Add(after) }
		return d
	}
	// Before the limit it waits, whatever the sweep.
	if err := Sweep(ctx, at(HeldExpiry-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s := f.attempt(a.ID).State; s != StateHeld {
		t.Fatalf("before the limit: state %s", s)
	}
	// After it: a no, and only ever a no.
	if err := Sweep(ctx, at(HeldExpiry+time.Minute)); err != nil {
		t.Fatal(err)
	}
	end := f.attempt(a.ID)
	if end.State != StateWithdrawn || !strings.Contains(end.Cause, "14 days") {
		t.Fatalf("after the limit: %s, %q", end.State, end.Cause)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the copy is still there: %v", err)
	}
	if n := f.startedCount(); n != 0 {
		t.Errorf("%d agents started", n)
	}
	evs := f.audits("fix.hold.withdraw")
	if len(evs) != 1 || evs[0].Evidence["author"] != "expired" {
		t.Errorf("audit = %+v", evs)
	}
	// It does not ask again on the same commit.
	if tried, err := f.d.alreadyTried(ctx, f.finding); err != nil || !tried {
		t.Errorf("alreadyTried = %v, %v", tried, err)
	}
}

func TestOnlyTheTwoDoorsOfAPersonAnswer(t *testing.T) {
	for actor, want := range map[string]bool{"cli": true, "web": true, "serve": false, ActorAuto: false, "mcp": false, "michel": false, "": false, "digest": false, "anything": false} {
		if got := actorAnswers(actor); got != want {
			t.Errorf("actorAnswers(%q) = %v", actor, got)
		}
	}
}

func TestMessagesMaskAFileNamedLikeAKey(t *testing.T) {
	name := "src/" + holdKey() + ".php"
	hit := mask.Hit{File: name, Line: 1, Kind: mask.KindAWSKey, Strong: true}
	if text := secretHitsMessage(i18n.EN, []mask.Hit{hit}); strings.Contains(text, holdKey()) {
		t.Errorf("the message shows the name: %s", text)
	}
	hit.Strong = false
	if text := weakHitsMessage(i18n.EN, []mask.Hit{hit}); strings.Contains(text, holdKey()) {
		t.Errorf("the warning shows the name: %s", text)
	}
}
