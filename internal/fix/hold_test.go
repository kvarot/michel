package fix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/agent"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/scan"
)

// holdKey is a value the detectors always find, built so that no scanner sees
// a key in this file.
func holdKey() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

// plantKey commits a key in the project, line 2 of src/config.php.
func (f *fixture) plantKey() {
	f.t.Helper()
	writeFile(f.t, f.proj.Path, "src/config.php", "<?php\n$aws = '"+holdKey()+"';\n")
	gitT(f.t, f.env, f.proj.Path, "add", "-A")
	gitT(f.t, f.env, f.proj.Path, "commit", "-q", "-m", "a key")
}

// removeKey commits the removal of the key.
func (f *fixture) removeKey() {
	f.t.Helper()
	writeFile(f.t, f.proj.Path, "src/config.php", "<?php\n$aws = getenv('AWS');\n")
	gitT(f.t, f.env, f.proj.Path, "add", "-A")
	gitT(f.t, f.env, f.proj.Path, "commit", "-q", "-m", "no key")
}

func (f *fixture) startedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

// held starts an attempt on the planted key and checks that it waits.
func (f *fixture) held() Attempt {
	f.t.Helper()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		f.t.Fatalf("Start: %v", err)
	}
	if a.State != StateHeld {
		f.t.Fatalf("state %s, want held", a.State)
	}
	return a
}

// checkNothingLeft says no agent started, no update ran and no token exists.
func (f *fixture) checkNothingLeft(a Attempt) {
	f.t.Helper()
	if n := f.startedCount(); n != 0 {
		f.t.Errorf("%d agents started", n)
	}
	if tokenStillSet(f.d.Secrets, a.ID) {
		f.t.Error("a held attempt has a token for michel mcp")
	}
	for _, n := range f.rec.names() {
		if n == "composer" || n == "npm" {
			f.t.Errorf("%s ran while the attempt was held: it would use the network", n)
		}
	}
}

func holdHash(t *testing.T, a Attempt) string {
	t.Helper()
	h, ok := HoldOf(a)
	if !ok || h.Hash == "" {
		t.Fatalf("no hold on %+v", a)
	}
	return h.Hash
}

func TestStartHoldsOnAKeyBeforeAnythingLeaves(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	f.checkNothingLeft(a)
	got := f.attempt(a.ID)
	if got.Work.Copy.Dir == "" {
		t.Fatal("a held attempt keeps its copy")
	}
	if _, err := os.Stat(got.Work.Copy.Dir); err != nil {
		t.Errorf("the copy is gone: %v", err)
	}
	h, ok := HoldOf(got)
	if !ok || h.Count != 1 || len(h.Files) != 1 || h.Files[0].File != "src/config.php" || len(h.Files[0].Lines) != 1 || h.Files[0].Lines[0] != 2 {
		t.Errorf("hold = %+v", h)
	}
	if evs := f.audits("fix.start"); len(evs) != 0 {
		t.Errorf("fix.start audited while held: %+v", evs)
	}
	evs := f.audits("fix.hold")
	if len(evs) != 1 || evs[0].Result != "ok" {
		t.Fatalf("fix.hold = %+v", evs)
	}
	if n, _ := evs[0].Evidence["secret_hits"].(float64); n != 1 {
		t.Errorf("fix.hold evidence = %+v", evs[0].Evidence)
	}
}

func TestHoldAtEveryOriginAndLevel(t *testing.T) {
	for _, level := range []int{1, 2, 3} {
		f := newFixture(t)
		f.d.Repo.Now = f.d.Now
		f.consent()
		p := f.proj
		p.FixLevel = level
		p.AutoFixMinor = level == 3
		f.update(p)
		f.plantKey()
		if level == 1 {
			f.held()
		} else {
			if n, err := QueueEligible(context.Background(), f.d, f.proj.ID); err != nil || n != 1 {
				t.Fatalf("level %d: QueueEligible = %d, %v", level, n, err)
			}
			if ok, err := WorkOnce(context.Background(), f.d); err != nil || !ok {
				t.Fatalf("level %d: WorkOnce = %v, %v", level, ok, err)
			}
		}
		list, _ := f.d.Repo.ListAttempts(context.Background(), f.proj.ID, "")
		if len(list) != 1 || list[0].State != StateHeld {
			t.Fatalf("level %d: attempts %+v", level, list)
		}
		f.checkNothingLeft(list[0])
		// No pass of the worker answers for the person.
		for i := 0; i < 3; i++ {
			if _, err := QueueEligible(context.Background(), f.d, f.proj.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := WorkOnce(context.Background(), f.d); err != nil {
				t.Fatal(err)
			}
			if _, err := ApplyAutoServer(context.Background(), f.d); err != nil {
				t.Fatal(err)
			}
		}
		if err := Sweep(context.Background(), f.d); err != nil {
			t.Fatal(err)
		}
		got := f.attempt(list[0].ID)
		if got.State != StateHeld {
			t.Errorf("level %d: state %s after the worker's passes", level, got.State)
		}
		if _, err := os.Stat(got.Work.Copy.Dir); err != nil {
			t.Errorf("level %d: a sweep removed the held copy: %v", level, err)
		}
		f.checkNothingLeft(got)
	}
}

func TestOnlyAPersonAnswersAHold(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	hash := holdHash(t, f.attempt(a.ID))
	for _, actor := range []string{"serve", ActorAuto, "mcp", ""} {
		d := f.d
		d.Actor = actor
		if _, err := ContinueHeld(context.Background(), d, a.ID, hash); !errors.Is(err, ErrHoldPerson) {
			t.Errorf("actor %q: err = %v", actor, err)
		}
	}
	if got := f.attempt(a.ID); got.State != StateHeld {
		t.Errorf("state %s", got.State)
	}
	f.checkNothingLeft(a)
}

func TestHoldBlocksTheProjectAndTheAgentTools(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	if _, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent); !errors.Is(err, ErrBusy) {
		t.Errorf("a second start: %v", err)
	}
	if _, err := Propose(context.Background(), f.d, a.ID, ProposeInput{Summary: "x"}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("Propose on a held attempt: %v", err)
	}
	if err := SendMessage(context.Background(), f.d, a.ID, "hello"); err == nil {
		t.Error("a message reached a held attempt")
	}
	f.checkNothingLeft(a)
}

func TestYesStartsTheAgentOnceAndIsNotStored(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	got, err := ContinueHeld(context.Background(), f.d, a.ID, holdHash(t, f.attempt(a.ID)))
	if err != nil {
		t.Fatalf("ContinueHeld: %v", err)
	}
	if got.State == StateHeld || got.State == StateFailed {
		t.Fatalf("state %s after the yes", got.State)
	}
	f.wait(a.ID)
	if n := f.startedCount(); n != 1 {
		t.Errorf("%d agents started, want 1", n)
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("state %s, cause %q", got.State, got.Cause)
	}
	evs := f.audits("fix.hold.continue")
	if len(evs) != 1 || evs[0].Result != "ok" {
		t.Fatalf("fix.hold.continue = %+v", evs)
	}
	if st := f.audits("fix.start"); len(st) != 1 {
		t.Errorf("fix.start = %+v", st)
	}
	// A second yes finds nothing to answer.
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, "x"); !errors.Is(err, ErrBadTransition) {
		t.Errorf("a second yes: %v", err)
	}
	// The yes was for that attempt: the next one waits again.
	if err := Refuse(context.Background(), f.d, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	b := f.held()
	if b.ID == a.ID {
		t.Error("the same attempt")
	}
	if n := f.startedCount(); n != 1 {
		t.Errorf("the second attempt started an agent")
	}
}

func TestNoEndsTheAttemptAndARetryWithoutTheKeyStartsDirectly(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	dir := f.attempt(a.ID).Work.Copy.Dir
	if err := WithdrawHeld(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("WithdrawHeld: %v", err)
	}
	got := f.attempt(a.ID)
	if got.State != StateWithdrawn {
		t.Errorf("state %s", got.State)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the copy stays: %v", err)
	}
	f.checkNothingLeft(a)
	if evs := f.audits("fix.hold.withdraw"); len(evs) != 1 || evs[0].Result != "ok" {
		t.Errorf("fix.hold.withdraw = %+v", evs)
	}
	// The key is still there: Michel asks again.
	b := f.held()
	if err := Refuse(context.Background(), f.d, b.ID, ""); err != nil {
		t.Fatalf("Refuse on a held attempt: %v", err)
	}
	if got := f.attempt(b.ID); got.State != StateWithdrawn {
		t.Errorf("Refuse on a held attempt: %s", got.State)
	}
	// The key is gone from the code: no question.
	f.removeKey()
	c, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != StatePreparing && c.State != StateProposed {
		t.Errorf("state %s", c.State)
	}
	f.wait(c.ID)
	if n := f.startedCount(); n != 1 {
		t.Errorf("%d agents started, want 1", n)
	}
	if evs := f.audits("fix.hold"); len(evs) != 2 {
		t.Errorf("fix.hold = %d rows, want 2", len(evs))
	}
}

func TestYesIsRefusedWhenAnythingChanged(t *testing.T) {
	cases := map[string]func(f *fixture, a Attempt){
		"a file of the copy changed": func(f *fixture, a Attempt) {
			writeFile(f.t, a.Work.Copy.Dir, "README.md", "changed\n")
		},
		"a new file in the copy": func(f *fixture, a Attempt) {
			writeFile(f.t, a.Work.Copy.Dir, "other.txt", "changed\n")
		},
		"another key in the copy": func(f *fixture, a Attempt) {
			writeFile(f.t, a.Work.Copy.Dir, "src/other.php", "<?php\n$k = '"+holdKey()+"';\n")
		},
		"the project moved on": func(f *fixture, a Attempt) { f.removeKey() },
		"the project excludes a folder now": func(f *fixture, a Attempt) {
			p := f.proj
			p.Exclude = []string{"src"}
			f.update(p)
		},
		"the copy is gone": func(f *fixture, a Attempt) {
			if err := os.RemoveAll(a.Work.Copy.Dir); err != nil {
				f.t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.consent()
			f.plantKey()
			a := f.attempt(f.held().ID)
			hash := holdHash(t, a)
			change(f, a)
			if _, err := ContinueHeld(context.Background(), f.d, a.ID, hash); !errors.Is(err, ErrHoldStale) {
				t.Fatalf("err = %v", err)
			}
			got := f.attempt(a.ID)
			if got.State != StateFailed || got.Cause == "" {
				t.Errorf("state %s, cause %q", got.State, got.Cause)
			}
			f.checkNothingLeft(a)
			evs := f.audits("fix.hold.continue")
			if len(evs) != 1 || evs[0].Result != "refused" {
				t.Errorf("fix.hold.continue = %+v", evs)
			}
		})
	}
}

func TestYesWithAnOldHashLeavesTheAttemptWaiting(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, "not-what-was-shown"); !errors.Is(err, ErrHoldStale) {
		t.Fatalf("err = %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateHeld {
		t.Errorf("state %s", got.State)
	}
	f.checkNothingLeft(a)
}

func TestYesChecksTheGatesAgainAndKeepsWaiting(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	hash := holdHash(t, f.attempt(a.ID))
	d := f.d
	d.AgentStatus = func(context.Context) agent.Status { return agent.Status{Hint: "not_logged_in"} }
	if _, err := ContinueHeld(context.Background(), d, a.ID, hash); !errors.Is(err, ErrAgentUnavailable) {
		t.Errorf("no agent: %v", err)
	}
	p := f.proj
	p.Classification = "health"
	f.update(p)
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, hash); !errors.Is(err, ErrHealthForbidden) {
		t.Errorf("health: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateHeld {
		t.Errorf("state %s", got.State)
	}
	f.checkNothingLeft(a)
}

func TestYesRefusedOnAFlawNoLongerSeen(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	hash := holdHash(t, f.attempt(a.ID))
	f.setFindingStatus(f.finding.ID, scan.StatusGone)
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, hash); !errors.Is(err, ErrHoldStale) {
		t.Errorf("err = %v", err)
	}
	f.checkNothingLeft(a)
}

func TestHoldKeepsNoValueAnywhere(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.plantKey()
	a := f.held()
	hash := holdHash(t, f.attempt(a.ID))
	check := func(what, text string) {
		t.Helper()
		if strings.Contains(text, holdKey()) {
			t.Errorf("%s holds the value: %s", what, text)
		}
	}
	got := f.attempt(a.ID)
	b, _ := json.Marshal(got)
	check("the attempt", string(b))
	h, _ := HoldOf(got)
	b, _ = json.Marshal(h)
	check("the hold", string(b))
	check("the stored work", workOf(t, f, a.ID))
	if _, err := ContinueHeld(context.Background(), f.d, a.ID, hash); err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	msgs, _ := f.d.Repo.ListMessages(context.Background(), a.ID)
	if len(msgs) == 0 {
		t.Error("no message of Michel")
	}
	for _, m := range msgs {
		check("a message", m.Text)
	}
	for _, action := range []string{"fix.hold", "fix.hold.continue", "fix.start"} {
		for _, ev := range f.audits(action) {
			b, _ := json.Marshal(ev.Evidence)
			check(action, string(b))
			if strings.Contains(string(b), "config.php") {
				t.Errorf("%s names a file, counts only: %s", action, b)
			}
		}
	}
}

// workOf is the work_json stored for the attempt.
func workOf(t *testing.T, f *fixture, id string) string {
	t.Helper()
	var s string
	if err := f.st.DB().QueryRow(`SELECT work_json FROM fix_attempt WHERE id = ?`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHoldOfOnlyForAHeldAttempt(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if _, ok := HoldOf(f.attempt(a.ID)); ok {
		t.Error("a hold without any key")
	}
	if got := f.attempt(a.ID); got.State != StateProposed {
		t.Errorf("a flow without a key: %s", got.State)
	}
	if evs := f.audits("fix.hold"); len(evs) != 0 {
		t.Errorf("fix.hold without a key: %+v", evs)
	}
}

func TestHoldListsAtMostSomeFilesAndSaysHowManyMore(t *testing.T) {
	a := Attempt{State: StateHeld}
	for i := 0; i < maxHoldFiles+3; i++ {
		a.Work.Copy.SecretHits = append(a.Work.Copy.SecretHits, secretHit("src/f"+string(rune('a'+i))+".php", i+1))
	}
	h, ok := HoldOf(a)
	if !ok || h.Count != maxHoldFiles+3 || len(h.Files) != maxHoldFiles || h.More != 3 {
		t.Errorf("hold = %+v", h)
	}
}

func TestHeldAndWithdrawnStatesAreKnown(t *testing.T) {
	if finished(StateHeld) {
		t.Error("a held attempt needs its copy")
	}
	if !finished(StateWithdrawn) {
		t.Error("a withdrawn attempt has no use for its copy")
	}
	if ErrorKey(ErrHoldStale) == "" || ErrorKey(ErrHoldPerson) == "" {
		t.Error("the refusals have no key")
	}
	if Explain(i18n.FR, ErrHoldStale) == "" {
		t.Error("no sentence")
	}
}

func secretHit(file string, line int) mask.Hit {
	return mask.Hit{File: file, Line: line, Kind: mask.KindAWSKey}
}
