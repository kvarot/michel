package fix

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

var t0 = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := NewRepo(st)
	r.Now = func() time.Time { return t0 }
	return r
}

func newAttempt(t *testing.T, r *Repo, finding, project, origin string) Attempt {
	t.Helper()
	a, err := r.CreateAttempt(context.Background(), Attempt{FindingID: finding, ProjectID: project, Origin: origin, CloneDir: "/work/x"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAttemptTransitions(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if a.State != StatePreparing || a.ID == "" {
		t.Fatalf("new attempt = %+v", a)
	}
	steps := [][2]State{{StatePreparing, StateProposed}, {StateProposed, StateApproved}, {StateApproved, StateApplied}, {StateApplied, StateProvenFixed}}
	for _, s := range steps {
		if err := r.SetState(ctx, a.ID, []State{s[0]}, s[1], ""); err != nil {
			t.Fatalf("%s -> %s: %v", s[0], s[1], err)
		}
	}
	got, err := r.GetAttempt(ctx, a.ID)
	if err != nil || got.State != StateProvenFixed || got.CloneDir != "/work/x" {
		t.Fatalf("got %+v, %v", got, err)
	}
	b := newAttempt(t, r, "f2", "p1", OriginAgent)
	for _, s := range steps[:3] {
		if err := r.SetState(ctx, b.ID, []State{s[0]}, s[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	err = r.SetState(ctx, b.ID, []State{StateProposed}, StateProposed, "")
	if !errors.Is(err, ErrBadTransition) {
		t.Fatalf("applied -> proposed = %v, want ErrBadTransition", err)
	}
	if err := r.SetState(ctx, "nope", []State{StatePreparing}, StateFailed, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id = %v", err)
	}
	if err := r.SetState(ctx, b.ID, []State{StateApplied}, StateFailed, "boom"); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.GetAttempt(ctx, b.ID); got.Cause != "boom" {
		t.Errorf("cause = %q", got.Cause)
	}
}

func TestAddProposalSupersedesPrevious(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if _, ok, err := r.CurrentProposal(ctx, a.ID); err != nil || ok {
		t.Fatalf("no proposal yet: ok=%v err=%v", ok, err)
	}
	p1, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "one", Diff: "d1", Files: []string{"composer.json"}, Hash: "h1", RescanClean: true, StepsServer: []string{"composer install"}})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "two", Diff: "d2", Hash: "h2"})
	if err != nil {
		t.Fatal(err)
	}
	cur, ok, err := r.CurrentProposal(ctx, a.ID)
	if err != nil || !ok || cur.ID != p2.ID || cur.Superseded || cur.Hash != "h2" {
		t.Fatalf("current = %+v ok=%v err=%v", cur, ok, err)
	}
	all, err := r.Proposals(ctx, a.ID)
	if err != nil || len(all) != 2 {
		t.Fatalf("proposals = %v, %v", all, err)
	}
	if all[0].ID != p1.ID || !all[0].Superseded || !all[0].RescanClean || all[0].Files[0] != "composer.json" || all[0].StepsServer[0] != "composer install" {
		t.Errorf("first = %+v", all[0])
	}
}

func TestQueueOneAttemptPerProject(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	for _, f := range []string{"f1", "f2"} {
		if err := r.Enqueue(ctx, f, "p1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Enqueue(ctx, "f1", "p1"); err != nil { // again: no duplicate
		t.Fatal(err)
	}
	f, p, ok, err := r.NextQueued(ctx)
	if err != nil || !ok || f != "f1" || p != "p1" {
		t.Fatalf("first = %s %s %v %v", f, p, ok, err)
	}
	a := newAttempt(t, r, "f1", "p1", OriginAgentAuto)
	if _, _, ok, _ := r.NextQueued(ctx); ok {
		t.Fatal("the second is returned while the first runs")
	}
	if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, "x"); err != nil {
		t.Fatal(err)
	}
	f, _, ok, err = r.NextQueued(ctx)
	if err != nil || !ok || f != "f2" {
		t.Fatalf("second = %s %v %v", f, ok, err)
	}
	if _, _, ok, _ := r.NextQueued(ctx); ok {
		t.Fatal("queue should be empty")
	}
}

func TestStartedTodayCountsAutoOnly(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	newAttempt(t, r, "f1", "p1", OriginAgentAuto)
	newAttempt(t, r, "f2", "p1", OriginAgentAuto)
	newAttempt(t, r, "f3", "p1", OriginAgent)
	newAttempt(t, r, "f4", "p2", OriginAgentAuto)
	r.Now = func() time.Time { return t0.Add(-48 * time.Hour) }
	newAttempt(t, r, "f5", "p1", OriginAgentAuto)
	n, err := r.StartedToday(ctx, "p1", t0)
	if err != nil || n != 2 {
		t.Fatalf("StartedToday = %d, %v; want 2", n, err)
	}
}

func TestPurgeMessagesOlderThan30Days(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	for i, at := range []time.Time{t0.AddDate(0, 0, -40), t0.AddDate(0, 0, -31), t0.AddDate(0, 0, -1)} {
		if _, err := r.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleUser, Text: "m", At: at}); err != nil {
			t.Fatal(i, err)
		}
	}
	n, err := r.PurgeMessages(ctx, t0.AddDate(0, 0, -30))
	if err != nil || n != 2 {
		t.Fatalf("purged %d, %v", n, err)
	}
	left, err := r.ListMessages(ctx, a.ID)
	if err != nil || len(left) != 1 {
		t.Fatalf("left = %v, %v", left, err)
	}
}
