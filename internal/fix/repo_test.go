package fix

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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
	// One attempt at a time per project: each one ends before the next.
	ended := func(finding, project, origin string) {
		a := newAttempt(t, r, finding, project, origin)
		if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, "x"); err != nil {
			t.Fatal(err)
		}
	}
	ended("f1", "p1", OriginAgentAuto)
	ended("f2", "p1", OriginAgentAuto)
	ended("f3", "p1", OriginAgent)
	ended("f4", "p2", OriginAgentAuto)
	r.Now = func() time.Time { return t0.Add(-48 * time.Hour) }
	ended("f5", "p1", OriginAgentAuto)
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

func TestProposalTreeRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if _, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "one", Hash: "h1", Tree: "abc"}); err != nil {
		t.Fatal(err)
	}
	cur, ok, err := r.CurrentProposal(ctx, a.ID)
	if err != nil || !ok || cur.Tree != "abc" {
		t.Fatalf("current = %+v ok=%v err=%v", cur, ok, err)
	}
}

func TestAddProposalIfCurrentStale(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if _, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "zero", Hash: "h0"}); err != nil {
		t.Fatal(err)
	}
	p1, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "one", Hash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	_, err = r.AddProposalIfCurrent(ctx, Proposal{AttemptID: a.ID, Summary: "tested", Hash: "h2"}, "h0")
	if !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("AddProposalIfCurrent with an old hash: %v, want ErrStaleProposal", err)
	}
	cur, ok, err := r.CurrentProposal(ctx, a.ID)
	if err != nil || !ok || cur.ID != p1.ID || cur.Hash != "h1" {
		t.Fatalf("current = %+v ok=%v err=%v", cur, ok, err)
	}
	if all, _ := r.Proposals(ctx, a.ID); len(all) != 2 {
		t.Errorf("proposals = %d, want 2", len(all))
	}
}

func TestAddProposalIfCurrentSupersedes(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	p1, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Summary: "one", Hash: "h1", Tree: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	p2, err := r.AddProposalIfCurrent(ctx, Proposal{AttemptID: a.ID, Summary: "one", Hash: "h2", Tree: "t1"}, "h1")
	if err != nil {
		t.Fatal(err)
	}
	cur, ok, err := r.CurrentProposal(ctx, a.ID)
	if err != nil || !ok || cur.ID != p2.ID || cur.Hash != "h2" || cur.Tree != "t1" {
		t.Fatalf("current = %+v ok=%v err=%v", cur, ok, err)
	}
	all, _ := r.Proposals(ctx, a.ID)
	if len(all) != 2 || all[0].ID != p1.ID || !all[0].Superseded {
		t.Errorf("proposals = %+v", all)
	}
	// The attempt must still be proposed: an approved attempt takes no new proposal.
	if err := r.Approve(ctx, a.ID, "test", p2.ID, "h2"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddProposalIfCurrent(ctx, Proposal{AttemptID: a.ID, Summary: "x", Hash: "h3"}, "h2"); !errors.Is(err, ErrBadTransition) {
		t.Errorf("on an approved attempt: %v, want ErrBadTransition", err)
	}
}

func attemptEvents(t *testing.T, r *Repo, id string) []string {
	t.Helper()
	rows, err := r.s.DB().Query(`SELECT seq, state, reconstructed FROM fix_attempt_event WHERE attempt_id = ? ORDER BY seq`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	want := 1
	for rows.Next() {
		var seq, rec int
		var state string
		if err := rows.Scan(&seq, &state, &rec); err != nil {
			t.Fatal(err)
		}
		if seq != want || rec != 0 {
			t.Errorf("event %s: seq %d (want %d), reconstructed %d", state, seq, want, rec)
		}
		want++
		out = append(out, state)
	}
	return out
}

func TestAttemptEventsFollowStates(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	p, err := r.AddProposal(ctx, Proposal{AttemptID: a.ID, Hash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, a.ID, "test", p.ID, "h1"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.SetState(ctx, a.ID, []State{StateApplied}, StateProvenFixed, ""); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(attemptEvents(t, r, a.ID), ",")
	if want := "preparing,proposed,approved,applied,proven_fixed"; got != want {
		t.Errorf("events = %s, want %s", got, want)
	}
	b := newAttempt(t, r, "f2", "p2", OriginAgent)
	if err := r.SetState(ctx, b.ID, []State{StatePreparing}, StateApproved, ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.Claim(ctx, b.ID, t0.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	if got := strings.Join(attemptEvents(t, r, b.ID), ","); got != "preparing,approved,running" {
		t.Errorf("events = %s", got)
	}
}

func TestAttemptEventNotWrittenWhenStateKept(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if err := r.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
		t.Fatal(err)
	}
	// the touch of lockProposed and a same-state SetState keep the state
	if err := r.SetState(ctx, a.ID, []State{StateProposed}, StateProposed, "cause"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.DB().Exec(`UPDATE fix_attempt SET updated_at = updated_at WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(attemptEvents(t, r, a.ID), ","); got != "preparing,proposed" {
		t.Errorf("events = %s", got)
	}
	// a stale approval touches the row and fails: no event either
	if err := r.Approve(ctx, a.ID, "test", "nope", "h"); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("approve = %v", err)
	}
	if got := strings.Join(attemptEvents(t, r, a.ID), ","); got != "preparing,proposed" {
		t.Errorf("events after stale approve = %s", got)
	}
}

func TestAttemptEventNotWrittenWhenUpdateMissed(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	a := newAttempt(t, r, "f1", "p1", OriginAgent)
	if err := r.SetState(ctx, a.ID, []State{StateApplied}, StateProvenFixed, ""); !errors.Is(err, ErrBadTransition) {
		t.Fatalf("set state = %v", err)
	}
	if ok, err := r.Claim(ctx, a.ID, t0); err != nil || ok {
		t.Fatalf("claim of a preparing attempt = %v, %v", ok, err)
	}
	if err := r.SetState(ctx, "nope", []State{StatePreparing}, StateFailed, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	if got := strings.Join(attemptEvents(t, r, a.ID), ","); got != "preparing" {
		t.Errorf("events = %s", got)
	}
	if n := len(attemptEvents(t, r, "nope")); n != 0 {
		t.Errorf("events of an unknown attempt = %d", n)
	}
	if _, err := r.CreateAttempt(ctx, Attempt{FindingID: "f2", ProjectID: "p1", Origin: OriginAgent}); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy = %v", err)
	}
	var n int
	if err := r.s.DB().QueryRow(`SELECT COUNT(*) FROM fix_attempt_event`).Scan(&n); err != nil || n != 1 {
		t.Errorf("rows = %d, %v (a busy create writes none)", n, err)
	}
}
