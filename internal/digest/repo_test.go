package digest

import (
	"context"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
)

func TestRunRoundTripAndLast(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	if _, ok, err := repo.Last(ctx); ok || err != nil {
		t.Fatalf("Last on an empty table: %v %v", ok, err)
	}
	first := Run{Since: now.Add(-48 * time.Hour), Until: now.Add(-24 * time.Hour), Lang: i18n.FR,
		Projects:  []ProjectSummary{{Name: "demo", New: 2, Gone: 1, Superseded: 1, Due: 3}},
		Summary:   map[string]int{"new_total": 2, "attention_total": 4},
		Channels:  []ChannelResult{{Name: "mail", Type: "email", Result: "error", Error: "connection refused"}},
		CreatedAt: now.Add(-24 * time.Hour)}
	second := Run{Since: now.Add(-24 * time.Hour), Until: now, Lang: i18n.EN, CreatedAt: now}
	for _, r := range []Run{first, second} {
		if err := repo.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	last, ok, err := repo.Last(ctx)
	if err != nil || !ok || last.ID == "" || !last.Until.Equal(now) || last.Lang != i18n.EN ||
		last.Projects == nil || last.Channels == nil || last.Summary == nil {
		t.Errorf("Last = %+v %v %v", last, ok, err)
	}
	all, err := repo.List(ctx, 10)
	if err != nil || len(all) != 2 || all[0].ID != last.ID {
		t.Fatalf("List = %+v %v", all, err)
	}
	got := all[1]
	if got.ID == last.ID || !got.Since.Equal(first.Since) || !got.Until.Equal(first.Until) || got.Lang != i18n.FR ||
		!got.CreatedAt.Equal(first.CreatedAt) || len(got.Projects) != 1 || got.Projects[0] != first.Projects[0] ||
		got.Summary["attention_total"] != 4 || len(got.Channels) != 1 || got.Channels[0] != first.Channels[0] {
		t.Errorf("round trip = %+v", got)
	}
	if one, err := repo.List(ctx, 1); err != nil || len(one) != 1 || one[0].ID != last.ID {
		t.Errorf("List(1) = %+v %v", one, err)
	}
}

func TestClaimIsWonByOneOfTwo(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	seen, err := repo.Newest(ctx)
	if err != nil || seen != "" {
		t.Fatalf("Newest on an empty table: %q %v", seen, err)
	}
	a := Run{ID: "A", Since: now.Add(-24 * time.Hour), Until: now, Lang: i18n.EN, CreatedAt: now}
	b := Run{ID: "B", Since: now.Add(-24 * time.Hour), Until: now, Lang: i18n.EN, CreatedAt: now}
	okA, err := repo.Claim(ctx, a, seen)
	if err != nil || !okA {
		t.Fatalf("first claim: %v %v", okA, err)
	}
	// The second one read the same state before the first wrote.
	if okB, err := repo.Claim(ctx, b, seen); err != nil || okB {
		t.Fatalf("second claim: %v %v", okB, err)
	}
	if n := dbCount(t, f, `SELECT COUNT(*) FROM digest_run`); n != 1 {
		t.Errorf("rows = %d", n)
	}
	// While it is pending, it is not "the last digest sent": the window does not move.
	if _, ok, err := repo.Last(ctx); ok || err != nil {
		t.Errorf("Last sees a pending claim: %v %v", ok, err)
	}
	if list, err := repo.List(ctx, 10); err != nil || len(list) != 0 {
		t.Errorf("List sees a pending claim: %v %v", list, err)
	}
	if busy, err := repo.InFlight(ctx, now.Add(time.Minute)); err != nil || !busy {
		t.Errorf("InFlight = %v %v", busy, err)
	}
	// It is finished once delivered: from then on it is the last one.
	if err := repo.Finish(ctx, "A", []ChannelResult{{Name: "hook", Type: "webhook", Result: "ok"}}); err != nil {
		t.Fatal(err)
	}
	last, ok, err := repo.Last(ctx)
	if err != nil || !ok || last.ID != "A" || last.Pending() || len(last.Channels) != 1 {
		t.Errorf("Last = %+v %v %v", last, ok, err)
	}
	if busy, _ := repo.InFlight(ctx, now.Add(time.Minute)); busy {
		t.Error("a finished claim is still in flight")
	}
}

func TestClaimReleasedWhenNothingWasDelivered(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	if ok, err := repo.Claim(ctx, Run{ID: "A", Until: now, CreatedAt: now, Lang: i18n.EN}, ""); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if err := repo.Release(ctx, "A"); err != nil {
		t.Fatal(err)
	}
	if n := dbCount(t, f, `SELECT COUNT(*) FROM digest_run`); n != 0 {
		t.Errorf("rows = %d", n)
	}
	// Free again for the next attempt.
	if ok, err := repo.Claim(ctx, Run{ID: "B", Until: now, CreatedAt: now, Lang: i18n.EN}, ""); err != nil || !ok {
		t.Errorf("claim after release: %v %v", ok, err)
	}
}

func TestAbandonedClaimIsIgnored(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	sent := Run{ID: "S", Since: now.Add(-48 * time.Hour), Until: now.Add(-24 * time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-24 * time.Hour)}
	if err := repo.Save(ctx, sent); err != nil {
		t.Fatal(err)
	}
	// A process that stopped between the claim and the end of the send.
	if ok, err := repo.Claim(ctx, Run{ID: "Z", Until: now, CreatedAt: now, Lang: i18n.EN}, "S"); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	later := now.Add(PendingTTL + time.Minute)
	if busy, err := repo.InFlight(ctx, later); err != nil || busy {
		t.Errorf("an abandoned claim is in flight: %v %v", busy, err)
	}
	last, ok, _ := repo.Last(ctx)
	if !ok || last.ID != "S" {
		t.Errorf("the window starts after %+v, not after the last digest sent", last)
	}
	seen, _ := repo.Newest(ctx)
	if ok, err := repo.Claim(ctx, Run{ID: "N", Until: later, CreatedAt: later, Lang: i18n.EN}, seen); err != nil || !ok {
		t.Errorf("new claim: %v %v", ok, err)
	}
}

func dbCount(t *testing.T, f *fixture, q string) int {
	t.Helper()
	var n int
	if err := f.st.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
