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
	seen, err := repo.Newest(ctx, now)
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
	if err := repo.Finish(ctx, "A", []ChannelResult{{Name: "hook", Type: "webhook", Result: "ok"}}, false); err != nil {
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
	seen, _ := repo.Newest(ctx, now)
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

func TestExpiredClaimsArePurgedAndDoNotHideTheLastRun(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	sent := Run{ID: "S", Until: now.Add(-48 * time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-48 * time.Hour),
		Channels: []ChannelResult{{Name: "hook", Type: "webhook", Result: "ok"}}}
	if err := repo.Save(ctx, sent); err != nil {
		t.Fatal(err)
	}
	// Thirty claims of processes that died, one after the other.
	seen := "S"
	for i := 0; i < 30; i++ {
		at := now.Add(-time.Duration(40-i) * time.Hour)
		id := string(rune('a' + i))
		if ok, err := repo.Claim(ctx, Run{ID: id, Until: at, Lang: i18n.EN, CreatedAt: at}, seen); err != nil || !ok {
			t.Fatalf("claim %d: %v %v", i, ok, err)
		}
		seen = id
	}
	if _, err := repo.Newest(ctx, now); err != nil {
		t.Fatal(err)
	}
	if n := dbCount(t, f, `SELECT COUNT(*) FROM digest_run`); n != 1 {
		t.Errorf("rows after the purge = %d", n)
	}
	if last, ok, _ := repo.Last(ctx); !ok || last.ID != "S" {
		t.Errorf("last = %+v", last)
	}
}

func TestLastDeliveredIgnoresARunNobodyGot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	ok := Run{ID: "A", Until: now.Add(-48 * time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-48 * time.Hour),
		Channels: []ChannelResult{{Name: "hook", Type: "webhook", Result: "ok"}}}
	failed := Run{ID: "B", Until: now.Add(-time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-time.Hour),
		Channels: []ChannelResult{{Name: "mail", Type: "email", Result: "error"}}}
	for _, r := range []Run{ok, failed} {
		if err := repo.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if last, _, _ := repo.Last(ctx); last.ID != "B" {
		t.Errorf("the window starts after the last run, whatever happened: %q", last.ID)
	}
	if last, has, _ := repo.LastDelivered(ctx); !has || last.ID != "A" {
		t.Errorf("last delivered = %+v", last)
	}
}

func TestFirstWindowStartIsKept(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	if _, has, err := repo.HeldStart(ctx); has || err != nil {
		t.Fatalf("held start on a new store: %v %v", has, err)
	}
	if err := repo.HoldStart(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := repo.HoldStart(ctx, now.Add(time.Hour)); err != nil { // a later attempt does not move it
		t.Fatal(err)
	}
	got, has, err := repo.HeldStart(ctx)
	if err != nil || !has || !got.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("held start = %v %v %v", got, has, err)
	}
	// Compute starts there when no digest was sent, 30 hours later too.
	d, err := Compute(ctx, f.st, now.Add(30*time.Hour), i18n.EN, Options{})
	if err != nil || !d.Since.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("since = %v %v", d.Since, err)
	}
}
