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
