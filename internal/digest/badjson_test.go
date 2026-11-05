package digest

import (
	"context"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
)

// A digest run whose stored JSON is damaged is not read as an empty one.
func TestRunWithBadJSONFailsToRead(t *testing.T) {
	for _, col := range []string{"projects", "summary", "channels"} {
		t.Run(col, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			repo := NewRepo(f.st)
			if err := repo.Save(ctx, Run{Since: now, Until: now, Lang: i18n.EN, CreatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.st.DB().Exec(`UPDATE digest_run SET ` + col + ` = '[{'`); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.List(ctx, 10); err == nil {
				t.Errorf("List read a run with damaged %s", col)
			}
		})
	}
}

// Finishing a claim whose summary is damaged fails instead of overwriting it.
func TestFinishWithBadSummaryFails(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := NewRepo(f.st)
	run := Run{ID: "01RUNDEMO", Since: now, Until: now, Lang: i18n.EN, CreatedAt: now}
	if won, err := repo.Claim(ctx, run, ""); err != nil || !won {
		t.Fatalf("Claim = %v %v", won, err)
	}
	if _, err := f.st.DB().Exec(`UPDATE digest_run SET summary = 'nope' WHERE id = '01RUNDEMO'`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Finish(ctx, "01RUNDEMO", nil, true); err == nil {
		t.Error("Finish accepted a damaged summary")
	}
	var sm string
	if err := f.st.DB().QueryRow(`SELECT summary FROM digest_run WHERE id = '01RUNDEMO'`).Scan(&sm); err != nil || sm != "nope" {
		t.Errorf("summary = %q %v", sm, err)
	}
}
