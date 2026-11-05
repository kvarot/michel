package decide

import (
	"context"
	"testing"

	"github.com/kvarot/michel/internal/scan"
)

// A decision whose stored JSON is damaged is not read as one with no fixed
// version: the read fails.
func TestDecisionWithBadJSONFailsToRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seedFinding(t, f.proj.ID, "f1", scan.StatusPending, "high", "1.2.5")
	if _, err := f.repo.Set(ctx, Decision{FindingID: "f1", Action: Fix, Author: "cli"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE decision SET seen_fixed_versions = '[not json'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.repo.Current(ctx, "f1"); err == nil {
		t.Error("Current read a decision with damaged JSON")
	}
	if _, err := f.repo.List(ctx, f.proj.ID, ""); err == nil {
		t.Error("List read a decision with damaged JSON")
	}
}

// A finding whose fixed versions are damaged is not decided on.
func TestSetWithBadFixedVersionsFails(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, f.proj.ID, "f1", scan.StatusPending, "high")
	if _, err := f.st.DB().Exec(`UPDATE finding SET fixed_versions = '{' WHERE id = 'f1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Set(context.Background(), Decision{FindingID: "f1", Action: Fix, Author: "cli"}, now); err == nil {
		t.Error("Set stored a decision on a finding with damaged JSON")
	}
	if s, _ := f.findingStatus(t, "f1"); s != scan.StatusPending {
		t.Errorf("finding is %s", s)
	}
}
