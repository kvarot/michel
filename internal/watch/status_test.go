package watch

import (
	"context"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

// ProjectStatus says the newest scan of any status and the next check from
// the last one that counts, in RFC 3339 UTC.
func TestProjectStatus(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo")
	p := r.projects[0]
	ctx := context.Background()
	repo := NewRepo(r.st)

	st, err := ProjectStatus(ctx, repo, p, policy.Defaults(), r.now)
	if err != nil || st.HasScan || st.LastScanAt != "" || st.NextCheck != at("2026-11-05", "07:00").UTC().Format(time.RFC3339) {
		t.Fatalf("never scanned: %+v %v", st, err)
	}
	for _, row := range [][3]string{{"a", "2026-11-04T06:00:00Z", "ok"}, {"b", "2026-11-05T06:50:00Z", "interrupted"}} {
		if _, err := r.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES (?,?,?,?)`, row[0], p.ID, row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	st, err = ProjectStatus(ctx, repo, p, policy.Defaults(), r.now)
	if err != nil || !st.HasScan || st.LastScanAt != "2026-11-05T06:50:00Z" || st.LastScanStatus != "interrupted" {
		t.Fatalf("last scan: %+v %v", st, err)
	}
	if want := at("2026-11-05", "07:00").UTC().Format(time.RFC3339); st.NextCheck != want {
		t.Errorf("next %q, want %q (the interrupted scan does not count)", st.NextCheck, want)
	}
	p.AutoScan = false
	if st, _ = ProjectStatus(ctx, repo, p, policy.Defaults(), r.now); st.NextCheck != "" {
		t.Errorf("project not watched: next %q", st.NextCheck)
	}
}

// An unreadable stored date is an error, never an empty answer.
func TestProjectStatusUnreadableDateFails(t *testing.T) {
	r := newRig(t, at("2026-11-05", "08:00"), "demo")
	if _, err := r.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES ('a','p0','not a date','ok')`); err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectStatus(context.Background(), NewRepo(r.st), r.projects[0], policy.Defaults(), r.now); err == nil {
		t.Error("an unreadable date was accepted")
	}
}
