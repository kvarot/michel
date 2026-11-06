package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/history"
	"github.com/kvarot/michel/internal/project"
)

// event writes one finding event in the fixture's store.
func (f *fixture) event(id string, at time.Time, kind string) {
	f.t.Helper()
	tx, err := f.st.DB().Begin()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := history.AddFindingEvent(context.Background(), tx, id, at, kind, nil); err != nil {
		f.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		f.t.Fatal(err)
	}
}

// outsideFindings stores a server finding and a finding of a removed
// project, both seen, and returns their ids.
func (f *fixture) outsideFindings() (server, removed string) {
	f.t.Helper()
	ctx := context.Background()
	server = "fserver000000001"
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, kind)
		VALUES (?, 'T0000000000000000000000001', 'dpkg', 'Debian', 'openssl', 'DSA-1', 'critical', '1.0', 'new', 's1', 's1', ?, ?, 'server_package')`,
		server, ts(now.Add(-time.Hour)), ts(now.Add(-time.Hour))); err != nil {
		f.t.Fatal(err)
	}
	f.event(server, now.Add(-time.Hour), history.KindSeen)
	old, err := project.NewRepo(f.st).Add(ctx, project.Project{Name: "old", Path: f.t.TempDir()})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := project.NewRepo(f.st).Remove(ctx, old.ID); err != nil {
		f.t.Fatal(err)
	}
	removed = "fremoved00000001"
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		VALUES (?, ?, 'composer.lock', 'npm', 'left-pad', 'ACME-9', 'critical', '1.0', 'new', 's1', 's1', ?, ?)`,
		removed, old.ID, ts(now.Add(-time.Hour)), ts(now.Add(-time.Hour))); err != nil {
		f.t.Fatal(err)
	}
	f.event(removed, now.Add(-time.Hour), history.KindSeen)
	return server, removed
}

func TestTimelineRoute(t *testing.T) {
	f := newFixture(t, nil)
	id := f.ids["ACME-2026-0001"]
	f.event(id, now.Add(-2*time.Hour), history.KindSeen)
	f.event(id, now.Add(-time.Hour), history.KindGone)
	var got struct {
		Entries []struct {
			At            string         `json:"at"`
			Kind          string         `json:"kind"`
			Detail        map[string]any `json:"detail"`
			Reconstructed bool           `json:"reconstructed"`
		} `json:"entries"`
		HistoryStart string `json:"history_start"`
	}
	f.get("/api/v1/findings/"+id+"/timeline", &got)
	if len(got.Entries) != 2 || got.Entries[0].Kind != "gone" || got.Entries[1].Kind != "seen" ||
		got.Entries[0].At != ts(now.Add(-time.Hour)) || got.Entries[0].Detail == nil || got.Entries[0].Reconstructed {
		t.Errorf("entries = %+v", got.Entries)
	}
	if _, err := time.Parse(time.RFC3339, got.HistoryStart); err != nil {
		t.Errorf("history_start = %q", got.HistoryStart)
	}
	server, removed := f.outsideFindings()
	for _, other := range []string{server, removed, "nope"} {
		if resp, body := f.do("GET", "/api/v1/findings/"+other+"/timeline", testToken, ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("timeline of %s = %d %s", other, resp.StatusCode, body)
		}
	}
}

func TestStatsOpenRoute(t *testing.T) {
	f := newFixture(t, nil)
	f.event(f.ids["ACME-2026-0001"], now.Add(-30*24*time.Hour), history.KindSeen)
	f.event(f.ids["ACME-2026-0002"], now.Add(-30*24*time.Hour), history.KindSeen)
	f.event(f.ids["ACME-2026-0002"], now.Add(-10*24*time.Hour), history.KindGone)
	f.outsideFindings()
	type answer struct {
		Days []struct {
			Date          string         `json:"date"`
			Open          map[string]int `json:"open"`
			Reconstructed bool           `json:"reconstructed"`
		} `json:"days"`
		HistoryStart string `json:"history_start"`
	}
	var def answer
	f.get("/api/v1/stats/open", &def)
	if len(def.Days) != 90 {
		t.Fatalf("%d days by default", len(def.Days))
	}
	last := def.Days[89]
	if last.Date != now.In(time.Local).Format("2006-01-02") {
		t.Errorf("last day = %s", last.Date)
	}
	want := map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0}
	if len(last.Open) != len(want) {
		t.Errorf("open = %v, want %v", last.Open, want)
	}
	for k, v := range want {
		if n, ok := last.Open[k]; !ok || n != v {
			t.Errorf("open = %v, want %v", last.Open, want)
		}
	}
	if _, err := time.Parse(time.RFC3339, def.HistoryStart); err != nil {
		t.Errorf("history_start = %q", def.HistoryStart)
	}
	var year answer
	f.get("/api/v1/stats/open?days=365", &year)
	if len(year.Days) != 365 {
		t.Errorf("%d days for days=365", len(year.Days))
	}
	for _, bad := range []string{"0", "366", "-1", "abc", "1.5"} {
		if resp, body := f.do("GET", "/api/v1/stats/open?days="+bad, testToken, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("days=%s = %d %s", bad, resp.StatusCode, body)
		}
	}
}

// today is the local date of the fixture's now, moved by days.
func today(days int) string {
	y, m, d := now.In(time.Local).Date()
	return time.Date(y, m, d+days, 0, 0, 0, 0, time.Local).Format("2006-01-02")
}

func TestReportsRefusesFuture(t *testing.T) {
	f := newFixture(t, nil)
	if resp, body := f.do("GET", "/api/v1/reports?from="+today(1)+"&to="+today(7), testToken, ""); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(body, "Michel cannot read this period") {
		t.Errorf("a period after today = %d %s", resp.StatusCode, body)
	}
	// the current week, ending after today, is accepted.
	var got struct {
		From      string         `json:"from"`
		To        string         `json:"to"`
		Found     map[string]int `json:"found"`
		OpenEnd   map[string]int `json:"open_end"`
		Decisions map[string]int `json:"decisions"`
		Checks    struct {
			Projects struct{ Done, Failed int } `json:"projects"`
			Servers  struct {
				Done   int  `json:"done"`
				Failed *int `json:"failed"`
			} `json:"servers"`
		} `json:"checks"`
		Projects []struct {
			Name string `json:"name"`
		} `json:"projects"`
	}
	f.get("/api/v1/reports?from="+today(0)+"&to="+today(6), &got)
	if got.From != today(0) || got.To != today(6) {
		t.Errorf("period = %s..%s", got.From, got.To)
	}
	for _, sev := range severities {
		if _, ok := got.Found[sev]; !ok {
			t.Errorf("found = %v, missing %s", got.Found, sev)
		}
		if _, ok := got.OpenEnd[sev]; !ok {
			t.Errorf("open_end = %v, missing %s", got.OpenEnd, sev)
		}
	}
	for _, a := range []string{"fix", "defer", "ignore"} {
		if _, ok := got.Decisions[a]; !ok {
			t.Errorf("decisions = %v, missing %s", got.Decisions, a)
		}
	}
	if got.Checks.Projects.Done != 1 || got.Checks.Servers.Failed != nil {
		t.Errorf("checks = %+v", got.Checks)
	}
	if len(got.Projects) != 1 || got.Projects[0].Name != "demo" {
		t.Errorf("projects = %+v", got.Projects)
	}
}

func TestReportsRefusesBadRange(t *testing.T) {
	f := newFixture(t, nil)
	for _, q := range []string{"", "from=" + today(-3), "to=" + today(0), "from=abc&to=" + today(0), "from=2026-1-05&to=" + today(0),
		"from=2026-02-30&to=2026-03-02", "from=" + today(0) + "&to=" + today(-1), "from=" + today(-62) + "&to=" + today(0),
		"from=" + today(-3) + "%20&to=" + today(0)} {
		if resp, body := f.do("GET", "/api/v1/reports?"+q, testToken, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s", q, resp.StatusCode, body)
		}
	}
	f.get("/api/v1/reports?from="+today(-61)+"&to="+today(0), nil)
}

func TestReportNoPathOrSecret(t *testing.T) {
	f := newFixture(t, nil)
	id := f.ids["ACME-2026-0001"]
	f.event(id, now.Add(-2*time.Hour), history.KindSeen)
	f.event(f.ids["ACME-2026-0002"], now.Add(-3*time.Hour), history.KindSeen)
	f.event(f.ids["ACME-2026-0002"], now.Add(-time.Hour), history.KindGone)
	f.outsideFindings()
	body := f.get("/api/v1/reports?from="+today(-6)+"&to="+today(0), nil)
	for _, leak := range []string{f.proj.Path, f.dir, filepath.ToSlash(f.proj.Path), filepath.ToSlash(f.dir), testToken, `\`} {
		if strings.Contains(body, leak) {
			t.Errorf("the report holds %q:\n%s", leak, body)
		}
	}
	if !strings.Contains(body, `"package":"acme/vuln"`) {
		t.Errorf("the oldest open finding is missing:\n%s", body)
	}
}
