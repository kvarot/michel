package scan

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// findingEvents returns the kinds of the events of a finding, in order, and
// the details of its events.
func (e env) findingEvents(t *testing.T, id string) (kinds string, details []map[string]any) {
	t.Helper()
	rows, err := e.st.DB().QueryContext(context.Background(), `SELECT kind, detail FROM finding_event WHERE finding_id = ? ORDER BY seq`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ks []string
	for rows.Next() {
		var k, d string
		if err := rows.Scan(&k, &d); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("detail %q: %v", d, err)
		}
		ks, details = append(ks, k), append(details, m)
	}
	return strings.Join(ks, ","), details
}

func TestApplyWritesFindingEvents(t *testing.T) {
	e := newEnv(t)
	f := codeFinding(e.proj.ID, "plugin.semgrep", "php.exec", "src/a.php:12")
	e.applyExternal(t, "plugin.semgrep", "run-1", []Finding{f})
	if kinds, _ := e.findingEvents(t, f.ID); kinds != "seen" {
		t.Fatalf("after the first run: %q", kinds)
	}
	e.applyExternal(t, "plugin.semgrep", "run-2", []Finding{f}) // new -> pending: no event
	e.applyExternal(t, "plugin.semgrep", "run-3", nil)
	if kinds, _ := e.findingEvents(t, f.ID); kinds != "seen,gone" {
		t.Fatalf("after a run without it: %q", kinds)
	}
	e.applyExternal(t, "plugin.semgrep", "run-4", nil) // still gone: no event
	e.applyExternal(t, "plugin.semgrep", "run-5", []Finding{f})
	kinds, details := e.findingEvents(t, f.ID)
	if kinds != "seen,gone,back" {
		t.Fatalf("after it came back: %q", kinds)
	}
	for _, d := range details {
		if len(d) != 0 {
			t.Errorf("detail = %v, want {}", d)
		}
	}
}

// A deferral that has reached its date is superseded by the scan: the
// finding is reopened, with the reason.
func TestApplyWritesReopenedWhenTheScanSupersedes(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	ids := make([]string, 0)
	for osv := range e.statuses(t) {
		ids = append(ids, osv)
	}
	sort.Strings(ids)
	id := e.decideFinding(t, ids[0], "defer", "2026-01-01T00:00:00Z")
	e.run(t)
	kinds, details := e.findingEvents(t, id)
	if kinds != "seen,reopened" || details[1]["reason"] != ReasonDueReached {
		t.Errorf("events = %q %v", kinds, details)
	}
}
