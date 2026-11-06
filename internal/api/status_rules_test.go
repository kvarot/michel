package api

import (
	"net/http"
	"strings"
	"testing"
)

// The page refuses "fix" on an open service like the CLI does: a refused
// decision (400), nothing stored.
func TestDecisionFixRefusedOnExposure(t *testing.T) {
	f := newFixture(t, nil)
	id := f.ids["ACME-2026-0002"]
	if _, err := f.st.DB().Exec(`UPDATE finding SET kind = 'server_exposure' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	resp, b := f.do("POST", "/api/v1/findings/"+id+"/decision?lang=fr", testToken, `{"action":"fix"}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(b, "Michel ne sait pas fermer ce service") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if rows := f.auditRows("decision.set"); len(rows) != 0 {
		t.Errorf("decision.set = %+v", rows)
	}
}

// An unreadable stored scan date is a 500 on the page, not a card with a
// blank date.
func TestProjectsWithUnreadableScanDateFail(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.st.DB().Exec(`INSERT INTO scan (id, project_id, started_at, status) VALUES ('Sbad', ?, 'not a date', 'ok')`, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ := f.do("GET", "/api/v1/projects", testToken, "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d", resp.StatusCode)
	}
}
