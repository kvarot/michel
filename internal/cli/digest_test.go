package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

type digestRunRow struct{ id, since, until, lang, projects, summary, channels string }

func digestRuns(t *testing.T, dir string) []digestRunRow {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT id, since, until, lang, projects, summary, channels FROM digest_run ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []digestRunRow
	for rows.Next() {
		var r digestRunRow
		if err := rows.Scan(&r.id, &r.since, &r.until, &r.lang, &r.projects, &r.summary, &r.channels); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// statuses returns "id=status" of every finding, sorted by id.
func statuses(t *testing.T, dir string) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT id, status, status_changed_at FROM finding ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, st, at string
		if err := rows.Scan(&id, &st, &at); err != nil {
			t.Fatal(err)
		}
		b.WriteString(id + "=" + st + "@" + at + "\n")
	}
	return b.String()
}

func TestDigestPrintsTextByDefault(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	before := statuses(t, dir)
	_, out, _, err := run(t, dir, "--lang", "en", "digest")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Michel found 3 new findings since the last digest, 2 need your attention\n") || !strings.Contains(out, "== demo ==") ||
		!strings.Contains(out, "[critical] acme/vuln 1.0.0 → 1.0.1 (2 advisories: ACME-2026-0001, ACME-2026-0002)") {
		t.Errorf("text:\n%s", out)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "digest")
	if err != nil || !strings.HasPrefix(out, "Michel a trouvé 3 nouveautés depuis le dernier résumé, 2 méritent ton attention\n") {
		t.Errorf("fr: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "digest", "--json")
	var doc map[string]any
	if err != nil || json.Unmarshal([]byte(out), &doc) != nil || doc["michel_digest"] != float64(1) || doc["new_total"] != float64(3) {
		t.Errorf("json: %v\n%s", err, out)
	}
	_, out, _, err = run(t, dir, "digest", "--html")
	if err != nil || !strings.Contains(out, "<h1>") || strings.Contains(out, "<script") {
		t.Errorf("html: %v\n%s", err, out)
	}
	if _, _, _, err := run(t, dir, "--lang", "en", "digest", "--json", "--html"); err == nil || !strings.Contains(err.Error(), "--json or --html") {
		t.Errorf("--json --html: %v", err)
	}
	if after := statuses(t, dir); after != before {
		t.Errorf("digest changed statuses:\n%s\n%s", before, after)
	}
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Errorf("digest without --send saved %d runs", len(runs))
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 0 {
		t.Errorf("digest.run = %+v", rows)
	}
}

func TestDigestSendRecordsRunAndAudit(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	_, out, _, err := run(t, dir, "--lang", "en", "digest", "--send")
	if err != nil || !strings.HasPrefix(out, "Michel found 3 new findings since the last digest") {
		t.Fatalf("send: %v\n%s", err, out)
	}
	runs := digestRuns(t, dir)
	if len(runs) != 1 || runs[0].lang != "en" || runs[0].channels != "[]" || !strings.Contains(runs[0].projects, `"name":"demo"`) ||
		!strings.Contains(runs[0].summary, `"new_total":3`) {
		t.Fatalf("runs = %+v", runs)
	}
	rows := auditRows(t, dir, "digest.run")
	if len(rows) != 1 || rows[0].result != "ok" || rows[0].target != runs[0].id {
		t.Fatalf("digest.run = %+v", rows)
	}
	ev := rows[0].evidence
	if ev["run_id"] != runs[0].id || ev["since"] != runs[0].since || ev["until"] != runs[0].until || ev["projects"] != float64(1) ||
		ev["new_total"] != float64(3) || ev["attention_total"] != float64(2) {
		t.Errorf("evidence = %v", ev)
	}
	if ch, ok := ev["channels"].([]any); !ok || len(ch) != 0 {
		t.Errorf("channels = %#v", ev["channels"])
	}
	// The next digest starts where the last one ended.
	_, out, _, err = run(t, dir, "--lang", "en", "digest", "--send")
	if err != nil || !strings.HasPrefix(out, "Michel found nothing new since the last digest") {
		t.Errorf("second send: %v\n%s", err, out)
	}
	runs = digestRuns(t, dir)
	if len(runs) != 2 || runs[1].since != runs[0].until {
		t.Errorf("runs = %+v", runs)
	}
}

func TestDigestSendExpiresDue(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	id := findingByOSV(t, dir, "ACME-2026-0002")
	if _, _, _, err := run(t, dir, "decide", id, "defer"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := s.DB().Exec(`UPDATE decision SET due_at = ? WHERE finding_id = ? AND superseded_at = ''`, past, id); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, out, _, err := run(t, dir, "--lang", "en", "digest")
	if err != nil || !strings.Contains(out, "acme/vuln ACME-2026-0002: deferred until ") || !strings.Contains(out, "(overdue)") {
		t.Errorf("digest: %v\n%s", err, out)
	}
	if st := findingStatusIn(t, dir, id); st != "decided" {
		t.Errorf("digest without --send changed the status to %s", st)
	}
	if _, _, _, err := run(t, dir, "--lang", "en", "digest", "--send"); err != nil {
		t.Fatal(err)
	}
	if st := findingStatusIn(t, dir, id); st != "pending" {
		t.Errorf("status = %s", st)
	}
	var due []auditRow
	for _, r := range auditRows(t, dir, "decision.superseded") {
		if r.evidence["reason"] == "due_reached" {
			due = append(due, r)
		}
	}
	if len(due) != 1 || due[0].target != id || due[0].evidence["previous_action"] != "defer" {
		t.Errorf("decision.superseded = %+v", due)
	}
}

func TestDigestSendSinceOverride(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	if _, _, _, err := run(t, dir, "--lang", "en", "digest", "--since", "01/10/2026"); err == nil || !strings.Contains(err.Error(), "YYYY-MM-DD") {
		t.Errorf("bad --since: %v", err)
	}
	if _, _, _, err := run(t, dir, "--lang", "en", "digest", "--send", "--since", "2026-10-01"); err != nil {
		t.Fatal(err)
	}
	runs := digestRuns(t, dir)
	if len(runs) != 1 || runs[0].since != "2026-10-01T00:00:00Z" {
		t.Fatalf("runs = %+v", runs)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 1 || rows[0].evidence["since"] != "2026-10-01T00:00:00Z" {
		t.Errorf("digest.run = %+v", rows)
	}
}

func TestScanAllDigestChains(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "--lang", "en", "scan", "--project", "demo", "--digest", "--osv-db", db); err == nil || !strings.Contains(err.Error(), "--all") {
		t.Errorf("--digest without --all: %v", err)
	}
	if _, _, _, err := run(t, dir, "scan", "--all", "--no-analyze", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 0 {
		t.Errorf("digest.run without --digest = %+v", rows)
	}
	_, out, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
	if err != nil || !strings.Contains(out, "== demo ==") {
		t.Fatalf("scan --all --digest: %v\n%s", err, out)
	}
	rows := auditRows(t, dir, "digest.run")
	if len(rows) != 1 || len(digestRuns(t, dir)) != 1 {
		t.Errorf("digest.run = %+v", rows)
	}
	finish := auditRows(t, dir, "scan.finish")
	if len(finish) != 2 || lastEventID(t, dir, "digest.run") < lastEventID(t, dir, "scan.finish") {
		t.Errorf("the digest did not follow the scan")
	}
}

func TestDigestNeverWritesUnderProject(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	proj := copyProject(t, "project-a")
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--all", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	before := cliTreeDigest(t, proj)
	for _, args := range [][]string{{"digest"}, {"digest", "--json"}, {"digest", "--html"}, {"digest", "--send"},
		{"scan", "--all", "--digest", "--osv-db", db}} {
		if _, _, _, err := run(t, dir, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if after := cliTreeDigest(t, proj); after != before {
		t.Error("digest wrote under the project folder")
	}
}
