package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// findingByOSV returns the id of the finding of list with that advisory id.
func findingByOSV(t *testing.T, dir, osvID string) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var id string
	if err := s.DB().QueryRow(`SELECT id FROM finding WHERE osv_id = ?`, osvID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func findingStatusIn(t *testing.T, dir, id string) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var status string
	if err := s.DB().QueryRow(`SELECT status FROM finding WHERE id = ?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestDecideIgnoreWithoutWhyRefused(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	id := findingByOSV(t, dir, "ACME-2026-0002")
	_, _, _, err := run(t, dir, "--lang", "en", "decide", id, "ignore")
	if err == nil || !strings.Contains(err.Error(), "Ignoring a finding needs a reason") || !strings.Contains(err.Error(), "--why") {
		t.Errorf("en: %v", err)
	}
	_, _, _, err = run(t, dir, "--lang", "fr", "decide", id, "ignore", "--why", "   ")
	if err == nil || !strings.Contains(err.Error(), "Pour ignorer une faille, donne une raison") || !strings.Contains(err.Error(), "--why") {
		t.Errorf("fr: %v", err)
	}
	if s := findingStatusIn(t, dir, id); s != "new" {
		t.Errorf("status = %s", s)
	}
	if rows := auditRows(t, dir, "decision.set"); len(rows) != 0 {
		t.Errorf("decision.set = %+v", rows)
	}
	_, out, _, err := run(t, dir, "decide", id[:12], "ignore", "--why", "only used by a dev tool")
	if err != nil || out != fmt.Sprintf("Ignored acme/vuln (ACME-2026-0002) in demo: only used by a dev tool.\naudit event %s\n", lastEventID(t, dir, "decision.set")) {
		t.Errorf("ignore with why: %v %q", err, out)
	}
}

// lastEventID returns the id of the last audit event with that action.
func lastEventID(t *testing.T, dir, action string) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var id string
	_ = s.DB().QueryRow(`SELECT id FROM audit_event WHERE action = ? ORDER BY id DESC LIMIT 1`, action).Scan(&id)
	return id
}

func TestDecideDeferDefaultShowsDate(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	id := findingByOSV(t, dir, "ACME-2026-0002")
	due := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	_, out, _, err := run(t, dir, "--lang", "en", "decide", id, "defer")
	if err != nil || !strings.Contains(out, "Decided defer for acme/vuln (ACME-2026-0002) in demo. Deferred until "+due+" (30 days by default).\naudit event ") {
		t.Errorf("en: %v %q", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "decide", id, "defer")
	if err != nil || !strings.Contains(out, "Reportée au "+due+" (30 jours par défaut).") {
		t.Errorf("fr: %v %q", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "decide", id, "defer", "--until", "2099-12-01")
	if err != nil || !strings.Contains(out, "Deferred until 2099-12-01.") || strings.Contains(out, "by default") {
		t.Errorf("--until: %v %q", err, out)
	}
	in7 := time.Now().UTC().Add(7 * 24 * time.Hour).Format("2006-01-02")
	_, out, _, err = run(t, dir, "--lang", "en", "decide", id, "defer", "--for", "7d")
	if err != nil || !strings.Contains(out, "Deferred until "+in7+".") {
		t.Errorf("--for: %v %q", err, out)
	}
	rows := auditRows(t, dir, "decision.set")
	if len(rows) != 4 || rows[3].evidence["due_at"] == "" || rows[2].evidence["due_at"] != "2099-12-01T00:00:00Z" {
		t.Errorf("decision.set = %+v", rows)
	}
	if sup := auditRows(t, dir, "decision.superseded"); len(sup) != 3 || sup[0].evidence["reason"] != "redecided" || sup[0].evidence["previous_action"] != "defer" {
		t.Errorf("decision.superseded = %+v", sup)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"decide", id, "defer", "--until", "2001-01-01"}, "is not in the future"},
		{[]string{"decide", id, "defer", "--until", "01/12/2099"}, "Write it as YYYY-MM-DD"},
		{[]string{"decide", id, "defer", "--for", "0d"}, "number of days followed by d"},
		{[]string{"decide", id, "defer", "--for", "2w"}, "number of days followed by d"},
		{[]string{"decide", id, "defer", "--for", "7d", "--until", "2099-12-01"}, "not both"},
		{[]string{"decide", id, "fix", "--for", "7d"}, "only apply to defer"},
		{[]string{"decide", id, "later"}, "Unknown action \"later\""},
		{[]string{"decide", id}, "Michel needs a finding and an action"},
		{[]string{"decide", "--package", "acme/vuln", "fix"}, "--package needs --project"},
		{[]string{"decide", "--project", "demo", "fix"}, "Michel needs a finding and an action"},
		{[]string{"decide", "ZZZZ", "fix"}, "No finding has the id"},
		{[]string{"decide", id, "fix", "--why", strings.Repeat("a", 1001)}, "too long (1001 characters, at most 1000)"},
	} {
		if _, _, _, err := run(t, dir, append([]string{"--lang", "en"}, c.args...)...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	if rows := auditRows(t, dir, "decision.set"); len(rows) != 4 {
		t.Errorf("a refused decision was audited: %d rows", len(rows))
	}
}

func TestDecideByPackage(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	_, out, _, err := run(t, dir, "--lang", "en", "decide", "--project", "demo", "--package", "acme/vuln", "fix", "--verbose")
	if err != nil || !strings.HasPrefix(out, "Decided fix for 2 findings of acme/vuln in demo.\n") ||
		!strings.Contains(out, "ACME-2026-0001: audit event ") || !strings.Contains(out, "ACME-2026-0002: audit event ") {
		t.Fatalf("by package: %v %q", err, out)
	}
	if rows := auditRows(t, dir, "decision.set"); len(rows) != 2 || rows[0].evidence["package"] != "acme/vuln" {
		t.Errorf("decision.set = %+v", rows)
	}
	_, out, _, err = run(t, dir, "findings", "--project", "demo", "--status", "decided")
	if err != nil || strings.Count(out, "acme/vuln") != 2 || strings.Contains(out, "vuln-pkg") {
		t.Errorf("findings --status decided: %v\n%s", err, out)
	}
	_, _, _, err = run(t, dir, "--lang", "en", "decide", "--project", "demo", "--package", "acme/vuln", "defer")
	if err == nil || !strings.Contains(err.Error(), "No finding of acme/vuln in demo waits for a decision") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("already decided: %v", err)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "decide", "--project", "demo", "--package", "acme/vuln", "defer", "--force", "--for", "10d")
	if err != nil || !strings.HasPrefix(out, "2 failles de acme/vuln décidées (reportées jusqu'au ") || !strings.Contains(out, " dans demo. Journal d'audit : ") ||
		strings.Count(out, "\n") != 1 {
		t.Errorf("--force: %v %q", err, out)
	}
	_, _, _, err = run(t, dir, "--lang", "en", "decide", "--project", "nope", "--package", "acme/vuln", "fix")
	if err == nil || !strings.Contains(err.Error(), "no project has this name") {
		t.Errorf("unknown project: %v", err)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "decide", "--project", "demo", "--package", "vuln-pkg", "fix")
	if err != nil || !strings.HasPrefix(out, "1 finding of vuln-pkg decided (fix) in demo; audit: ") || strings.Contains(out, "→") {
		t.Errorf("one finding: %v %q", err, out)
	}
}

func TestDecisionsTableAndJSON(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	ignored := findingByOSV(t, dir, "ACME-2026-0002")
	fixed := findingByOSV(t, dir, "ACME-2026-0001")
	if _, _, _, err := run(t, dir, "decide", fixed, "defer", "--until", "2099-12-01"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "decide", fixed, "fix"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "decide", ignored, "ignore", "--why", "dev tool only\x1b[2J\nnot shipped"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err := run(t, dir, "decisions", "--project", "demo")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != "package osv_id action due author decided_at why" {
		t.Fatalf("table:\n%s", out)
	}
	if !strings.Contains(lines[1], "ACME-2026-0002") || !strings.Contains(lines[1], "ignore") || !strings.Contains(lines[1], "dev tool only[2J not shipped") ||
		!strings.Contains(lines[2], "ACME-2026-0001") || !strings.Contains(lines[2], " fix ") || strings.Contains(out, "\x1b") {
		t.Errorf("rows:\n%s", out)
	}
	_, out, _, err = run(t, dir, "decisions", "--project", "demo", "--status", "superseded")
	if err != nil || !strings.Contains(out, "2099-12-01") || !strings.Contains(out, "defer") || !strings.Contains(out, "redecided") {
		t.Errorf("superseded:\n%s %v", out, err)
	}
	_, out, _, err = run(t, dir, "decisions", "--project", "demo", "--status", "all", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil || len(docs) != 3 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	for _, k := range []string{"id", "finding_id", "project_id", "action", "justification", "due_at", "author", "created_at",
		"seen_severity", "seen_fixed_versions", "superseded_at", "superseded_reason"} {
		if _, ok := docs[0][k]; !ok {
			t.Errorf("json lacks %q: %v", k, docs[0])
		}
	}
	if docs[0]["action"] != "ignore" || docs[0]["due_at"] != "" || docs[0]["author"] != "cli" || docs[2]["superseded_reason"] != "redecided" {
		t.Errorf("json = %s", out)
	}
	_, out, _, err = run(t, dir, "decisions", "--project", "demo", "--status", "fix")
	if err != nil || strings.Count(out, "\n") != 2 || !strings.Contains(out, "ACME-2026-0001") {
		t.Errorf("--status fix:\n%s %v", out, err)
	}
	_, _, _, err = run(t, dir, "--lang", "en", "decisions", "--project", "demo", "--status", "later")
	if err == nil || !strings.Contains(err.Error(), "Unknown status \"later\"") {
		t.Errorf("bad status: %v", err)
	}
	_, out, _, err = run(t, dir, "--lang", "en", "decisions", "--project", "demo", "--status", "defer")
	if err != nil || !strings.HasPrefix(out, "No decisions to show for demo.") {
		t.Errorf("none: %v %q", err, out)
	}
	_, _, _, err = run(t, dir, "--lang", "en", "decisions")
	if err == nil || !strings.Contains(err.Error(), "--project") {
		t.Errorf("no project: %v", err)
	}

	// findings shows the decision in force.
	_, out, _, err = run(t, dir, "findings", "--project", "demo")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if head[len(head)-1] != "decision" {
		t.Errorf("findings header: %v", head)
	}
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n")[1:] {
		f := strings.Fields(l)
		last := f[len(f)-1]
		switch {
		case strings.Contains(l, "ACME-2026-0001") && last != "fix",
			strings.Contains(l, "ACME-2026-0002") && last != "ignore",
			strings.Contains(l, "ACME-2026-0101") && last != "-":
			t.Errorf("findings row: %q", l)
		}
	}
	_, out, _, err = run(t, dir, "findings", "--project", "demo", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		OSVID    string         `json:"osv_id"`
		Package  string         `json:"package"`
		Decision map[string]any `json:"decision"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 3 {
		t.Fatalf("findings json: %v\n%s", err, out)
	}
	for _, r := range rows {
		switch r.OSVID {
		case "ACME-2026-0001":
			if r.Decision == nil || r.Decision["action"] != "fix" {
				t.Errorf("%s decision = %v", r.OSVID, r.Decision)
			}
		case "ACME-2026-0101":
			if r.Decision != nil || r.Package == "" {
				t.Errorf("%s decision = %v", r.OSVID, r.Decision)
			}
		}
	}
	if !strings.Contains(out, `"decision":null`) {
		t.Errorf("an undecided finding should have a null decision:\n%s", out)
	}
}

func TestDecideIsAuditedWithoutCode(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	path := copyProject(t, "project-a")
	if _, _, _, err := run(t, dir, "project", "add", path, "--name", "demo", "--test-cmd", "make test"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze"); err != nil {
		t.Fatal(err)
	}
	id := findingByOSV(t, dir, "ACME-2026-0002")
	if _, _, _, err := run(t, dir, "decide", id, "ignore", "--why", "dev only"); err != nil {
		t.Fatal(err)
	}
	rows := auditRows(t, dir, "decision.set")
	if len(rows) != 1 {
		t.Fatalf("decision.set = %+v", rows)
	}
	r := rows[0]
	want := map[string]any{"finding_id": id, "action": "ignore", "due_at": "", "author": "cli", "justification": "dev only",
		"package": "acme/vuln", "osv_id": "ACME-2026-0002"}
	for k, v := range want {
		if r.evidence[k] != v {
			t.Errorf("evidence[%s] = %v, want %v", k, r.evidence[k], v)
		}
	}
	if r.evidence["project_id"] == nil || r.evidence["project_id"] == "" || len(r.evidence) != 8 || r.target != id || r.result != "ok" {
		t.Errorf("event = %+v", r)
	}
	raw, _ := json.Marshal(r.evidence)
	for _, banned := range []string{"make test", filepath.ToSlash(path), strings.ReplaceAll(path, `\`, `\\`), "composer.lock"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("evidence contains %q: %s", banned, raw)
		}
	}
}

// cliTreeDigest is the SHA-256 of every path, size and modification time
// under root (the same as treeDigest in the scan tests).
func cliTreeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%v\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), info.Mode())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestDecideNeverWritesUnderProject(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	path := copyProject(t, "project-a")
	if _, _, _, err := run(t, dir, "project", "add", path, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze"); err != nil {
		t.Fatal(err)
	}
	before := cliTreeDigest(t, path)
	id := findingByOSV(t, dir, "ACME-2026-0001")
	for _, args := range [][]string{
		{"decide", id, "ignore", "--why", "x"},
		{"decide", id, "defer"},
		{"decide", "--project", "demo", "--package", "acme/vuln", "fix", "--force"},
		{"decisions", "--project", "demo", "--status", "all"},
	} {
		if _, _, _, err := run(t, dir, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--osv-db", db, "--no-analyze"); err != nil {
		t.Fatal(err)
	}
	if after := cliTreeDigest(t, path); after != before {
		t.Error("the project folder changed")
	}
	if _, err := os.Stat(filepath.Join(path, "osv-scanner.toml")); !os.IsNotExist(err) {
		t.Errorf("osv-scanner.toml was written: %v", err)
	}
}

// addFindings copies the finding with osvID n times under new ids and
// advisory ids, so a package carries many findings.
func addFindings(t *testing.T, dir, osvID string, n int) {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	db.SetMaxOpenConns(1) // the temporary table lives on one connection
	if _, err := db.Exec(`CREATE TEMP TABLE f AS SELECT * FROM finding WHERE osv_id = ?`, osvID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`UPDATE f SET id = ?, osv_id = ?`, fmt.Sprintf("01TESTFINDING%013d", i), fmt.Sprintf("ACME-2026-9%03d", i)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO finding SELECT * FROM f`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecidePackagePrintsOneSummaryLine(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	addFindings(t, dir, "ACME-2026-0001", 57) // acme/vuln: 2 + 57 findings
	_, out, _, err := run(t, dir, "--lang", "en", "decide", "--project", "demo", "--package", "acme/vuln", "defer", "--until", "2099-11-25")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if err != nil || len(lines) != 1 || !strings.Contains(lines[0], "59") || !strings.Contains(lines[0], "acme/vuln") ||
		!strings.Contains(lines[0], "2099-11-25") || !strings.Contains(lines[0], "→") {
		t.Fatalf("summary: %v %q", err, out)
	}
	_, out, _, err = run(t, dir, "--lang", "fr", "decide", "--project", "demo", "--package", "acme/vuln", "fix", "--force", "--verbose")
	lines = strings.Split(strings.TrimRight(out, "\n"), "\n")
	items := 0
	for _, l := range lines {
		if strings.Contains(l, "journal d'audit") {
			items++
		}
	}
	if err != nil || items != 59 {
		t.Errorf("--verbose: %v, %d item lines\n%s", err, items, out)
	}
}
