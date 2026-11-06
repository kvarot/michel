package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAppliesMigrationsIdempotently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "michel.db")
	for i := 0; i < 2; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 29 {
			t.Fatalf("schema_migrations rows = %d, err %v", n, err)
		}
		var mode string
		if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode = %q, err %v", mode, err)
		}
		var fk int
		if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys = %d, err %v", fk, err)
		}
		for _, tbl := range []string{"audit_event", "project", "scan", "scan_manifest", "finding"} {
			if _, err := s.DB().Exec(`SELECT 1 FROM ` + tbl + ` LIMIT 1`); err != nil {
				t.Errorf("table %s: %v", tbl, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrationAppliedByAnotherProcessMeanwhileIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	// Another process applies the migrations between this process's
	// "already applied?" check and its transaction.
	beforeMigrationTx = func() {
		beforeMigrationTx = nil
		other, err := Open(path)
		if err != nil {
			t.Errorf("other process: %v", err)
			return
		}
		other.Close()
	}
	t.Cleanup(func() { beforeMigrationTx = nil })
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open after a concurrent migration: %v", err)
	}
	defer s.Close()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 29 {
		t.Fatalf("schema_migrations rows = %d err %v", n, err)
	}
}

func TestOpenErrorDoesNotAdviseDeletingTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "michel.db")
	if err := os.WriteFile(path, []byte("this is not a SQLite database, just enough bytes to look like a damaged file....."), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("expected an error on a damaged file")
	}
	msg := err.Error()
	if strings.Contains(msg, "move it aside") || strings.Contains(msg, "start fresh") ||
		!strings.Contains(msg, "restore it from a backup; Michel never deletes it for you") {
		t.Errorf("message = %q", msg)
	}
}

func TestMigration0002Applies(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	have := map[string]bool{}
	rows, err := s.DB().Query(`PRAGMA table_info(project)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range []string{"core_packages", "risk_overrides"} {
		if !have[c] {
			t.Errorf("project.%s missing", c)
		}
	}
	if _, err := s.DB().Exec(`SELECT finding_id, risk_score, recommendation, warning FROM analysis LIMIT 1`); err != nil {
		t.Errorf("analysis table: %v", err)
	}
}

func TestMigration0002UpgradesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	db, err := sql.Open("sqlite", "file:///"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	body, err := migrationFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		string(body),
		`INSERT INTO schema_migrations VALUES (1, '2026-01-01T00:00:00Z')`,
		`INSERT INTO project (id, name, source_type, path, classification, created_at) VALUES ('p1','old','local_path','/x','sensitive','2026-01-01T00:00:00Z')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var name, core, over string
	if err := s.DB().QueryRow(`SELECT name, core_packages, risk_overrides FROM project WHERE id='p1'`).Scan(&name, &core, &over); err != nil {
		t.Fatal(err)
	}
	if name != "old" || core != "[]" || over != "{}" {
		t.Errorf("row = %q %q %q", name, core, over)
	}
	var versions string
	if err := s.DB().QueryRow(`SELECT group_concat(version) FROM (SELECT version FROM schema_migrations ORDER BY version)`).Scan(&versions); err != nil || versions != "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29" {
		t.Errorf("versions = %q err %v", versions, err)
	}
}

func TestMigration0003AddsAnalysisInputs(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().Exec(`SELECT inputs_hash, project_id, changelog_note FROM analysis LIMIT 1`); err != nil {
		t.Errorf("analysis inputs columns: %v", err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_analysis_project'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("idx_analysis_project: n=%d err=%v", n, err)
	}
}

func tableColumns(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		have[name] = true
	}
	return have
}

func TestMigration0004Applies(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for table, cols := range map[string][]string{
		"project": {"exclude"},
		"finding": {"status_changed_at"},
		"analysis": {"notes", "calls_unreadable", "calls_unreadable_paths", "calls_test_files", "calls_test_file_count",
			"calls_test_hit_count", "calls_source_files", "coverage_skipped", "coverage_unreadable"},
		"decision": {"id", "finding_id", "project_id", "action", "justification", "due_at", "author", "created_at",
			"seen_severity", "seen_fixed_versions", "superseded_at", "superseded_reason"},
		"digest_run": {"id", "since", "until", "lang", "projects", "summary", "channels", "created_at"},
	} {
		have := tableColumns(t, s.DB(), table)
		for _, c := range cols {
			if !have[c] {
				t.Errorf("%s.%s missing", table, c)
			}
		}
	}
	for _, idx := range []string{"idx_decision_finding", "idx_decision_project", "idx_digest_run_created"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: n=%d err=%v", idx, n, err)
		}
	}
	body, err := migrationFS.ReadFile("migrations/0004_decisions_digest.sql")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, banned := range []string{"rowid", "autoincrement", "datetime("} {
		if strings.Contains(lower, banned) {
			t.Errorf("0004 is not portable: it contains %q", banned)
		}
	}
}

func TestMigration0004BackfillsStatusChangedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "michel.db")
	db, err := sql.Open("sqlite", "file:///"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"0001_init.sql", "0002_analysis.sql", "0003_analysis_inputs.sql"} {
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES (?, '2026-01-01T00:00:00Z')`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, installed_version,
		status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		VALUES ('f1','p1','composer.lock','Packagist','acme/lib','ACME-1','1.0.0','pending','s1','s2','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var changed string
	if err := s.DB().QueryRow(`SELECT status_changed_at FROM finding WHERE id='f1'`).Scan(&changed); err != nil || changed != "2026-01-02T00:00:00Z" {
		t.Errorf("status_changed_at = %q err %v", changed, err)
	}
}

func TestMigration0005Applies(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for table, cols := range map[string][]string{
		"source": {"id", "key", "kind", "origin", "name", "url", "hosts", "purpose", "enabled", "hidden",
			"config_catalog", "config_user", "tech", "catalog_version", "last_read_at", "last_read_result",
			"last_read_error", "last_read_items", "last_read_etag", "status", "created_at", "updated_at"},
		"tech":           {"tag", "created_at"},
		"feed_item":      {"id", "source_id", "guid", "title", "url", "published_at", "summary", "tech", "seen_at", "read_at"},
		"kev":            {"cve", "vendor", "product", "name", "date_added", "due_date", "ransomware", "notes_url"},
		"epss":           {"cve", "score", "percentile", "model_date"},
		"cve_enrichment": {"cve", "cvss_score", "cvss_vector", "cvss_source", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact", "cwe", "fetched_at", "source_key"},
		"plugin_run":     {"id", "source_id", "project_id", "started_at", "finished_at", "tool_version", "report_path", "status", "error", "findings", "log"},
		"discovery":      {"repo", "topic", "stars", "description", "html_url", "first_seen_at", "state"},
		"finding": {"kind", "source_key", "rule_id", "location", "fingerprint", "kev", "kev_added", "epss",
			"epss_percentile", "malicious", "cvss_enriched"},
		"decision": {"seen_kev"},
		"project":  {"tech", "tech_auto"},
	} {
		have := tableColumns(t, s.DB(), table)
		for _, c := range cols {
			if !have[c] {
				t.Errorf("%s.%s missing", table, c)
			}
		}
	}
	for _, idx := range []string{"idx_source_kind", "idx_feed_item_source", "idx_plugin_run_project", "idx_finding_kind", "idx_finding_kev"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: n=%d err=%v", idx, n, err)
		}
	}
	body, err := migrationFS.ReadFile("migrations/0005_sources.sql")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, banned := range []string{"rowid", "autoincrement", "datetime("} {
		if strings.Contains(lower, banned) {
			t.Errorf("0005 is not portable: it contains %q", banned)
		}
	}
}

func TestMigration0011DropsServerFixLevel(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().Exec(`SELECT server_fix_level FROM project LIMIT 1`); err == nil {
		t.Error("project.server_fix_level still exists")
	}
	for _, tbl := range []string{"target", "target_project", "target_inventory", "server_backup", "server_snapshot_ack"} {
		if _, err := s.DB().Exec(`SELECT 1 FROM ` + tbl + ` LIMIT 1`); err != nil {
			t.Errorf("table %s: %v", tbl, err)
		}
	}
	if _, err := s.DB().Exec(`SELECT scripts FROM fix_proposal LIMIT 1`); err != nil {
		t.Errorf("fix_proposal.scripts: %v", err)
	}
}

// BLOB is not a PostgreSQL type; BYTEA holds bytes in both databases.
func TestMigrationsAvoidBlobType(t *testing.T) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), " BLOB") {
			t.Errorf("%s uses BLOB", e.Name())
		}
	}
}

func TestMigration0023AddsProposalTree(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().Exec(`SELECT tree FROM fix_proposal LIMIT 1`); err != nil {
		t.Errorf("fix_proposal.tree: %v", err)
	}
}
