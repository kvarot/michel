-- source is the registry of every source Michel reads or offers (OSV
-- databases, enrichments, feeds, plugins, skills, MCP servers, references).
-- tech holds the technologies the user declares outside any project.
-- feed_item, kev, epss, cve_enrichment, plugin_run and discovery hold what
-- the sources bring. The finding columns carry external findings (plugins)
-- and the denormalised enrichment signals; decision.seen_kev and the project
-- tech columns complete the snapshot and the "to read" filter.
CREATE TABLE source (
    id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, origin TEXT NOT NULL,
    name TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', hosts TEXT NOT NULL DEFAULT '[]', purpose TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0,
    config_catalog TEXT NOT NULL DEFAULT '{}', config_user TEXT NOT NULL DEFAULT '{}', tech TEXT NOT NULL DEFAULT '[]',
    catalog_version INTEGER NOT NULL DEFAULT 0,
    last_read_at TEXT NOT NULL DEFAULT '', last_read_result TEXT NOT NULL DEFAULT '', last_read_error TEXT NOT NULL DEFAULT '',
    last_read_items INTEGER NOT NULL DEFAULT 0, last_read_etag TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX idx_source_kind ON source(kind);
CREATE TABLE tech (tag TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE feed_item (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL, guid TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', tech TEXT NOT NULL DEFAULT '[]',
    seen_at TEXT NOT NULL, read_at TEXT NOT NULL DEFAULT '', UNIQUE (source_id, guid)
);
CREATE INDEX idx_feed_item_source ON feed_item(source_id, published_at);
CREATE TABLE kev (cve TEXT PRIMARY KEY, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
    date_added TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '', ransomware TEXT NOT NULL DEFAULT '', notes_url TEXT NOT NULL DEFAULT '');
CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL DEFAULT 0, percentile REAL NOT NULL DEFAULT 0, model_date TEXT NOT NULL DEFAULT '');
CREATE TABLE cve_enrichment (cve TEXT PRIMARY KEY, cvss_score REAL NOT NULL DEFAULT 0, cvss_vector TEXT NOT NULL DEFAULT '',
    cvss_source TEXT NOT NULL DEFAULT '', ssvc_exploitation TEXT NOT NULL DEFAULT '', ssvc_automatable TEXT NOT NULL DEFAULT '',
    ssvc_technical_impact TEXT NOT NULL DEFAULT '', cwe TEXT NOT NULL DEFAULT '[]', fetched_at TEXT NOT NULL, source_key TEXT NOT NULL);
CREATE TABLE plugin_run (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, project_id TEXT NOT NULL, started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '', tool_version TEXT NOT NULL DEFAULT '', report_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', findings INTEGER NOT NULL DEFAULT 0, log TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_plugin_run_project ON plugin_run(project_id, started_at);
CREATE TABLE discovery (repo TEXT PRIMARY KEY, topic TEXT NOT NULL, stars INTEGER NOT NULL DEFAULT 0, description TEXT NOT NULL DEFAULT '',
    html_url TEXT NOT NULL DEFAULT '', first_seen_at TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new');
ALTER TABLE finding ADD COLUMN kind TEXT NOT NULL DEFAULT 'dependency';
ALTER TABLE finding ADD COLUMN source_key TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN rule_id TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN location TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN kev_added TEXT NOT NULL DEFAULT '';
ALTER TABLE finding ADD COLUMN epss REAL NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN epss_percentile REAL NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN malicious INTEGER NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN cvss_enriched REAL NOT NULL DEFAULT 0;
CREATE INDEX idx_finding_kind ON finding(kind);
CREATE INDEX idx_finding_kev ON finding(kev);
ALTER TABLE decision ADD COLUMN seen_kev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE project ADD COLUMN tech TEXT NOT NULL DEFAULT '[]';
ALTER TABLE project ADD COLUMN tech_auto TEXT NOT NULL DEFAULT '[]';
