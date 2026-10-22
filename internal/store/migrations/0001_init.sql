CREATE TABLE audit_event (
    rowid          INTEGER PRIMARY KEY AUTOINCREMENT,
    id             TEXT NOT NULL UNIQUE,
    ts             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    result         TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    evidence       TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_audit_event_action ON audit_event(action);

CREATE TABLE project (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    source_type    TEXT NOT NULL,
    path           TEXT NOT NULL,
    classification TEXT NOT NULL,
    fix_level      INTEGER NOT NULL DEFAULT 0,
    test_cmd       TEXT NOT NULL DEFAULT '',
    install_cmd    TEXT NOT NULL DEFAULT '',
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL
);

CREATE TABLE scan (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES project(id),
    started_at        TEXT NOT NULL,
    finished_at       TEXT NOT NULL DEFAULT '',
    osv_db_version    TEXT NOT NULL DEFAULT '',
    osv_db_fetched_at TEXT NOT NULL DEFAULT '',
    scanner_version   TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL,
    error             TEXT NOT NULL DEFAULT ''
);

CREATE TABLE scan_manifest (
    scan_id       TEXT NOT NULL,
    rel_path      TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,
    lock_sha256   TEXT NOT NULL DEFAULT '',
    package_count INTEGER NOT NULL DEFAULT 0,
    error         TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, rel_path)
);

CREATE TABLE finding (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL,
    manifest_rel_path  TEXT NOT NULL,
    ecosystem          TEXT NOT NULL,
    package            TEXT NOT NULL,
    osv_id             TEXT NOT NULL,
    aliases            TEXT NOT NULL DEFAULT '[]',
    severity_label     TEXT NOT NULL DEFAULT '',
    cvss_score         REAL,
    installed_version  TEXT NOT NULL,
    fixed_versions     TEXT NOT NULL DEFAULT '[]',
    dep_groups         TEXT NOT NULL DEFAULT '[]',
    status             TEXT NOT NULL,
    first_seen_scan    TEXT NOT NULL,
    last_seen_scan     TEXT NOT NULL,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    summary            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_finding_project_status ON finding(project_id, status);
