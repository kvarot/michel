ALTER TABLE project ADD COLUMN core_packages TEXT NOT NULL DEFAULT '[]';
ALTER TABLE project ADD COLUMN risk_overrides TEXT NOT NULL DEFAULT '{}';

CREATE TABLE analysis (
    finding_id          TEXT PRIMARY KEY,
    computed_at         TEXT NOT NULL,
    michel_version      TEXT NOT NULL,
    directness          TEXT,
    via                 TEXT NOT NULL DEFAULT '[]',
    root_constraint     TEXT NOT NULL DEFAULT '',
    has_root_manifest   INTEGER NOT NULL DEFAULT 0,
    target_version      TEXT NOT NULL DEFAULT '',
    jump                TEXT NOT NULL DEFAULT 'unknown',
    constraint_allows   INTEGER,
    call_sites          TEXT NOT NULL DEFAULT '[]',
    call_site_count     INTEGER NOT NULL DEFAULT 0,
    call_sites_quality  TEXT NOT NULL DEFAULT 'low',
    namespaces          TEXT NOT NULL DEFAULT '[]',
    test_files          TEXT NOT NULL DEFAULT '[]',
    test_count          INTEGER NOT NULL DEFAULT 0,
    test_method         TEXT NOT NULL DEFAULT 'none',
    changelog_source    TEXT NOT NULL DEFAULT '',
    changelog_excerpt   TEXT NOT NULL DEFAULT '',
    changelog_available INTEGER NOT NULL DEFAULT 0,
    breaking            INTEGER NOT NULL DEFAULT 0,
    breaking_lines      TEXT NOT NULL DEFAULT '[]',
    risk_score          INTEGER NOT NULL DEFAULT 0,
    risk_terms          TEXT NOT NULL DEFAULT '{}',
    recommendation      TEXT NOT NULL DEFAULT 'report_only',
    warning             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_analysis_recommendation ON analysis(recommendation);
