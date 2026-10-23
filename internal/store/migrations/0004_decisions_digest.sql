-- exclude lists the folder names a project's scans and analyses skip, on top
-- of the defaults. status_changed_at is when a finding last changed status
-- (existing rows start from their last sighting). The analysis columns keep
-- the facts that were computed but not stored before (notes, unreadable files,
-- test hits, skipped reference names). decision and digest_run hold the
-- user's decisions on findings and the digests Michel sent.
ALTER TABLE project ADD COLUMN exclude TEXT NOT NULL DEFAULT '[]';
ALTER TABLE finding ADD COLUMN status_changed_at TEXT NOT NULL DEFAULT '';
UPDATE finding SET status_changed_at = last_seen_at WHERE status_changed_at = '';
ALTER TABLE analysis ADD COLUMN notes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE analysis ADD COLUMN calls_unreadable INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN calls_unreadable_paths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE analysis ADD COLUMN calls_test_files TEXT NOT NULL DEFAULT '[]';
ALTER TABLE analysis ADD COLUMN calls_test_file_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN calls_test_hit_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN calls_source_files TEXT NOT NULL DEFAULT '[]';
ALTER TABLE analysis ADD COLUMN coverage_skipped TEXT NOT NULL DEFAULT '[]';
ALTER TABLE analysis ADD COLUMN coverage_unreadable INTEGER NOT NULL DEFAULT 0;
CREATE TABLE decision (
    id                   TEXT PRIMARY KEY,
    finding_id           TEXT NOT NULL,
    project_id           TEXT NOT NULL,
    action               TEXT NOT NULL,
    justification        TEXT NOT NULL DEFAULT '',
    due_at               TEXT NOT NULL DEFAULT '',
    author               TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    seen_severity        TEXT NOT NULL DEFAULT '',
    seen_fixed_versions  TEXT NOT NULL DEFAULT '[]',
    superseded_at        TEXT NOT NULL DEFAULT '',
    superseded_reason    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_decision_finding ON decision(finding_id, created_at);
CREATE INDEX idx_decision_project ON decision(project_id);
CREATE TABLE digest_run (
    id          TEXT PRIMARY KEY,
    since       TEXT NOT NULL,
    until       TEXT NOT NULL,
    lang        TEXT NOT NULL,
    projects    TEXT NOT NULL DEFAULT '[]',
    summary     TEXT NOT NULL DEFAULT '{}',
    channels    TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_digest_run_created ON digest_run(created_at);
