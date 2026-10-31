-- Fix attempts: an agent works on a copy of a project to fix one finding; the
-- user validates the proposal before anything is applied.
CREATE TABLE fix_attempt (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  state TEXT NOT NULL,
  clone_dir TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  cause TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX fix_attempt_project ON fix_attempt (project_id, state);
CREATE INDEX fix_attempt_finding ON fix_attempt (finding_id);

CREATE TABLE fix_proposal (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  diff TEXT NOT NULL,
  files TEXT NOT NULL DEFAULT '[]',
  tests_status TEXT NOT NULL DEFAULT '',
  tests_output TEXT NOT NULL DEFAULT '',
  rescan_clean INTEGER NOT NULL DEFAULT 0,
  risk INTEGER NOT NULL DEFAULT 0,
  hash TEXT NOT NULL,
  steps_server TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  superseded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX fix_proposal_attempt ON fix_proposal (attempt_id, created_at);

CREATE TABLE fix_message (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  role TEXT NOT NULL,
  text TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX fix_message_attempt ON fix_message (attempt_id, at);

CREATE TABLE fix_queue (
  finding_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  queued_at TEXT NOT NULL
);

ALTER TABLE project ADD COLUMN server_fix_level INTEGER NOT NULL DEFAULT 1;
ALTER TABLE project ADD COLUMN auto_fix_minor INTEGER NOT NULL DEFAULT 0;
