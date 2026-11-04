-- One row per project that answered the question of the guided interface.
CREATE TABLE project_remote (
  project_id TEXT PRIMARY KEY,
  answer TEXT NOT NULL CHECK (answer IN ('yes','no','unknown')),
  remote_name TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',       -- Remote.Address: never a password, a token or an SSH user
  host TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  rule_written INTEGER NOT NULL DEFAULT 0,
  answered_at TEXT NOT NULL
);
-- One row per fix branch that reached the remote.
CREATE TABLE fix_push (
  attempt_id TEXT PRIMARY KEY,
  commit_sha TEXT NOT NULL,
  host TEXT NOT NULL,
  pushed_at TEXT NOT NULL
);
