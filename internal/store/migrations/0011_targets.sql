-- Servers (targets) checked over SSH. A server finding keeps the target id in
-- finding.project_id (ULIDs of projects and targets never collide) and has a
-- kind of server_package or server_config.
CREATE TABLE target (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  ssh_user TEXT NOT NULL DEFAULT '',
  alias TEXT NOT NULL DEFAULT '',
  host_key TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  env TEXT NOT NULL,
  classification TEXT NOT NULL,
  fix_level INTEGER NOT NULL DEFAULT 1,
  check_interval_s INTEGER NOT NULL DEFAULT 86400,
  preprod_id TEXT NOT NULL DEFAULT '',
  executor TEXT NOT NULL DEFAULT 'user',
  sudo TEXT NOT NULL DEFAULT 'none',
  site_url TEXT NOT NULL DEFAULT '',
  auto_config INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  last_check_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE target_project (
  target_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  remote_dir TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (target_id, project_id)
);
CREATE INDEX target_project_project ON target_project (project_id);

CREATE TABLE target_inventory (
  target_id TEXT NOT NULL,
  at TEXT NOT NULL,
  body TEXT NOT NULL,
  PRIMARY KEY (target_id, at)
);

CREATE TABLE server_backup (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  remote_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  blob TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX server_backup_attempt ON server_backup (attempt_id);

CREATE TABLE server_snapshot_ack (
  attempt_id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  actor TEXT NOT NULL
);

ALTER TABLE fix_proposal ADD COLUMN scripts TEXT NOT NULL DEFAULT '';

ALTER TABLE project DROP COLUMN server_fix_level;
