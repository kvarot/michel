-- Server logs read over SSH (plan 7). Dates are RFC 3339 text. A server id is
-- kept in target_id without a foreign key, like the other server tables.
CREATE TABLE log_source (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  path TEXT NOT NULL,
  format TEXT NOT NULL,
  level_field TEXT NOT NULL DEFAULT '',
  channel_field TEXT NOT NULL DEFAULT '',
  pattern TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE INDEX log_source_target ON log_source (target_id);

-- One read position per source and file (a wildcard source reads many files).
CREATE TABLE log_cursor (
  source_id TEXT NOT NULL,
  file TEXT NOT NULL,
  file_id TEXT NOT NULL DEFAULT '',
  offset_bytes INTEGER NOT NULL DEFAULT 0,
  read_at TEXT NOT NULL,
  PRIMARY KEY (source_id, file)
);

CREATE TABLE log_settings (
  target_id TEXT PRIMARY KEY,
  interval_s INTEGER NOT NULL,
  store_text INTEGER NOT NULL DEFAULT 0,
  alert_text INTEGER NOT NULL DEFAULT 0,
  retention_days INTEGER NOT NULL,
  resolve_after_s INTEGER NOT NULL,
  read_cap INTEGER NOT NULL,
  read_timeout_s INTEGER NOT NULL,
  max_alerts_per_hour INTEGER NOT NULL,
  sms INTEGER NOT NULL DEFAULT 0,
  route_critical TEXT NOT NULL,
  route_error TEXT NOT NULL,
  route_warning TEXT NOT NULL,
  route_info TEXT NOT NULL
);

-- A recurring error. id is the SHA-256 of source, level, type, location and
-- channel, never of the text. text_enc holds the cleaned text encrypted at
-- rest, or NULL when no text is kept.
CREATE TABLE log_signature (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  level TEXT NOT NULL,
  type TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT '',
  channel TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  first_at TEXT NOT NULL,
  last_at TEXT NOT NULL,
  last_alert_at TEXT NOT NULL DEFAULT '',
  total INTEGER NOT NULL DEFAULT 0,
  text_enc BYTEA
);
CREATE INDEX log_signature_target ON log_signature (target_id);
CREATE INDEX log_signature_source ON log_signature (source_id);

-- Occurrences of a signature per hour.
CREATE TABLE log_bucket (
  signature_id TEXT NOT NULL,
  hour TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (signature_id, hour)
);

-- What Michel could not read or kept out: gaps, skipped lines, rotations...
CREATE TABLE log_note (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  from_at TEXT NOT NULL,
  to_at TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX log_note_target ON log_note (target_id);
