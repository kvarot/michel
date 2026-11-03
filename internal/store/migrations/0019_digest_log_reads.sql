-- What the digest counts for server log errors, by the time Michel read them
-- (not by the hour written in the log, which can be older than the last
-- digest). One row per error and read; purged with the other log counts.
CREATE TABLE log_read (
  signature_id TEXT NOT NULL,
  read_at TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (signature_id, read_at)
);

-- When an error last came back after being resolved ('' if it never did).
ALTER TABLE log_signature ADD COLUMN reopened_at TEXT NOT NULL DEFAULT '';

-- The start of the first digest window, kept when the first digest reaches
-- nobody: the window must not slide with the clock until one is delivered.
CREATE TABLE digest_start (
  id TEXT PRIMARY KEY,
  since TEXT NOT NULL
);
