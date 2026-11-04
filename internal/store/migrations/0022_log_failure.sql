-- The cause of the last failed read of a server's logs, kept until the next good
-- read so that the page can say it. reason is a closed key (no_agent, refused,
-- timeout, ...), never what the server printed. source_id is the log that failed,
-- or '' when the connection to the server failed (the cause is then the whole
-- server's). The set of a server is replaced at each pass.
CREATE TABLE log_failure (
  target_id TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (target_id, source_id)
);
