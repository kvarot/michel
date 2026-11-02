-- The bound of a server fix's script run, set when the run is claimed: a
-- sweeper judges a running attempt by it, never by its own settings.
ALTER TABLE fix_attempt ADD COLUMN run_deadline TEXT NOT NULL DEFAULT '';

-- The fingerprint of the key that seals the server backups (the key itself
-- is in the secret store): one row, written by the one process that makes
-- the key, so two processes never seal with two keys.
CREATE TABLE server_backup_key (
  id INTEGER PRIMARY KEY,
  fingerprint TEXT NOT NULL
);
