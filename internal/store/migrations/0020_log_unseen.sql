-- The files of a log source that the last read could not open, and why (a
-- closed cause code: denied, link, absent, not_file, tools, other). The set of
-- a source is replaced at each read, so a fixed permission clears it. It holds
-- the paths of declared sources only, never a line of a log.
CREATE TABLE log_unseen (
  source_id TEXT NOT NULL,
  file TEXT NOT NULL,
  cause TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (source_id, file)
);

-- The spike threshold of a server's errors: an hour counts as a spike when it
-- holds at least spike_min occurrences and spike_factor times the hour before.
ALTER TABLE log_settings ADD COLUMN spike_factor INTEGER NOT NULL DEFAULT 10;
ALTER TABLE log_settings ADD COLUMN spike_min INTEGER NOT NULL DEFAULT 100;

-- When the path of a source last changed ('' if never): the errors last seen
-- before that came from another file, and no command to look at them is given.
ALTER TABLE log_source ADD COLUMN path_at TEXT NOT NULL DEFAULT '';
