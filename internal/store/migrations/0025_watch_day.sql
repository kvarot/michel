-- One row per local day (YYYY-MM-DD) whose daily watch of michel serve read
-- the sources: the read happens once a day, whichever serve starts it, and not
-- again after a restart. Rows older than 30 days are deleted.
CREATE TABLE watch_day (
  day TEXT PRIMARY KEY,
  sources_at TEXT NOT NULL
);
