-- The history of the findings and of the fix attempts. finding_event holds
-- one row per change a finding goes through (seen, gone, back, reopened),
-- fix_attempt_event one row per state an attempt reaches. seq numbers the
-- events of one finding or one attempt, from 1, in the order they happened.
-- The past of an existing database is reconstructed from what it kept: a
-- finding was seen at first_seen_at and, if gone, went at status_changed_at;
-- an attempt started at created_at and reached its state at updated_at. Those
-- rows are flagged as reconstructed. history_start holds when the history
-- began to be written; Michel fills it right after this migration, in the
-- same transaction, with the migration instant.
CREATE TABLE finding_event (
  finding_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (finding_id, seq)
);
CREATE INDEX idx_finding_event_at ON finding_event (at);
CREATE INDEX idx_finding_event_finding ON finding_event (finding_id);

CREATE TABLE fix_attempt_event (
  attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  at TEXT NOT NULL,
  state TEXT NOT NULL,
  reconstructed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (attempt_id, seq)
);
CREATE INDEX idx_fix_attempt_event_at ON fix_attempt_event (at);

CREATE TABLE history_start (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  at TEXT NOT NULL
);

INSERT INTO finding_event (finding_id, seq, at, kind, detail)
  SELECT id, 1, first_seen_at, 'seen', '{"reconstructed":true}' FROM finding;
INSERT INTO finding_event (finding_id, seq, at, kind, detail)
  SELECT id, 2, status_changed_at, 'gone', '{"reconstructed":true}' FROM finding WHERE status = 'gone';

INSERT INTO fix_attempt_event (attempt_id, seq, at, state, reconstructed)
  SELECT id, 1, created_at, 'preparing', 1 FROM fix_attempt;
INSERT INTO fix_attempt_event (attempt_id, seq, at, state, reconstructed)
  SELECT id, 2, updated_at, state, 1 FROM fix_attempt WHERE state <> 'preparing';
