-- The audit chain is ordered by seq, a column of its own, instead of a column
-- only SQLite knows. The events of an old database keep their order and every
-- hashed field: the table is rebuilt and the rows copied as they are, the first
-- column of 0001 becoming seq. hmac is the seal of an event (empty for the
-- events written before the protection). audit_anchor counts the events, so
-- that writing one never counts the table.
CREATE TABLE audit_event_seq (
    seq            INTEGER NOT NULL UNIQUE,
    id             TEXT NOT NULL PRIMARY KEY,
    ts             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    result         TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    evidence       TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL UNIQUE
);
INSERT INTO audit_event_seq (seq, id, ts, actor, action, target, result, correlation_id, evidence, prev_hash, hash)
    SELECT * FROM audit_event;
DROP TABLE audit_event;
ALTER TABLE audit_event_seq RENAME TO audit_event;
ALTER TABLE audit_event ADD COLUMN hmac TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_audit_event_action ON audit_event(action);
CREATE INDEX idx_audit_event_action_target ON audit_event(action, target);

CREATE TABLE audit_anchor (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    events INTEGER NOT NULL
);
INSERT INTO audit_anchor (id, events) SELECT 1, COUNT(*) FROM audit_event;
