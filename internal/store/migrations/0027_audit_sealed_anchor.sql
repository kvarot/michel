-- The sealed anchor: where the seals of the audit chain begin (sealed_from,
-- 0 while the log is not sealed) and its last sealed event (sealed_seq,
-- sealed_head), the three bound by sealed_mac, an HMAC made with the key of
-- the seals. Without the key nobody can move the start of the seals, nor
-- drop or rewrite sealed events, without audit verify seeing it.
ALTER TABLE audit_anchor ADD COLUMN sealed_from INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_anchor ADD COLUMN sealed_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_anchor ADD COLUMN sealed_head TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_anchor ADD COLUMN sealed_mac TEXT NOT NULL DEFAULT '';
