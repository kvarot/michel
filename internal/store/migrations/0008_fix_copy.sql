-- The fix service persists, with each attempt, its work copy (folders,
-- base and root commits, exclusions, configuration fingerprint) and the
-- validated update plan Michel runs at proposal time; a proposal keeps the
-- fix commit of the mirror and the raw patch its fingerprint covers; the AI
-- consent is recorded per project.
ALTER TABLE fix_attempt ADD COLUMN work_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE fix_attempt ADD COLUMN approved_by TEXT NOT NULL DEFAULT '';
-- The approval is bound to one proposal: its id and hash, checked again at apply.
ALTER TABLE fix_attempt ADD COLUMN approved_proposal TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_attempt ADD COLUMN approved_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_proposal ADD COLUMN commit_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_proposal ADD COLUMN diff_raw TEXT NOT NULL DEFAULT '';

CREATE TABLE fix_consent (
  project_id TEXT PRIMARY KEY,
  given_at TEXT NOT NULL,
  hosts TEXT NOT NULL DEFAULT '[]'
);
