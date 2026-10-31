-- A proposal names the versions it moves its package between: the one
-- installed when the attempt started and the one the fix commit's lockfile
-- resolves (else the planned target), so the page can say it in clear.
ALTER TABLE fix_proposal ADD COLUMN from_version TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_proposal ADD COLUMN to_version TEXT NOT NULL DEFAULT '';
