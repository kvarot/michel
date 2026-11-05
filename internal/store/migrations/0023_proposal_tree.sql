-- The tree of the snapshot a code proposal was built from (a git tree id of the
-- agent's copy, excluded files left out): a click on "Run the tests" materialises
-- that very tree. '' for a proposal written before this column (no button) and for
-- a server fix.
ALTER TABLE fix_proposal ADD COLUMN tree TEXT NOT NULL DEFAULT '';
