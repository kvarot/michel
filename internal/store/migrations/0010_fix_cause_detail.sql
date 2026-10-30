-- The cause of an attempt is a plain sentence for the user; the short
-- technical detail behind it (sanitized, no path, no secret) is kept apart,
-- for the page's "Voir le détail".
ALTER TABLE fix_attempt ADD COLUMN cause_detail TEXT NOT NULL DEFAULT '';
