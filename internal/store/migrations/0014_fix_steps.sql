-- The steps of a server fix as Michel ran them (op, ok, a short detail that
-- never holds what the server printed).
ALTER TABLE fix_proposal ADD COLUMN steps TEXT NOT NULL DEFAULT '[]';
