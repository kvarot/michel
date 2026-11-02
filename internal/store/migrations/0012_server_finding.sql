-- A server finding can be a mitigation (a setting that only holds a flaw back,
-- never closing it) and names the PHP SAPI it is about.
ALTER TABLE finding ADD COLUMN mitigation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE finding ADD COLUMN sapi TEXT NOT NULL DEFAULT '';
