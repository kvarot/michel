-- The daily watch of michel serve checks a project unless this is 0
-- (michel project set <name> --auto-scan=false). Existing projects are watched.
ALTER TABLE project ADD COLUMN auto_scan INTEGER NOT NULL DEFAULT 1;
