-- inputs_hash fingerprints the settings an analysis depends on (risk rule,
-- core packages, exclusions): a stored analysis whose hash differs is
-- recomputed. project_id ties the analysis to its project.
-- changelog_note keeps why a changelog result is degraded (for example a file
-- without readable version headings, whose breaking changes are not assessed).
ALTER TABLE analysis ADD COLUMN inputs_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE analysis ADD COLUMN project_id TEXT NOT NULL DEFAULT '';
ALTER TABLE analysis ADD COLUMN changelog_note TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_analysis_project ON analysis(project_id);
