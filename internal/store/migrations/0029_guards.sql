-- The guards: a gate threshold per project (soft, normal or strict), the
-- components each scan found (kept for the CycloneDX export), and the git
-- hooks Michel installed (so that it removes only its own).
ALTER TABLE project ADD COLUMN gate_threshold TEXT NOT NULL DEFAULT 'normal';
CREATE TABLE scan_component (
  project_id TEXT NOT NULL,
  manifest_rel_path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  purl TEXT NOT NULL DEFAULT '',
  dep_group TEXT NOT NULL DEFAULT '',
  scan_id TEXT NOT NULL,
  PRIMARY KEY (project_id, manifest_rel_path, ecosystem, name, version)
);
CREATE TABLE repo_hook (
  repo_root TEXT PRIMARY KEY,
  hook_path TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  installed_at TEXT NOT NULL
);
