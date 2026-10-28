-- cve_enrichment_miss remembers which on-demand source did not know a CVE (or
-- gave no CVSS), so that source is not asked again and the others still are.
CREATE TABLE cve_enrichment_miss (cve TEXT NOT NULL, source_key TEXT NOT NULL, fetched_at TEXT NOT NULL, PRIMARY KEY (cve, source_key));
