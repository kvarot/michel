# Plan 1 (socle) - first real scan on the reference project

Date: 2026-10-22. Binary: `michel dev` (built from branch `feat/socle`, `go build -o bin/michel.exe ./cmd/michel`).

## Configuration used (paths only)

- Config: `%AppData%\michel\config.yaml` (defaults from `config.example.yaml` plus the two lines below)
- Data dir: `%AppData%\michel\` (default)
- `db.osv_path: <osv-db-root>` (zips downloaded earlier today by osv-scanner)
- `network.allow: [{host: osv-vulnerabilities.storage.googleapis.com, purpose: osv.db}]` (not used: `db update` was not needed)

## db status

```
ecosystem  present  fetched_at  size       state
Packagist  true     -           10988996   STALE
npm        true     -           218843332  STALE
```

The zips were detected at the expected layout (`osv-scalibr/<eco>/all.zip`). They have no `fetched_at` sidecar (they were not downloaded by Michel), so no date is shown and the state is STALE. Expected, not a defect.

## project add

```
Added project demo (<path to the project>), classification sensitive, fix level 1.
```

## scan

```
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo     7          1369      215       12/66/116/21/0                    215/0
Michel found 215 new findings in demo, 12 critical. Next: michel findings --project demo --severity critical
```

Exit code 0, no failures. Only the totals are kept here: manifests 7, packages 1369, findings 215, by severity critical 12, high 66, medium 116, low 21, unknown 0.

## Comparison with a plain osv-scanner run

Michel skips lockfiles under `vendor/` (`DefaultExclude`: `node_modules`, `vendor`, `.git`), which lowers its count, and records one finding per (manifest, package, OSV id), which raises it compared with a per-package count. The two effects pull in opposite directions, so no package-level comparison was attempted.

## audit verify

```
audit: 15 events verified, head 094d61463194
```

Exit code 0.

## audit list --last 20

15 events: `app.start`, `project.add`, `scan.start`, 7 x `scan.manifest` (all `ok`), `scan.finish`. No `egress.attempt` event: the scan made no network request.

## Findings

12 critical findings. Details are deliberately not published here: see `michel findings --project demo --severity critical` locally.
