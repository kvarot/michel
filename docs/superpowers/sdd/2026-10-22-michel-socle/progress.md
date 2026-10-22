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
Added project demo (<path to the project>), classification health, fix level 1.
```

## scan

```
project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone
demo      7          1369      215       12/66/116/21/0                    215/0
Michel found 215 new findings in demo, 12 critical. Next: michel findings --project demo --severity critical
```

Duration about 17 s, exit code 0, no failures.

Manifests scanned (7), with package counts:

| Manifest | Packages |
|---|---|
| api/service-a/composer.lock | 136 |
| api/service-b/composer.lock | 141 |
| front/package-lock.json | 276 |
| lib/composer.lock | 202 |
| tooling/package-lock.json | 499 |
| app/composer.lock | 111 |
| e2e/package-lock.json | 4 |

Counts by severity: critical 12, high 66, medium 116, low 21, unknown 0. Manifests: 7.

## Comparison with the osv-scanner run of 2026-10-22

Reference: 9 lockfiles (2 under `vendor/`), 233 vulnerabilities on 65 packages. Michel: 7 manifests, 215 findings.

- 9 - 2 = 7: the two lockfiles under `vendor/` are excluded by Michel (`DefaultExclude`: `node_modules`, `vendor`, `.git`). This lowers Michel's count relative to the reference.
- Michel records one finding per (manifest, package, OSV id), so a package present in two lockfiles counts twice. This raises Michel's count relative to a per-package count.
- The two effects pull in opposite directions, so the net gap (215 vs 233) cannot be attributed to either. That osv-scanner groups aliases per package is an assumption, not verified. No attempt was made to force agreement and no package-level comparison was done.

## audit verify

```
audit: 15 events verified, head 094d61463194
```

Exit code 0.

## audit list --last 20

15 events: `app.start`, `project.add`, `scan.start`, 7 x `scan.manifest` (all `ok`), `scan.finish`. No `egress.attempt` event: the scan made no network request.

## Findings

12 critical findings. Details are deliberately not published here: see `michel findings --project demo --severity critical` locally.
