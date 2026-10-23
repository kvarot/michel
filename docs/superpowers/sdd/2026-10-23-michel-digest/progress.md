# Plan 3 (decisions, digest) - real run on the reference projects

Date: 2026-10-23. Binary: `michel dev` (branch `feat/digest`, `npm run build` in `web/`, then `go build`). Only aggregates are published here: no project name, path, package, version or package-specific sentence. The real run was performed by the controller on the author's projects of this machine, registered under neutral names, with a throw-away data folder (fresh OSV databases, fresh store), never writing into the projects.

## Commands run

```
michel db update                                       (allow rule for the OSV bucket only)
michel project add <folder> --name refN --fix-level 1  (8 folders)
michel scan --all --digest --json                      (channel: one toast)
michel findings --project ref1 --severity critical --json
michel decide --project ref1 --package <pkg> defer --for 30d --why "..."
michel decisions --project ref1 --json
michel scan --project ref1 --json                      (re-scan after the decision)
michel findings --project ref1 --status decided --json
michel digest / michel digest --json
michel serve --listen 127.0.0.1:7391                   (page, manifest, service worker, API probed with curl)
michel audit verify
michel audit list --last 2000
```

Configuration: one `osv.db` allow rule, `assistant.lang: fr`, a `notify` section with one `toast` channel (no network rule needed).

## Aggregates

| item | value |
|---|---|
| `db update` (Packagist + npm) | 2 databases, about 7 s |
| folders registered | 8 |
| projects scanned (`scan --all`) | 6 scanned: 5 `ok`, 1 `partial`; 2 failed with "no lockfile" (folders without composer.lock or package-lock.json, expected) |
| lockfiles read | 33 |
| findings after the first scan | 1161 (critical 89, high 484, medium 474, low 114), all new |
| `scan --all --digest` total duration | 6 min 15 s (scan and analysis of 6 projects, then digest and toast) |
| `digest --send` (chained) channels ok / error | 1 / 0 (toast delivered) |
| decisions before / after `decide --package` | 0 / 59 |
| findings covered by the by-package deferral | 59 (one package, one project), deferred 30 days |
| findings still `decided` after a re-scan | 59 / 59 (unchanged advisories: not asked again) |
| `digest` after the chained run | nothing new since the last digest, 0 to review, 0 due; 2 projects reported as not scanned |
| `digest` duration | 0.17 s |
| `michel serve`: `/`, manifest, `sw.js` | 200 (manifest served as `application/manifest+json`) |
| API without token / with token / foreign Host | 401 / 200 / 421 |
| `/today` and `/projects` responses | no absolute path, no project folder name |

The `partial` project is the known plan 1 residual risk: some package-lock.json files are valid JSON but yield no package to Michel's own check, so they are reported as unreadable and their findings are kept.

## Audit

- `michel audit verify`: 159 events verified, exit code 0.
- Events by action: `app.start` 18, `osv.db.update` 1, `egress.attempt` 2, `project.add` 8, `scan.start` 9, `scan.manifest` 36, `scan.finish` 9, `analyze.start` 7, `analyze.finish` 7, `digest.run` 1, `notify.send` 1, `decision.set` 59, `api.start` 1.
- The only two `egress.attempt` events are the allowed OSV downloads of `db update`. Scans, analysis, digest, toast and the local page made no network request.
- No `api.stop`: the server was stopped by killing the process, not by Ctrl+C.

## Observations from the run (deferred, see deferred-and-rulings.md)

- `decide --package` prints one audit line per finding (59 lines here); a one-line summary with the count would read better.
- osv-scanner prints three `interpreting as regex/glob` warnings per project on stderr (pre-existing since plan 1).
- The digest says "the last scan of 2 projects could not finish" for folders that simply hold no lockfile; a distinct wording for "nothing to scan" would be clearer.

## Manual checks carried from the tasks

- Toast (Task 7): delivered on this Windows machine; the banner is hidden by Windows do-not-disturb and visible in the notification center (confirmed by the author).
- Today page (Task 9): checked with fixture data (`demo`) under Chrome DevTools; PWA install prompt still to be confirmed in a normal Chrome window.
- `make`: not installed on the development machine; the Makefile's npm conditional is untested.
