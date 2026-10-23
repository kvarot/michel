# Plan 3 (decisions, digest) - real run on the reference project

Date: 2026-10-23. Binary: `michel dev` (branch `feat/digest`, `make web` when npm is present, then `go build -o bin/michel.exe ./cmd/michel`). Only aggregates are published here: no project name, path, package, version or package-specific sentence. The real run was performed by the controller on the reference project; the implementer of Task 10 wrote this file from the aggregates it sent.

## Commands run

```
michel version
michel scan --all
michel decisions --project <ref>                       (empty before the first decision)
michel decide --project <ref> --package <pkg> defer --for 30d --why "..."
michel decisions --project <ref>
michel digest
michel digest --send                                   (channel: toast; email only if a test SMTP was provided)
michel serve                                           (Today page opened with the printed token link)
michel audit verify
michel audit list --last 60
go test ./internal/hygiene/
```

Configuration: plan 2 configuration plus a `notify` section with one `toast` channel (no network rule needed); default data dir.

## Aggregates

TODO(controller): aggregates

| item | value |
|---|---|
| projects scanned (`scan --all`) | TODO |
| findings open after the scan | TODO |
| decisions before / after `decide --package` | TODO |
| findings covered by the by-package deferral | TODO |
| `digest` duration | TODO |
| `digest --send` channels ok / error | TODO |
| Today page loaded (`serve`) | TODO |

## Audit

TODO(controller): `michel audit verify` result; presence of `decision.set`, `digest.run`, `notify.send`, `api.start` in `audit list --last 60`; `egress.attempt` only for configured channel hosts (none with a toast-only setup).

## Manual checks carried from the tasks

- Toast (Task 7): delivered on this Windows machine; the banner is hidden by Windows do-not-disturb and visible in the notification center.
- Today page (Task 9): checked with fixture data (`demo`) under Chrome DevTools; PWA install prompt still to be confirmed in a normal Chrome window.
- `make`: not installed on the development machine; the Makefile's npm conditional is untested.
