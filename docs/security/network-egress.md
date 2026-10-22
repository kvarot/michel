# Network egress inventory (plan 1)

🇫🇷 Version française : [network-egress.fr.md](network-egress.fr.md)

All outbound HTTP goes through the egress gateway (`internal/egress`), which applies the `sovereignty.network` policy: default deny, every request checked against `network.allow` rules (host and purpose), every attempt written to the audit log (`egress.attempt`).

## Destinations and purposes

| Purpose | Destination | When |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (only) | Explicit `michel db update`, and only if an allow rule exists. |
| `osv.scan` | none | Never used in practice. It exists so that any unexpected request from the scanner library (osv-scalibr) during a scan is denied and logged. |

There is no other destination in plan 1: no telemetry, no error reporting, no update check, no AI provider.

## Limits

- The gateway re-checks every redirect hop against the policy. A redirect to a host that is not allowed is denied.
- Loopback (`127.0.0.1`, `::1`, `localhost`) is allowed without a rule for purposes prefixed `local.`. No purpose of that kind is used in plan 1.
- A database download is capped at 2 GiB.
- A database zip is rejected above 2,000,000 entries or 8 GiB uncompressed.
- On any download or validation failure the previous database is kept.

## Tested vs declared only

Tested (automated tests):

- A scan makes zero network requests (zero-egress scan test).
- A denied redirect is refused and audited.
- The download, entry-count and uncompressed-size caps.

Declared only (not enforced by a test today):

- A dependency that uses `http.DefaultClient` or `http.DefaultTransport` directly would not be seen by the gateway. `internal/egress/boundary_test.go` (run by `go test ./...` in CI, and by `make lint`) parses the Michel code outside `internal/egress` and fails on `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, `http.Client{}` and `http.Transport{}` literals, `net.Dial`, `net.DialTimeout` and `net.Dialer{}`, but it does not read the dependencies. A test that installs a deny-all default transport is planned.

## Not in plan 1

- Local proxy for subprocesses (needed once fixes run in an isolated environment).
- Signed audit checkpoints (the audit log is hash-chained and tamper-evident, not signed).
- Secret masking.
