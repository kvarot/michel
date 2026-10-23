# Network egress inventory (plans 1 to 3)

🇫🇷 Version française : [network-egress.fr.md](network-egress.fr.md)

All outbound HTTP goes through the egress gateway (`internal/egress`), which applies the `sovereignty.network` policy: default deny, every request checked against `network.allow` rules (host and purpose), every attempt written to the audit log (`egress.attempt`).

## Destinations and purposes

| Purpose | Destination | When |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (only) | Explicit `michel db update`, and only if an allow rule exists. |
| `osv.scan` | none | Never used in practice. It exists so that any unexpected request from the scanner library (osv-scalibr) during a scan is denied and logged. |
| `notify.email` | the SMTP server of an email channel (`notify.channels[].host`) | `michel digest --send`, `michel scan --all --digest`, `michel notify test`. TCP through `Gateway.DialContext`, STARTTLS (587) or implicit TLS (465) only. The policy is refused at load when an enabled channel has no rule. |
| `notify.webhook` | the host of a webhook channel's `url` | Same commands. HTTPS POST (plain http only on loopback), signed with HMAC-SHA256; redirects are not followed. |

There is no other destination in plans 1 to 3: no telemetry, no error reporting, no update check, no AI provider.

## Local only, no network

| What | Why it is not egress |
|---|---|
| Desktop notification (`toast` channel) | A local subprocess with a fixed command line (Windows PowerShell 5.1 from `%SystemRoot%`, `notify-send`, `/usr/bin/osascript`); the text is passed as data on stdin or after `--`. No socket, no rule needed. |
| `michel serve` (Today page and `/api/v1`) | A listener on a loopback address only (127.0.0.1, [::1] or localhost; any other `--listen` is refused). It accepts connections from this computer and makes no outbound connection. API calls need the local access token. |
| Decisions, digest without `--send`, secrets | Read and write the data folder only. |

## Limits

- The gateway re-checks every redirect hop against the policy. A redirect to a host that is not allowed is denied.
- Loopback (`127.0.0.1`, `::1`, `localhost`) is allowed without a rule for purposes prefixed `local.`. No purpose of that kind is used yet; a webhook on this machine still needs its `notify.webhook` rule.
- `Gateway.DialContext` (raw connections, used by the email channel) dials TCP only (`tcp`, `tcp4`, `tcp6`); any other network (udp, unix, ip) is refused. It applies the same allow rules and writes the same `egress.attempt` event as HTTP, and refuses the connection when the audit log cannot be written.
- A database download is capped at 2 GiB.
- A database zip is rejected above 2,000,000 entries or 8 GiB uncompressed.
- On any download or validation failure the previous database is kept.

## Tested vs declared only

Tested (automated tests):

- A scan makes zero network requests (zero-egress scan test).
- A denied redirect is refused and audited.
- `DialContext` refuses a host without rule, a non-TCP network, and fails closed when the audit cannot be written.
- `michel serve` refuses a non-loopback `--listen` address; the API answers 401 without the token.
- The download, entry-count and uncompressed-size caps.

Declared only (not enforced by a test today):

- A dependency that uses `http.DefaultClient` or `http.DefaultTransport` directly would not be seen by the gateway. `internal/egress/boundary_test.go` (run by `go test ./...` in CI, and by `make lint`) parses the Michel code outside `internal/egress` and fails on `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, `http.Client{}` and `http.Transport{}` literals, `net.Dial`, `net.DialTimeout`, `net.DialTCP/DialUDP/DialIP/DialUnix`, `net.Dialer{}`, `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer{}` and `smtp.Dial`, but it does not read the dependencies. A test that installs a deny-all default transport is planned.

## Not yet

- Local proxy for subprocesses (needed once fixes run in an isolated environment).
- Signed audit checkpoints (the audit log is hash-chained and tamper-evident, not signed).
- System keychain for secrets on Linux and macOS (libsecret, Keychain): secrets are DPAPI-encrypted files on Windows, plain files readable by the user only (0600) elsewhere.
