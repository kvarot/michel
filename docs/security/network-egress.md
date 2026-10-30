# Network egress inventory (plans 1 to 4)

🇫🇷 Version française : [network-egress.fr.md](network-egress.fr.md)

All outbound HTTP goes through the egress gateway (`internal/egress`), which applies the `sovereignty.network` policy: default deny, every request checked against `network.allow` rules (host and purpose), every attempt written to the audit log (`egress.attempt`).

## Destinations and purposes

| Purpose | Destination | When |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (only) | Explicit `michel db update`, and only if an allow rule exists. |
| `osv.scan` | none | Never used in practice. It exists so that any unexpected request from the scanner library (osv-scalibr) during a scan is denied and logged. |
| `notify.email` | the SMTP server of an email channel (`notify.channels[].host`) | `michel digest --send`, `michel scan --all --digest`, `michel notify test`. TCP through `Gateway.DialContext`, STARTTLS (587) or implicit TLS (465) only. The policy is refused at load when an enabled channel has no rule. |
| `notify.webhook` | the host of a webhook channel's `url` | Same commands. HTTPS POST (plain http only on loopback), signed with HMAC-SHA256; redirects are not followed. |
| `osv.db` (sources) | `osv-vulnerabilities.storage.googleapis.com` | `michel source update` and `scan --update`, for each enabled `osv.*` source (23 in the catalog, one host for all). Whole databases, nothing sent. |
| `source.enrich` | `www.cisa.gov` (KEV), `epss.empiricalsecurity.com` (EPSS) | `source update`, once the source is enabled and consented. Whole files, nothing sent. |
| `source.enrich` | `raw.githubusercontent.com` (Vulnrichment), `services.nvd.nist.gov` (NVD), `vulnerability.circl.lu` (CIRCL) | `source update`, on-demand sources (off by default). One CVE number per request, for findings without a severity. NVD carries the `nvd-api-key` secret as a header when it is set. |
| `source.feed` | the vendor sites of the feeds: `about.gitlab.com`, `community.openvpn.net`, `developer.joomla.org`, `grafana.com`, `httpd.apache.org`, `mariadb.com`, `msrc.microsoft.com`, `nginx.org`, `nodejs.org`, `opensearch.org`, `openssl-library.org`, `rubyonrails.org`, `source.android.com`, `support.apple.com`, `symfony.com`, `wordpress.org`, `www.atlassian.com`, `www.debian.org`, `www.djangoproject.com`, `www.drupal.org`, `www.elastic.co`, `www.jenkins.io`, `www.keycloak.org`, `www.openssh.com`, `www.oracle.com`, `www.php.net`, `www.postgresql.org`; and `api.github.com` for the 28 feeds read from GitHub repository advisories | `source update`, for each enabled feed (55 in the catalog, all off by default). A GET of the feed; the GitHub token secret as `Authorization` when it is set. |
| `source.repo` | `api.github.com`, `codeload.github.com` | Skills and MCP servers: `source install` and `source upgrade` (archive of the pinned commit), `source update` (repository state, 3 requests per repository). The repository state of a plugin is read only if `api.github.com` is already allowed for this purpose. Sends the repository name and the commit; the GitHub token when it is set. |
| `source.discover` | `api.github.com` | `source update` with `discover.github` enabled. Sends the topic names. |
| `plugin.<key>` | none | Never allowed. The purpose of the requests that a tool run by Michel (Trivy, Semgrep) sends to the local refusal proxy; each one is denied and logged. |

The source hosts above are those of the embedded catalog (`internal/source/catalog/catalog.yaml`, version 4). A source you add yourself (`michel source add`) brings its own host, which you accept like the others. There is no other destination: no telemetry, no error reporting, no update check, no AI provider.

Michel writes the rules of a source after your consent (`michel source enable`, or the Sources page): one `{host, purpose}` rule per host, with a `.bak` copy of the policy file. See [sources.md](../sources.md).

## Local only, no network

| What | Why it is not egress |
|---|---|
| Desktop notification (`toast` channel) | A local subprocess with a fixed command line (Windows PowerShell 5.1 from `%SystemRoot%`, `notify-send`, `/usr/bin/osascript`); the text is passed as data on stdin or after `--`. No socket, no rule needed. |
| `michel serve` (Today page and `/api/v1`) | A listener on a loopback address only (127.0.0.1, [::1] or localhost; any other `--listen` is refused). It accepts connections from this computer and makes no outbound connection. API calls need the local access token. |
| Decisions, digest without `--send`, secrets | Read and write the data folder only. |
| Plugins (Trivy, Semgrep) | A subprocess with a fixed argument list, started from `<data dir>/plugins/<tool>/`, with an allowlisted environment (no secret or token) and its proxy variables pointing to the refusal proxy (`internal/egress/denyproxy`, on `127.0.0.1`, a free port). The proxy answers 403 to every request, refuses every `CONNECT` and records each try as a denied `egress.attempt` (purpose `plugin.<key>`, at most 200 recorded per run; later ones are still refused, without being recorded). See [sources.md](../sources.md). |
| MCP servers | Michel fetches and pins the source (purpose `source.repo`) but never starts the server. The `claude mcp add` line is yours to run; a server started with `npx` downloads at start-up, outside Michel. |

## Limits

- The gateway re-checks every redirect hop against the policy. A redirect to a host that is not allowed is denied.
- Loopback (`127.0.0.1`, `::1`, `localhost`) is allowed without a rule for purposes prefixed `local.`. No purpose of that kind is used yet; a webhook on this machine still needs its `notify.webhook` rule.
- `Gateway.DialContext` (raw connections, used by the email channel) dials TCP only (`tcp`, `tcp4`, `tcp6`); any other network (udp, unix, ip) is refused. It applies the same allow rules and writes the same `egress.attempt` event as HTTP, and refuses the connection when the audit log cannot be written.
- A source waiting for consent (enabled, with a host that has no rule) is not read: `source update` makes no request for it.
- If a new version of Michel changes the server address of a source, your former consent no longer applies: the source waits for your consent for the new address. The old rule stays in your policy file until you remove it.
- A database download is capped at 2 GiB.
- KEV is capped at 50 MB, EPSS at 200 MB once decompressed, an on-demand answer at 5 MB, a feed at 5 MB and 200 items, a skill or MCP archive at 50 MB compressed and 200 MB and 5,000 files extracted, a plugin report at 50 MB and 10,000 results.
- On-demand enrichments: 200 CVEs per update for Vulnrichment and CIRCL, 100 for NVD (one request every 6 s, 0.6 s with a key); a 403 or 429 answer stops that source for the update.
- GitHub: one update spends at most 50 requests without a token, 500 with one; the rest waits for the next update (recorded as `rate budget` in the audit log and in `michel source show`).
- The GitHub status reads, the on-demand JSON reads and the NVD requests with a key do not follow redirects.
- A database zip is rejected above 2,000,000 entries or 8 GiB uncompressed.
- On any download or validation failure the previous database is kept.

## Tested vs declared only

Tested (automated tests):

- A scan makes zero network requests (zero-egress scan test).
- A denied redirect is refused and audited.
- `DialContext` refuses a host without rule, a non-TCP network, and fails closed when the audit cannot be written.
- `michel serve` refuses a non-loopback `--listen` address; the API answers 401 without the token.
- The download, entry-count and uncompressed-size caps.
- Sources: a source waiting for consent makes zero egress attempts during an update (`TestRunSkipsWaitingConsentWithoutNetwork`); consent writes the rule, creates the policy file when absent and records `source.consent`, and the gateway applies new rules without restart (`TestEnableWritesRuleRecordsConsentAndReloads`, `TestEnableCreatesPolicyFileWhenAbsent`, `TestGatewaySetRulesTakesEffect`); a host change sends the source back to waiting for consent (`TestSyncHostChangeWaitsForConsentAgain`).
- Caps of the source readers: KEV body (`TestReadKEVCapsBody`), on-demand answers (`TestRunOnDemandCapsBody`), feeds at 5 MB and 200 items (`TestRSSReaderCapsAndSanitizes`), archive files and bytes, traversal and symbolic links (`TestExtractCapsFilesAndBytes`, `TestExtractRefusesTraversalAndSymlinks`), plugin report size and result count (`TestOversizedReportFailsAndClosesNothing`); the rate-limit stop and the GitHub budget (`TestRunOnDemandStopsAtRateLimit`, `TestRunRespectsGitHubBudget`); no redirect on the GitHub status and on-demand reads (`TestStatusDoesNotFollowRedirects`, `TestGetJSONDoesNotFollowRedirects`); the NVD key never in an error (`TestNVDErrorsNeverCarryTheKey`).
- Plugins: the refusal proxy answers 403, refuses `CONNECT` and records denied attempts (`TestDenyProxyRefusesAndRecords`); a fake tool that tries a request through the proxy is denied, and the project tree is unchanged after the run (`TestPluginRunDeniesEgressAndNeverWritesInProject`); the tool's environment is an allowlist without the user's home (`TestEnvIsAnAllowlist`, `TestEnvNeverPassesTheUserHome`).

Declared only (not enforced by a test today):

- The refusal proxy stops only a tool that honours the proxy settings. A tool (or a program it starts) that opens its own connections is not stopped and does not appear in the log. It is a safeguard, not a guarantee.
- Trivy, Semgrep and their rules are installed and updated by you, outside Michel. Michel passes the switches that keep them offline but does not check what the tool does with them.
- The EPSS cap after decompression is in the code but no test exercises it (the KEV cap is tested).
- No test ties the URL each reader calls (for example `enrich.KEVURL`, `enrich.EPSSURL`) to the hosts of its catalog entry. If they drift apart, the gateway denies and logs the request; nothing is sent elsewhere.
- A dependency that uses `http.DefaultClient` or `http.DefaultTransport` directly would not be seen by the gateway. `internal/egress/boundary_test.go` (run by `go test ./...` in CI, and by `make lint`) parses the Michel code outside `internal/egress` and fails on `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, `http.Client{}` and `http.Transport{}` literals, `net.Dial`, `net.DialTimeout`, `net.DialTCP/DialUDP/DialIP/DialUnix`, `net.Dialer{}`, `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer{}` and `smtp.Dial`, but it does not read the dependencies. A test that installs a deny-all default transport is planned.

## Not yet

- A full proxy for subprocesses that lets only allowed hosts through (needed once fixes and dynamic tests run in an isolated environment). Today's refusal proxy denies everything.
- Michel does not yet remove the old rule on its own when the address of a source changes.
- Signed audit checkpoints (the audit log is hash-chained and tamper-evident, not signed).
- System keychain for secrets on Linux and macOS (libsecret, Keychain): secrets are DPAPI-encrypted files on Windows, plain files readable by the user only (0600) elsewhere.

## History

- Catalog version 4 (plan 4): the EPSS file moved to `epss.empiricalsecurity.com` (the former host `epss.cyentia.com` answers a permanent redirect, which the gateway would deny). If you had consented to the former host, that rule stays in your policy file and `enrich.epss` waits for your consent for the new one: run `michel source enable enrich.epss` to give it.
