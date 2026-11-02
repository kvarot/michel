# Network egress inventory (plans 1 to 6)

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
| `source.discover` | `api.github.com` | `source update` with `discover.github` enabled. Sends the topic names, plus your GitHub token if you set one. |
| `plugin.<key>` | none | Never allowed. The purpose of the requests that a tool run by Michel (Trivy, Semgrep) sends to the local refusal proxy; each one is denied and logged. |
| `fix.install` | `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com` (Composer archives), `registry.npmjs.org` | A fix attempt (plan 5), after the project's AI consent: Michel's own update of the copy, the install and the project's tests in the scratch folder. Through the allow proxy (below). Sends what any `composer`/`npm` run sends: the names and versions of the packages asked for. |
| `agent.claude` | `api.anthropic.com` (the API), `platform.claude.com` (renewal of a subscription login) | A fix attempt, after the project's AI consent: Claude Code, through the allow proxy. Sends what the agent reads and says: the code of the copy (excluded files are not copied), the masked brief and MCP answers, your messages. Claude Code knows other hosts (docs, downloads, telemetry, error reports, claude.ai connectors): Michel turns them off at launch; if Claude Code still tries them, the proxy refuses and records them. |
| `target.ssh` | the host of each server you added (any port) | Plan 6: a check of the server (`michel target check`, the schedule of `michel serve`, **Check now**) and the run of a fix you validated with `executor: michel`. A raw TCP connection through `Gateway.DialContext`, then the SSH handshake: the server's fingerprint is checked, the keys of your SSH agent are the only credential. Michel writes the rule when you add the server and removes the rules it wrote when you delete it. Sends nothing but the read commands listed in [servers.md](../servers.md) and, for a fix, the validated script. |
| `target.http` | the host of the `site_url` of each server | The check of the site after a fix, and the `Server` / `X-Powered-By` headers: a plain GET, redirects checked by the gateway. Written when you add a server that has a site address. |
| `notify.sms` | `smsapi.free-mobile.fr` for the Free Mobile provider, or the host of the `url` of a generic SMS channel | An urgent server alert only (a flaw exploited in the wild or critical on a production server, a failed rollback, an unknown state, a package upgrade to restore), at most `sms_per_day` (default 3). One short text, no version and no setting. Free Mobile: an HTTPS request carrying your login and its key (secret store). Generic: a signed POST like a webhook. Needs its own rule. |

The source hosts above are those of the embedded catalog (`internal/source/catalog/catalog.yaml`, version 4). A source you add yourself (`michel source add`) brings its own host, which you accept like the others. There is no other destination: no telemetry, no error reporting, no update check, and no AI provider besides Claude Code for the fix agent, after your consent.

Michel writes the rules of a source after your consent (`michel source enable`, or the Sources page): one `{host, purpose}` rule per host, with a `.bak` copy of the policy file. See [sources.md](../sources.md).

The rules of the fix agent (`agent.claude` and `fix.install`) are written by the project's AI consent (the consent screen of the Fix page, or `michel fix consent <project> --yes`), which also turns `ai.external_providers_enabled` on; under `strict_local`, only the explicit button of the page switches the policy to standard. See [fix.md](../fix.md).

## Local only, no network

| What | Why it is not egress |
|---|---|
| Desktop notification (`toast` channel) | A local subprocess with a fixed command line (Windows PowerShell 5.1 from `%SystemRoot%`, `notify-send`, `/usr/bin/osascript`); the text is passed as data on stdin or after `--`. No socket, no rule needed. |
| `michel serve` (Today page and `/api/v1`) | A listener on a loopback address only (127.0.0.1, [::1] or localhost; any other `--listen` is refused). It accepts connections from this computer and makes no outbound connection. API calls need the local access token. |
| Decisions, digest without `--send`, secrets | Read and write the data folder only. |
| Plugins (Trivy, Semgrep) | A subprocess with a fixed argument list, started from `<data dir>/plugins/<tool>/`, with an allowlisted environment (no secret or token) and its proxy variables pointing to the refusal proxy (`internal/egress/denyproxy`, on `127.0.0.1`, a free port). The proxy answers 403 to every request, refuses every `CONNECT` and records each try as a denied `egress.attempt` (purpose `plugin.<key>`, at most 200 recorded per run; later ones are still refused, without being recorded). See [sources.md](../sources.md). |
| MCP servers | Michel fetches and pins the source (purpose `source.repo`) but never starts the server. The `claude mcp add` line is yours to run; a server started with `npx` downloads at start-up, outside Michel. |
| Fix work copy and branch | `git` runs locally only: the private mirror is cloned from your repository on disk, the agent's copy is filled from it, and the approved branch is fetched from the mirror into your repository. No remote is contacted. Although these steps use no network, the programs that run them get the `fix.install` proxy setting too. |
| `michel mcp` | Started by Claude Code as a subprocess, it talks over stdin/stdout (stdio) only; it never listens on the network. |

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
- The allow proxy (`internal/egress/allowproxy`, plan 5) is the only proxy that lets traffic through. Michel starts one per attempt and per purpose (`fix.install`, `agent.claude`), on `127.0.0.1` and a free port, and closes it at the end.
  - Access: it requires a random token (`Proxy-Authorization`; URL `http://michel:<token>@127.0.0.1:<port>`). The token goes in the environment only (`HTTPS_PROXY`, `HTTP_PROXY`, npm's proxy settings), never on a command line, in the audit or in an error message.
  - What it lets through: a `CONNECT` tunnel to port 443 only, and only if the gateway allowed that host for that purpose. Plain HTTP, another port or a malformed target is refused.
  - What it records: every decision of the gateway is an `egress.attempt` in the audit log, and so are the proxy's own refusals, at most 200 per proxy; beyond that, later ones are refused without being recorded. The proxy records the opening of a tunnel, not the requests that then go through it: a program that keeps the same tunnel shows up once.
  - Limits: 64 tunnels at once; a tunnel idle for 5 minutes is closed.
- The subprocesses of a fix (git, composer, npm, the tests, Claude Code) get an allowlisted environment, never Michel's whole environment. composer, npm and the tests use Michel's home folder (`<data>/fix-home`); Claude Code gets your profile folder as its home only to find its login, and none of the variables that would send it to another provider (such as `ANTHROPIC_BASE_URL`).

## Tested vs declared only

Tested (automated tests):

- A scan makes zero network requests (zero-egress scan test).
- A denied redirect is refused and audited.
- `DialContext` refuses a host without rule, a non-TCP network, and fails closed when the audit cannot be written.
- `michel serve` refuses a non-loopback `--listen` address; the API answers 401 without the token.
- The download, entry-count and uncompressed-size caps.
- Sources: a source waiting for consent makes zero egress attempts during an update (`TestRunSkipsWaitingConsentWithoutNetwork`); consent writes the rule, creates the policy file when absent and records `source.consent`, and the gateway applies new rules without restart (`TestEnableWritesRuleRecordsConsentAndReloads`, `TestEnableCreatesPolicyFileWhenAbsent`, `TestGatewaySetRulesTakesEffect`); a host change sends the source back to waiting for consent (`TestSyncHostChangeWaitsForConsentAgain`).
- Hosts of the sources: `source update` reads every catalog entry with a reader, one at a time, with the readers' real URLs (only the part that actually sends the requests is replaced, by a stand-in that answers "not found" (404) without touching the network) and a witness sink; every attempt must be to a host of that entry, for its purpose, and leave an `egress.attempt` audit event (`TestUpdateContactsOnlyTheCatalogHosts`). If a reader aims at a host missing from the list declared for its source, this test fails. The fixed GitHub endpoints (API and archives), used for the skills, MCP servers and discovery, are compared with the allowed hosts of the catalog (`TestBaseURLHostsAreInTheCatalog`).
- Caps of the source readers: KEV body (`TestReadKEVCapsBody`), size of the EPSS file after decompression (`TestReadEPSSCapsDecompressedText`), on-demand answers (`TestRunOnDemandCapsBody`), feeds at 5 MB and 200 items (`TestRSSReaderCapsAndSanitizes`), archive files and bytes, traversal and symbolic links (`TestExtractCapsFilesAndBytes`, `TestExtractRefusesTraversalAndSymlinks`), plugin report size and result count (`TestReportOverTheSizeCapFailsAndClosesNothing`, `TestOversizedReportFailsAndClosesNothing`); the rate-limit stop and the GitHub budget (`TestRunOnDemandStopsAtRateLimit`, `TestRunRespectsGitHubBudget`); no redirect on the GitHub status and on-demand reads (`TestStatusDoesNotFollowRedirects`, `TestGetJSONDoesNotFollowRedirects`); the NVD key never in an error (`TestNVDErrorsNeverCarryTheKey`).
- Plugins: the refusal proxy answers 403, refuses `CONNECT` and records denied attempts (`TestDenyProxyRefusesAndRecords`); a fake tool that tries a request through the proxy is denied, and the project tree is unchanged after the run (`TestPluginRunDeniesEgressAndNeverWritesInProject`); the tool's environment is an allowlist without the user's home (`TestEnvIsAnAllowlist`, `TestEnvNeverPassesTheUserHome`).
- Fix agent, allow proxy: the proxy URL carries a token and a request without it is refused (`TestListenReturnsProxyURLWithToken`, `TestAllowProxyRequiresToken`); an allowed host is tunnelled (`TestAllowProxyTunnelsAllowedHost`, `TestAllowProxyAcceptsHostHeaderWithoutPort`); an unknown host, a rule of another purpose, plain HTTP and malformed targets are refused and recorded (`TestAllowProxyRefusesUnknownHost`, `TestAllowProxyRefusesWrongPurpose`, `TestAllowProxyRefusesPlainHTTP`, `TestAllowProxyRefusesMalformedTargets`), without echoing the request (`TestAllowProxyAnswersNoEcho`); the caps and the closing (`TestAllowProxyCapsConcurrentTunnels`, `TestAllowProxyCapsRecordedRefusals`, `TestAllowProxyCloseEndsTunnels`, `TestAllowProxyIdleTunnelTimesOut`). The proxies dial only through `Gateway.DialContext` (`TestProxyPackagesDialOnlyThroughGateway`), and the automatic code check that looks for direct network access also covers `internal/workcopy` and `internal/agent`.
- Fix agent, environment and isolation: the environments of git, composer, npm, the tests and Claude Code are allowlists that carry the proxy (`TestExecEnvIsAllowlisted`, `TestEnvAcceptsProxyURL`, `TestLaunchEnvAllowlisted`); Claude Code is launched with a closed command line, no Bash, no web tool and none of the user's or the project's settings (`TestLaunchArgvIsClosedAndIsolated`, `TestLaunchDeniesBash`, `TestLaunchLoadsNoProjectOrUserSettings`); git hooks planted in the copy, the mirror or Michel's folders do not run (`TestPlantedHooksDoNotRun`); the MCP server has no approval tool (`TestMCPHasNoApprovalTool`).
- Fix agent, consent: the consent writes the rules of `AgentHosts` and `InstallHosts`, turns external providers on and records `ai.consent` (`TestGiveConsentWritesRulesAndAudit`, `TestConsentScreenPerProject`); `strict_local` is left only on the user's click (`TestConsentSwitchesStrictLocalOnTheClick`, `TestConsentSwitchesStrictLocalOnlyOnTheClick`); an attempt does not start without consent, for a health project, or under `strict_local` (`TestStartNeedsConsent`, `TestStartRefusesHealthEvenWithConsent`, `TestStartRefusesStrictLocalWithoutExternalProviders`).
- Fix agent, the user's project: nothing is written in it while the copy is prepared (`TestPrepareNeverWritesInProject`), and applying adds only the branch, the working tree and the index untouched (`TestApplyLeavesWorkingTreeUntouched`).

Declared only (not enforced by a test today):

- The refusal proxy stops only a tool that honours the proxy settings. A tool (or a program it starts) that opens its own connections is not stopped and does not appear in the log. It is a safeguard, not a guarantee.
- Trivy, Semgrep and their rules are installed and updated by you, outside Michel. Michel passes the switches that keep them offline but does not check what the tool does with them.
- The installation of a skill or MCP server is not tested end to end against the allowed hosts of the catalog; only its fixed endpoints are checked to be among them (`TestBaseURLHostsAreInTheCatalog`).
- A dependency that uses `http.DefaultClient` or `http.DefaultTransport` directly would not be seen by the gateway. `internal/egress/boundary_test.go` (run by `go test ./...` in CI, and by `make lint`) parses the Michel code outside `internal/egress` and fails on `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, `http.Client{}` and `http.Transport{}` literals, `net.Dial`, `net.DialTimeout`, `net.DialTCP/DialUDP/DialIP/DialUnix`, `net.Dialer{}`, `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer{}` and `smtp.Dial`, but it does not read the dependencies. A test that installs a deny-all default transport is planned.
- The allow proxy stops only a program that honours the proxy settings. Claude Code, git, composer, npm, the project's tests, or a program they start, could open their own connections: they would be neither stopped nor recorded. It is a safeguard, not a guarantee.
- The list of Anthropic hosts (`fix.AgentHosts`) was read from Claude Code 2.1.314. Another version may need another host: the attempt then fails, and the refusals are recorded in the audit log (`michel audit list`). You can add the missing host yourself in `sovereignty.network.allow` with the purpose `agent.claude`, or wait for a version of Michel that knows it. Another version may also honour differently the variables that turn its other traffic off.
- The install and the tests run with your rights, without an operating-system sandbox: code they run (the project's, or the agent's) is not confined to the proxy. See "Residual risks" in [fix.md](../fix.md).

## Not yet

- An isolated environment (sandbox) for the install and the tests of a fix. The allow proxy exists since plan 5, but it does not confine a program that ignores it.
- Michel does not yet remove the old rule on its own when the address of a source changes.
- Signed audit checkpoints (the audit log is hash-chained and tamper-evident, not signed).
- System keychain for secrets on Linux and macOS (libsecret, Keychain): secrets are DPAPI-encrypted files on Windows, plain files readable by the user only (0600) elsewhere.

## History

- Catalog version 4 (plan 4): the EPSS file moved to `epss.empiricalsecurity.com` (the former host `epss.cyentia.com` answers a permanent redirect, which the gateway would deny). If you had consented to the former host, that rule stays in your policy file and `enrich.epss` waits for your consent for the new one: run `michel source enable enrich.epss` to give it.
