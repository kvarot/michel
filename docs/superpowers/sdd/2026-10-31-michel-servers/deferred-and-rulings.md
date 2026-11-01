# Plan 6 (servers): rulings, deferred minors, residual risks

Written at the end of plan 6 (branch `feat/servers`). Each ruling was binding on the tasks that followed it; "costs" says what it gives up. The task ledger is `ledger.md` (mirrored by the controller). Fixtures in the tests are `demo`, `srv-demo`, `example.test`, `192.0.2.x`; no real project or server is named here.

## 1. Rulings

### Preflight rulings

| Ruling | Decision | Costs |
|---|---|---|
| R1 | Task 1 defines every inventory type Task 4 lists (OSInfo, PHPRuntime, WebServer, Package, Directive, FileSeen, Unseen). | Task 4 may need field tweaks (it did, a few). |
| R2 | Task 1 adds `scan.KindServerPackage` and `KindServerConfig`; Task 5 adds only `Mitigation`, `SAPI`. | None. |
| R3 | Task 2's `sshtest` offers `Options.Commands` and an empty shell hook; Task 9 adds `sshtest/shell.go`, a mini POSIX interpreter. | Task 9 grew one file. |
| R4 | Check, schedule, rematch and alerts live in a new package `internal/servercheck`; `internal/target` stays a leaf. | Names differ from the plan text. |
| R5 | Task 1 removes `server_fix_level` from the web code. | A small web diff in Task 1. |
| R6 | The egress `boundary_test.go` list of walked folders gets each new package in the task that creates it. | None. |

### Rulings made during the plan

| Ruling | Decision | Costs |
|---|---|---|
| R7 | A confirmed `target.HostKey` pins the host key **exclusively**; `known_hosts` is only used while it is empty. | A re-keyed server needs a new confirmation even if `known_hosts` was updated. |
| R8 | PHP branches older than 8.2 are treated as end of life and affected by PHP2Shell (the advised version is the lowest supported fixed one). | A false alarm if an old branch got an unofficial backport. |
| Task 4 | A missing parent folder reads "not read" instead of "missing" on GNU `readlink -f`. Kept as a display-only minor. | On GNU servers an absent folder shows "Michel could not read this file". |
| Task 6 | `vulnmatch.Match` returns `Result{Hits, Unjudged, ReleaseKnown, Skipped}`; an unparseable version or bound counts as affected (`Uncertain`). | Failing closed and visible, at the price of a bigger signature. |
| Task 7 (1) | Task 7 code lives in `servercheck` (see R4). | None. |
| Task 7 (2) | Distro advisories that name PHP2Shell CVEs feed `serverrules`, so the mitigation advice also applies to distro PHP. | A small `serverrules` API change. |
| Task 7 (3) | Unfixed distro advisories (no fixed version) are stored but never urgent unless in KEV. | A critical unfixed non-KEV CVE only shows in the digest. |
| Task 7 (4) | `CheckResult` carries `Unjudged`, `ReleaseKnown`, `SkippedAdvisories`: zero findings with an unknown release or unjudged packages is not "clean". | A bigger struct. |
| Task 7 (5) | "Only by hand" is `CheckInterval < 0` (stored -1, `target.ManualOnly`); 0 means the 24 h default. | The API and CLI must map "manual" to -1. |
| Task 8 | The Free Mobile login number is a plain policy field; only the key goes to the secret store. | The login number is readable in the policy file. |
| Task 9 (1) | Spec amendment § 8.1 bis: root-file scripts run **wholly as root** (`sudo -n sh -s`), backups and staging in `/var/lib/michel/backups/<id>`, `undo` refuses non-root backups, root never writes under `/home`; `.user.ini` scripts run as the SSH user with `~/.michel/backups`. | The executor must use `sudo -n sh -s`; scripts run by the user need root for root files. |
| Task 9 (2) | `test_config` allowlist: basename `php` / `php-fpm` with optional version, under `/usr/(local/)?s?bin`, shared by validation, rendering and lint. | PHP compiled under `/opt` is not testable. |
| Task 10 (1) | The rolled-back cause is stored as `digest.CauseRolledBack`; the text key is `fix.server.rolled_back`. | None. |
| Task 10 (2) | A root bundle with `sudo_mode != nopasswd`, or an untestable binary, is for the executor user only. | None. |
| Task 10 (3) | `ErrUntestableBinary` gives **no script at all**, not even for the user. | PHP outside system folders gets no scripted fix. |
| Task 10 (4) | A linked preprod that does not show the finding gives `ErrPreprodMissing` (fail closed). | The user must unlink or fix the preprod first. |
| Task 10 (5) | Apply scripts are exempt from the 60 s cap: 5 min for config bundles, 30 min for package bundles, no SIGKILL; past the bound or on SSH drop the state becomes `unknown`, urgent alert, recollection, no guessed undo. | A hung script can hold the attempt for up to 30 min. |
| Task 10 (6) | Package plans never use `CauseRolledBack`: failure or site down after an upgrade is `failed` (`package_failed`, `site_down_after_upgrade`) with an urgent "restore your snapshot". | No automatic package rollback (as specified). |
| Task 11 | `AutoApplicableServer` is also false when the server has a running or `unknown` attempt, a root bundle without `nopasswd`, or an untestable binary. | None. |
| Task 12 (1) | Adding a server (explicit user action) **is** the spec § 5.1 per-server opt-in: Michel writes its `target.ssh` and `target.http` rules then, never otherwise, and removes them with the server. The UI says so. | None. |
| Task 12 (2) | `unknown` has an exit: `fix.ResolveUnknown` (unknown to failed, cause `user_checked`, audited), `POST /fix/{id}/resolve`, `michel fix resolve`; deleting a server answers distinct messages for unknown and for user-run approved attempts. | One more state transition. |
| Task 12 (3) | Michel releases only the network rules **it wrote** for that server (owner recorded in `target_rule`); hand-written rules are never removed. | Servers added before migration 0016 own no rule: theirs stay (the safe side). |
| Task 13 | The manual browser check (Step 5) is done by the controller in the built-in browser, not by the implementer. | One controller pass. |

## 2. Deferred minors, by area

### SSH client (`internal/sshx`)

- `egress.DialLocalSocket` is exported and unaudited: restrict callers to `internal/sshx` in `boundary_test.go` or document it as agent-only.
- `ErrNoKeyAccepted` is matched on the x/crypto message "unable to authenticate": pin with a comment or test.
- `open()`: the return of `stop()` after `NewClientConn` is not checked (a context cancel race can return a closed client).
- A revoked key and an unreadable `known_hosts` are both audited as "error".
- `TestDialThroughGateway` "no TCP" check is weakly asynchronous; no audit test for a failed dial.
- `Quote` assumes a POSIX login shell (csh and fish differ); documented in `servers.md`.
- `known_hosts` that lists only types the server lacks gives a generic "no common algorithm" instead of the typed host-key-changed error (still refused before authentication). `@cert-authority` entries are ignored when deriving algorithms.
- A Windows Unix-socket agent path widens the agent surface; accepted because the path only comes from the user's policy.

### Discovery (`internal/target`)

- A broken `~/.ssh/config` scanner error fails all of `Discover` while a broken `.idea` is skipped silently; include errors are swallowed.
- `HostName`, `User`, `Port` are last-wins (OpenSSH is first-wins); `Host *` defaults are not applied.
- Known-host matching is case-sensitive and exact on the user; a HOME containing `[` breaks the `Include` glob; `~\` is not handled; an unparsable `deployment.xml` silently drops the remote folder; the include-depth test is weak.
- `PreprodID` and links: `Repo.Remove` leaves orphan findings; `target_project` rows are not cleaned when a project is purged; `FindByIDPrefix` crosses kinds; no test that project views and digest counts ignore server findings.

### Collection (`internal/collect`)

- Truncation is only checked for package lists (a truncated `php -i` or `php -r` is silent); a symlinked `.ini` is followed on health servers; `ErrRefusedPath` / `ErrHealthPath` are capitalised English outside i18n; a test ignores `rows.Scan` errors; a directive name has no length bound; Alpine has no package-owner lookup (the inventory implies "compiled").
- `homeRefusal`: a linked `RemoteDir` of `/home` or `/root` would open every home (now refused in `Repo.Link`); `not_read` shown for optional `.user.ini` probes if `LC_ALL` is ignored; the refusal text has a redundant tail; `id_*` over-refusal; a `.cnf` is readable (hashed only).
- `readlink` of a missing parent gives `not_read`, not `missing` (ruled, see above); `secretParam` does not match `authtoken=` / `api_key=`; `unseen()` takes the raw path; `runFile` refusal uses the raw path (unreachable); the doc comments of `runFile`/`run` are misplaced; `collect.go` is about 520 lines.
- `php-fpm -tt` as a non-root user may touch log or pid files; its stderr carries `env[]` values: nothing logs sshx stderr (checked at final review).
- An exit 127 with empty stdout (a shell without `command`) reads as "not installed": harden with a `command -v sh` sentinel.

### Rules and advisories (`internal/serverrules`, `internal/vulnmatch`)

- Inline `;` comments in `php.ini` lines are not stripped (`display_errors = On ; dev` is missed, a fail-open). Fix in `collect/files.go` and in `isOn` (listed as a final-wave must-fix).
- The PHP-VERSION-UNKNOWN finding has no i18n key: the UI maps it by OSV ID. The 8.2 date-based end of life (2026-12-31) is not modelled.
- The source version is not collected (only `${source:Package}`); Ubuntu Pro (ESM) ecosystems are not handled; the Rocky test lacks `Fixed`/`Uncertain` assertions; no real Alma or Rocky record was checked.
- `Match` has no repository: Task 7 checks `osvdb.Enabled` first. `Uncertain` appears only in the summary prose, not as a structured flag.
- The `ReasonTimeout` branch in `judge` is effectively dead; an unreadable `.user.ini` keeps every `fpm:` finding of the server open (documented).

### Scripts (`internal/serverfix`)

- One pool sets a directive and another does not: `php.ini` is not also fixed.
- Debian `conf.d` links into `mods-available` are refused (exit 6); BSD without `stat -c` gives exit 7.
- A `.user.ini` is accepted anywhere the collection read it (written as the SSH user only); intermediate links of a `readlink` chain (`/etc/alternatives`) are not checked one by one; dnf wrapped names; `.user.ini` `cache_ttl`.

### Execution, agent, levels (`internal/fix`)

- Old backups after a key rotation read "key lost" rather than "does not match"; a key mismatch audit needs its own reason; a hung `Alert` leaves one goroutine (accepted).
- Level-3 runner: in-memory maps are unbounded and the dedup key is unstable without a reason key; the agent folder is created before the id check; revoking a consent does not stop a live proposed session.
- `fix.server.agent_refused.simulation_limit` reads as an order to the user (FR pass).
- A failed or capped urgent alert is never re-sent (findings are fresh once; the digest lists them). The SMS 160 limit is counted in runes; accented French text falls to UCS-2 at 70 characters per segment, so 2 or 3 real segments (the cap counts one). The scoped-channel skip test covers the webhook only.

### API, CLI, pages

- A busy hint for a Michel-run approved fix on an unreachable server should name Refuse; the `ResolveUnknown` code-attempt guard is untested; the policy file and `target_rule` can drift on a partial failure; the CLI `changeRules` reads the startup policy; scheduler checks are not shown as "checking"; a backup size is the sealed size.
- Web (final wave): `canApproveServer` must refuse when `scripts_unreadable`; the `fix.intro_server` text says nothing changes without validation, false at level 3 (fix FR and EN); counts of raw findings vs merged cards (B11); an info banner shown as a red error (B12); a secret-store read error shows "key lost"; the server headline hides urgent project news; the merged card's proposal does not name the other runtime; the key `srvfix.rolled_back` is unused; "preprod critical but not urgent" is untested; the 21 FR keys added in the Task 13 fix round have not had the French review.
- A rule written before `target_rule` existed is never released (acknowledged, no backfill: it would mark hand-written rules as Michel's).

## 3. Residual risks

1. **PHP CLI is not the site's PHP.** Michel reads CLI and FPM when it finds them and says so, but cannot detect every layout (per-vhost settings, container PHP, a reverse proxy). Not detectable everywhere.
2. **The embedded PHP advisory list** (PHP2Shell and the rules) is current only as far as the installed version of Michel; there is no live feed for it.
3. **A Pageant agent is untested.** Only the OpenSSH named pipe and Unix sockets are covered by tests.
4. **Scripts run by the user are outside Michel's control.** They protect themselves (`set -eu`, trap, root check), but who runs them, when and with which shell is the user's choice.
5. **nginx and Apache are only reported**, never changed.
6. **Debian `conf.d` symlinks** into `mods-available` cannot be fixed by script (exit 6).
7. **BSD is not supported** (no `stat -c`, other service tools).
8. **A cPanel-style PHP tree** that is not the loaded `php.ini`, its scanned files, a pool or a `.user.ini` is not writable.
9. **IPv6 literal hosts are refused** (a network rule is a host name or IPv4).
10. **PHP outside the system folders** (compiled under `/opt`) has no config test and so no script.
11. **No automatic rollback of a package upgrade**; the snapshot made by the user is the way back, and Michel depends on the user having made it.
12. **A script that runs past its limit** leaves the attempt `unknown` until the user checks; a hung script can hold an attempt up to 30 minutes.
13. **Tests never touch a real server.** Everything is checked against an in-memory SSH server and a mini POSIX interpreter (also run against real dash, bash and busybox as root in WSL during Task 9). **The run on a real test server, by Kévin, is still to do.**
14. **Windows agent via a Unix socket** widens what can answer sign-in requests; the path is only read from the user's own policy file and must sit in a user-only folder.

## 4. Final wave (closed before merge)

- **One server fix at a time** (final review I1): for a server, `applied` and `unknown` count as busy (`CreateAttempt`, `serverBusy`, `NextQueued`, the level 3 guard, `TargetBlock`), and `Claim` refuses while another attempt of the same server is `running`, `applied` or `unknown` (one conditional `UPDATE … NOT EXISTS`).
- **Rollback exit** (I2): `rollback()` ends with its own `exit 9`; the new copies and the line checks (exit 5) come before the trap is armed; `classifyExit` reads codes 8/9 and the rollback lines first, and a code 3–7 only with its own line. A re-proposal after a moved line happens once; a second moved line alerts (`line_moved_again`) and prepares nothing.
- **Discovery sentinel** (I3, Task 7 deferred): `command -v sh …` must print a path to `sh`, else the lookup is `Unseen` (`discovery`), never "no PHP".
- **Unreadable scripts** (Task 13 n2) are refused by `approveServer` and by `canApproveServer`.
- **Texts**: `fix.intro_server` (F1), the 16 FR rewordings, the server alert webhook marker `michel_server_alert` (Task 14), the M6 regression test in `serverrules`, the unused key `srvfix.rolled_back` (n5), README scheduler and package rollback wording, the never-kills and redirect notes in `docs/servers*.md`, exit 4 for `undo`.
