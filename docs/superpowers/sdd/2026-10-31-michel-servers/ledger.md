# SDD ledger — plan: docs/superpowers/plans/2026-10-31-michel-servers.md

Spec: docs/superpowers/specs/2026-10-31-michel-plan6-servers-design.md (reachable).
Branch: feat/servers (created in Task 1 from docs/plan6-design tip b1bd375).

## Preflight scan

| tasks | shared file / interface | produced vs consumed | finding |
|---|---|---|---|
| 1 / 4 | `internal/target/target.go` inventory types | T1 declares `Inventory` whose field types are "detailed in Task 4" | gap: T1 cannot compile without them → R1 |
| 1 / 5 | `scan.KindServerPackage/Config` | T1 test filters `server_%` kinds; T5 defines constants | order → R2 |
| 2 / 9 | `sshtest` `sh -s` interpreter "limited to Task 9 grammar" | T2 runs before T9 defines grammar | conflict → R3 |
| 2 / 7 / 1 | package graph `target` ↔ `sshx` ↔ `collect` | T7 puts `Check` in `target` using `sshx`,`collect`, which import `target` | import cycle → R4 |
| 7 / 8 / 10 / 11 | `target.AlertInput` | defined T7, consumed T8/T10/T11 | renamed by R4 |
| 1 / 13 | `server_fix_level` drop vs web FixSettings/api.js | T1 drops column + API field, web still may send it until T13 | breakage window → R5 |
| 9 / 10 / 13 | `serverfix.Bundle`, sshtest shell | T9 produces, T10 executes on sshtest, T13 demo | consistent after R3 |
| 10 / 11 | `internal/fix/*` | sequential edits, T11 extends T10 types | ok |
| 6 / 7 | `vulnmatch.Match/Findings`, `ErrSourceDisabled` | T6 produces, T7 consumes | ok |
| 5 / 7 | `serverrules.Rules/Evaluate` | ok | ok |
| 12 / 2,4,9,10,11 | typed errors → i18n | ok | ok |

Per task self-consistency: T1 ok after R1/R2; T2 ok after R3; T3 ok; T4 ok (tests use sshtest command handlers only); T5 ok; T6 ok (fixture zip fabricated); T7 ok after R4; T8 ok; T9 ok after R3 (adds sshtest shell); T10 ok; T11 ok; T12 ok; T13 ok (demo cmd uses T9 shell); T14 ok.

Ruling R1: Task 1 defines every inventory type listed in Task 4's Interfaces (OSInfo, PHPRuntime, WebServer, Package, Directive, FileSeen, Unseen) — the struct must exist to store it — costs: Task 4 may need field tweaks.
Ruling R2: Task 1 adds `scan.KindServerPackage="server_package"`, `scan.KindServerConfig="server_config"` in scan/normalize.go; Task 5 adds only `Mitigation`, `SAPI` fields — costs: none.
Ruling R3: Task 2's sshtest offers `Options.Commands` handlers and an empty shell hook; Task 9 adds `internal/sshx/sshtest/shell.go`, a mini POSIX interpreter for exactly the grammar it renders — costs: Task 9 grows one file.
Ruling R4: check/schedule/rematch/alerts move to new package `internal/servercheck` (`servercheck.CheckDeps`, `Check`, `CheckResult`, `Rematch`, `Scheduler`, `AlertInput`, `Urgent`); `internal/target` stays a leaf (types, repo, discovery) imported by sshx/collect — avoids import cycle — costs: names differ from plan text.
Ruling R5: Task 1 also removes `server_fix_level` from web (api.js payloads, FixSettings grayed row stays as text only, no field sent) so the UI never sends a now-rejected field — costs: small web diff in Task 1.
Ruling R6: boundary_test.go "dirs walked" list gets each new package in the task that creates it (sshx T2, collect T4, serverfix T9), not in Task 1 (dirs absent then) — costs: none.

## Progress
Task 1: dispatched (BASE b1bd375, implementer a36f57809ba8bfb44, sonnet)
Task 1: complete (commits b1bd375..8b2997c, review clean; ⚠️ web grep verified by controller: no server_fix_level in web/src)
Task 1: minor (deferred): target.Repo.Add stores FixLevel 0 / CheckInterval 0 when unset (spec default 1 / 24h) — Task 12 API/CLI add must apply defaults (carried to T12 dispatch)
Task 1: minor (deferred): PreprodID not validated (exists, not self)
Task 1: minor (deferred): target Remove leaves orphan findings; target_project rows not cleaned on project purge; FindByIDPrefix cross-kind
Task 1: minor (deferred): no test that project view/digest counts ignore server findings
Task 2: dispatched (BASE cc531d5, implementer a4a724694b6b9d16d, opus)
Ruling R7: a confirmed target.HostKey pins the host key exclusively (known_hosts consulted only when HostKey is empty) — stricter than "fingerprint or known_hosts", safer against a stale known_hosts entry — costs: a re-keyed server needs re-confirmation even if known_hosts was updated.
Task 2: review — Needs fixes (1 Important: default HostKeyAlgorithms order gives false ErrHostKeyChanged with Ed25519-only known_hosts; Fingerprint shows ECDSA)
Task 2: minor (deferred): egress.DialLocalSocket exported & unaudited — restrict callers to internal/sshx in boundary_test or document agent-only
Task 2: minor (deferred): ErrNoKeyAccepted matched on x/crypto message "unable to authenticate" — pin with comment/test
Task 2: minor (deferred): open(): stop() return not checked after NewClientConn (ctx cancel race returns closed client)
Task 2: minor (deferred): revoked key / unreadable known_hosts both audited as "error"
Task 2: minor (deferred): TestDialThroughGateway "no TCP" check async-weak; no audit test for failed Dial
Task 2: minor (deferred): Quote assumes POSIX login shell (csh/fish differ) — document in docs/servers
Task 2: minor (deferred): ErrNoAgent wraps socket path text — API must show sentinel only (carry to T12)
Task 2: ⚠️ ssh.agent_pipe setting not wired (only SystemAgent(path)) — carry to T12 serve wiring
Task 2: fix round 1/5 (1 addressed, 0 open — host key algorithms from known_hosts, Ed25519 preferred; commits af71400..2b50f6d)
Task 2: minor (deferred): known_hosts listing only types the server lacks → generic "no common algorithm" instead of typed ErrHostKeyChanged (still refused pre-auth)
Task 2: minor (deferred): @cert-authority entries ignored when deriving algorithms
Task 2: complete (commits cc531d5..2b50f6d, review clean)
Task 3: dispatched (BASE e4f1aa0, implementer a48ebb893bfa50113, sonnet)
Task 3: complete (commits e4f1aa0..b50ec2e, review clean)
Task 3: minor (deferred, LIKELY MUST-FIX before merge — real PhpStorm recall): webServers.xml servers using a saved SSH configuration carry only sshConfigId/sshConfig="user@host:22", skipped today
Task 3: minor (deferred): ~/.ssh/config scanner error fails all Discover while broken .idea skipped silently; include errors swallowed
Task 3: minor (deferred): HostName/User/Port last-wins (OpenSSH first-wins); Host * defaults not applied
Task 3: minor (deferred): Known matching case-sensitive & exact on user; HOME with [ breaks Include glob; ~\ not handled; unparsable deployment.xml silently drops RemoteDir; include-depth test weak
Task 4: dispatched (BASE b50ec2e, implementer a13329831690433be, opus)
Task 4: automated security review (2 MEDIUM, collect/parse.go): (a) secretPrefixesOK skips name check for session./opcache./… — session.save_path "tcp://h:6379?auth=pw" leaks; word list lacks auth/credential/pw/license; (b) php -i 3-part lines parsed outside directive sections (Environment / PHP Variables). Both accepted as real → join Task 4 fix round with reviewer findings.
Task 4: review — Needs fixes (3 Important: user paths not limited to config / /home of others; missing-vs-unreadable relies on English locale; FPM directives not tied to a runtime) + 2 security MEDIUM → fix round 1
Task 4: minor (deferred): truncation checked only for packages (php -i / php -r truncation silent); symlinked .ini followed on health; ErrRefusedPath/ErrHealthPath capitalized English bypassing i18n; test ignores rows.Scan errors; directive name length unbounded; Alpine has no package owner lookup (inventory implies "compiled")
Task 4: ⚠️ php-fpm -tt as non-root may touch log/pid; -tt stderr carries env[] values — verify nothing logs sshx stderr (final review)
Task 4: fix round 1/5 (4 addressed, 1 open — maskParams misses phpredis auth[]= form; commits 74745ea..a4f7dbd)
Task 4: minor (deferred): homeRefusal — linked RemoteDir "/home" or "/root" would open every home; not_read shown for optional .user.ini probes if LC_ALL ignored; refused text redundant tail; id_* over-refusal; .cnf readable (hashed only)
Task 4: automated security review of a4f7dbd (2 MEDIUM: secretSegment only *key suffix; symlinked config bypasses name-only path check) accepted → added to fix round 2
Task 4: fix round 2/5 (3 addressed, 1 new open — readlink -f gated by binaryRe aborts whole collection on config path with space; commits a4f7dbd..7af4096)
Task 4: minor (deferred): readlink failure on missing parent → not_read instead of missing; secretParam doesn't match authtoken=/api_key= params; unseen() raw p vs cleanPath
Task 4: fix round 3/5 (regression addressed — readlink gated like head, shape refusal is per-file Unseen; commits 7af4096..f2c10ef)
Ruling: Task 4 parent-folder "missing" vs "not_read" (GNU readlink -f silent) stays deferred Minor — it was a Minor (round-1 re-review) the controller folded into round 3; display-only, no security impact — costs: on GNU servers an absent folder shows "Michel n'a pas pu lire ce fichier" instead of "absent"; also the test mock prints "No such file" unlike GNU readlink (fix mock in final wave).
Task 4: minor (deferred): runFile refusal uses raw p (unreachable); runFile/run doc comments misplaced in collect.go; collect.go ~520 lines
Task 4: complete (commits b50ec2e..f2c10ef, review clean after 3 rounds; 1 minor ruled deferred)
Ruling R8: Task 5 treats PHP branches < 8.2 as EOL and vulnerable to PHP2Shell (no fixed version on the branch; advised = lowest supported fixed) — spec silent; safest reading — costs: a false alarm if an old branch got an unofficial backport.
Task 5: dispatched (BASE 24b3e40, implementer a0ab95bfab68f76dc, sonnet)
Task 5: automated security review (MEDIUM, eval.go): .user.ini directive overrides runtime value even for PHP_INI_SYSTEM directives (allow_url_include, expose_php) and when Binary empty → false 'not risky' (fail-open). Accepted → joins Task 5 fix round.
Task 5: implementer DONE (commits 24b3e40..9be7b7e incl. FR fix); review dispatched (opus)
Task 5: review — Needs fixes (3 Important: I1 .user.ini fail-open incl. per-site + php_admin precedence; I2 pool php_admin_value[]/php_flag[] unmatched; I3 unreadable compiled version skipped silently; 7 minors in task-5-review.md) → fix round 1 sent to implementer
Task 5: fix round 1/5 (3 Important + M1-M4,M7 addressed; M5,M6 skipped; commits 9be7b7e..ef7f416) → re-review
Task 5: complete (commits 24b3e40..ef7f416, re-review clean)
Task 5: minor (deferred, Task 6 input): M5 open distro advisories passed to Evaluate (PHP2Shell via distro backport) — carry to T6 dispatch
Task 5: minor (deferred, MUST-FIX final wave): M6 inline ";" comments not stripped — "display_errors = On ; dev" missed (fail-open); fix in collect/files.go + strip in isOn
Task 5: minor (deferred): PHP-VERSION-UNKNOWN finding has no i18n Key — UI (T13) must map by OSVID; 8.2 date-based EOL (2026-12-31) not modelled
Task 6: dispatched (BASE 9d8e545, implementer a229f5e724012fc42, sonnet)
Task 6: implementer DONE_WITH_CONCERNS (commit cab6be2; unparsable versions skipped silently, CVSS vector-only → unknown, Ubuntu Pro, binary vs source version) → review dispatched (sonnet) incl. concerns
Task 6: review — Needs fixes (5 Important: I1 unparseable version/bound fail-open; I2 unknown release looks clean; I3 CVSS vector unscored; I4 one finding per binary, unstable IDs; I5 RPM/Alpine lookup by Source only) → fix round 1
Ruling: vulnmatch.Match returns Result{Hits, Unjudged, ReleaseKnown, Skipped} instead of []Hit; unparseable version/bound counts as affected (Hit.Uncertain); Findings takes Result — fail closed and visible beats brief signature — costs: Task 7 brief text names []Hit (carry to T7 dispatch).
Task 6: minor (deferred, T7 input): Match has no repo — Task 7 must check osvdb.Enabled before Match to raise ErrSourceDisabled for a disabled source with archive present
Task 6: minor (deferred): source version not collected (collect reads only ${source:Package}); Ubuntu Pro (ESM) ecosystems not handled
Task 6: fix round 1/5 (I1-I5 + M2 part, M6, M7 addressed; M1, M2 Pro, M4, M5 skipped; commits cab6be2..b8a9e0c; tests written with fix, not seen failing) → re-review
Task 6: complete (commits 9d8e545..b8a9e0c, re-review clean)
Task 6: minor (deferred, T7 input): surface ReleaseKnown=false, Unjudged, Skipped>0 — zero hits with any of these is not "clean"; Uncertain only in summary prose (no structured flag)
Task 6: minor (deferred): Rocky test lacks Fixed/Uncertain asserts; no real Alma/Rocky record checked
Ruling: Task 7 code lives in internal/servercheck (R4); files check.go/findings.go/schedule.go/check_test.go there; names servercheck.CheckDeps/Check/CheckResult/Rematch/Scheduler/AlertInput/Urgent.
Ruling: Task 7 closes Task 5 M5 — Check passes distro vulnmatch hits whose Aliases include CVE-2026-109618/109619 to serverrules so PHP2Shell mitigation advice is evaluated for distro runtimes too (minimal additive signature change) — spec 7.2 wants mitigation advice whatever the install source — costs: small serverrules API change.
Ruling: Task 7 unfixed distro advisories (no Fixed version) are stored as findings but never Urgent unless KEV — avoids daily alert floods from Debian unfixed CVEs while keeping them visible — costs: a critical unfixed non-KEV CVE alerts only in the digest.
Ruling: Task 7 CheckResult gains Unjudged int, ReleaseKnown bool, SkippedAdvisories int; zero findings with ReleaseKnown=false or Unjudged>0 is not shown "clean" — fail visible — costs: brief struct grows.
Task 7: dispatched (BASE cd66b8d, implementer a056179903c44726c, opus)
Task 7: implementer DONE_WITH_CONCERNS (commit ea6d4f4; ApplyServerFindings gains ServerApply{Unread,Enriched} + superseded; CheckDeps gains Audit, Lookup; EvaluateWith Options{DistroOpen})
Ruling: "seulement à la main" (spec) = CheckInterval < 0 (stored -1), Due skips it; 0 = default 24h — my T7 ruling 8 had erased manual-only — costs: Task 12 API/CLI must map "manual" to -1 → added to T7 fix round + carry to T12.
Task 7: ⚠️ carry to T10: apply turns missing findings into gone — must not overwrite proven_fixed
Task 7: ⚠️ carry to T8: Alert nil in michel serve until alert channel exists
Task 7: review — spec ❌ (manual-only missing), Needs fixes (3 Important: I1 manual-only; I2 distro mitigation findings gone when packages unjudged; I3 partial collection closes PHP findings then re-alerts) → fix round 1 (+ minors: db update rematch, inactive target, PHP-VERSION-UNKNOWN urgent in prod, no user@host in scheduler log)
Task 7: fix round 1/5 (I1-I3 + minors db-update rematch, ErrInactive, PHP-VERSION-UNKNOWN urgent, scheduler log, stale rematch guard, no re-alert on decided, RematchError; M8 skipped with reason; commits ea6d4f4..f181756) → re-review
Task 7: ⚠️ carry to T12: API/CLI "manual" → CheckInterval -1 (target.ManualOnly)
Task 7: re-review round 1 — I1-I3 + M1-M7 addressed; new N1 Important (command -v exit 127 on dash/busybox = discovery failed forever), N2-N4 minor → fix round 2
Task 7: fix round 2/5 (N1-N4 addressed; N3 also protects os-package findings on Skipped>0; commits f181756..5313ca9) → re-review
Task 7: complete (commits cd66b8d..5313ca9, re-review clean after 2 rounds)
Task 7: minor (deferred, final wave): exit 127 with empty stdout (shell lacking `command`) silently = "not installed" → only cli:/fpm: config findings could close; harden with a `command -v sh` sentinel
Task 7: minor (deferred): ReasonTimeout branch in judge effectively dead; unreadable .user.ini keeps all fpm: findings of the server open (broad, document in docs/servers)
Task 8: dispatched (BASE e726bed, implementer af0106e74c034224d, sonnet)
Task 8: implementer DONE_WITH_CONCERNS (commit 0ece193; migration 0013_sms_count; signedPost shared with webhook; Alert wired via internal/cli/servercheck.go)
Ruling: Free Mobile `user` (account login number) stays a plain policy field, only the API key goes to secret.Store — it is an identifier like a mail address, useless without the key — costs: the login number is readable in the policy file.
Task 8: ⚠️ carry to T13: server link is <page_url>/#/servers/<id> (hash routing) — route must exist
Task 8: ⚠️ carry to T10: digest counts rolled back = fix_attempt state failed + cause digest.CauseRolledBack for target id — T10 must write exactly that
Task 8: automated security review (MEDIUM, notify/server.go): SendServerAlert ignores channel project scope — a channel limited to some projects (e.g. a client's webhook) receives server alerts; Filter excludes scoped channels for digest. Accepted → joins Task 8 fix round (skip Scoped notifiers with Projects(), or explicit per-channel server opt-in).
Task 8: review — spec ✅, Needs fixes (1 Important: notify build failure drops alert silently; + controller Important: Rematch never alerts, Task 7 spec requires it; + security MEDIUM scoped channels) → fix round 1 (+ minors local-time day, SMS ≤160, concurrent Take test, url override doc); minor deferred: failed urgent alert never re-sent (digest shows it)
Task 8: fix round 1/5 (security scoped skip, build-failure audit, minors; rematch alert already via judge→alertNew, verified by controller check.go:176/267; commits 0ece193..b6158d4) → re-review
Task 8: minor (deferred): skipped (cap) or failed urgent alert never re-sent — findings fresh once; digest lists them
Task 8: complete (commits e726bed..b6158d4, re-review clean)
Task 8: minor (deferred): SMS 160 counted in runes; accented FR → UCS-2 70/segment, worst case 2-3 segments (cap counts one); scoped-skip test covers webhook only
Task 9: dispatched (BASE 19254a8, implementer a6168524c8038913b, opus)
Task 9: automated security review (2 HIGH, in-progress serverfix): (a) .user.ini passed to php -c as root → extension load / privesc; (b) root cp/cat follows symlinks on user-writable .user.ini. Accepted → sent to implementer before commit (no -c on .user.ini, -L guards, .user.ini steps as owner).
Task 9: implementer DONE (commit 7181a57; 2 HIGH fixed pre-commit: no php -c on .user.ini, -L guards, .user.ini steps as SSH user only; Action gains Key/Line/Append/Binary/Manager)
Task 9: automated security review of 7181a57 (HIGH: backups in $HOME used by root — user can swap backup then undo restores it into php.ini as root; MEDIUM: -L check then root cp TOCTOU, parent chain not checked; MEDIUM: package_upgrade allows downgrade, no version-order check). Accepted → join Task 9 fix round with reviewer findings.
Task 9: ⚠️ carry to T10: run simulation and ParseSimulation before apply; a failed apply refuses the same correction ID (exit 4) → new ID for retry; Bundle.Explain English, i18n display in T10/11
Task 9: review — spec ✅ (amendment needed), Needs fixes (2 Critical: C1 root-mode backups/staging in SSH user's $HOME → root code exec; C2 test_config runs any inventory binary as root, Lint accepts '/bin/sh' -c; 8 Important: I1 TOCTOU/parent chain, I2 downgrade, I3 ParseSimulation fails open, I4 apt --no-remove / apk pin / ucf, I5 sh -s stdin read, I6 rollback failure invisible, I7 Place first php_admin line not last, I8 risky values accepted; 10 minor)
Ruling: spec amendment § 8.1 bis (committed with this round): root-file scripts run wholly as root (uid check at top, "lance ce script en root"), Michel sends them by `sudo -n sh -s`, no per-line sudo; backups/staging in /var/lib/michel/backups/<id> (root, mkdir -m 700, no link); undo refuses non-root-owned backups; root writes only in root-owned non-other-writable dirs, never /home; .user.ini scripts run as SSH user with ~/.michel/backups — closes C1/I1 — costs: Task 10 executor must use sudo -n sh -s; user-run scripts need root for root files (already said).
Ruling: test_config binary allowlist — basename php|php-fpm with optional version, under /usr/(local/)?s?bin, shared by Validate, Render and Lint — closes C2 — costs: PHP compiled under /opt is not testable → correction proposed executor user only.
Task 9: fix round 1 → implementer (C1, C2, I1-I8, minors 1,2,4,8; others listed)
Task 9: fix round 1/5 (C1, C2, I1-I8, minors 1,2,4,8 + 3,9 doc; skipped 5,6,7,10; commits d5ce052..c2328eb; implementer caught quoted-case bug that sshtest shell missed) → re-review (opus)
Task 9: ⚠️ carry to T10: Bundle.RunAsRoot → sudo -n sh -s; ParseSimulation(manager,out,pkg,version); errors ErrAmbiguous/ErrUntestableBinary/ErrDowngrade/ErrNotValidated/ErrSimulation; exit codes 3 user,4 applied,5 line moved,6 link,7 unsafe dir/backup,8 rollback failed (urgent); stored plan re-validated before Render; php -c stderr = failure; consider diff before Undo
Task 9: minor (deferred): one pool sets directive, another not → php.ini not also fixed; Debian conf.d symlinks into mods-available refused (exit 6); BSD without stat -c → exit 7
Task 9: re-review round 1 — C1, C2, I1-I6 fixed (real-shell runs dash/bash/busybox as root in WSL: 88/88); new I-N1 (isOn misses "1x"/"1.0" ⇒ allow_url_include bypass, also false negative in evaluation), I-N2 (root may write any .ini/.conf under /etc, target file owner unchecked) + minors N3-N8 → fix round 2 (N9 apk install of forged-inventory pkg, N10 display_errors=stderr skipped)
Task 9: ⚠️ carry to T10: hash must be stored/checked together with target ID and correction ID, never alone
Task 9: fix round 2/5 (I-N1, I-N2, N3-N8, conf.d ErrLinkedFile; N9 → T10 simulation right before apply; N10 moot; cPanel tree dropped; merged-sbin Fedora fails closed exit 7; commits c2328eb..57740b4) → re-review
Task 9: re-review round 2 — clean (real-root dash/bash/busybox 78/79, the one failure = N-b); 6 minors N-a..N-f → short fix round 3 while implementer has context
Task 9: ⚠️ carry to T10: package simulation runs in the same SSH session right before apply (N9)
Task 9: fix round 3/5 (N-a..N-f; commits 57740b4..6d6b820) → re-review
Task 9: automated security review of 6d6b820 (MEDIUM, serverrules/eval.go): open_basedir '/' check is literal — '//', '/./', '/tmp/..' bypass; empty entry unhandled. Accepted → path.Clean each entry, empty or ./.. entry = risky; joins Task 9 after re-review 3.
Task 9: re-review round 3 — clean (N-a..N-f addressed); new minor N-g readlink case `*` matches `/`; .user.ini-anywhere minor accepted (written as SSH user only)
Task 9: fix round 4/5 (fresh implementer a5e21eea0ba01c6c0, opus): open_basedir path.Clean + empty/relative entries risky, N-g pattern, doc comment
Task 9: fix round 4/5 (open_basedir riskyPathList, two-pattern readlink case — [!/]* idea was wrong, implementer proved with real sh; commits 6d6b820..e4e6ac5); controller verified: real sh case table (phpfoo/evil, php/x, python, binx → 7; php8.2 ok), tests green, eval.go diff read
Task 9: complete (commits 19254a8..e4e6ac5, 4 fix rounds; reviews clean; spec amended d5ce052)
Task 9: minor (deferred): .user.ini accepted anywhere collect read it (written as SSH user only); readlink chain intermediates (/etc/alternatives) not checked individually; dnf wrapped names; .user.ini cache_ttl
Ruling: Task 10 rolled-back cause stored as digest.CauseRolledBack ("rolled_back") on fix_attempt (Task 8 digest reads it); i18n text key fix.server.rolled_back displays it — brief named the key as the cause — costs: none.
Ruling: Task 10 RunAsRoot bundle with sudo_mode != nopasswd, or ErrUntestableBinary → executor user only (Michel never runs it) — spec § 8.1 bis — costs: none.
Task 10: dispatched (BASE 667a651, implementer a687fff52a348f53b, opus)
Task 10: implementer DONE_WITH_CONCERNS (commit 6e11a84; tests written after code, mutation-checked by hand; migration 0014 fix_proposal.steps; new AlertUndoNow kind; StepResults derived after run)
Ruling: ErrUntestableBinary → no script at all (not even for the user) — reloading PHP without a config test can take the site down; Michel explains why — costs: PHP outside system dirs gets no scripted fix.
Ruling: preprod linked but not showing the finding ⇒ ErrPreprodMissing (fail closed) — costs: user must unlink or fix preprod first.
Task 10: ⚠️ carry to T12: wire StartServer/SnapshotDone/AppliedByMe in API/CLI; production CheckServer=servercheck.Check, SiteCheck=GET via target.http, Alert in fix.Deps (serve) — SiteCheck nil ⇒ always inconclusive
Task 10: ⚠️ carry to T11/T13: button labels "Snapshot fait"/"Je l'ai appliqué" must match page; level-3 auto run in T11
Task 10: FR review — 4 rewordings (task-10-fr-review.md) → join fix round
Task 10: review — spec ❌ (C1 package failure/site-down reported as rolled_back), Needs fixes (I1 no atomic state claim before run; I2 caller ctx kills script and recording; I3 60s SIGKILL cap hits long upgrades; I4 mutations survive: apply-time snapshot gate, sudo/executor recheck, connection-lost alert; 10 minors incl. backups plaintext on Linux, dnf simulation unprivileged)
Ruling: apply scripts are exempt from the 60 s per-command cap: bound 5 min for config bundles, 30 min for package bundles, no SIGKILL from Michel; on bound exceeded or SSH drop mid-run the state becomes `unknown` (no undo guessed), urgent alert "état inconnu, vérifie le serveur", then a recollection — killing dpkg mid-run is worse than waiting — costs: a hung script holds the attempt up to 30 min.
Ruling: package plans never use CauseRolledBack; failure or site down after upgrade ⇒ state failed, cause package_failed / site_down_after_upgrade, Urgent alert "restaure ton snapshot" (spec § 8.1 bis: no automatic package rollback).
Task 10: fix round 1 → implementer (C1, I1-I4, all minors, FR 4 rewordings)
Task 10: fix round 1/5 (C1, I1-I4, minors, FR; new states running/unknown, RunWith NoKill, backups AES-256-GCM key in secret store; 15 tests failed first; commits 6e11a84..be670fa) → re-review
Task 10: ⚠️ carry to T11/T13: page calls fix.BackupList; AlertInput.Backups not stored; 8 new FR keys unreviewed → T13 FR pass
Task 10: re-review round 1 — spec ✅; C1, I1-I4, minors fixed (mutations M1/M8/M11 now caught); new I-R1 (stale running: Sweep only at start, no alert), I-R2 (post-script phase unbounded, alert before state change) + minors key race, AAD target_id, stderr tail → fix round 2
Task 10: ⚠️ carry to T12: API fixStates add running, unknown; carry to T11/T13: warn when preparing a fix on a server with an unknown-state attempt
Task 10: fix round 2/5 (I-R1 SweepRunning + 5 min RunningSweeper, run_deadline; I-R2 post-script 2 min bound, state before alert; key one-row table CAS; AAD target_id; StderrTail; migration 0015; commits be670fa..17d6de7) → re-review
Task 10: re-review round 2 — I-R1/I-R2 order fixed; new I-R3 (one 2 min deadline for whole post-script phase leaves attempt stuck applied), I-R4 (backup key overwritten after 1 s wait → old backups unreadable) + N1 INSERT not PG race-safe, N2 → fix round 3
Task 10: fix round 3/5 (I-R3 per-step bounds 30 s/5 min/5 min + fresh 2 min ctx per state/alert, stale applied swept; I-R4 key rotate only on persistent NotFound after 10 s, never overwrite; N1 ON CONFLICT; N2 StderrCut; commits 17d6de7..f5a2205) → re-review
Task 10: complete (commits 667a651..f5a2205, 3 fix rounds, re-review approved)
Task 10: minor (deferred, T11/T13): old backups after key rotation shown as "clé perdue" not "ne correspond pas"; key mismatch audit needs own reason; hung Alert leaves one goroutine (accepted)
Ruling: Task 11 AutoApplicableServer also false when target has a running/unknown attempt, RunAsRoot without nopasswd, or untestable binary — never auto into a state Michel itself could not run — costs: none.
Task 11: dispatched (BASE aebc96a, implementer a764d4ed272fd8e60, opus)
Task 11: implementer DONE_WITH_CONCERNS (commit 2db3197; AutoApplicableServer 4th param preprodProven; .user.ini never auto (no config test); ApplyAutoServer every 30 s worker pass; agent consent = preprod's when preprod linked; fixDeps wired Targets/SSH/CheckServer/SiteCheck/Alert in serve/mcp/fix CLI; OnChecked → QueueEligibleServer; consent key server:<id> in fix_consent)
Task 11: FR review — 3 rewordings (task-11-fr-review.md) → join fix round
Task 11: review — spec ✅, Needs fixes (I1 any proven preprod attempt unlocks prod level 3; I2 auto error audit every 30 s forever; I3 server agent keeps file tools near michel.db; I4 daily agent cap bypassed via preprod id; 9 minors) → fix round 1 (+ FR 3, most minors)
Task 11: fix round 1/5 (I1 PreprodAttemptID lineage; I2 audit once per reason; I3 server agents `--tools ""` + only mcp__michel__*; found real-driver worktree path bug (fake agent hid it) → <data>/worktrees/<server>/<attempt>; I4 cap counts preprod; minors incl. RevokeServerConsent, auto_not_run alert, sim cap 3; commits 2db3197..2702ade) → re-review
Task 11: ⚠️ carry to T13: level 3 switch / Préparer button must say hand-prepared fixes run alone if rules hold; consent shown = server whose inventory leaves (preprod); SSH user name in /home paths (strip to ~ or say in consent); revoke consent button; state "approuvée par la règle, pas encore lancée"
Task 11: complete (commits aebc96a..2702ade, re-review approved); controller verified `claude --help`: --tools "" = "disable all tools" (n1 closed)
Task 11: minor (deferred): level 3 runner in-memory maps unbounded + dedup key unstable without reason key; agent folder created before id check; revocation doesn't stop live proposed session; FR simulation_limit text reads as an order to the user → T13 FR pass
Task 12: dispatched (BASE 31e66d3, implementer a3b512b8039885118, sonnet; carries: defaults 1/24h, manual=-1, PreprodID validation, ErrNoAgent sentinel, ~/ for SSH user home in views, ssh.agent_pipe wiring, fixStates running/unknown, StartServer/StartServerAgent/consent routes)
Task 12: implementer DONE_WITH_CONCERNS (commit 4aa24d5; add writes target.ssh/target.http policy rules; per-server check lock; ssh.agent_pipe in policy.SSHConfig; one sshDeps builder; extra routes fix/agent-fix/ai-consent/snapshot-done/applied-by-me; michel fix prepare not routed to StartServer in CLI)
Ruling: adding a server (explicit user action, API or CLI) is the spec § 5.1 per-server opt-in — Michel writes its target.ssh/target.http rules then, never otherwise; deleting the server must remove them (fix round); UI (T13) must say "ajouter ce serveur autorise Michel à s'y connecter" — costs: none.
Task 12: FR review — 10 rewordings (task-12-fr-review.md) → join fix round
Task 12: automated security review (MEDIUM, cli/target.go): CLI links RemoteDir from discovery without the API's validation (absolute, remoteDirRe, no .., not /, not /home or /root) — a linked '/home' opens every home to collection (Task 4 deferred homeRefusal). Accepted → validation moves into target.Repo.Link for every caller; joins Task 12 fix round.
Task 12: review — spec ❌ (I1 rules not removed), Needs fixes (I2 delete races scheduler/CLI checks; I3 raw SSH error leak on approve; 9 minors) → fix round 1 (+ security RemoteDir in Repo.Link, minors 1-7, FR 10, Task 3 PhpStorm sshConfigId MUST-FIX)
Task 12: fix round 1/5 (I1-I3, RemoteDir in Repo.Link, minors 1-7, PhpStorm sshConfig/sshConfigId resolved, FR 10; tests written with code, not seen red; IPv6 hosts now refused?; commits 4aa24d5..c439a1d) → re-review
Task 12: re-review round 1 — I1-I3, security, minors 1-7, PhpStorm resolved (7 mutations caught); new R1 (unknown attempt blocks delete forever, no exit from unknown) + n1 host case, n2 hand-written rules released, n3 sshConfig suffix, n4 check reads before lock → fix round 2
Ruling: `unknown` gets an exit: fix.ResolveUnknown (unknown → failed, cause user_checked, audited), API POST /fix/{id}/resolve, CLI michel fix resolve — the user checked the server; delete answers distinct keys for unknown (resolve first) and user-run approved (refuse first) — costs: one more state transition.
Ruling: Michel releases only network rules it wrote for that server (owner recorded); hand-written rules never removed.
Task 12: fix round 2/5 (R1 ResolveUnknown + TargetBlock keys; n1 lowercase; n2 migration 0016 target_rule owner; n3; n4; commits c439a1d..95fcb4b); controller ran full go vet + go test ./... green
Task 12: automated security review (MEDIUM, 0016): rules written before target_rule existed are never released. Acknowledged, no change: plan 6 is unreleased (only dev/test DBs hold pre-0016 targets); backfilling would mark hand-written rules as Michel's, contrary to ruling n2. Final docs: say Michel only removes rules it wrote.
Task 12: complete (commits 31e66d3..95fcb4b, 2 fix rounds, re-review approved)
Task 12: minor (deferred, final wave): m1 busy hint for Michel-run approved fix on unreachable server should name Refuse; m2 ResolveUnknown code-attempt guard untested; m3 policy file vs target_rule drift on partial failure; m4 CLI changeRules reads startup policy; scheduler checks not shown as checking; backup size sealed not plain
Ruling: Task 13 Step 5 (manual browser check) is done by the controller in the built-in browser after the implementer commits (subagent has no browser pane); implementer makes the demo runnable and writes the exact commands in the report — costs: one controller pass.
Task 13: dispatched (BASE fefd3e4, implementer a3bead54dc2cbba19, opus)
Task 13: implementer DONE_WITH_CONCERNS (commit 54e8b15; migration 0017 server_backup.key_fingerprint; attempt detail carries scripts + backup states; sshx.SystemAgent on Windows accepts absolute Unix socket path (security review); demo ran via CLI/API: PHP2Shell, expose_php proven_fixed, site cut → rolled back; 272 web FR keys)
Task 13: controller browser check done (task-13-browser.md): flow works end to end (discover, trust, check, expose_php proven_fixed, site cut → rollback); issues B1-B3 Important (Today says all calm with critical server finding; findings sorted ascending; duplicate PHP2Shell cards), B4-B10 minor
Task 13: review — spec ✅, Needs fixes (I1 internal/fix test fails: frozen-clock order; I2 BackupStates uses writing key path: 10 s wait/rotation on GET, errors swallowed; 8 minors; Windows Unix-socket agent widening accepted: path only from user's policy) + FR 17 + browser B1-B10 → fix round 1
Task 13: fix round 1/5 (I1, I2, m1-m8, B1-B10, FR 17; 21 new FR keys unreviewed; commits 54e8b15..f02822d) → re-review + controller browser re-check
Task 13: controller browser re-check — B1-B5, B8, B9 fixed; new minors B11 (counts raw vs merged cards), B12 (info shown as red error)
Task 13: complete (commits fefd3e4..f02822d, 1 fix round, re-review approved, controller browser check passed twice)
Task 13: minor (deferred, final wave): n2 canApproveServer must refuse when scripts_unreadable (fix); F1 fix.intro_server says nothing changes without validation — false at level 3 (fix FR+EN); B11 counts raw vs merged cards; B12 info banner red; n1 secret-store read error shows clé perdue; n3 server headline hides urgent project news; n4 merged card proposal doesn't name the other runtime; n5 srvfix.rolled_back unused key; preprod critical-not-urgent untested
