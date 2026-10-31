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
