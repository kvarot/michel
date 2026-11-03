# SDD ledger — plan: docs/superpowers/plans/2026-11-02-michel-server-logs.md

Spec: docs/superpowers/specs/2026-11-02-michel-plan7-server-logs-design.md
State 2026-11-02 16:09: no task started. Plan 6 real run not done yet (spec § 12 ordering holds). Waiting for Kévin.

## Pre-flight scan

| Tasks | Shared file or interface | Finding |
|---|---|---|
| 1-2 | Source, Cursor, Record, Level | Consistent |
| 1-4 | Settings, SaveSettings, Purge, EraseText | Repo.Purge has no logger, Task 4 wants it audited: see ruling R1 |
| 2-3 | Script, FilterOptions, Output, FileState | Consistent |
| 3-5 | Read, Output to Note kinds | Consistent |
| 3-8 | Try, Discover | Consistent |
| 4-5 | ChangeSettings, Purge | Nothing in Task 5 calls Resolve: see ruling R2 |
| 4-8 | ChangeSettings, ErrConfirmationNeeded | Consistent |
| 5-6 | AlertInput, AlertItem | Consistent; no import cycle (target, audit, sshx, mask, secret, store do not reach notify, digest, cli, api) |
| 5-7 | AlertItem, Note in digest | Consistent; digest gains an import of serverlog, no cycle |
| 5-6-7-8 | internal/cli/serve.go | Sequential edits, no conflict |
| 7-9-10 | digest_at, config.example.yaml | Consistent |
| 8-9 | API routes, TargetView fields | Consistent |

| Task | Agrees with itself? |
|---|---|
| 1 | Yes |
| 2 | Yes; busybox and mawk absent here, dash and gawk present, skips go to ledger |
| 3 | Yes |
| 4 | Yes, apart from R1 |
| 5 | TestLockedAgentIsOneAlert spans servers, Pass is per server: see R3 |
| 6 | Yes |
| 7 | TestDeviationRemindedWeekly has no named state: see R4 |
| 8 | Yes |
| 9 | Yes |
| 10 | Step 3 needs Docker, only inside WSL on this PC: see R5 |

## Rulings

- Ruling R1: Purge and EraseText audit through a wrapper in privacy.go taking the audit logger, the Repo methods stay plain — keeps Task 1 signatures — costs a small refactor if wrong.
- Ruling R2: retention purge runs in the existing serve retention loop (spec § 11, "boucle de rétention existante"), Resolve runs at the end of each Pass for that server — the plan names neither — costs a late status change if wrong.
- Ruling R3: common-cause grouping lives in Scheduler: one tick collects no_agent failures and emits one AlertNotReading; Pass reports the cause in PassResult.Reason — Pass cannot see other servers — costs a test move if wrong.
- Ruling R4: weekly reminder uses the last digest_run carrying a reminder, or a stored date in log_settings if digest_run cannot hold it; implementer picks after reading digest — spec fixes the rate only — costs a repeated or late reminder if wrong.
- Ruling R5 (corrected 2026-11-03): Task 10 Step 3 stays to do, and the branch is not called finished before that run; Docker does exist on this PC, but only inside WSL (`wsl -d Ubuntu -- docker`), see the WSL section of `real-run-checklist.md` — the first version of this ruling said no Docker here, which was wrong — costs a later fix round.

## Execution

Scope agreed with Kévin 2026-11-02: tasks 1 and 2 before plan 6 real run; stop before Task 3.
- Ruling R6: French `fix.intro_server` adopts reviewer's version, EN aligned — reviewer found "connues" ambiguous — costs one more wording if wrong.
- Note: texts.test.js pinned the old wording; updated with the rewording on main (test still checks the rule exception is stated). Main is ahead of origin, not pushed.
- Task 1: dispatched, BASE 1030d66.
- Note: flake `chunked line ends with bare LF` reproduced 2026-11-02 16:20 in a whole `go test ./...` run on feat/server-logs (TestAPIResponsesHaveNoAbsolutePathsNorCommands, TestItemsReadAndDiscoverActions, both POST /api/v1/sources/discoveries/example/mcp, 201 with empty body). Not caused by plan 7. To report to Kévin.
- Task 1: implementer DONE_WITH_CONCERNS, commit 321f137. Review: approved with one Important (spike test does not exercise the factor), plus Minor 1 (ignored signature regains text) sent to fix as a spec § 11 violation.
- Task 1: minor (deferred): Record.Hour not validated; last_at uses read time not record hour; collect-then-close loops repeated; repo.go 767 lines; no MarkAlerted yet (Task 5 adds it).
- Task 1: fix round 1 sent (spike factor test, ignored rows keep no text). FIX_BASE 321f137.
- Flake cause found: not Michel. Bare Go httptest server on loopback (scratchpad probe, no Michel code): any response to a URL whose last segment is `mcp` (case-insensitive) reaches the client with a lowercase `transfer-encoding: chunked` header added, Content-Length removed, body not chunked. `/x/mcp/y` and `/example/other` are untouched. Something on this PC rewrites loopback HTTP; product not identified. Intermittence: it was not always active. Tests fail through fixture repo `example/mcp`.
- Ruling R7: treat these internal/api failures as environmental in tasks 1-2 gates, quote them in reports, leave the fixture alone until Kévin decides — fixing is outside plan 7 — costs a noisy suite meanwhile.
- Task 1: fix round 1/5 (2 addressed, 0 open; commits 321f137..2894421)
- Task 1: complete (commits 1030d66..2894421, review clean)
- Task 1: minor (deferred): text of a non-ignored row refreshes on every Apply.
- Note: push of feat/server-logs refused by the session permission check. Commits stay local until Kévin decides.
- Task 2: implementer DONE_WITH_CONCERNS, commit 6cf93ba, BASE 21da80e. TestFilterVariants 9 of 15 skipped (mawk, busybox absent); symlink branch not run on this PC.
- Task 2: review needs fixes (1 Critical IP and numeric shapes in Channel and Location; 2 Important wildcard cap reads oldest, SQLSTATE takes pid or user). Compressed IPv6 in cleaned text raised from Minor to fix round: § 7.3 is absolute. FIX_BASE 6cf93ba.
- Ruling R8: FileID stays inode only, against spec § 5.2 "inode and device" — brief prescribes `ls -di` and no POSIX tool gives device portably — costs a missed rotation only if a path changes device with the same inode and a larger size.
- Ruling R9: identifier-shaped names (`jean_dupont`) in Type, Location or Channel cannot be closed by a whitelist: accepted, to document in Task 10, and to show to Kévin — no shape separates them from a class name — costs a possible personal name in a field if a real path or forged line holds one.
- Task 2: minor (deferred to Task 3): sshx.MaxOutput can cut output, F lines come after R lines, treat truncation as failed read; first read with no file needs an explicit decision for a later file; FileState.File must stay out of the API; ValidatePath must not accept more than the Script whitelist.
- Task 2: minor (deferred): no lower bound on hours; mid-line resume after skip; symlink case ends with t.Logf not t.Skip; hand-copied class in shell case; `withoutMessage` drops lines by substring.
- Task 2: fix round 1 implementer reply, commit 9e8810f, re-review dispatched. Implementer concerns: unbracketed pid or user with a valid class still passes as type; numbers of 6 digits or fewer and `ip-203-0-113-77` still pass; `Version20261102120000.php`, `messages.fr.php` and dotted channels lose detail; line numbers capped at 6 digits.
- Task 2: fix round 1/5 (4 addressed, 0 open; commits 6cf93ba..9e8810f)
- Ruling R10: suffixed hosts and hyphenated digit groups enter fix round 2 — "Jamais d'IP" is absolute and `ip-203-0-113-7` is a real form — costs folders such as `2026-11-02` and `v1.2.3` dropped from locations.
- Ruling R11: a 5-digit pid or a user in a listed SQLSTATE class right before the severity still passes as a type; accepted, Task 8 wording says `%e` must come last — only an exact list of codes closes it, and a pid is not personal data — costs split signatures on such prefixes.
- Task 2: minor (deferred): numbered rotation past the cap drops the live file (docs in Task 10); `Foo::bar` cleans to `[addr]` in opt-in text; glob expanded twice allows MAX + 1 under a race; dotted channels, `messages.fr.php` and `Version20261102120000.php` lose a field; serverlog test package takes about 250 s.
- Task 2: fix round 2/5 (2 addressed, 0 open; commits 9e8810f..f331630)
- Task 2: complete (commits 21da80e..f331630, review clean)
- Task 2: minor (deferred): Laravel and Doctrine migration names and `releases/1.2.3` lose their location; two digit groups (`ip-203-0`) and letter-split groups (`203x0x113`) still pass; TestFilterVariants 9 of 15 skipped, symlink branch not run on this PC.
- Stop point: Task 3 not started, it waits for the plan 6 real run.
- Scope change 2026-11-02 evening: Kévin, asked whether to start Task 3 before the plan 6 real run, answered "et continuer le plan", after "agit en autonomie". Tasks 3-10 run here, no push. Plan 6 real run and Task 10 Step 3 remain to do on the PC with Docker; branch not finished before that (R5).
- Ruling R12: "et continuer le plan" read as lifting the stop before Task 3 — it answered the question put to him, and work stays local — costs rework if the real run changes the server code or if he meant the home session only.
- Task 3: dispatched, BASE f0e8e5d.
- Task 3: stopped by Kévin before finishing, on another PC. Work not reviewed.
- Task 3: unfinished work kept on branch wip/plan7-task3 (compiles, go vet clean, tests not run, no report, no review). Task 3 still to finish from it or restart from feat/server-logs.
- Note 2026-11-03: plan 6 real run done and merged into main; results at the end of `docs/superpowers/sdd/2026-10-31-michel-servers/ledger.md`. Kévin chose to resume the Task 3 WIP. R12 has no object any more.
- Task 3: resumed from wip/plan7-task3, origin/feat/server-logs and origin/main merged without conflict (HEAD 79261da). WIP tests run for the first time: pass on this PC, symlink case not exercised (no privilege).
- Task 3: audit and finish dispatched, BASE f0e8e5d for the whole task, WIP commit 7aa7bff included in review.
- Task 3: implementer DONE_WITH_CONCERNS, commit 711419d. Fixed: placeholder cursor of a wildcard source refused by Script. Symlink case and mawk, busybox, dash variants skipped on this PC; symlink checked by hand under WSL. Discover keeps the default PostgreSQL folder, the inventory has no postgresql.conf directives.
- Task 3: review needs fixes (5 Important: cap per file, cut output can block a source, history read after activation, ValidatePath not guarding declaration, PostgreSQL proposal; 9 Minor). FIX_BASE 711419d.
- Ruling R13: the read cap and the output bound hold per source and per pass, newest files served first; a file past the budget jumps to its end and says the volume — spec § 5.2 and Global Constraints fix "par source et par passage" — costs fewer records from the oldest dated files of a large wildcard.
- Ruling R14: at activation a file present but unreadable is located by metadata only (`ls`, nothing read), and no placeholder is left when a parent folder exists but cannot be searched, when awk is missing or when a located line is rejected; a file that appears unreadable after activation stays unseen and is read from its start once readable — spec § 5.2 — costs a real file skipped up to the activation size.
- Ruling R15: `checkSource` calls `ValidatePath`, single validator for declaration and proposals — spec § 4 — costs a refusal for a stored path outside the whitelist, which no read could have served anyway.
- Ruling R16: Discover keeps `/var/log/postgresql/postgresql-*.log` for now, against spec § 4 "log_directory et log_filename si lisible" — the inventory has no postgresql.conf directives and the brief does not touch the collector; to show to Kévin — costs a wrong proposal on a server with a custom log folder, the source is then declared by hand.
- Ruling R17: FPM values holding `$pool` are not proposed, to state in the Task 10 docs — the pool name is not paired with the value in the inventory — costs a manual declaration for those pools.
- Task 3: minor (deferred to Task 5): cursors of files gone are never pruned, the placeholder stays once real cursors exist; Pass stores cursors and is the place to prune them.
- Task 3: minor (deferred to Task 8): `Output.Unseen` holds server paths; decide what the "non vu" list exposes.
- Task 3: minor (deferred to Task 10): `-L` checks the last component only and before the read; a symlinked parent or a swap in that window needs write access to the folder; state the limit in the docs.
- Task 3: FileID inode only stays under R8.
- Task 3: fix round 1 sent: I1 to I4, plus Minor awk records without a position, real file swap test, Why asserted per path, constants split. Done criterion is a review with nothing open, so cheap minors go in.
- Task 3: fix round 1 implementer reply, commit f181eb4, re-review dispatched. Whole package also run on Linux under WSL (dash, gawk, mawk), symlink and unsearchable folder cases included.
- Task 3: fix round 1/5 (8 addressed, 0 open; commits 711419d..f181eb4). Busybox not checked: absent on Windows and in WSL.
- Ruling R18: a resume in the middle of a line is raised from Minor to the fix loop — a fragment of a visitor-controlled line can become a valid record once the newline arrives, which is Review Focus 1 — costs one more round.
- Ruling R19: "newest first" is the last name in C order, not modification time, for the budget as for the 50-file cap; the skipped volume is stated, to explain in the Task 10 docs and to show to Kévin — dated names are the case wildcards serve, and POSIX sh has no portable sort by date without parsing `ls` — costs the newest errors skipped past the budget on a pattern such as `app.log*`.
- Task 3: minor (deferred): group share counts idle files too (31 daily files give 32 groups each, the rest folds into level records, visible); a shell without builtin `printf` could fail on an answer over 128 KiB, not reachable on dash or busybox ash; a missing folder under an unlistable parent keeps activation repeating, conservative.
- Task 3: fix round 2 sent: mid-line resume, tests (file appearing unreadable, `-r` branch, grammar), awk comment, tab count. FIX_BASE f181eb4.
- Task 3: fix round 2/5 (3 addressed, 0 open; commits f181eb4..cc6e9c9)
- Task 3: minor (deferred): a held fragment is read again each pass, within the cap; a half-line discarded after a resume is not counted as lost; a line of exactly the cap without its newline is jumped.
- Task 3: skips on this PC: symlink, unsearchable and unlistable folder cases, mawk, busybox and dash variants of TestFilterVariants; whole package passes under WSL (dash, gawk, mawk), busybox not run anywhere.
- Task 3: complete (commits 79261da..cc6e9c9, review clean)
- Stop point: Task 4 not started. Branch wip/plan7-task3 not merged into feat/server-logs, Kévin decides.
- Scope 2026-11-03: Kévin, relayed by the starting session: "Continue le plan en autonomie". Tasks 4-10 in order on wip/plan7-task3, no merge into feat/server-logs or main, he decides at the end. Rulings marked "to show to Kévin" are decided and go in the final report.
- Resume 2026-11-03 07:55: new session, Kévin: "Reprend le plan". Earlier session idle. Untracked internal/serverlog/privacy.go (implementer stopped before tests, builds, vet clean) kept as Task 4 starting point, unreviewed.
- Task 4: dispatched, BASE 678460b.
- Kévin 2026-11-03: "Tu peux fusionner en autonomie". feat/server-logs fast-forwarded to 678460b (Task 3). After each reviewed task the same; main after final review and real run.
- Task 4: implementer DONE_WITH_CONCERNS, commit e36bc48. Added beyond the draft: `sealText` re-checks `validText` (a text with an IP, email, URL or quote is dropped, the error still counted); erasure runs on every save with text off, so a failed erase heals on retry.
- Task 4: `secret.Protect` is identity off Windows, same as `mask_entry`: text is encrypted at rest on Windows only. Existing limit, to state in Task 10 docs and final report.
- Task 4: reviewer approved, no Critical or Important. Cannot-verify items resolved: `PurgeAudited` has no caller yet, Task 5 wires it in the serve retention loop (R2); `EraseTextAudited` goes to Task 8; page texts through i18n in Task 9.
- Task 4: minor (deferred to Task 5): `PurgeAudited` writes an audit event each tick even with nothing removed; skip it when all counts are 0.
- Task 4: minor (deferred): `log.settings` audited after the save, an audit failure leaves a saved setting with an error returned; before/after purge counts are outside one transaction and can mislead; read-check-save of settings not atomic, low risk single user; new masker per text restarts token numbers; no test of `Apply` with StoreText off storing nothing, nor of the 200 cap after masking grows a text.
- Task 4: complete (commits 678460b..e36bc48, review clean)
- Task 5: dispatched, BASE e36bc48.
- Correction 2026-11-03: the "Earlier session idle" note above was wrong. The Task 3 session was still at work (listed not running, it was diagnosing CI) and its own Task 4 implementer wrote the same files until it stopped; e36bc48 may mix both. The review judged the commit itself, so its verdict stands. That session stopped and writes nothing more here. This session drives from Task 5.
- CI: origin/main 11882b8 fixes the ubuntu job (reported by that session); merge origin/main into this branch after Task 5's commit, not while the implementer works.
- Task 10 step 3, relayed by that session: Docker in WSL per the WSL section of real-run-checklist.md, keep a WSL session open; Windows ssh-agent service untouched, user-space test agent via ssh.agent_pipe outside the repo; ledger states Windows OpenSSH agent not tested; everything disposable and removed at the end; no fingerprint, host or token in the repo.
- Task 5: implementer DONE_WITH_CONCERNS, commit 0617cd1. `-race` not run: no gcc here or in WSL. RED shown by mutation, not test first. Concerns in its report: manual stored as -1s; hourly cap counts errors; no serve retention loop exists, purge runs from the log scheduler; Apply accepted empty Type (Task 1 bug fixed); Alert nil in serve until Task 6; failure counts in memory; any failing source fails the pass.
- Task 5: review needs fixes (5 Important: Resolve crosses servers, stale carrier silences agent alerts, non-prod digest carrier lost, Focus 3 test too weak, log.read audit failure invisible; 13 Minor). Findings: task-5-findings-1.md. Implementer stopped by the controller after it looped on its final message, fix goes to a fresh one.
- Ruling R20: one pass sends at most one alert for errors, new, reopened and spike together, `AlertItem.Kind` keeps each reason; volume and cap stay separate; a spike inside a read gap is ignored — spec § 8.2 "regroupée par passage", Focus 3 — costs a plain per-kind message if Kévin wants them apart.
- Ruling R21: the purge runs from the log scheduler at start and every 6 h, there is no serve retention loop against spec § 11 and R2 — only place that runs with serve — costs moving one call.
- Task 5: minor (deferred): `Apply` and `SaveCursors` not atomic, a stop between them re-reads lines and can fake a spike; `settle` waits for the whole round; `AlertedSince` counts rows so a spike on a told signature does not use the cap. `-race` not run on this PC, no gcc; CI to carry it if it can.
- Note: internal/serverlog/sh.exe.stackdump appeared at 08:37:58, an msys sh crash during a test run, around when the Task 5 implementer was stopped. Removed, cause not established. Watch for a repeat.
- Kévin 2026-11-03, in this session: "fusion". Read as: merge reviewed work into feat/server-logs. Fast-forwarded to 1f3d68d (Tasks 1-4). After each reviewed task, feat/server-logs advances. main not touched: scope not stated, asked.
- Kévin 2026-11-03, in this session, after "fusion": "et continue", "il faut que tu fasse tout seul je te donne les autorisations". Read as: no more questions, merges mine. feat/server-logs after each reviewed task, main after Task 10 and the final review. No force-push. Report at the end.
- Task 5: fix round 1 implementer reply, commit bf3db04. Its open readings: prod alert goes even if the gap note fails; running hour still alerts on return; manual server has no gap; cause change restarts the count; volume once-an-hour kept in process; SourceID to be labelled in Task 6.
- Task 5: fix round 1/5 (5 Important and 9 Minor addressed, 0 open; commits a2a05f4..bf3db04)
- Ruling R22: a spike is ignored on return only for an hour already over, the running hour alerts; its previous hour can be incomplete if the cap cut the backlog — otherwise a running spike would never alert — costs a rare false spike right after a return.
- Ruling R23: volume and cap "once an hour" and not-reading counts stay in memory, a restart can repeat one message or restart a count — persisting needs a schema change for a rare case — costs one extra message after a restart.
- Task 5: minor (deferred): a manual server has no gap, an old hour read by hand can alert as a spike; a cause change restarts the failure count at 1; `AlertItem.SourceID` is an id, Task 6 turns it into a label.
- Task 5: complete (commits e36bc48..bf3db04, review clean)
- Task 6: dispatched, BASE 222a384.
- Task 6: implementer DONE_WITH_CONCERNS, commit 9c33927. RED was a compile failure only, implementation written first. SourceID left out of messages; at most 5 errors listed then "and N more"; SMS needs the per-server `Settings.SMS` and the channel's urgent flag, under the daily cap; Task 8 only has to expose `Settings.SMS`.
- Ruling R24: errors stay marked as told even when no channel delivered the alert, no retry — the digest carries them anyway and a retry needs unmarked state re-read each pass — costs a critical on prod seen only in the digest if every channel is down at that moment; to show to Kévin.
- Task 6: French reader review done, wording applied, commit 4863ab6. Digest word kept as in the catalogue; host key text says confirm the fingerprint, the page has no accept action; "the rest waits" was false, now "was not read".
- Task 6: reviewer: spec compliant, no Critical or Important, no explicit verdict line. Cannot-verify item checked by the controller: cleaned text passes `validText` upstream.
- Task 6: minor (deferred to Task 8): a ticked log SMS shares the daily counter with flaws, say so where the box is ticked (spec § 8.3).
- Task 6: minor (deferred): text cap test does not pin the exact length; per-channel audit uses `ctx`, a stop during send can lose lines; plural of not_reading follows the count of names.
- Task 6: complete (commits 222a384..4863ab6, review clean)
- Task 7: dispatched, BASE 35361db.
- Task 7: implementer DONE_WITH_CONCERNS, commit 04c818e. R4 settled on digest_run.summary, no migration. Claim by conditional INSERT, deleted if no channel took it, older than 10 min counts as dead. One ok channel plus a failure counts as delivered. Log errors added to NewTotal. Reopened error listed in each digest until marked seen. FR "résumé" in new text, "digest" in older keys.
- Task 7: French reader review done, sent to the implementer.
- Ruling R25: French prose says "résumé" everywhere, never "digest", except command names — a non-specialist reader understands it at once, the titles and web page already use it — costs a rename if Kévin prefers "digest". Supersedes the Task 6 note keeping "digest".
- Task 7: wording applied, commit ef05303. No warning exists yet at source activation without a channel (spec § 8.3): Task 8 and 9 to carry it.
- Task 7: review needs fixes (1 Critical: error read after a digest with an older log hour is in no digest; 3 Important: first window slides, reopened told daily, catch-up digest before the first read; 14 Minor). Findings: task-7-findings-1.md. Send-once claim, lifecycle and race test judged sound.
- Ruling R26: the digest counts by read time, each occurrence exactly once; `log_bucket` stays by log hour for spikes; new migration allowed; first digest at serve start waits for the first log round, 2 min at most — spec § 8.3 "jamais perdus ni envoyés deux fois", § 5.4 — costs a migration and a later first digest.
- Ruling R27: "plus fréquentes" means most frequent in the window, not only spikes; only new and reopened count as new — spec § 8.3, an error steady at 90 an hour would never show — costs a steady error listed daily until silenced; to show to Kévin.
- Ruling R28: with an unscoped channel enabled, delivered needs an ok on an unscoped channel, only those carry server sections; with only scoped channels any ok counts — spec § 8.3 — costs a repeat for scoped channels when only unscoped ones failed.
- Task 7: fix round 1 sent, FIX_BASE ef05303.
- Task 7: fix round 1 implementer reply, commit 730e431, migration 0019 (log_read, reopened_at, digest_start). Choices to check: 100 reads as frequent, 5 s LogReadLag, reading stamped with a fresh clock.
- Task 7: fix round 1/5 (1 Critical, 3 Important, R26, R28 and 13 Minor addressed; R27 open: floor of 100 not ruled; new Important: log_read orphans on DeleteSource, scoped channels re-sent every 15 min under R28; commits ef05303..730e431). Full suite passes on 730e431, run by the controller.
- Ruling R27b: no floor on frequent errors, listed by count up to the cap, no "often" label — R27 as written, a floor needs a number the spec does not give — costs a rarely seen error listed when the list has room.
- Ruling R29: a channel that received a held digest gets no copy on a retry the same local day, memory in process, next day everyone again if still held; messages say some channels received it — spec "un seul par jour" with R28 — costs one repeat after a restart.
- Task 7: minor (deferred): a spike in the boundary hour can be labelled again in the next digest; read_at stamped before the transaction, a commit later than the 5 s lag falls in no digest, rare, error stays on the page; manual send with scoped ok and unscoped failure moves the window, expected for manual.
- Task 7: fix round 2 sent, FIX_BASE 730e431.
- Task 7: fix round 2 implementer reply, commit 0008fd2. Limit: scan --digest keeps no memory between runs, a second run the same day after a held digest can re-send.
- Task 7: fix round 2/5 (R27b, N1, N2, R29 and 4 Minor addressed, 0 open; commits 730e431..0008fd2), wording nit commit 9da1594.
- Task 7: minor (deferred): scan --digest keeps no memory between runs, a second run the same day after a held digest can re-send to a channel that got it; a channel removed mid-day leaves `no_channel` with the digest held.
- Task 7: complete (commits 35361db..9da1594, review clean)
- Ruling R30: the "non vu" list exposes the paths of declared sources and their reason, no content — the user typed those paths, wildcards resolve under the declared folder — costs a server path shown on a local page.
- Task 8: dispatched, BASE 66f4be6.
- Task 8: implementer DONE_WITH_CONCERNS, commit b32bfc9. Its choices: try audited as log.read with counts only; extra audit actions for source update, remove, error status; path change or re-activation resets positions; store_text off also turns alert_text off; duplicate path 409; errors list capped at 500; DELETE target leaves log data to expire. R30 in the try answer only; R11 note on postgres discover and try.
- Task 8: French reader review done, wording applied, commit d5d2311.
- Task 8: review needs fixes (7 Important: non vu without path or reason and last read stays fresh, removed server orphans log data, one reason for every non vu cause, try skips the masker, try audit row incomplete, copy-paste command can carry an SSH option, Linux path gap; 13 Minor). Auth and raw-line protection held. Findings: task-8-findings-1.md.
- Ruling R31: `/sources/try` writes one audit row and no log data — spec § 7.4 and § 14 want every read traceable, § 10 says "sans rien stocker" — brief says "n'écrit rien" — costs one row to remove if Kévin reads it strictly.
- Task 8: minor (deferred to Task 10): detail command uses the UTC date, a server on local time can miss lines around midnight; say so in the docs.
- Task 8: minor (deferred): overlapping sources pass the duplicate check; dynamic prefix `api.logs.` turns off unused-key detection; `TestNoLogDataReachesAnAgent` checks direct imports only.
- Task 8: fix round 1 sent, FIX_BASE d5d2311.
- Task 8: fix round 1 implementer reply, commit dead316, migration 0020 (log_unseen, path_at, spike settings). Beyond findings: masked text could not be read back (Repo.Text refused the marker's digits), fixed; GET /errors now {errors,total,truncated}; 409 api.logs.busy while a read runs. WSL proof for api and serverlog with dash, gawk, mawk; busybox still not run.
- Task 8: fix round 1/5 (5 Important, R31 and 12 Minor addressed; open: I1 wildcard source keeps a fresh last read, new Important: server removed before its logs, a failed erase leaves data nothing can erase and the CLI says erased; 4 new Minor, French fixes; commits d5d2311..dead316). Full suite and vet clean on dead316, uncached, run by the controller.
- Task 8: minor (deferred): `serverlog.TryLock` is per process, a CLI `target remove` during a `serve` read does not see it; older pattern, same as `servercheck.TryLock`.
- Task 8: fix round 2 sent, FIX_BASE dead316.
- Task 8: fix round 2 implementer reply, commit ca97290.
- Ruling R32: a source that read nothing shows its last real read, empty only if it never read, instead of the finding's literal zero — spec § 5.4 "dernière lecture réussie il y a X min" — costs nothing visible; the finding's defect is what the re-review checks.
- Task 8: fix round 2/5 (I1 under R32, B1, B2, B3-B6, French addressed, 0 open; commits dead316..ca97290).
- Task 8: minor (deferred): a source matching no file for hours no longer moves its date, a file appearing later can add a gap note; failed audit after a good erase records `logs_error:true`; forget error not logged on the API failure path.
- Task 8: complete (commits 66f4be6..ca97290, review clean)
- Kévin 2026-11-03: wants a clean, professional interface for Michel, guided step by step for someone who knows nothing of computing, possibly an advanced mode, every field and action understandable. Separate design under discussion, session card could not be shown (message came from a remote client).
- Ruling R33: Task 9 goes ahead in the current visual style, every field and action explained in plain words, the redesign restyles it later — plan 7 should not wait on an open design — costs a restyle of one block.
- Task 9: dispatched, BASE d625b9a.
- Task 9: implementer DONE_WITH_CONCERNS, commit 999418f. Browser check in light and dark on demo data; not checked: Copier click, purge and remove dialogs, hds wording, EN, mobile, successful Essayer with records. No "read now" in the API while the manual sentence says "quand tu le demandes". 137 new `logs.*` keys.
- Task 9: French reader review done, sent to the implementer with the remaining browser checks. Reviewer's "noms" corrected: the filter does not remove names.
- Task 9: wording and remaining browser checks done, commit a2e505e. Fixed: Copier fallback, overflow at 375 px. Not checked after this commit: dark theme, actual clipboard content.
- Task 9: reviewer approved, no Critical or Important. Resolve delay, read cap, spike threshold, max alerts stay API only, § 10 does not list them for the page.
- Task 9: minor (deferred to Task 10): manual interval promises "when you ask" with no button on the page, only `michel target logs read`; say so in the docs.
- Task 9: minor (deferred): candKey in ids breaks aria-describedby on a path with a space; `now` set only at load, "il y a X min" goes stale on an open sheet; `load()` has no sequencing; `refreshView` swallows its error; interval warning recomputed locally, API's `interval_note` unused; `c.strong` computed and unread; no component test of the 409 flow; dark theme not rechecked after the last commit. Redesign to pick these up.
- Task 9: complete (commits d625b9a..a2e505e, review clean)
