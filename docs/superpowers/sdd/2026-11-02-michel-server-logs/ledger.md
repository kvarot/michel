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
| 10 | Step 3 needs Docker, absent on this PC: see R5 |

## Rulings

- Ruling R1: Purge and EraseText audit through a wrapper in privacy.go taking the audit logger, the Repo methods stay plain — keeps Task 1 signatures — costs a small refactor if wrong.
- Ruling R2: retention purge runs in the existing serve retention loop (spec § 11, "boucle de rétention existante"), Resolve runs at the end of each Pass for that server — the plan names neither — costs a late status change if wrong.
- Ruling R3: common-cause grouping lives in Scheduler: one tick collects no_agent failures and emits one AlertNotReading; Pass reports the cause in PassResult.Reason — Pass cannot see other servers — costs a test move if wrong.
- Ruling R4: weekly reminder uses the last digest_run carrying a reminder, or a stored date in log_settings if digest_run cannot hold it; implementer picks after reading digest — spec fixes the rate only — costs a repeated or late reminder if wrong.
- Ruling R5: Task 10 Step 3 runs with Kévin on the PC with Docker; on this PC the task delivers docs, image and checklist, and the branch is not called finished before that run — no Docker here — costs a later fix round.

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
- Task 3: stopped by Kévin before finishing, on a work PC. Work not reviewed.
- Task 3: unfinished work kept on branch wip/plan7-task3 (compiles, go vet clean, tests not run, no report, no review). Task 3 still to finish from it or restart from feat/server-logs.
