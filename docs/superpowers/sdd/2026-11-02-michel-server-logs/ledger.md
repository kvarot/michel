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
