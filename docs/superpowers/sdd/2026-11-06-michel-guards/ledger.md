# SDD ledger — plan: docs/superpowers/plans/2026-11-06-michel-guards.md

Spec: docs/superpowers/specs/2026-11-06-michel-guards-design.md. Branch feat/guards from 8473c95.

## Pre-flight scan

| Rows | Produces / consumes | Found |
|---|---|---|
| T1–T4 | T1 threshold + PATCH in handlers.go; T4 adds ProjectView.Light/gate_threshold in same file | compatible, sequential |
| T1–T2 | scan_component table (T1) used by replaceComponents (T2) | ok |
| T1–T6 | repo_hook table (T1) used by Install/Remove (T6) | ok |
| T2–T7 | Component, PURL, ListComponents (T2) used by Build (T7) | TestPurlScopedNpm in T7 tests T2's PURL: ok, T2 must handle scope |
| T3–T4 | ignore keeps due_at as review date (T3); T4 counts ignore in force as passing whatever its date | consistent |
| T3–T9 | API `review` field (T3) sent by DecisionPanel (T9) | ok |
| T4–T5 | Compute/Worst (T4) used by gate (T5) | ok |
| T5–T6 | hook runs `gate --repo --data-dir --config` | needs --data-dir/--config accepted by gate: root persistent flags (fix.go passes them to mcp) |
| T6–T8 | hook routes (T6) used by settings UI (T8) | State built by a function T6 does not name |
| T8–T9 | both edit ProjectCard.vue, FindingsPage.vue | sequential, ok |
| each task | tests vs code vs files | T3 lists internal/digest/* without file: implementer finds the digest builder; T6 Interfaces lack the State builder |

Ruling: T6 adds `func StateOf(ctx context.Context, db *sql.DB, projectPath string, all []project.Project) (State, error)` — the plan names State but no builder — cost if wrong: a rename.
Ruling: the API gets the hook's exe from os.Executable() and dataDir/cfg from its Deps, as fix.go does for mcp — cost if wrong: hook points at a wrong binary, caught by TestAPIHookAudit reading the script.
Task 1: review 1 spec ok, quality: 0 crit/imp; controller found store tests failing (migration count) — Important; fix round 1 dispatched to same implementer (+2 minors: no-op audit, catalog order)
Task 1: fix round 1/5 (3 addressed, 0 open; commits 9c4f9e8..d33c91c)
Task 1: complete (commits 8473c95..d33c91c, review clean)
Task 2: dispatched (BASE c72cfee, sonnet)
Task 2: implemented 1be2a2b; review dispatched
Task 2: minor (deferred): fixture has no vulnerable package (still proves non-vulnerable ones are stored); dev-merge of duplicates untested; failed/empty not tested (same guard)
Task 2: complete (commits c72cfee..1be2a2b, review clean)
Task 3: dispatched (BASE 1be2a2b, sonnet)
Task 3: stopped by Kévin mid-implementation (no commit beyond 1be2a2b; working tree left as is)
Task 3: unfinished work saved on branch wip/guards-task3 (untested, not reviewed)
