# Tests gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Michel never runs a project's tests on a tree the fix agent changed unless a person clicks, bound to the proposal shown.

**Architecture:** `Propose` keeps installing and rescanning, but runs `test_cmd` only when the snapshot tree equals Michel's own update tree; otherwise the proposal carries tests status `awaiting` and its tree. A new `fix.RunTests` (API `POST /api/v1/fix/{attempt}/run-tests`, CLI `michel fix test`) materializes that tree in its own scratch folder, installs, runs the tests and inserts a superseding proposal only if the current one still has the clicked hash.

**Tech Stack:** Go 1.27, SQLite (portable SQL), Vue 3 + Vuetify, vitest.

**Spec:** `docs/superpowers/specs/2026-11-05-michel-fix-tests-gate-design.md`

## Global Constraints

- No private project name anywhere (test `internal/hygiene`); examples use `demo`.
- SQL portable to PostgreSQL: `?` placeholders, `ON CONFLICT`, RFC 3339 TEXT dates, no `rowid`/`AUTOINCREMENT`/`datetime()`.
- Every French text reviewed by a non-specialist francophone reader, tutoiement; same keys in `en.json`/`fr.json` and in the Go catalog `internal/i18n/catalog`.
- Never write inside scanned projects; all network through `internal/egress`.
- Never replace this control with an instruction to the agent; the agent gets no tool to run tests.
- Unknown tests status displays as "not run", never as "passed".

## Review Focus

1. The agent proposes again while a clicked run is going: the clicked result must be dropped, never supersede the newer proposal (Task 3 test `TestRunTestsDroppedWhenAgentProposedMeanwhile`).
2. Two clicked runs at once (page and CLI): each in its own folder; the second to finish fails stale, nothing wiped mid-run (Task 3 test `TestRunTestsTwoRunsOwnFolders`).
3. A proposal written before the migration (empty tree): no button, run refused with a clear error (Task 3 test `TestRunTestsRefusedWithoutTree`).
4. Level 3 auto-apply unchanged: snapshot equal to Michel's tree still runs tests itself and can auto-approve (Task 2 test `TestProposeUnchangedTreeStillRunsTests`).
5. Tests that hang: the clicked run is bounded like today's run (`workcopy.RunTests` context) and the attempt stays `proposed` (Task 3 test `TestRunTestsTimeoutKeepsProposed`).

---

### Task 1: Store the proposal's tree and the `awaiting` status

**Files:**
- Create: `internal/store/migrations/0023_proposal_tree.sql`
- Modify: `internal/workcopy/run.go:16-18`, `internal/fix/fix.go` (Proposal), `internal/fix/repo.go:307-480` (AddProposal, scan, CurrentProposal)
- Test: `internal/fix/repo_test.go`, `internal/store` migration tests

**Interfaces:**
- Produces: `workcopy.TestsAwaiting = "awaiting"`; `Proposal.Tree string` (json `-`, not exposed by the API); `(*Repo).AddProposalIfCurrent(ctx, p Proposal, hash string) (Proposal, error)` returning `ErrStaleProposal` when the attempt's current proposal hash is not `hash`.

- [ ] Step 1: migration `ALTER TABLE fix_proposal ADD COLUMN tree TEXT NOT NULL DEFAULT ''`.
- [ ] Step 2: failing tests `TestProposalTreeRoundTrip` (AddProposal with Tree "abc", CurrentProposal returns "abc"), `TestAddProposalIfCurrentStale` (current hash H1, call with H0 → `ErrStaleProposal`, current still H1), `TestAddProposalIfCurrentSupersedes` (call with H1 → new current, old superseded). The check and the insert run in one transaction (same form as `Repo.Approve`, `repo.go:140`).
- [ ] Step 3: implement; run `go test ./internal/fix/ ./internal/store/ -count=1`; commit.

### Task 2: `Propose` runs tests only on Michel's own tree

**Files:**
- Modify: `internal/fix/service.go:1140-1260` (Propose), helper for "code files" next to `internal/fix/auto.go`
- Test: `internal/fix/service_test.go` (fake agent tests already exist; follow them)

**Interfaces:**
- Consumes: Task 1.
- Produces: `codeFiles(plan Plan, files []string) []string` (files that are neither the plan's manifest nor its lockfile); proposal `Tree = snap.Tree`; message key `fix.msg.tests_awaiting` (with up to 10 code files then "and N more").

- [ ] Step 1: failing tests: `TestProposeChangedTreeAwaitsTests` (fake agent writes a test file that creates a marker file outside the copy; after Propose the marker does not exist, `TestsStatus == "awaiting"`, `Tree != ""`), `TestProposeUnchangedTreeStillRunsTests` (tests run, status passed/failed as today), `TestProposeChangedTreeInstallFailsStaysFailed`, `TestProposeChangedTreeNoTestCmdStaysNotRun`, `TestCodeFiles`.
- [ ] Step 2: implement: when `!unchanged` and install succeeded and `SplitCommand(p.TestCmd)` gives a non-empty argv, skip `RunTests`, set `awaiting`, say `fix.msg.tests_awaiting`; audit `fix.propose` gains `"tests_awaiting": true`. Go catalog keys EN + FR.
- [ ] Step 3: `go test ./internal/fix/ ./internal/i18n/ -count=1`; commit.

### Task 3: `fix.RunTests`, API and CLI

**Files:**
- Modify: `internal/fix/service.go` (new `RunTests`), `internal/api/fix.go` (route + handler, ProposalView gains `code_files []string` when awaiting), `internal/cli/fix.go` (command `test`)
- Test: `internal/fix/service_test.go`, `internal/api/fix_test.go`, `internal/cli/fix_test.go`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces: `func RunTests(ctx context.Context, d Deps, attemptID, hash string) (Proposal, error)`; errors `ErrStaleProposal`, `ErrNotAwaiting`, `ErrNoTree`, `ErrBadTransition`; API `POST /api/v1/fix/{attempt}/run-tests` body `{"hash": "..."}` → 200 AttemptView, 409 on stale/not awaiting, using the existing long-run pattern (`extend`/`s.detached`, `api/fix.go:328`); CLI `michel fix test <attempt> [--yes]` prints the code files and asks for `--yes`.

- [ ] Step 1: failing tests: `TestRunTestsSupersedesWithResult` (new proposal: same diff, commit, tree, rescan, commands + tests line, new hash; old hash no longer approves), `TestRunTestsDroppedWhenAgentProposedMeanwhile`, `TestRunTestsTwoRunsOwnFolders`, `TestRunTestsRefusedWithoutTree`, `TestRunTestsTimeoutKeepsProposed`, `TestRunTestsNotAwaitingRefused`, `TestRunTestsAudited` (`fix.tests_run` with attempt_id, proposal_id, hash, author, tests, files_code), API 200/409 tests, CLI refuses without `--yes`.
- [ ] Step 2: implement: state must be `proposed`; scratch folder `fix-tmp/<attempt>/tests-<random>` removed at the end; `workcopy.Materialize` on `prop.Tree`, `Install`, `RunTests`; build the new Proposal, `AddProposalIfCurrent(ctx, newProp, hash)`; on stale, return `ErrStaleProposal` and say `fix.msg.tests_dropped`; on success say the result in the conversation; no "waiting" notification.
- [ ] Step 3: `go test ./internal/fix/ ./internal/api/ ./internal/cli/ -count=1`; commit.

### Task 4: Page

**Files:**
- Modify: `web/src/components/FixProposal.vue`, `web/src/components/FixPage.vue`, `web/src/lib/fixView.js:153,178`, `web/src/lib/serversView.js:337`, `web/src/i18n/fr.json`, `en.json`
- Test: `web/src/lib/fixView.test.js`

**Interfaces:**
- Consumes: API of Task 3.
- Produces: `testsState(s)` in fixView.js returns one of passed/failed/not_run/awaiting (unknown → not_run).

- [ ] Step 1: failing vitest: `testsState('awaiting') === 'awaiting'`, `testsState('weird') === 'not_run'`, never 'passed' for unknown.
- [ ] Step 2: FixProposal shows, when awaiting: the warning that running the tests runs code the agent wrote on this computer, the code files (10 then "et N autres"), a link to the diff, and a « Lancer les tests » button emitting `run-tests` with the shown hash; FixPage posts it, shows a wait sentence while it runs, then reloads the attempt; a 409 stale reloads and says the proposal changed. Valider stays available and the page says the tests were not run.
- [ ] Step 3: `npx vitest run`, `npm run build`; commit.

### Task 5: Docs and gates

**Files:**
- Modify: `docs/fix.md`, `docs/fix.fr.md` (where they describe tests before approval), `internal/mcp/tools.go:438` only if a label list needs `awaiting`

- [ ] Step 1: document the rule, the button and `michel fix test`.
- [ ] Step 2: gates: `go test ./... -count=1` (background), `go vet ./...`, `gofmt -l .`, `npx vitest run`, `npm run build`; commit.
