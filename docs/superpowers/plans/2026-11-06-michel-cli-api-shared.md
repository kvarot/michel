# CLI/API shared logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every business rule used by both `michel` commands (`internal/cli`) and the local page (`internal/api`) lives once, in its domain package, with its audit events; the drifted copies are reconciled as the spec decides.

**Architecture:** One domain function per operation (in `internal/project`, `internal/target`, `internal/decide`, `internal/watch`, `internal/fix`, `internal/source`/`internal/gitrepo`). It validates, writes, rolls back and records the audit events. CLI and API keep only input parsing, error-to-message/HTTP mapping and output. Typed errors (sentinel or a small error type with an i18n key) let each side say the refusal in its own way.

**Tech Stack:** Go 1.27, SQLite (portable SQL), cobra, net/http.

**Spec:** `docs/superpowers/specs/2026-11-06-michel-cli-api-shared-design.md`

## Global Constraints

- No private project name anywhere (test `internal/hygiene`); examples use `demo`.
- SQL portable to PostgreSQL: `?` placeholders, `ON CONFLICT`, RFC 3339 TEXT dates, no `rowid`/`AUTOINCREMENT`/`datetime()`.
- Every French text reviewed by a non-specialist francophone reader, tutoiement; same keys in `internal/i18n/catalog/en.json` and `fr.json`.
- Never write inside scanned projects; all network through `internal/egress`.
- No secret value in an error or audit event.
- Visible behaviour stays the same except the divergences the spec decides; existing tests of both sides keep passing (adjust a test only when the spec changes the behaviour it asserts, and say so in the report).
- Where two copies differed, the most protective rule wins unless the spec says otherwise.
- Domain packages must not import `internal/api` or `internal/cli`.
- Go is at `%LOCALAPPDATA%\Programs\go\bin` (bash: `export PATH="$LOCALAPPDATA/Programs/go/bin:$PATH"`); no cgo, so no `-race` locally. Full `go test ./...` takes minutes. staticcheck must stay at 0 findings (`go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...`).

## Review Focus

1. `michel project add` now refuses what the page refuses (system/home/data/network folders, reparse points, a second active project on the same folder), with the same audit trace, and purges the project if its audit write fails.
2. No audit event lost or doubled by the move: each operation writes the same events (action, result, evidence keys) from both entries, except the renames the spec decides (`project.set` becomes `project.update`; `changed` names `fix_level`, `site_url`).
3. Rollbacks kept: target add removes the target if linking or rules fail; target update restores rules on failure.
4. Allow rules: a rule the user added by hand to the policy file stays theirs, from the CLI too.

---

### Task 1: project.Register — one way to add a project

**Files:**
- Create: `internal/project/folder.go` (folder checks moved from `internal/api/projects_run.go`: `projectFolder`, `isNetworkPath`, `hasDotDot`, `isDriveLetterPath`, `hasDeviceName`, `strangeOnWindows`, `reparsePointOnTheWay`, `forbiddenFolder`, `foldPath`, name rule `validProjectName`, bounds `maxPathLen`, `maxProjectName`, with their tests), `internal/project/register.go`
- Modify: `internal/api/projects_run.go` (addProject calls Register), `internal/cli/project.go` (newProjectAddCmd calls Register)
- Test: `internal/project/*_test.go` (moved tests + Register), existing `internal/api` and `internal/cli` project add tests

**Behaviour (spec case 1):**
- `project.Register(ctx, repo *Repo, log *audit.Logger, req RegisterRequest) (Project, error)`; `RegisterRequest` carries the actor, the raw name and path, and the optional fields the CLI sets today (classification, fix level and whether it was set, auto-fix-minor, test/install commands, core packages, exclude, tech), plus what forbiddenFolder needs (data dir, home; inject so tests can set them).
- Order: trim name and path; name rule; folder check (returns the real folder); refuse a second active project on the same folder (case-folded as today); `repo.Add`; audit `project.add` `ok` with evidence `path`, `classification`, `fix_level`; on audit failure purge the project and return the audit error.
- Every refusal is audited `project.add` `denied` with evidence `path` (bounded, no control characters, as `boundedForAudit`) and `reason` = the i18n key (`api.project.bad_name`, `api.project.relative_path`, `api.project.forbidden_path`, `api.project.not_dir`, `api.project.duplicate`, and the existing keys for other validation errors of `repo.Add` such as a bad classification or fix level); a storage error is audited `error`. Return a `*RefusalError{Key string}` (or equivalent) so the API keeps its HTTP status and hint keys, and the CLI prints the translated key (use the same `api.project.*` texts, or add `cli.project.add.*` keys if a page text says "the page" or a button; any new FR text goes to the FR reviewer).
- The CLI makes a relative path absolute (`filepath.Abs`) before Register; nothing else differs.
- [ ] Move the folder checks and their tests; API tests unchanged and green.
- [ ] Write failing tests for Register (each refusal audited with its key, duplicate active folder, purge on audit failure, success evidence).
- [ ] Implement Register; switch the API and the CLI to it.
- [ ] CLI tests: `michel project add` refuses the data folder and a second project on the same folder; existing CLI tests green (they use `t.TempDir()` folders).
- [ ] Commit.

### Task 2: project update and active lookup

**Files:**
- Modify: `internal/project` (new `Patch` type and `(*Repo).Apply` or a `project.Update(ctx, repo, log, actor, name, patch)` function; `(*Repo).GetActive`), `internal/cli/project.go` (set command), `internal/api/handlers.go` (PATCH /projects/{name}, `activeProject`), CLI commands on findings/decisions/consent
- Test: `internal/project`, existing api/cli tests

**Behaviour (spec cases 2 and 3):**
- One update function: applies the fields sent, validates in `project` (fix level 0..3 via `ErrInvalidFixLevel`, no second check in the handler), `repo.Update`, audit `project.update` (`ok`, `denied` with reason, `not_found`, `error`) with the evidence the CLI writes today; the API now audits refusals too. Both entries write `project.update`.
- `GetActive(ctx, name)` returns not found for an inactive project. The API's `activeProject` uses it. CLI commands that act on findings, decisions or fix consent of a project use it; `project set` (incl. reactivation), `project remove`, `project list` keep `Get`.
- [ ] Failing tests: update audits `project.update` from both entries; refused update audited from the API; `GetActive` hides inactive; a CLI decision on a removed project is refused like the page.
- [ ] Implement, switch both sides; commit.

### Task 3: small shared rules — scan status and exposure decision

**Files:**
- Modify: `internal/watch` (new `ProjectStatus(ctx, repo *Repo, p project.Project, pol policy.Policy, now time.Time)` returning last scan at/status/has and next check, using `LastScan` and `LastStart` as today), `internal/api/handlers.go:185-203`, `internal/cli/watch.go` status command; `internal/decide` (`Validate` refuses `fix` on a `KindServerExposure` finding), `internal/cli/decide.go:94-96`
- Test: `internal/watch`, `internal/decide`, existing `internal/api/next_scan_test.go`, `internal/cli/watch_test.go`

**Behaviour (spec cases 4 and 5):**
- API and CLI get last and next check from `ProjectStatus`; last scan time always RFC 3339 UTC; an unreadable stored date is an error on both sides (the API answers 500 through its usual path).
- `decide.Validate` (or the function both entries call) refuses action `fix` for an exposure finding with the error the CLI uses today; the CLI's own check goes; the API answers it as a refused decision (400 with the existing refusal mechanism; add an `api.decision.*` key if none fits, FR reviewed).
- [ ] Failing tests, implement, commit.

### Task 4: target allow rules and target add

**Files:**
- Modify: `internal/target` (or `internal/servercheck` if `target` cannot import what is needed: say which in the report) — new `ChangeRules(...)` and `Register(...)`; `internal/cli/target.go:234-266, 296-361`; `internal/api/targets.go:518-560, 913-980`
- Test: domain package tests, existing api/cli target tests

**Behaviour (spec cases 6 and 7):**
- `ChangeRules`: computes `NewRules`/`OwnedOnly` against the policy file as read now (not the policy loaded at start), adds/removes allow rules, records/forgets owned rules, reloads, sets the gateway rules; no-op without a policy file path. The page keeps its `policyMu` around the call.
- Target `Register`: name from alias or host, kind `vps`, fix level 1, trims name/alias/host/user, accepts classification and auto_config (the CLI does not expose them), `ParseInterval` then `Check` (one order for both; keep the page's order), empty user refused (keep the CLI's refusal if `Check` does not already do it, and say which), `ResolvePreprod`, `Add`, `Link` (remove target on failure), rules (remove target on failure), audit `target.add` with today's evidence.
- [ ] Failing tests (hand-added rule stays the user's from the CLI path; rollback on link failure; same audit from both), implement, commit.

### Task 5: target update, remove and host key trust

**Files:**
- Modify: domain package chosen in Task 4 — `ApplyUpdate(...)`, `Remove(...)` orchestration, `ConfirmHostKey(...)`; `internal/cli/target.go:424-441, 500-589, 602-675`; `internal/api/targets.go:989-1108, 1124-1209, 1258-1288`
- Test: domain tests, existing api/cli target tests

**Behaviour (spec case 7):**
- Update: one sequence (ParseInterval, Check, CheckEnv, ResolvePreprod, add new rules first, Update with rules rolled back on failure, release old rules, audit `target.update`); rules rewritten on a host or site change; `host_key_reset` recorded as the page does; `changed` names `fix_level`, `site_url` (snake_case, the page's names) from both sides.
- Remove: same locks, TargetBlock handling, dependents count, logs erased first, Remove, rules released, audit `target.remove`; the store removal runs detached from cancellation (the page's choice) on both sides.
- Host key: same mismatch and "changed without replace" refusals audited `refused`, `SetHostKey`, audit with `replaced`.
- [ ] Failing tests where behaviour is new for one side, implement, commit.

### Task 6: fix consent status and sources

**Files:**
- Modify: `internal/fix` (`ConsentStatus(ctx, d Deps, p project.Project, pol policy.Policy)` returning the lines, ready and the refusal), `internal/cli/fix.go:698-737`, `internal/api/fix.go:937-1024`; `internal/source` / `internal/gitrepo` (`AddUserEntry`, discovery `Add`/`Ignore` with their audits), `internal/cli/source_discover.go`, `internal/cli/source.go:376-393`, `internal/api/sources_items.go:137-173`, `internal/api/sources.go:413-441`
- Test: domain tests, existing api/cli tests

**Behaviour (spec cases 8 and 9):**
- Consent: both sides compute the state from `ConsentStatus`; the page keeps its switch to standard; the CLI keeps refusing `strict_local` and its message points to the page or the policy (FR reviewed if new).
- Sources: case-insensitive repository match, skill/mcp kind check, `NewUserEntry`, exists check, `Upsert`, `SetState(added)`, audit `source.add` with `from=discover`; ignore audited `source.discover`; same from both sides.
- [ ] Failing tests where needed, implement, commit.
