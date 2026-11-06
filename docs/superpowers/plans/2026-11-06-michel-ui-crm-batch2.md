# Security CRM interface, batch 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each finding keeps the history of its status changes and of its fix attempts. The page shows it as a timeline on the finding sheet, as a 90-day curve of open findings on the overview, and as weekly and monthly reports that can be printed.

**Architecture:** Two event tables, `finding_event` and `fix_attempt_event` (migration 0028, with a reconstructed past for the existing rows). They are written in the same transaction as each status or state change. A new package `internal/history` reads them, together with the `decision` table, to build the timeline, replay "open at instant T", and aggregate a period. Three API routes expose this. The front gets pure modules in `web/src/lib`, thin components, a "Rapports" page and a print style sheet.

**Tech Stack:** Go 1.27, SQLite (portable SQL), Vue 3 + Vuetify, vitest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-06-michel-ui-crm-batch2-design.md`, which includes the section « Précisions après la relecture du constructeur ». That section is binding.

## Global Constraints

- No private project name anywhere (test `internal/hygiene`); examples use `demo`.
- SQL portable to PostgreSQL: `?` placeholders, `ON CONFLICT`, RFC 3339 TEXT dates, no `rowid`/`AUTOINCREMENT`/`datetime()`/`INSERT OR REPLACE`.
- Every French text is reviewed by a non-specialist francophone reader, with tutoiement. The same keys exist in `web/src/i18n/en.json`/`fr.json` and, for Go texts, in `internal/i18n/catalog/en.json`/`fr.json`.
- Never write inside scanned projects; all network through `internal/egress`. No path, machine name or secret in a timeline entry, an API answer or a report beyond what the page already shows.
- No new JS or Go dependency, no downloaded font (CSP). Charts are SVG or CSS.
- A figure that cannot be read shows as "not read" (`UnreadValue`), never 0. Reconstructed history is always flagged as reconstructed.
- Severity is never a colour alone (colour + word + shape), and stays readable when printed in black and white.
- Accessibility: one `h1` per page, visible focus, `aria-current` in the nav, charts with an equivalent text, and `prefers-reduced-motion` respected.
- Server findings: the curve excludes them using the same filter as `ListFindings`. Reports count them apart. The timeline is for project findings. Findings of inactive (removed) projects are excluded everywhere, as on the Failles page.
- Gates: `go test ./...`, `gofmt -l`, staticcheck `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...` at 0, `cd web && npm test && npm run build`.
- Go is at `%LOCALAPPDATA%\Programs\go\bin` (bash: `export PATH="$LOCALAPPDATA/Programs/go/bin:$PATH"`). There is no cgo, so no `-race` locally.

## Review Focus

1. **A finding seen, gone and back within one local day.** The curve counts it by its state at the end of that day. The timeline shows the three events in order. Test: `TestOpenAtReplaysSameDayChanges` (Task 3).
2. **DST days in Europe/Paris** (the last Sunday of March and of October). Each local day is one point, and the week runs Monday 00:00 to the next Monday 00:00, local time. Test: `TestDaysAcrossDST` (Task 3), with `time.LoadLocation("Europe/Paris")`.
3. **A period with no activity at all.** Each count is 0 when the data was read, and "not read" only when the source cannot be read. Test: `TestReportEmptyPeriodIsZeros` (Task 4) and `reportView` test (Task 6).
4. **A report period in the future.** The API refuses `from` after today with 400. The page never offers a period after the current one. Tests: `TestReportsRefusesFuture` (Task 4) and `reportsView` navigation test (Task 6).
5. **An ignore decision taken and then superseded.** The finding is open before the decision, closed while it is in force, and open again after `superseded_at`. Test: `TestOpenAtFollowsIgnoreDecisions` (Task 3).

---

### Task 1: Event tables, migration with reconstructed past, finding events written at each status change

**Files:**
- Create: `internal/store/migrations/0028_history.sql`, `internal/history/events.go` (the writer only)
- Modify: `internal/scan/repo.go` (the `apply` insert and its status updates at ~323-339), `internal/decide/repo.go` (`setStatus` at ~145, callers `Set`, `Supersede`, `expire`), `internal/store/store_test.go:149` (versions list and count up to 28)
- Test: `internal/history/events_test.go`, `internal/scan` and `internal/decide` tests, store migration test

**Interfaces:**
- Produces:
  - Tables:
    - `finding_event(finding_id TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (finding_id, seq))`, with indexes on `(at)` and `(finding_id)`.
    - `fix_attempt_event(attempt_id TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, state TEXT NOT NULL, reconstructed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (attempt_id, seq))`, with an index on `(at)`.
  - `history.FindingEvent` kinds: the constants `KindSeen = "seen"`, `KindGone = "gone"`, `KindBack = "back"`, `KindReopened = "reopened"`.
  - `history.AddFindingEvent(ctx context.Context, tx *sql.Tx, findingID string, at time.Time, kind string, detail map[string]any) error`. It sets `seq = COALESCE(MAX(seq),0)+1` for that finding, read inside `tx`. `detail` is marshalled as JSON and must hold no path.
  - `history.StatusEvents(from, to string, reason string) []string` returns the kinds to write for a status change `from` → `to` (`from == ""` for an insert):
    - insert gives `seen`;
    - any → `gone` gives `gone`;
    - `gone` → non-gone gives `back`, plus `reopened` when `to == "pending"` and a decision was superseded (`reason != ""`);
    - `decided` → `pending` gives `reopened`;
    - anything else gives none.
  - Import rule: `internal/history` must not import `scan`, `decide` or `fix`, so that they can call it.
- Migration reconstruction (literal `seq`, portable SQL, no `rowid`):
  - every finding gets `(id, 1, first_seen_at, 'seen', '{"reconstructed":true}')`;
  - every finding with `status = 'gone'` also gets `(id, 2, status_changed_at, 'gone', '{"reconstructed":true}')`;
  - every attempt gets `(id, 1, created_at, 'preparing', 1)`, plus `(id, 2, updated_at, state, 1)` when its state is not `preparing`.
  - The migration also writes a row in a small table `history_start(id INTEGER PRIMARY KEY CHECK (id = 1), at TEXT NOT NULL)` holding the migration instant. Use the time of migration, as other migrations set dates (check how 0024-0027 do it; if SQL cannot produce an RFC 3339 now portably, have the Go migration runner fill it, or insert it lazily from Go at the first read and say which).

- [ ] **Step 1: Failing tests**
  - `TestStatusEvents` (table: insert→seen; new→gone; pending→gone; gone→decided gives back; gone→pending with reason gives back,reopened; decided→pending gives reopened; new→pending gives none; pending→decided gives none).
  - `TestAddFindingEventNumbersPerFinding` (two findings, three events, `seq` 1,2 then 1).
  - `TestMigrationReconstructsHistory` (store test: seed a gone finding and an applied attempt at migration 27, migrate, read the rows with `reconstructed`).
  - scan test `TestApplyWritesFindingEvents` (first scan gives seen; next scan without the finding gives gone; next with it gives back).
  - decide test `TestSupersedeWritesReopened` (`detail.reason` equals the supersession reason).
- [ ] **Step 2: Run them, see them fail** (`go test ./internal/history/ ./internal/scan/ ./internal/decide/ ./internal/store/`).
- [ ] **Step 3: Implement** the migration, the writer and the hooks. Every place that changes `finding.status` calls `StatusEvents` then `AddFindingEvent` in the same `tx`, with the previous status read where it is already known. Update the store version test to `…,26,27,28`.
- [ ] **Step 4: Run the package tests, then `go test ./...`; all green.**
- [ ] **Step 5: Commit.**

### Task 2: Fix attempt state events

**Files:**
- Modify: `internal/fix/repo.go`: the insert at ~104 and every `UPDATE fix_attempt SET state` (~153, ~277, ~478, ~941). Grep for `SET state` in the whole package, server attempts included.
- Create: `history.AddAttemptEvent(ctx context.Context, q execQuerier, attemptID string, at time.Time, state string) error` in `internal/history/events.go`. `execQuerier` is a small interface that `*sql.DB` and `*sql.Tx` both satisfy, because some updates run outside a tx.
- Test: `internal/fix/repo_test.go`, `internal/history/events_test.go`

**Interfaces:**
- Consumes: the `fix_attempt_event` table (Task 1).
- Produces: one row per real state change (the insert included), never a row for an update that keeps the state, `reconstructed = 0`.

- [ ] **Step 1: Failing tests**
  - `TestAttemptEventsFollowStates` (create → preparing; SetState proposed; approve; apply; prove; read the events: states in order, increasing `seq`).
  - `TestAttemptEventNotWrittenWhenStateKept` (the touch update at ~168 writes no row).
  - `TestAttemptEventNotWrittenWhenUpdateMissed` (a conditional update that affects 0 rows writes no row).
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement.** Write the event only when the update reports one row affected. Use the same `at` as `updated_at`. When an update is a plain `ExecContext` on the DB, wrap the update and the event write in one transaction.
- [ ] **Step 4: `go test ./internal/fix/ ./internal/history/` then `go test ./...`; green.**
- [ ] **Step 5: Commit.**

### Task 3: Timeline and replay (`internal/history`) and their routes

**Files:**
- Create: `internal/history/timeline.go`, `internal/history/open.go`, tests; `internal/api/history.go`, test
- Modify: `internal/api/server.go` (routes)

**Interfaces:**
- Produces:
  - `history.Entry{At time.Time; Kind string; Detail map[string]any; Reconstructed bool}`, with Kind one of:
    - the finding kinds of Task 1;
    - `decision` (Detail: `action`, `author`, `due` when set, `superseded_at` when set, `reason` when superseded);
    - `attempt` (Detail: `attempt_id`, `state`).
  - `history.Timeline(ctx context.Context, db *sql.DB, findingID string) ([]Entry, error)`, newest first. The attempt states it shows are `preparing` (named "launched"), `proposed`, `approved`, `refused`, `applied`, `proven_fixed`, `inconclusive`, `failed`, `withdrawn`, `superseded` and `held`. `running` and `unknown` show only when they are the attempt's last state.
  - `history.Day{Date string /* YYYY-MM-DD local */; Open map[string]int /* severity -> count */; Reconstructed bool}`.
  - `history.OpenByDay(ctx context.Context, db *sql.DB, now time.Time, loc *time.Location, days int, severity func(findingRow) string) ([]Day, error)`. The severity func is the current effective severity, computed the way `ListFindings` computes it. Pass it in so that `history` does not import `scan`; define `findingRow` with the columns needed.
  - `history.OpenAt(...)` is the shared rule, also used by Task 4: not gone at T, and no `ignore` decision in force at T. A day is `Reconstructed` when its end is before `history_start.at`.
  - `history.LocalDays(now time.Time, loc *time.Location, n int) []struct{Start, End time.Time; Date string}`: day boundaries built with `time.Date(y, m, d, 0, 0, 0, 0, loc)`, never by adding 24h.
  - Routes, both 404 for a finding of an inactive project or a server finding:
    - `GET /api/v1/findings/{id}/timeline` → `{"entries":[{at,kind,detail,reconstructed}], "history_start": at}`;
    - `GET /api/v1/stats/open?days=90` → `{"days":[{date, open:{critical,high,medium,low,unknown}, reconstructed}], "history_start": at}`. `days` defaults to 90, maximum 365, and any other value gives 400.

- [ ] **Step 1: Failing tests**
  - `TestTimelineMergesSources` (events + decision + attempt, ordered newest first, reconstructed flag kept);
  - `TestOpenAtReplaysSameDayChanges`;
  - `TestOpenAtFollowsIgnoreDecisions`;
  - `TestOpenByDayExcludesServerAndInactive`;
  - `TestDaysAcrossDST` (Europe/Paris: 2026-03-29 and 2026-10-25 are one day each, 23h and 25h long);
  - API `TestTimelineRoute`, `TestStatsOpenRoute` (bad `days` gives 400; a server finding gives 404).
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement.** Load the events, decisions and findings of the active projects once, then replay in Go. Do not run one query per day. Write a benchmark-style test, `TestOpenByDayIsFast`: 5 000 findings, 365 days of events, under 1 s on this PC; skip it with `testing.Short()`.
- [ ] **Step 4: `go test ./internal/history/ ./internal/api/`, then `go test ./...`; green.**
- [ ] **Step 5: Commit.**

### Task 4: Period report (`internal/history`) and its route

**Files:**
- Create: `internal/history/report.go`, tests; route in `internal/api/history.go`

**Interfaces:**
- Consumes: `OpenAt`, `LocalDays` and the events (Task 3).
- Produces:
  - `history.Report` (JSON names in snake_case) with these fields:
    - `from`, `to` (local dates, `to` included);
    - `found` and `gone_by_michel`, `gone_elsewhere` (each by severity);
    - `decisions` (by action);
    - `fixes`: `{proposed, applied, proven}`, each counted from the events in the period;
    - `open_start` and `open_end` (by severity, from `OpenAt` at the period's start and end);
    - `oldest_open`: `{finding_id, package, osv_id, first_seen_at}` or null;
    - `checks`: `{projects: {done, failed}, servers: {done, failed} | null}` (null = not read);
    - `servers`: `{found, closed}` (server findings, counted apart);
    - `projects`: a list of `{name, found, gone, open_end, decisions}`;
    - `reconstructed bool`, true when any part of the period is before `history_start`.
  - `history.BuildReport(ctx, db, from, to string, loc *time.Location, now time.Time, severity func(findingRow) string) (Report, error)`.
  - "Gone by Michel" means that a `gone` event of the finding comes after an `applied` or `proven_fixed` event of one of its attempts.
  - Server checks: find where server check runs are stored. If only the last check is kept per server, count what falls in the period and return `null` when the storage cannot tell. Say which in the report.
  - Route: `GET /api/v1/reports?from=YYYY-MM-DD&to=YYYY-MM-DD`. It gives 400 when the dates are malformed, when `to` is before `from`, when `from` is after today (local), or when the span is over 62 days.

- [ ] **Step 1: Failing tests**
  - `TestReportCountsPeriod` (seeded week: 3 found, 1 gone by Michel, 1 elsewhere, 2 decisions, 1 proven);
  - `TestReportEmptyPeriodIsZeros`;
  - `TestReportOpenStartEndMatchOpenAt`;
  - `TestReportsRefusesFuture`;
  - `TestReportsRefusesBadRange`;
  - `TestReportNoPathOrSecret` (no `\` or `/` path in the JSON beyond package names, which may hold `/`: check the project path and the data dir instead).
- [ ] **Step 2: Run, fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `go test ./internal/history/ ./internal/api/`, then `go test ./...`; green.**
- [ ] **Step 5: Commit.**

### Task 5: Front: timeline on the finding sheet and 90-day curve on the overview

**Files:**
- Create: `web/src/lib/timelineView.js` (+ test), `web/src/lib/openCurveView.js` (+ test), `web/src/components/FindingTimeline.vue`, `web/src/components/OpenCurve.vue`
- Modify: `web/src/api.js` (two calls), the finding sheet shown at `#/fix?finding=<id>` (`FixPage.vue` / `FindingSheet.vue`: find which one renders the guided sheet), `web/src/components/OverviewPanel.vue`, `web/src/i18n/en.json`, `fr.json`

**Interfaces:**
- Consumes: the routes of Task 3.
- Produces:
  - `timelineView.lines(entries, lang, now)` → `[{date, text, reconstructed}]`. The words are plain ("Vue pour la première fois", "N'est plus trouvée", "Revenue", "Remise à traiter : …", "Décision : …", "Correctif proposé", …). Expert mode adds the attempt id. Above 10 lines it returns `{shown, hidden}`.
  - `openCurveView.series(days)` → stacked SVG paths per severity, plus `summary` (start, end, highest, lowest as numbers, for the equivalent text), plus `reconstructedUntil`.

- [ ] **Step 1: Failing vitest tests**
  - `timelineView`: each kind gets its words in en and fr; reconstructed is flagged; the 10-line fold works.
  - `openCurveView`: the stack sums; an empty list gives no path and an "aucune donnée" summary; the reconstructed part is marked.
- [ ] **Step 2: `cd web && npm test`; fail.**
- [ ] **Step 3: Implement the modules and the thin components.** The curve uses `aria-describedby` on the summary text. The reconstructed part is drawn dashed, with the sentence from the spec. A sentence under the curve says that the severity used is today's.
- [ ] **Step 4: `npm test && npm run build`; green. Then `go test ./web/...` (embed).**
- [ ] **Step 5: Commit.** List every new French text in the report.

### Task 6: Front: Rapports page and print style

**Files:**
- Create: `web/src/lib/reportsView.js` (+ test), `web/src/components/ReportsPage.vue`
- Modify: `web/src/App.vue` / router (route `#/reports`), `web/src/components/AppNav.vue` + `web/src/lib/navView.js` (+ test: entry "Rapports" in the "Suivi" group, desktop sidebar only, the bottom bar keeps its 5 entries), `web/src/api.js`, `web/src/styles.css` (`@media print`), i18n en/fr

**Interfaces:**
- Consumes: `GET /api/v1/reports` (Task 4).
- Produces:
  - `reportsView.period(kind /* "week"|"month" */, at /* YYYY-MM-DD */, today)` → `{from, to, label, current, prev, next /* null past the current period */}`. Weeks run Monday to Sunday, months run the 1st to the last day, local time. With no `at`, the default is the previous complete week.
  - `reportsView.summary(report, lang)` gives the lead sentence (« Cette semaine : 4 failles trouvées, 6 corrigées, 2 en attente de ta validation »). Plurals are right for 0 and 1. A null value says « non lu ».

- [ ] **Step 1: Failing vitest tests**
  - `period`: the week of 2026-11-04 is 2026-11-02 → 2026-11-08; the month of February 2028 ends on the 29th; `next` is null in the current period; the default is the previous week.
  - `summary`: en/fr, 0/1/many, null gives « non lu ».
  - `navView`: "Rapports" is listed in "Suivi" on the desktop, and the bottom bar is unchanged.
- [ ] **Step 2: `npm test`; fail.**
- [ ] **Step 3: Implement the page.**
  - Period switch (week / month) and arrows.
  - Lead sentence and tables (by severity, by project).
  - Servers section.
  - « Imprimer » button (`window.print()`).
  - The reconstructed notice when `reconstructed`.
  - The address keeps `period` and `at`.
  - Print sheet: hide the nav, the buttons and the banners; black text on white; severity as word + shape; no page break inside a table row; the period and the date of printing in the header.
- [ ] **Step 4: `npm test && npm run build && go test ./web/...`; green.**
- [ ] **Step 5: Commit.** List every new French text in the report.
