# Michel audit batch B

Design: `docs/superpowers/specs/2026-11-05-michel-audit-batch-b-design.md`
(audit points 03, 04, 05, 07, 08, 09). Branch `feat/audit-batch-b`. Each
task: failing test first, seen failing, minimal code, seen passing, one
commit.

Out of scope (another branch changes them): internal/fix/service.go,
internal/fix/repo.go, internal/fix/runtests.go, internal/workcopy,
internal/api/fix.go, web FixProposal/FixPage. internal/cli/fix.go is touched
only where it reads `deps.Policy` (task 1, mechanical). Migrations start at
0024 (0023 is the tests gate); the migration-count tests of internal/store
will say 22 + ours until the merge reconciles them.

## Task 1: the policy behind an atomic pointer (point 05)

Files: internal/cli/root.go (Deps), every reader of `deps.Policy` in
internal/cli, internal/cli/source.go and internal/cli/fix.go (Reload).

Interface:

```go
func (d *Deps) Policy() policy.Policy        // the policy in force (a copy)
func (d *Deps) PolicySource() policy.Source
func (d *Deps) SetPolicy(p policy.Policy, src policy.Source)
```

Both values sit in one `atomic.Pointer[loadedPolicy]`; a Deps never set
reads the zero policy. Tests: `TestPolicyReloadUnderConcurrentReads` (readers
in goroutines while Reload swaps the policy; every read is one whole policy,
never a mix), root_test updated.

## Task 2: the `watch` section of the policy

Files: internal/policy/policy.go, defaults.go, validate.go.

```go
type WatchConfig struct {
    Enabled *bool  `yaml:"enabled"` // nil = true
    ScanAt  string `yaml:"scan_at"` // HH:MM local; "" = 60 minutes before notify.digest_at
}
func (w WatchConfig) IsEnabled() bool
func (p Policy) WatchHour() (hour, minute int, on bool)
```

Empty `scan_at` is the digest hour minus one hour (07:00 with the defaults),
never before 00:00; with `digest_at: off`, 07:00. Tests:
`TestWatchDefaults`, `TestWatchScanAtIsValidated`,
`TestWatchHourFollowsTheDigest`.

## Task 3: `project.auto_scan` (migration 0024)

Files: internal/store/migrations/0024_project_auto_scan.sql,
internal/project (Project.AutoScan, repo cols, Update), internal/cli/project.go
(`project set --auto-scan`), catalogs.

Tests: `TestMigration0024AddsAutoScanToAnOldDatabase` (a database built by
migrations 0001..0022 with a project opens, the project has auto_scan true),
`TestAutoScanDefaultsTrueAndUpdates` (project), `TestProjectSetAutoScan`
(cli, audited field).

## Task 4: one scan of a project at a time across processes (point 04)

Files: internal/scan/scan.go, internal/scan/sweep.go.

The `running` row is inserted in an immediate transaction that first looks
for a `running` scan of the same project started less than StaleScanAfter
ago; if there is one, `ErrScanRunning` and nothing is written. Every final
UPDATE of the scan row carries `AND status = 'running'`; the commit
transaction rolls back when it changed no row (a scan another process marked
interrupted stays interrupted, its findings are not written).

Tests: `TestRunRefusesWhileTheProjectIsScanned`,
`TestRunIgnoresAStaleRunningScan`, `TestRunDoesNotRewriteAnInterruptedScan`.
The page and the CLI say ErrScanRunning in plain words
(`cli.scan.already_running`, `api.project.scan_running`).

## Task 5: the watch schedule (internal/watch, migration 0025)

Files: internal/watch/watch.go, repo.go, loop.go;
internal/store/migrations/0025_watch_day.sql.

```go
func DayStart(now time.Time, hour, minute int) time.Time
func Due(last time.Time, has bool, now time.Time, hour, minute int) bool
func Next(last time.Time, has bool, now time.Time, hour, minute int) time.Time
type Repo struct{...}
func (r *Repo) LastStarts(ctx) (map[string]time.Time, error)  // newest scan start per project
func (r *Repo) ClaimSources(ctx, day string, at time.Time) (bool, error) // once per local day
type Deps struct {
    Now      func() time.Time
    Policy   func() policy.Policy
    Projects func(ctx) ([]project.Project, error)
    Repo     *Repo
    Sources  func(ctx) // reads the enabled sources (michel source update)
    Scan     func(ctx, project.Project) error // nil, api.ErrNothingToScan and scan.ErrScanRunning are not failures
    Log      *slog.Logger
}
func Loop(ctx context.Context, d Deps, every time.Duration)
```

A project is due when its newest scan started before today's watch hour
(local time) and the hour has come. The source read runs once per local day
(table `watch_day`, claimed with ON CONFLICT DO NOTHING, so a restart or a
second serve does not read again). A failed scan is tried again at most 2
times, 30 minutes apart (memory). ErrScanRunning is not a failure. Inactive
projects and auto_scan false are never scanned.

Tests (pure and with a fake scanner): `TestDueAndNext`,
`TestDueClockGoesBack`, `TestLoopRestartAfterTheHourScansOnce`,
`TestLoopRetriesAFailedScanTwice`, `TestLoopSkipsInactiveAndOptedOut`,
`TestLoopFollowsScanAtChange`, `TestLoopStopsTheRunningScanOnCancel`,
`TestLoopScansEvenWhenSourcesFail`, `TestClaimSourcesOncePerDay`.

## Task 6: the watch in `michel serve`, `michel watch status`

Files: internal/cli/watch.go, internal/cli/serve.go, root.go, catalogs.

serve starts `watch.Loop` with the shared one-at-a-time scanner of the page
(serveScanProject) and the source update of `michel source update`; a source
waiting for consent is said on stderr, the offline scans happen. `michel watch
status` prints the hour, the next pass and, per active project, the last scan
and the next one. Tests: `TestServeWatchScansDueProjects` (real loop,
real scan of a demo project), `TestWatchStatusSaysNextPass`,
`TestWatchSourcesWithoutConsentSaySo`.

## Task 7: the page says the next check

Files: internal/api/views.go, handlers.go; web/src/lib/projectsView.js,
ProjectCard.vue, en.json, fr.json.

ProjectView gains `auto_scan` and `next_scan_at` (RFC 3339, "" when the
watch is off). Tests: `TestProjectsSayTheNextScan` (api),
`nextScanText` cases in projectsView.test.js.

## Task 8: audit sequence, count and portable SQL (points 08, 09)

Files: internal/store/migrations/0026_audit_seq.sql, internal/audit,
internal/api/targets.go, internal/cli/audit.go, internal/serverlog/unseen.go,
internal/hygiene/sql_test.go.

0026 rebuilds audit_event with `seq INTEGER NOT NULL UNIQUE` (the old
column's values, copied positionally), adds `hmac TEXT NOT NULL DEFAULT ''`,
the index `(action, target)` and the table `audit_anchor(id, events)` filled
with the current count. Record reads the last event by `seq`, increments
`audit_anchor.events` in its transaction and writes that count to the head
file: no COUNT(*). Tests: `TestRecordDoesNotCountTheTable` (a statement hook
proves no COUNT), `TestEventsOrderBySeq`,
`TestMigration0026KeepsTheChainOfAnOldDatabase`,
`TestLogFailureUpsertIsPortable`, `TestSQLIsPortable` (hygiene: no rowid,
AUTOINCREMENT, INSERT OR REPLACE or datetime( outside a closed list of shipped
migrations; test files are not checked).

## Task 9: the audit seal (point 07)

Files: internal/audit (SetKey, LoadOrCreateKey, VerifyWith),
internal/secret (ReservedAuditKey), internal/cli/root.go, audit.go, secret.go,
catalogs.

With `integrity_protection: required`, each event carries
`hmac = HMAC-SHA256(key, hash)` (hex). The key (32 random bytes) is the secret
`audit-key`, created at the first start; `michel secret set` refuses the
name. `michel audit verify` checks the chain and the seals; events before the
first sealed one are counted as "before the protection"; an unsealed event
after a sealed one, a wrong seal, or an absent anchor with events is a
failure. `none` keeps the old behavior. Tests: `TestSealedEventsVerify`,
`TestWrongSealIsBroken`, `TestStrippedSealIsBroken`,
`TestOldEventsAreBeforeTheProtection`, `TestAbsentAnchorFailsWhenRequired`,
`TestAuditVerifyChecksSeals` (cli).

## Task 10: docs

docs/operations/daily-digest.md and .fr.md: serve now watches by itself; the
scheduled task stays for a computer without serve.

Gates before the last commit: `go test ./... -count=1`, `go vet ./...`,
`gofmt -l .`, `cd web && npx vitest run && npm run build`.
