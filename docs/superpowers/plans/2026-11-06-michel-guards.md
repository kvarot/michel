# Project light, ignore review date, CycloneDX export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a light per project (green/red/grey) with an optional `pre-push` guard, an "Ignore" decision that comes back at a review date (1 year by default), and a CycloneDX 1.6 JSON export with VEX analysis, all reachable from the page.

**Architecture:** one Go rule for the light (`internal/gate`), read by the API, the CLI `michel gate` and the hook. Components of the last `ok` scan stored in a new table and written by `internal/cyclonedx`. The ignore review date reuses `decision.due_at` and the existing expiry paths, with a new reason `review_due`. The page only shows what the API returns.

**Tech Stack:** Go (stdlib `encoding/json`, `database/sql` on SQLite), cobra CLI, Vue 3 + Vuetify, vitest.

**Spec:** `docs/superpowers/specs/2026-11-06-michel-guards-design.md`

## Global Constraints

- Every feature is on the page first; the CLI mirrors it (Kévin: "pas une usine à gaz où il faut connaître toutes les commandes").
- Three thresholds only: `soft`, `normal` (default), `strict`. Grey when in doubt, never a false green.
- No new Go or JS dependency. No network egress. No `AUTOINCREMENT`. Migrations numbered after `0028_history.sql`.
- Texts in FR (tutoiement, as the catalog tests require) and EN: `internal/i18n/catalog/{fr,en}.json`, `web/src/i18n/{fr,en}.json`.
- Severity never shown by color alone. No absolute path, host name or secret in an export, an audit event or an API answer beyond what the page already shows.
- Every change of threshold, hook install, hook removal and export writes an audit event (`audit.Logger.Record`).
- Windows and Linux: the hook is a `sh` script with `/` in paths, quoted.
- Before blaming a change, compare failing Go tests with `main`: 4 tests already fail on this PC (bare LF on example/mcp, x509 on 127.0.0.1).

## Review Focus

1. Project path with spaces or accents on Windows: the hook still runs Michel (quoted paths). Test in Task 6: `TestHookScriptQuotesPaths`.
2. Repo where `.git` is a file (worktree, submodule) or `core.hooksPath` is set: hooks folder taken from `git rev-parse --git-path hooks`, never `<path>/.git/hooks` by hand. Test in Task 6: `TestInstallInWorktree`.
3. Project folder missing or moved: light grey `folder_missing`, export refused. Test in Task 4: `TestLightFolderMissing`.
4. An ignored finding that goes away and comes back before its review date stays ignored; after the date it comes back with `review_due`. Test in Task 3: `TestIgnoreReviewSurvivesGoneBack`.
5. npm scoped package `@scope/name` in a purl: `pkg:npm/%40scope/name@1.2.3`. Test in Task 7: `TestPurlScopedNpm`.

---

### Task 1: Storage and threshold setting

**Files:**
- Create: `internal/store/migrations/0029_guards.sql`
- Modify: `internal/project/project.go`, `internal/project/repo.go` (Patch, scan of the row), `internal/api/handlers.go` (`projectPatch`)
- Test: `internal/project/project_test.go`, `internal/api/handlers_test.go`

**Interfaces:**
- Produces: column `project.gate_threshold TEXT NOT NULL DEFAULT 'normal'`; table `scan_component (project_id TEXT NOT NULL, manifest_rel_path TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, purl TEXT NOT NULL DEFAULT '', dep_group TEXT NOT NULL DEFAULT '', scan_id TEXT NOT NULL, PRIMARY KEY (project_id, manifest_rel_path, ecosystem, name, version))`; table `repo_hook (repo_root TEXT PRIMARY KEY, hook_path TEXT NOT NULL, content_sha256 TEXT NOT NULL, installed_at TEXT NOT NULL)`.
- Produces: `project.Threshold` string type with `ThresholdSoft="soft"`, `ThresholdNormal="normal"`, `ThresholdStrict="strict"`; `Project.GateThreshold Threshold` (`json:"gate_threshold"`); `project.Patch.GateThreshold *Threshold`; `project.ErrInvalidThreshold`.
- Produces: `PATCH /api/v1/projects/{name}` accepts `{"gate_threshold":"strict"}`, records audit action `project.threshold` with evidence `{from,to}`.

- [ ] **Step 1: Failing tests** — `TestPatchThreshold` (patch to `strict`, read back `strict`; `"loose"` → `ErrInvalidThreshold`; new project reads `normal`), `TestAPIPatchThresholdAudited` (PATCH 200, one audit event `project.threshold` with `from:"normal", to:"strict"`; bad value → 400 with key `api.project.bad_threshold`).
- [ ] **Step 2: Run** `go test ./internal/project ./internal/api -run 'Threshold'` → FAIL.
- [ ] **Step 3: Implement** migration, field, patch, API body field, audit, FR/EN key `api.project.bad_threshold`.
- [ ] **Step 4: Run** same command → PASS; `go test ./internal/store` → PASS.
- [ ] **Step 5: Commit** `feat(project): gate threshold per project and guard tables`.

### Task 2: Components of the last ok scan

**Files:**
- Create: `internal/scan/components.go`, `internal/scan/components_test.go`
- Modify: `internal/scan/scan.go` (inside the tx of `Run`, after `insertManifests`)

**Interfaces:**
- Consumes: Task 1's `scan_component` table.
- Produces: `type Component struct { ManifestRelPath, Ecosystem, Name, Version, PURL, DepGroup string }`; `func componentsOf(vr models.VulnerabilityResults, root string, accepted map[string]bool) []Component` (same relative paths and accepted manifests as the findings; `ShowAllPackages` is already on); `func replaceComponents(ctx context.Context, tx *sql.Tx, projectID, scanID string, cs []Component) error` (delete the project's rows, insert these); `func (r *Repo) ListComponents(ctx context.Context, projectID string) (scanID string, cs []Component, err error)` sorted by manifest, ecosystem, name, version.
- Produces: `func PURL(ecosystem, name, version string) string` — `Packagist` → `pkg:composer/vendor/name@v`, `npm` → `pkg:npm/name@v` with `@` of a scope as `%40`, `Go` → `pkg:golang/module@v`; unknown ecosystem → `""`.
- `DepGroup`: `"dev"` when the package's dep groups contain `dev`, else `""`.

- [ ] **Step 1: Failing tests** — `TestRunStoresComponentsOnOK` (testdata project with a `composer.lock` of 3 packages, 1 vulnerable: 3 rows, scan id = the scan's); `TestPartialScanKeepsComponents` (second scan made partial by an unreadable lockfile: rows still those of the first scan); `TestPURL` (table: `Packagist monolog/monolog 2.0.0` → `pkg:composer/monolog/monolog@2.0.0`; `npm lodash 4.17.0` → `pkg:npm/lodash@4.17.0`; `Go golang.org/x/net 0.1.0` → `pkg:golang/golang.org/x/net@0.1.0`; `Foo x 1` → `""`).
- [ ] **Step 2: Run** `go test ./internal/scan -run 'Components|PURL'` → FAIL.
- [ ] **Step 3: Implement**; `replaceComponents` is called only when `status == ScanOK`.
- [ ] **Step 4: Run** → PASS, then `go test ./internal/scan` → PASS.
- [ ] **Step 5: Commit** `feat(scan): keep every package of the last complete scan`.

### Task 3: Ignore with a review date

**Files:**
- Modify: `internal/decide/decide.go` (`Validate`), `internal/decide/repo.go` (`ExpireDue`, `expire`), `internal/scan/repo.go` (`ReasonReviewDue`, `decisionView.dueReached` → `expiry(now) Reason`), `internal/api/handlers.go` (decision body), `internal/cli/decide.go` (`--review`), `internal/digest/*` (section « À revoir »), catalogs
- Test: `internal/decide/decide_test.go`, `internal/decide/repo_test.go`, `internal/scan/repo_test.go`, `internal/api/handlers_test.go`, `internal/cli/decide_test.go`, `internal/digest/*_test.go`

**Interfaces:**
- Produces: `scan.ReasonReviewDue = "review_due"`, `decide.ReviewDue Reason`. An `ignore` keeps `DueAt` as its review date; zero = never. `decide.DefaultReview = 365 * 24 * time.Hour` applies only when the caller asks for the default (API: field absent; CLI: flag absent); an explicit `"never"` gives zero.
- API: `POST /api/v1/findings/{id}/decision` body gains `"review": "1y"|"6m"|"3m"|"never"` (absent = `1y`) used only with `ignore`; unknown value → 400 `api.decision.bad_review`. The decision view's `due_at` carries the review date.
- CLI: `michel decide … --ignore --review 1y|6m|3m|never` (default `1y`).
- Expiry: `ExpireDue` and the scan supersede an `ignore` whose `due_at <= now` with `review_due`, a `defer` with `due_reached` (unchanged). Same `reopened` history event as today.
- Digest: findings superseded with `review_due` since the last digest go in a section titled `digest.review.title` (« À revoir » / "To review again"), each line « Ignorée le JJ/MM/AAAA, raison : <justification masquée> ».
- Old `ignore` rows (empty `due_at`) never expire; no migration touches them.

- [ ] **Step 1: Failing tests** — `TestValidateIgnoreKeepsReview` (ignore with DueAt in 1 year kept; in the past → `ErrDueInPast`); `TestExpireDueIgnore` (ignore due yesterday → superseded `review_due`, finding pending, one audit event); `TestOldIgnoreNeverExpires`; `TestIgnoreReviewSurvivesGoneBack` (ignore due in 10 days, scan without it then with it: still decided; scan 11 days later: pending, reason `review_due`); `TestAPIDecisionReview` (`ignore` without `review` → due ≈ now+365d; `never` → `due_at:""`; `"2y"` → 400); `TestDecideReviewFlag`; `TestDigestReviewSection` (FR line contains « Ignorée le » and the justification, masked secret replaced).
- [ ] **Step 2: Run** `go test ./internal/decide ./internal/scan ./internal/api ./internal/cli ./internal/digest -run 'Review|ExpireDueIgnore|OldIgnore'` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** the same → PASS, then `go test ./internal/...` and compare failures with `main`.
- [ ] **Step 5: Commit** `feat(decide): an ignore comes back at its review date, one year by default`.

### Task 4: The light rule and its API field

**Files:**
- Create: `internal/gate/gate.go`, `internal/gate/gate_test.go`
- Modify: `internal/api/handlers.go` (`ProjectView.Light`, filled for all projects by one call), `internal/api/views.go`, catalogs

**Interfaces:**
- Consumes: Task 1 threshold; `scan.EffectiveSeverity`, `scan.Urgent`; tables `scan`, `finding`, `decision`.
- Produces:
  ```go
  type State string // "green" | "red" | "grey"
  type Light struct {
      State  State  `json:"state"`
      Reason string `json:"reason"` // code, see below
      Count  int    `json:"count"`  // blocking findings when red; days when stale
  }
  func Compute(ctx context.Context, db *sql.DB, ps []project.Project, now time.Time) (map[string]Light, error) // key: project id
  func Blocks(f scan.Finding, t project.Threshold) bool
  func Worst(ls ...Light) Light // red > grey > green
  ```
- Reason codes: red → `blocking`; grey → `never_scanned`, `scan_failed`, `scan_partial`, `scan_empty`, `scan_old` (last finished scan > 7 days, Count = days), `db_old` (`scan.osv_db_fetched_at` > 7 days, Count = days), `folder_missing`; green → `ok`.
- `Blocks`: `Urgent(f)` → true in all thresholds; else effective severity `critical` (normal, strict) or `high` (strict); `unknown` never.
- Counted: project findings (not server) with status not `gone` and with no decision in force of action `defer` or `ignore`. Red wins over grey.
- `Compute` uses one grouped query for last scans and one for open undecided findings across `ps`, not one per project.
- API: `GET /api/v1/projects` items gain `"light": {...}` and `"gate_threshold"`; `GET /api/v1/projects/{name}/findings?blocking=1` returns only the findings `Blocks` counts. The sentence is built on the page from `reason` and `count` (keys `light.reason.<code>`).

- [ ] **Step 1: Failing tests** — `TestBlocksTable` (KEV low + soft → true; MAL- + soft → true; critical + soft → false; critical + normal → true; high + normal → false; high + strict → true; unknown + strict → false); `TestLightRedWinsOverPartial`; `TestLightGreyReasons` (never scanned; failed; partial with nothing blocking; empty; last scan 8 days old → `scan_old` count 8; OSV db 9 days → `db_old` count 9); `TestLightFolderMissing`; `TestLightDeferAndIgnorePass` (critical with defer in force → green; with fix decided → red); `TestLightPerf` (200 projects, 50 000 findings, `Compute` < 300 ms, skipped under `-short`); `TestAPIProjectsLight`; `TestAPIFindingsBlocking`.
- [ ] **Step 2: Run** `go test ./internal/gate ./internal/api -run 'Light|Blocks|Blocking'` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(gate): one rule for the project light, in the projects API`.

### Task 5: `michel gate`

**Files:**
- Create: `internal/cli/gate.go`, `internal/cli/gate_test.go`
- Modify: `internal/cli/root.go` (`root.AddCommand(newGateCmd(deps))`), catalogs

**Interfaces:**
- Consumes: `gate.Compute`, `gate.Worst`, `scan.Run`, `scan.ErrScanRunning`.
- Produces: `michel gate <project>` and `michel gate --repo <folder>` (every active project whose path is inside the folder, after `filepath.EvalSymlinks` and case folding on Windows). Prints one sentence per project then exits 0 green, 1 red, 2 grey (worst wins). Before computing: for each project, if any lockfile's sha256 differs from the last scan's `scan_manifest.lock_sha256` (or a lockfile appeared or vanished), run `scan.Run` with a 60 s context; `ErrScanRunning`, a failure or the time limit → that project is grey with reason `scan_failed` and the sentence says why.
- Produces: `func gateExit(l gate.Light) int`.

- [ ] **Step 1: Failing tests** — `TestGateExitCodes` (green 0, red 1, grey 2); `TestGateRescansOnLockChange` (change `composer.lock` after a scan: a new scan row exists after `gate`); `TestGateNoRescanWhenSame` (no new scan row); `TestGateRepoWorst` (two projects in one folder, one red: exit 1, two sentences); `TestGateScanRunningIsGrey`.
- [ ] **Step 2: Run** `go test ./internal/cli -run Gate` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): michel gate, the light of a project or of a whole repo`.

### Task 6: The `pre-push` guard

**Files:**
- Create: `internal/hook/hook.go`, `internal/hook/hook_test.go`
- Modify: `internal/api/server.go` (routes), `internal/api/projects_hook.go` (new), catalogs

**Interfaces:**
- Consumes: Task 1 `repo_hook`; Task 5 command line.
- Produces:
  ```go
  type State struct {
      Repo      bool     `json:"repo"`       // the project is in a git repo
      Installed bool     `json:"installed"`  // Michel's hook is there, unchanged
      Foreign   bool     `json:"foreign"`    // another pre-push exists
      Shared    []string `json:"shared"`     // other Michel projects in the same repo
      Line      string   `json:"line"`       // the line to add by hand when Foreign
  }
  func Inspect(ctx context.Context, projectPath string) (root, hooksDir string, err error) // git rev-parse --show-toplevel, --git-path hooks
  func Script(exe, dataDir, cfg, repoRoot string) string
  func Install(ctx context.Context, db *sql.DB, projectPath, exe, dataDir, cfg string, now time.Time) error
  func Remove(ctx context.Context, db *sql.DB, projectPath string) error
  var ErrForeignHook, ErrNotARepo, ErrChanged, ErrHooksOutside error
  ```
- `Script`: `#!/bin/sh`, marker line `# michel-guard v1`, if the Michel binary is missing prints « Michel introuvable, envoi non vérifié » and exits 0; runs `"<exe>" gate --repo "<root>" --data-dir "<dataDir>" --config "<cfg>"`; exit 1 stops the push with « Envoi bloqué par Michel. Pour passer quand même : git push --no-verify »; exit 2 prints the warning and exits 0. Paths with `/`, every path double-quoted with `"`, `$` and `` ` `` escaped.
- `Install` refuses when a `pre-push` exists (`ErrForeignHook`), when the hooks folder is outside the repo root (`ErrHooksOutside`) or no repo (`ErrNotARepo`); writes the file 0755, records sha256 in `repo_hook`. `Remove` refuses `ErrChanged` when the file's sha256 differs from the recorded one.
- API: `GET /api/v1/projects/{name}/hook` → `State`; `POST …/hook` (install) and `DELETE …/hook` (remove), each with audit actions `hook.install` / `hook.remove`, evidence `{project}` only (no path). Errors as 409 with keys `api.hook.foreign|not_repo|changed|outside`.

- [ ] **Step 1: Failing tests** — `TestInstallAndRemove` (temp `git init`, install, file has marker, state Installed, remove, file gone); `TestInstallRefusesForeign` (existing hook untouched byte for byte, `Line` set); `TestRemoveRefusesChanged`; `TestInstallInWorktree` (`git worktree add`, install from the worktree lands in the folder `git rev-parse --git-path hooks` gives); `TestHookScriptQuotesPaths` (exe `C:/Program Files/Michel é/michel.exe`: the script runs it through `sh -n` without error and contains it quoted); `TestHookScriptMissingBinary` (run under `sh` with a missing exe: exit 0 and the sentence); `TestSharedProjects` (two projects in one repo: each state lists the other); `TestAPIHookAudit`. Tests that need `git`/`sh` skip when absent.
- [ ] **Step 2: Run** `go test ./internal/hook ./internal/api -run Hook` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(hook): a pre-push guard installed and removed from the page`.

### Task 7: CycloneDX export

**Files:**
- Create: `internal/cyclonedx/cyclonedx.go`, `internal/cyclonedx/cyclonedx_test.go`, `internal/cli/export.go`, `internal/cli/export_test.go`
- Modify: `internal/api/server.go`, `internal/api/projects_export.go` (new), `internal/cli/root.go`, catalogs

**Interfaces:**
- Consumes: `scan.Repo.ListComponents`, `scan.Repo.ListFindings`, `decide.Repo.CurrentByProject`, `internal/mask`, `buildinfo` version.
- Produces: `func Build(p project.Project, scanID string, cs []scan.Component, fs []scan.Finding, ds map[string]decide.Decision, now time.Time, version string) ([]byte, error)` — `bomFormat:"CycloneDX"`, `specVersion:"1.6"`, `serialNumber:"urn:uuid:<random>"`, `version:1`, `metadata.timestamp`, `metadata.tools.components[{type:"application",name:"Michel",version}]`, `metadata.component{type:"application",name:<project name>}`; `components[{type:"library",bom-ref:<purl or eco:name@v>,name,version,purl,scope:"required"|"optional"}]`; `vulnerabilities[{bom-ref,id:<osv id>,source{name:"OSV"},ratings[{severity,score,method:"CVSSv3"}],affects[{ref}],analysis,properties[{michel:kev},{michel:epss}]}]` for findings not `gone`, with the mapping table of the spec exactly. Justifications pass through `mask` before writing. `not_affected` is never written.
- `ErrNoComponents` when the last scan is not `ok` or wrote no components.
- API: `GET /api/v1/projects/{name}/export/cyclonedx` → `application/vnd.cyclonedx+json`, `Content-Disposition: attachment; filename="<name>-cyclonedx-AAAA-MM-JJ.json"` (name sanitized to `[A-Za-z0-9._-]`), audit `export.cyclonedx` evidence `{project, components, vulnerabilities}`; `ErrNoComponents` → 409 `api.export.rescan`.
- CLI: `michel export cyclonedx <project> [-o file]`, stdout by default, same audit.

- [ ] **Step 1: Failing tests** — `TestBuildMapping` (one finding per case: undecided → `in_triage`; fix → `exploitable` + `[update]`; defer → `in_triage` + detail starting « Reportée jusqu'au 2026-12-06. »; ignore → no state, `[will_not_fix]`, detail = justification; gone → absent); `TestBuildNeverNotAffected`; `TestBuildMasksJustification` (a justification with a token pattern `mask` knows: token absent in output); `TestBuildNoAbsolutePath` (output contains no project `Path`); `TestBuildDevScope`; `TestPurlScopedNpm` (`@babel/core 7.0.0` → `pkg:npm/%40babel/core@7.0.0`); `TestAPIExportCycloneDX` (headers, JSON parses, audit event); `TestAPIExportRefusedPartial` (409); `TestCLIExportStdout`.
- [ ] **Step 2: Run** `go test ./internal/cyclonedx ./internal/api ./internal/cli -run 'Build|Purl|Export'` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(export): CycloneDX 1.6 with the decisions as VEX`.

### Task 8: Page — light, threshold, guard

**Files:**
- Modify: `web/src/components/ProjectCard.vue`, `web/src/components/FixSettings.vue` (threshold and guard rows), `web/src/components/OverviewPanel.vue` (tile), `web/src/components/FindingsPage.vue` (`blocking=1`), `web/src/api.js`, `web/src/i18n/{fr,en}.json`
- Create: `web/src/lib/lightView.js`, `web/src/lib/lightView.test.js`

**Interfaces:**
- Consumes: Task 4 `light`, `gate_threshold`; Task 6 hook routes; Task 1 PATCH.
- Produces: `lightView(light, t) → {word, sentence, icon, tone}` — word « Prêt » / « Bloquant » / « Pas sûr » (EN "Ready" / "Blocking" / "Not sure"); icon differs per state (shape + word, not color only); sentence from `light.reason.<code>` with `count`.
- Card: light first, click when red → `#/findings?project=<name>&blocking=1`.
- Settings: « Quand bloquer ? » with the three choices and one sentence under each; « Bloquer l'envoi quand le feu est rouge » button opening a consent dialog with the exact text of the spec (file `.git/hooks/pre-push` or the hooks folder, not followed by git, `git push --no-verify`); states Installed (« Retirer le garde-fou », « partagé avec : A, B »), Foreign (the line and a « Copier » button), not a repo (sentence, no button).
- Overview: tile « Projets » with counts per light.

- [ ] **Step 1: Failing tests** — `lightView.test.js`: each state gives a distinct word and icon; `scan_old` with count 9 gives « dernier contrôle il y a 9 jours »; `blocking` count 2 gives « 2 failles à décider »; unknown reason gives the generic grey sentence, never green; `texts.test.js` keys present in FR and EN.
- [ ] **Step 2: Run** `cd web && npx vitest run src/lib/lightView.test.js` → FAIL.
- [ ] **Step 3: Implement** lib and components.
- [ ] **Step 4: Run** `cd web && npm test && npm run build` → PASS.
- [ ] **Step 5: Commit** `feat(ui): project light, when to block, pre-push guard`.

### Task 9: Page — review date and export button

**Files:**
- Modify: `web/src/components/DecisionPanel.vue`, `web/src/components/FindingsPage.vue` (ignored filter shows the review date), `web/src/components/ProjectCard.vue` (menu « Exporter (CycloneDX) »), `web/src/api.js`, `web/src/i18n/{fr,en}.json`
- Test: `web/src/lib/decisionView.test.js` (or the existing decision lib test file)

**Interfaces:**
- Consumes: Task 3 `review` field; Task 7 export route.
- Produces: when action is `ignore`, a choice « À revoir : dans 1 an (défaut) / dans 6 mois / dans 3 mois / jamais » sent as `review`; the done sentence says « Ignorée, à revoir le JJ/MM/AAAA » or « Ignorée, sans date de revue ». Export: fetch with the token, save the blob with the filename of `Content-Disposition`; on 409 show « Relance un contrôle pour avoir la liste complète des composants » with a button that starts the scan.

- [ ] **Step 1: Failing tests** — the decision payload for ignore with no choice has `review:"1y"`; with « jamais » `review:"never"`; defer payload has no `review`; filename parsing from `attachment; filename="demo-cyclonedx-2026-11-06.json"`.
- [ ] **Step 2: Run** `cd web && npx vitest run` → FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** `cd web && npm test && npm run build` → PASS; `go test ./internal/api` (embedded build) → PASS.
- [ ] **Step 5: Commit** `feat(ui): review date on ignore, CycloneDX export button`.
