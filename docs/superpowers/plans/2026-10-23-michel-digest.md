# Michel — Plan 3 : décisions, digest, canaux, page « Aujourd'hui », i18n

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fermer la boucle quotidienne : décider une fois par faille (fix / defer / ignore) sans être redemandé tant que rien ne change, lire chaque matin « ce qui a bougé depuis hier » par toast, email ou webhook, le voir sur une page « Aujourd'hui » embarquée dans le binaire, le tout en français et en anglais via un catalogue unique.

**Architecture:** Cinq paquets Go nouveaux (`internal/i18n`, `internal/decide`, `internal/digest`, `internal/secret`, `internal/notify`, `internal/api`), une migration `0004`, une méthode `DialContext` dans `internal/egress`, et un front `web/` (Vite + Vue 3 + Vuetify 4, Options API) embarqué par `//go:embed`. Les règles de statut vivent dans `internal/scan` (`applyScan`) ; la décision est append-only avec instantané ; le digest est calculé à la volée et enregistré seulement quand il est envoyé.

**Tech Stack:** Go 1.27.3 ; stdlib `net/smtp`, `crypto/hmac`, `net/http`, `embed`, `text/template` ; `golang.org/x/sys/windows` (déjà dans le graphe) pour DPAPI et la langue système ; SQLite via `internal/store` ; Node 24 / npm 11, Vite 8, Vue 3.5.x, Vuetify 4.3.x, `vite-plugin-vuetify`, Vitest 5.

**Spec:** `docs/superpowers/specs/2026-10-23-michel-plan3-decisions-digest-design.md` (§ 3 décisions, § 4 digest, § 5 canaux et secrets, § 6 page, § 7 i18n, § 8 migration et balayage, § 9 sécurité) ; design v1 `docs/superpowers/specs/2026-10-22-michel-design.md` § 4.3, § 4.8, § 4.11, § 5 ; politique `docs/security/sovereignty-policy.md`.

## Global Constraints

- Module `github.com/kvarot/michel` ; code, identifiants, commits et aide Cobra en anglais ; messages imprimés par les commandes via `internal/i18n` (EN référence, FR écrit à la main, **tutoiement**) ; `testing` standard ; Windows et Linux bloquants ; Conventional Commits avec le trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Branche `feat/digest` en place (ruling : rien d'autre en cours). Chaque tâche se termine par `go test ./...` vert et un commit.
- **Aucune trace du projet privé** : les fixtures s'appellent `demo`, `acme/lib`, `vuln-pkg` ; le ledger ne publie que des agrégats ; `go test ./internal/hygiene/` reste vert ; le dossier parent des projets de ce poste entre dans la liste hachée (Task 10), jamais en clair.
- **Jamais d'écriture sous `project.path`** : les tests qui touchent un projet fixture comparent l'arbre avant/après (`treeDigest`, Task 1).
- **SQL portable PostgreSQL** : pas de `rowid`, pas d'`AUTOINCREMENT`, pas de `datetime()` SQLite, `?` et `ON CONFLICT (…) DO UPDATE`, `INTEGER` 0/1 pour les booléens, dates `TEXT` RFC 3339 UTC.
- **Aucun HTTP ni `net.Dial` hors `internal/egress`** (test AST `boundary_test.go` étendu en Task 6) ; SMTP passe par `Gateway.DialContext`.
- **Minimisation** : digests, webhooks, emails, toasts et réponses d'API ne contiennent ni code, ni chemin absolu, ni `test_cmd` / `install_cmd`, ni secret ; justification bornée à 1 000 caractères et passée par `scan.SanitizeText`.
- **Phrases épinglées du plan 2 inchangées** : les tests `internal/explain` et `internal/cli` existants passent sans modification de leurs chaînes attendues (seuls les imports / chemins de gabarits bougent).
- Front : Options API uniquement, pas de TypeScript, pas de store externe, textes dans `web/src/i18n/{fr,en}.json`, jamais de fetch hors `/api/v1`.
- Relecture FR : chaque tâche qui crée ou modifie un fichier FR (`fr.json`, gabarits `fr/`, `*.fr.md`, front `fr.json`) dispatche un relecteur francophone non spécialiste **avant** la revue de code (consigne en Task 2, Step 7) et applique ses retours.

## Review Focus

1. Décision prise, puis re-scan avec la **même** gravité et les **mêmes** versions corrigées : la faille reste `decided`, n'apparaît pas dans le digest, n'est pas `actionable`. Test : Task 4 `TestDecidedFindingStaysDecidedWhenUnchanged`.
2. Décision `ignore`, puis l'avis OSV ajoute une version corrigée ou passe de `medium` à `critical` : la décision est supersédée avec la bonne raison, la faille repasse `pending`, le digest la liste sous « à revoir ». Test : Task 4 `TestDecisionSupersededOnSeverityOrFixChange`, Task 5 `TestDigestListsSupersededDecisions`.
3. Deux processus `michel` en même temps (scan planifié + `michel serve`) : le balayage des `running` ne touche pas un scan de moins d'une heure ; `SetMaxOpenConns(1)` + `busy_timeout` suffisent. Test : Task 1 `TestSweepStaleLeavesRecentRunning`.
4. Secret absent ou canal hors allowlist au moment de `digest --send` : les autres canaux sont quand même envoyés, le `digest_run` enregistre l'échec par canal, l'exit code vaut 1, le message dit quelle règle ajouter ou quel secret créer. Test : Task 7 `TestDigestSendContinuesAfterChannelFailure`, `TestEmailDeniedByPolicySaysWhichRule`.
5. Page ouverte sans jeton, ou avec un jeton périmé après rotation : 401 JSON `{error}` sans fuite, aucune donnée ; avec jeton : jamais de chemin absolu ni de commande dans les réponses. Test : Task 8 `TestAPIRejectsMissingToken`, `TestAPIResponsesHaveNoAbsolutePathsNorCommands`.

---

### Task 1: Migration `0004`, persistance complète de l'analyse, `exclude` projet, `status_changed_at`, balayage des scans

**Files:**
- Create: `internal/store/migrations/0004_decisions_digest.sql`, `internal/scan/sweep.go`
- Modify: `internal/analyze/repo.go` (Save/Get des nouveaux champs), `internal/analyze/analyze.go` (`Notes` persisté, `exclude` depuis le projet), `internal/project/project.go` + `repo.go` (champ `Exclude []string`, colonne `exclude`), `internal/cli/project.go` (`project set --exclude`, `project add --exclude`), `internal/scan/scan.go` (`exclude` du projet, `defer/recover`, `status_changed_at`, appel `SweepStale`), `internal/scan/repo.go` (`status_changed_at` dans `applyScan`), `internal/cli/scan.go` (`DefaultExclude` + `p.Exclude`)
- Test: `internal/store/store_test.go` (`TestMigration0004Applies`), `internal/analyze/analyze_test.go` (`TestSaveGetRoundTripEveryField`), `internal/project/repo_test.go` (`TestExcludeRoundTrip`), `internal/scan/sweep_test.go`, `internal/scan/scan_test.go` (`TestScanSetsStatusChangedAt`, `TestScanPanicIsRecordedAsFailed`, `TestScanNeverWritesUnderProject`), `internal/cli/project_test.go` (`TestProjectSetExclude`)

**Interfaces:**
- Produces:
  ```go
  // project
  type Project struct { …; Exclude []string `json:"exclude"` } // noms de dossiers, dédoublonnés, triés, sans séparateur ; "" interdit
  // scan
  const ScanInterrupted = "interrupted"
  // SweepStale marks every scan row left in status "running" for more than maxAge as interrupted and returns how many.
  func SweepStale(ctx context.Context, db *sql.DB, now time.Time, maxAge time.Duration) (int, error)
  const StaleScanAfter = time.Hour
  // EffectiveExclude merges DefaultExclude with the project's own list (sorted, unique).
  func EffectiveExclude(p project.Project) []string
  // test helper in internal/scan (exported for cli tests through scan/export_test.go is NOT needed: duplicate in cli)
  func treeDigest(t *testing.T, root string) string // SHA-256 of every path+size+mtime under root
  ```
- Migration SQL exact :
  ```sql
  ALTER TABLE project ADD COLUMN exclude TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE finding ADD COLUMN status_changed_at TEXT NOT NULL DEFAULT '';
  UPDATE finding SET status_changed_at = last_seen_at WHERE status_changed_at = '';
  ALTER TABLE analysis ADD COLUMN notes TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE analysis ADD COLUMN calls_unreadable INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE analysis ADD COLUMN calls_unreadable_paths TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE analysis ADD COLUMN calls_test_files TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE analysis ADD COLUMN calls_test_file_count INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE analysis ADD COLUMN calls_test_hit_count INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE analysis ADD COLUMN calls_source_files TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE analysis ADD COLUMN coverage_skipped TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE analysis ADD COLUMN coverage_unreadable INTEGER NOT NULL DEFAULT 0;
  CREATE TABLE decision (
      id                   TEXT PRIMARY KEY,
      finding_id           TEXT NOT NULL,
      project_id           TEXT NOT NULL,
      action               TEXT NOT NULL,
      justification        TEXT NOT NULL DEFAULT '',
      due_at               TEXT NOT NULL DEFAULT '',
      author               TEXT NOT NULL,
      created_at           TEXT NOT NULL,
      seen_severity        TEXT NOT NULL DEFAULT '',
      seen_fixed_versions  TEXT NOT NULL DEFAULT '[]',
      superseded_at        TEXT NOT NULL DEFAULT '',
      superseded_reason    TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX idx_decision_finding ON decision(finding_id, created_at);
  CREATE INDEX idx_decision_project ON decision(project_id);
  CREATE TABLE digest_run (
      id          TEXT PRIMARY KEY,
      since       TEXT NOT NULL,
      until       TEXT NOT NULL,
      lang        TEXT NOT NULL,
      projects    TEXT NOT NULL DEFAULT '[]',
      summary     TEXT NOT NULL DEFAULT '{}',
      channels    TEXT NOT NULL DEFAULT '[]',
      created_at  TEXT NOT NULL
  );
  CREATE INDEX idx_digest_run_created ON digest_run(created_at);
  ```
- `Analysis.Notes` perd son commentaire « not persisted » ; `analyze.Run` lit `exclude := EffectiveExclude(p)` (le `TODO(plan 3)` disparaît) ; `InputsHash` reçoit cette liste (déjà un paramètre).
- `applyScan` : chaque `UPDATE` qui change `status` écrit `status_changed_at = ts` ; un `UPDATE` qui ne change pas le statut ne le touche pas (requête séparée ou `CASE` portable : `status_changed_at = CASE WHEN status <> ? THEN ? ELSE status_changed_at END`). Les statuts `decided` et `reported_fixed`/`proven_fixed` ne sont **pas** traités ici (Task 4 étend `applyScan`).
- `scan.Run` : `defer func(){ if r := recover(); r != nil { marque failed "panic: %v" ; audit scan.finish failed ; panic(r) } }()` ; appelle `SweepStale` au début (compte dans `Result.Swept int` et événement `scan.sweep` si > 0).

- [ ] **Step 1: Tests qui échouent** — store : `TestMigration0004Applies` (ouvre une base, vérifie via `PRAGMA table_info` que `project.exclude`, `finding.status_changed_at`, `analysis.notes` … `coverage_unreadable` existent et que `decision`, `digest_run` existent avec leurs index ; **assert** que le SQL de `0004` ne contient ni `rowid` ni `AUTOINCREMENT` ni `datetime(`). analyze : `TestSaveGetRoundTripEveryField` (construit une `Analysis` où chaque champ est non nul, y compris `Notes`, `Calls.Unreadable(Paths)`, `Calls.TestFiles/TestFileCount/TestHitCount/SourceFiles`, `Coverage.Skipped/Unreadable`, puis `reflect.DeepEqual` après Save/Get, snippets exclus). project : `TestExcludeRoundTrip` (`Exclude: ["b","a","a"]` → stocké `["a","b"]` ; `"src/x"` et `""` refusés avec `ErrInvalidExclude`). scan : `TestSweepStaleMarksOldRunning` (ligne running vieille de 2 h → `interrupted`, `error` = `"Michel stopped before this scan finished"`, retour 1), `TestSweepStaleLeavesRecentRunning` (10 min → inchangée, retour 0), `TestScanSetsStatusChangedAt` (premier scan : `status_changed_at == last_seen_at` ; second scan sans changement : inchangé ; faille disparue : `status_changed_at` = date du second scan), `TestScanPanicIsRecordedAsFailed` (hook `panicAfterScan` en test → ligne `failed`, erreur contient `panic`), `TestScanNeverWritesUnderProject` (`treeDigest` identique avant/après `Run`), `TestEffectiveExcludeMergesDefaults`. cli : `TestProjectSetExclude` (`project set demo --exclude build --exclude dist` → `project list --json` montre `["build","dist"]` ; `--exclude ''` vide ; audit `project.set` evidence contient `exclude`).
- [ ] **Step 2: Lancer** `go test ./internal/store/ ./internal/analyze/ ./internal/project/ ./internal/scan/ ./internal/cli/ -run 'Migration0004|RoundTripEvery|ExcludeRoundTrip|SweepStale|StatusChangedAt|PanicIsRecorded|NeverWritesUnder|EffectiveExclude|ProjectSetExclude' -v` → FAIL.
- [ ] **Step 3: Implémenter** la migration, les colonnes dans `analyze/repo.go` (Save : 9 colonnes de plus ; Get : relecture ; `nonNil` partout), `Project.Exclude` (validation dans `normalizeExtras` : `ErrInvalidExclude` si vide ou contient `/`, `\`, `..`), `EffectiveExclude`, `SweepStale`, `recover`, `status_changed_at`, flags `--exclude` (`StringArrayVar`, `project add` et `project set`, sémantique de remplacement comme `--core-package`).
- [ ] **Step 4: Lancer** `go test ./...` → PASS (les tests existants d'`applyScan` passent toujours).
- [ ] **Step 5: Commit** `feat(store,scan,analyze,project): migration 0004, persisted analysis notes, project exclusions, stale scan sweep`.

### Task 2: Catalogue `internal/i18n`, migration des labels, du glossaire et des gabarits, garde de tutoiement, relecture FR

**Files:**
- Create: `internal/i18n/i18n.go`, `internal/i18n/catalog/en.json`, `internal/i18n/catalog/fr.json`, `internal/i18n/templates/en/{what,impact,cost}.tmpl` (déplacés depuis `internal/explain/templates/en/`), `internal/i18n/templates/fr/{what,impact,cost}.tmpl` (idem), `internal/i18n/locale.go`, `internal/i18n/locale_windows.go`, `internal/i18n/locale_other.go`, `internal/i18n/i18n_test.go`, `internal/i18n/tutoiement_test.go`, `internal/i18n/keys_test.go`
- Modify: `internal/explain/explain.go` (`Lang` = alias de `i18n.Lang` ; `renderOne` lit `i18n.Template(lang, name)`), `internal/explain/labels.go` (devient un pont : `Label(lang, key)` = `i18n.T(lang, "explain.label."+key)` ; la map disparaît), `internal/explain/glossary.go` (`Term` = `i18n.T(lang, "glossary."+key)`, `Terms()` inchangé), `internal/cli/root.go` (`deps.Lang` résolu par `i18n.Resolve(flag, policyLang, i18n.SystemLocale())`, type `i18n.Lang`), `internal/policy/defaults.go` (`Assistant.Lang = "auto"`), `internal/policy/validate.go` (`auto | en | fr`), `internal/policy/policy_test.go` (`TestAssistantLangDefaultEn` devient `TestAssistantLangDefaultAuto`), `config.example.yaml` (`lang: auto  # auto | en | fr`)
- Delete: `internal/explain/templates/` (déplacé)
- Test: `internal/explain/*_test.go` inchangés et verts

**Interfaces:**
- Produces:
  ```go
  package i18n
  type Lang string
  const ( EN Lang = "en"; FR Lang = "fr" )
  func (l Lang) Valid() bool
  // T returns the catalog entry for key in lang, formatted with args (fmt.Sprintf). Missing in lang → EN → "!"+key+"!".
  func T(lang Lang, key string, args ...any) string
  // N picks key+".one" when n == 1 (or n == 0 in French), else key+".other", and formats with n first then args.
  func N(lang Lang, key string, n int, args ...any) string
  // Has reports whether key exists in EN.
  func Has(key string) bool
  // Keys lists every EN key, sorted.
  func Keys() []string
  // Template returns the parsed explanation template name ("what" | "impact" | "cost") for lang (cached).
  func Template(lang Lang, name string, funcs template.FuncMap) (*template.Template, error)
  // Resolve picks the language: flag, then policy (only "en" or "fr"; "auto" and "" fall through), then system, then EN. Unknown values are skipped.
  func Resolve(flag, policy, system string) Lang
  // SystemLocale returns "fr" or "en" from the OS (LANG/LC_ALL/LC_MESSAGES; GetUserDefaultUILanguage on Windows).
  func SystemLocale() string
  ```
- Catalogue : JSON plat `{"key": "text"}` ; clés en `snake.dotted` ; familles réservées : `explain.label.*` (tous les labels actuels, même clés : `explain.label.what`, `explain.label.risk_major_jump`, `explain.label.tests_many`…), `explain.severity.{critical,high,medium,low,unknown}` (les `severityWords`), `glossary.*`, `cli.*` (Task 3), `digest.*` (Task 5), `notify.*` (Task 7), `api.*` (Task 8). Pluriel : `key.one` / `key.other`.
- Garde de tutoiement : regex `\b(vous|votre|vos|veuillez)\b` (insensible à la casse) sur `fr.json`, `templates/fr/*.tmpl`, `web/src/i18n/fr.json` (si présent), `docs/**/*.fr.md` et `README.fr.md` hors lignes de citation (`>`), hors blocs de code, hors la politique `docs/security/sovereignty-policy.md` (document juridique, exclu explicitement).
- Cohérence des clés : `keys_test.go` parse les sources Go du module (`go/ast`) et collecte les appels `i18n.T(`, `i18n.N(`, `explain.Label(`, `explain.Term(` avec clé littérale ; chaque clé référencée existe (pour `Label` préfixe `explain.label.`, pour `Term` `glossary.`, pour `N` les deux suffixes) ; chaque clé du catalogue est référencée, sauf préfixes déclarés dynamiques (`explain.label.risk_`, `explain.label.rec_`, `explain.label.jump_`, `explain.label.quality_`, `explain.label.method_`, `explain.severity.`, `glossary.`, `digest.reason.`, `notify.type.`).
- Locale Windows : `windows.GetUserDefaultUILanguage()` n'est pas dans x/sys ; utiliser `syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")` (LANGID, langue primaire `0x0C` = français). Sur les autres OS : première variable non vide parmi `LC_ALL`, `LC_MESSAGES`, `LANG`, préfixe `fr` → `fr`.

- [ ] **Step 1: Tests qui échouent** — `TestCatalogsHaveSameKeys` (ensemble des clés EN == FR, aucune valeur vide), `TestTFallsBackToEnglishThenKey`, `TestNPluralRules` (`N(FR,"x",0)` → `.one`, `N(EN,"x",0)` → `.other`, `N(EN,"x",1)` → `.one`), `TestResolveOrder` (table : flag>policy>system>en ; `auto` et valeur inconnue ignorées ; policy `auto` + système `fr` → `fr`), policy : `TestAssistantLangDefaultAuto`, `TestValidateAcceptsAutoLang`, cli : `TestLangAutoFollowsSystemLocale` (hook `i18n.SystemLocale` remplacé en test), `TestTemplatesRenderIdenticalToPlan2` (fixture `Facts` de `explain_test.go` : rendu via `explain.Render` identique aux chaînes attendues existantes), `TestFrenchUsesTutoiement` (crée un fichier temporaire contenant « vous » et vérifie que le scanner le signale ; puis scanne le dépôt réel → 0 violation), `TestEveryReferencedKeyExists`, `TestEveryCatalogKeyIsReferenced`.
- [ ] **Step 2: Lancer** `go test ./internal/i18n/ ./internal/explain/ -v` → FAIL.
- [ ] **Step 3: Implémenter** `i18n.go` (embed `catalog/*.json`, `templates/*/*.tmpl`, cache `sync.Map` par (lang, name)), déplacer les gabarits, réécrire `labels.go` / `glossary.go` en ponts, brancher `root.go`.
- [ ] **Step 4: Lancer** `go test ./...` → PASS (y compris tous les tests `explain` et `cli` existants, inchangés).
- [ ] **Step 5: Vérifier** `git diff --stat internal/explain/*_test.go internal/cli/*_test.go` → vide.
- [ ] **Step 6: Commit** `feat(i18n): message catalog en/fr, explanation templates and labels moved in, tutoiement guard`.
- [ ] **Step 7: Relecture FR** — dispatcher un subagent « relecteur francophone non spécialiste » avec la consigne : « Tu ne connais rien à la sécurité informatique. Lis `internal/i18n/catalog/fr.json` et `internal/i18n/templates/fr/*.tmpl`. Pour chaque phrase que tu devrais te faire expliquer à l'oral, propose une réécriture plus simple, en tutoyant, sans changer le sens. Ne touche pas aux termes du glossaire. Rends une liste `clé → proposition`. » Appliquer les propositions **sauf** sur les phrases épinglées par les tests du plan 2 (lister celles refusées dans le ledger). Relancer `go test ./...`. Commit `docs(i18n): french wording after non-specialist review` si des changements.

### Task 3: Messages CLI vers le catalogue (deux lots)

**Files:**
- Modify: lot A — `internal/cli/scan.go`, `internal/cli/analyze.go`, `internal/cli/findings.go`, `internal/cli/finding.go` ; lot B — `internal/cli/project.go`, `internal/cli/db.go`, `internal/cli/audit.go`, `internal/cli/root.go`, `internal/cli/version.go`, `internal/cli/messages.go` (nouveau : `func (d *Deps) T(key string, args ...any) string`, `func (d *Deps) N(key string, n int, args ...any) string`, `func (d *Deps) Errorf(key string, args ...any) error`)
- Modify: `internal/i18n/catalog/{en,fr}.json` (famille `cli.*`)
- Test: `internal/cli/lang_test.go` (`TestScanSummaryInFrench`, `TestFindingsEmptyInFrench`, `TestProjectAddDeniedInFrench`, `TestUsageErrorsInFrench`, `TestEnglishOutputUnchanged`)

**Interfaces:**
- Consumes: `i18n.T/N` (Task 2), `deps.Lang`.
- Règle : toute chaîne passée à `fmt.Fprintf(deps.Stdout|Stderr…)`, `errors.New`, `fmt.Errorf` **destinée à l'utilisateur** devient une clé `cli.<commande>.<sens>` ; les `%w` restent (`Errorf` enveloppe avec `fmt.Errorf(T(key)+": %w", err)` quand la clé finit par `_wrap`). Les en-têtes de tables (`severity\tpackage…`) restent en anglais (identifiants stables pour les scripts, documenté). `Short`/`Long`/descriptions de flags restent en anglais (design § 7).
- L'anglais du catalogue est **mot pour mot** la chaîne actuelle (les tests existants comparent des sous-chaînes) ; le français est écrit à la main, tutoyé, « quoi / pourquoi / quoi faire » conservé.

- [ ] **Step 1: Tests qui échouent** — `TestScanSummaryInFrench` (`--lang fr scan --project demo` → contient `Michel n'a trouvé aucune nouvelle faille dans demo` et `Ensuite : michel findings --project demo`), `TestFindingsEmptyInFrench` (`Aucune faille à montrer pour demo`), `TestProjectAddDeniedInFrench` (dossier inexistant → `n'est pas un dossier`), `TestUsageErrorsInFrench` (`scan` sans `--project` ni `--all` → `Michel a besoin de savoir quoi scanner`), `TestEnglishOutputUnchanged` (les mêmes commandes sans `--lang` donnent exactement les chaînes anglaises déjà épinglées dans `scan_test.go` / `findings` ; test de non-régression par sous-chaînes).
- [ ] **Step 2: Lancer** `go test ./internal/cli/ -run 'InFrench|EnglishOutputUnchanged' -v` → FAIL.
- [ ] **Step 3: Implémenter le lot A** (scan, analyze, findings, finding) + clés ; `go test ./...` vert ; commit `refactor(cli): scan, analyze, findings and finding messages through the i18n catalog`.
- [ ] **Step 4: Implémenter le lot B** (project, db, audit, root, version) + clés ; `go test ./...` vert ; commit `refactor(cli): project, db, audit and root messages through the i18n catalog`.
- [ ] **Step 5: Relecture FR** (même consigne que Task 2 Step 7, sur les clés `cli.*`) ; appliquer ; `go test ./...` ; commit si changements.

### Task 4: Décisions — modèle, règles de statut, `michel decide` / `decisions`

**Files:**
- Create: `internal/decide/decide.go` (types, validation), `internal/decide/repo.go`, `internal/decide/decide_test.go`, `internal/decide/repo_test.go`, `internal/cli/decide.go`, `internal/cli/decide_test.go`
- Modify: `internal/scan/repo.go` (`StatusDecided`, `applyScan` lit les décisions en vigueur, règles § 3.2), `internal/scan/scan_test.go`, `internal/cli/findings.go` (`validStatuses` + `decided` ; `--status all`), `internal/cli/root.go` (`newDecideCmd`, `newDecisionsCmd`), `internal/i18n/catalog/{en,fr}.json` (`cli.decide.*`, `cli.decisions.*`)

**Interfaces:**
- Produces:
  ```go
  package decide
  type Action string
  const ( Fix Action = "fix"; Defer Action = "defer"; Ignore Action = "ignore" )
  type Reason string // superseded reasons
  const ( Redecided Reason = "redecided"; SeverityChanged Reason = "severity_changed"; FixedVersionChanged Reason = "fixed_version_changed"; DueReached Reason = "due_reached"; ReappearedChanged Reason = "reappeared_changed" )
  type Decision struct {
      ID, FindingID, ProjectID string; Action Action; Justification string; DueAt time.Time /* zero unless Defer */
      Author string; CreatedAt time.Time; SeenSeverity string; SeenFixedVersions []string
      SupersededAt time.Time; SupersededReason Reason
  }
  const DefaultDefer = 30 * 24 * time.Hour
  const MaxJustification = 1000
  var ( ErrJustificationRequired, ErrInvalidAction, ErrFindingGone, ErrDueInPast, ErrJustificationTooLong error )
  // Validate checks action/justification/due; it sanitizes and trims the justification.
  func Validate(d *Decision, now time.Time) error
  // Changed tells whether the finding's severity or fixed versions differ from the snapshot (fixed versions compared as sorted sets).
  func Changed(d Decision, severity string, fixed []string) (changed bool, reason Reason)
  type Repo struct{…}; func NewRepo(s *store.Store) *Repo
  // Set stores d, supersedes the previous current decision (reason redecided) and moves the finding to "decided", in one transaction. It refuses a finding in status gone.
  func (r *Repo) Set(ctx context.Context, d Decision, now time.Time) (Decision, error)
  // Current returns the decision in force for a finding (ok=false if none).
  func (r *Repo) Current(ctx context.Context, findingID string) (Decision, bool, error)
  // CurrentByProject maps finding id -> decision in force for every finding of the project.
  func (r *Repo) CurrentByProject(ctx context.Context, projectID string) (map[string]Decision, error)
  // Supersede marks the current decision of a finding as superseded with reason and moves the finding to "pending".
  func (r *Repo) Supersede(ctx context.Context, tx *sql.Tx, findingID string, reason Reason, now time.Time) error
  // List returns the decisions of a project, newest first; filter: "" (current only), "fix"|"defer"|"ignore" (current with that action), "superseded", "all".
  func (r *Repo) List(ctx context.Context, projectID, filter string) ([]Decision, error)
  // ExpireDue supersedes (due_reached) every current defer whose due_at <= now, in all projects, moves those findings to pending, writes one decision.superseded audit event each, and returns the finding ids. Called by digest --send only (scan does the same inside applyScan).
  func (r *Repo) ExpireDue(ctx context.Context, now time.Time, log *audit.Logger) ([]string, error)
  // scan
  const StatusDecided = "decided"
  ```
- `applyScan` (scan/repo.go) reçoit en plus `current map[string]decisionView` (`{Action string; Severity string; Fixed []string; DueAt string}` chargé depuis `decision` dans la même transaction : `superseded_at = ''`) et applique :
  - présent + `decided` + inchangé → `decided`, `status_changed_at` intact ;
  - présent + `decided` + changé → `pending`, `UPDATE decision SET superseded_at=?, superseded_reason=? WHERE finding_id=? AND superseded_at=''` ;
  - présent + `decided(defer)` + `due_at ≤ now` → `pending`, supersede `due_reached` (vérifié avant la comparaison d'instantané) ;
  - présent + `gone` + décision en vigueur inchangée → `decided` (compté `reappeared`) ; changé → `pending` + supersede `reappeared_changed` ;
  - absent + `decided` → `gone` (décision intacte).
  Les décisions sont lues par `project_id` ; aucune requête inter-projets. `applyScan` renvoie la liste `superseded []struct{FindingID string; Reason Reason; Previous Action}` ; `scan.Run` écrit un événement d'audit `decision.superseded` par élément après le commit, et `Result.Superseded int`.
- CLI :
  ```
  michel decide <id-or-prefix> <fix|defer|ignore> [--why TEXT] [--until YYYY-MM-DD] [--for 30d]
  michel decide --project NAME --package PKG <fix|defer|ignore> [--why …] [--until …|--for …]
  michel decisions --project NAME [--status fix|defer|ignore|superseded|all] [--json]
  ```
  `--until` et `--for` exclusifs ; `--for` accepte `Nd` ; `defer` sans les deux → 30 jours, la confirmation l'affiche (« reportée au 2026-11-22 (30 jours par défaut) »). Sortie : une phrase « ce que ça a fait » + id d'événement d'audit. Audit `decision.set` : `{finding_id, project_id, action, due_at, author, justification, package, osv_id}`. `--package` : toutes les failles `new|pending` (et `decided` si `--force`) de ce paquet dans ce projet ; résumé « N failles décidées ».
- `findings` : `--status decided` accepté ; la table gagne une colonne `decision` (`fix` / `defer 2026-11-22` / `ignore` / `-`) via `CurrentByProject`.
- Les justifications : `scan.SanitizeText`, trim, ≤ 1 000 caractères ; refus au-delà.

- [ ] **Step 1: Tests qui échouent** — decide : `TestValidateIgnoreNeedsJustification`, `TestValidateDeferDefaultsTo30Days`, `TestValidateRejectsPastDue`, `TestValidateCapsJustification`, `TestChangedDetectsSeverityThenFix` (gravité différente → `severity_changed` ; versions `["1.2.5"]` vs `["1.2.5","2.0.0"]` → `fixed_version_changed` ; ordre différent seulement → inchangé) ; repo : `TestSetMovesFindingToDecided`, `TestSetSupersedesPrevious` (deux `Set` → première `superseded_reason == redecided`, `Current` = seconde), `TestSetRefusesGoneFinding`, `TestExpireDue`, `TestListFilters` ; scan : `TestDecidedFindingStaysDecidedWhenUnchanged` (Review Focus 1 : second scan identique → statut `decided`, `actionable` ne la liste pas, `status_changed_at` intact), `TestDecisionSupersededOnSeverityOrFixChange` (Review Focus 2 : on modifie l'avis dans la base OSV de test — nouvelle version corrigée — puis re-scan → `pending`, décision `fixed_version_changed`), `TestDecidedGoneThenBackUnchangedIsDecided`, `TestDecidedGoneThenBackChangedIsPending`, `TestScanExpiresDueDefer` (defer échu → `pending`, raison `due_reached`, événement `decision.superseded`), `TestScanDoesNotExpireFutureDefer` ; cli : `TestDecideIgnoreWithoutWhyRefused` (message FR et EN), `TestDecideDeferDefaultShowsDate`, `TestDecideByPackage`, `TestDecisionsTableAndJSON`, `TestDecideIsAuditedWithoutCode`, `TestDecideNeverWritesUnderProject` (`treeDigest`).
- [ ] **Step 2: Lancer** `go test ./internal/decide/ ./internal/scan/ ./internal/cli/ -run 'Validate|Changed|TestSet|ExpireDue|ListFilters|Decided|Supersede|Decide|Decisions' -v` → FAIL.
- [ ] **Step 3: Implémenter** (`decide.go`, `repo.go`, extension d'`applyScan` avec la lecture des décisions dans la transaction, CLI, clés `cli.decide.*`).
- [ ] **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** des clés `cli.decide.*` / `cli.decisions.*` ; appliquer.
- [ ] **Step 6: Commit** `feat(decide): per-finding decisions with snapshot, status rules on re-scan, michel decide and decisions`.

### Task 5: Digest — calcul, rendus texte / HTML / JSON, `digest_run`, `michel digest`, `scan --all --digest`

**Files:**
- Create: `internal/digest/digest.go` (types + `Compute`), `internal/digest/render.go` (texte, HTML, JSON ; gabarits `text/template` embarqués `internal/digest/templates/{en,fr}/{text.tmpl,html.tmpl}`), `internal/digest/repo.go` (`digest_run`), `internal/digest/digest_test.go`, `internal/digest/render_test.go`, `internal/digest/repo_test.go`, `internal/cli/digest.go`, `internal/cli/digest_test.go`
- Modify: `internal/cli/scan.go` (`--digest` avec `--all`), `internal/cli/root.go`, `internal/i18n/catalog/{en,fr}.json` (`digest.*` pour les libellés hors gabarits), `internal/osvdb/osvdb.go` (si besoin : `Oldest(root) (time.Time, bool)`)

**Interfaces:**
- Consumes: `scan.Repo.ListFindings`, `decide.Repo.CurrentByProject/List` (lecture seule ; `ExpireDue` est appelé par la CLI avant `Compute`, jamais par `Compute`), `analyze.Repo.Get`, `explain.Render` (phrase « what » par faille nouvelle), `osvdb.Statuses`, `project.Repo.List`, `scan.SweepStale`.
- Produces:
  ```go
  package digest
  const SchemaVersion = 1
  const DueHorizon = 3 * 24 * time.Hour
  type Package struct { Name, Ecosystem, Installed, Target, WorstSeverity string; OSVIDs []string; FindingIDs []string; What string /* phrase "what" de la faille la plus grave, en lang */ }
  type Superseded struct { Package, OSVID, FindingID, PreviousAction, Reason, Justification string } // reason "redecided" never listed
  type Due struct { Package, OSVID, FindingID, DueAt, Justification string; Overdue bool /* due_at <= now */ }
  type ProjectDigest struct {
      Name string; New []Package; Gone []Package; Superseded []Superseded; Due []Due
      ProvenFixed, ReportedFixed []Package // always empty in plan 3, omitted from JSON when empty
      Open map[string]int /* by severity */; Decided map[string]int /* by action */; Total int
      DaysWithoutCritical int; CriticalOpen int; LastScanStatus string /* ok|partial|failed|interrupted|never */
  }
  type Digest struct {
      SchemaVersion int `json:"michel_digest"`; Lang i18n.Lang; Since, Until time.Time; Assistant string
      Projects []ProjectDigest; NewTotal, AttentionTotal int /* attention = new critical/high + superseded + due */
      OSVFetchedAt time.Time; OSVStale bool; FailedScans int; PageURL string
      Title string /* « Michel a trouvé 3 nouveautés cette nuit, 1 mérite ton attention » */; Word string /* mot de Michel si tout est propre, sinon "" */
  }
  type Options struct { Since time.Time /* zero = until of the last saved run, else now-24h; no cap */; PageURL string; Assistant string; OSVRoot string }
  // Compute is pure: it reads the store and never writes (no status change, no audit event).
  func Compute(ctx context.Context, s *store.Store, now time.Time, lang i18n.Lang, opt Options) (Digest, error)
  func RenderText(d Digest) (string, error)
  func RenderHTML(d Digest) (string, error) // inline CSS only, no <script>, no <img>
  func RenderJSON(d Digest) ([]byte, error)
  func ToastLines(d Digest) (title, body string) // title = d.Title ; body = première ligne utile (projet le plus touché), ≤ 200 runes
  type Run struct { ID string; Since, Until time.Time; Lang i18n.Lang; Projects []ProjectSummary; Summary map[string]int; Channels []ChannelResult; CreatedAt time.Time }
  type ProjectSummary struct { Name string; New, Gone, Superseded, Due int }
  type ChannelResult struct { Name, Type, Result string /* ok|error|skipped */; Error string }
  type Repo struct{…}; func NewRepo(s *store.Store) *Repo
  func (r *Repo) Save(ctx context.Context, run Run) error
  func (r *Repo) Last(ctx context.Context) (Run, bool, error) // le dernier run enregistré, quel que soit le sort de ses canaux
  func (r *Repo) List(ctx context.Context, last int) ([]Run, error)
  ```
- Règles de `Compute` (§ 4.1) : `Since` = `Last.Until` sinon `now-24h`, sans plafond (`Digest.SinceLabel` = « depuis le JJ/MM » quand la fenêtre dépasse 36 h) ; nouvelles = `first_seen_at > Since` et statut ≠ gone ; disparues = gone et `status_changed_at > Since` ; à revoir = décisions `superseded_at > Since` et raison ≠ `redecided` ; échéances = defer en vigueur avec `due_at ≤ now + DueHorizon`, `Overdue` si `due_at ≤ now` ; `DaysWithoutCritical` = jours entiers depuis `first_seen_at` de la critique la plus récente du projet (ou depuis le premier scan) ; regroupement par (ecosystem, package) trié par pire gravité puis nom ; `AttentionTotal` = nouvelles critical/high + à revoir + échéances. `Title` et `Word` viennent du catalogue (`digest.title.*`, `digest.word.*`, pluriels via `N`). `OSVStale` = fraîcheur > 7 jours.
- Rendus : texte = en-tête `Title`, bandeau OSV si périmée, un bloc par projet (sections non vides seulement), pied « Page : <PageURL> » ; HTML = même structure, `<style>` inline minimal, sans script/image/lien externe autre que `PageURL` ; JSON = `json.Marshal(d)` avec `omitempty` sur les sections vides.
- CLI :
  ```
  michel digest [--since 2026-10-20] [--json] [--html]      # calcule et affiche ; n'enregistre rien, n'envoie rien
  michel digest --send                                       # ExpireDue (audit decision.superseded) puis Compute ; Task 7 branche l'envoi ; ici : enregistre le run avec channels=[] et écrit l'audit digest.run
  michel scan --all --digest                                 # après le scan, équivaut à digest --send
  ```
  Audit `digest.run` : `{run_id, since, until, projects, new_total, attention_total, channels}`.

- [ ] **Step 1: Tests qui échouent** — digest : `TestComputeWindowFromLastRunOrDay` (sans run → 24 h ; run vieux de 20 jours → `Since` = son `until`, `SinceLabel` non vide, tout listé), `TestComputeIsPure` (`treeDigest` de la base : aucune ligne `finding`/`decision`/`audit_event` modifiée ou ajoutée par `Compute`), `TestComputeNewAndGoneByPackage` (fixture `demo` : 2 avis sur `acme/lib` → une entrée `Package` avec 2 `OSVIDs`, `WorstSeverity == "high"`), `TestDigestListsSupersededDecisions` (Review Focus 2 ; une supersession `redecided` n'est pas listée), `TestComputeListsDueHorizon` (defer échu → listé `Overdue`, statut inchangé ; defer dans 2 jours → listé ; dans 10 jours → non), `TestDaysWithoutCritical`, `TestTitleAndWordFrenchAndEnglish` (`Michel a trouvé 3 nouveautés cette nuit, 1 mérite ton attention` / `Michel found 3 new findings tonight, 1 needs your attention` ; tout propre → `Word` non vide), `TestRenderTextHasNoAbsolutePathNorCommand` (projet avec `test_cmd` défini et chemin absolu : ni l'un ni l'autre dans le texte, le HTML, le JSON), `TestRenderHTMLHasNoScriptNorImg`, `TestToastLines`, repo : `TestRunRoundTripAndLast` ; cli : `TestDigestPrintsTextByDefault` (et ne change aucun statut), `TestDigestSendRecordsRunAndAudit`, `TestDigestSendExpiresDue` (defer échu → `pending`, audit `decision.superseded`), `TestDigestSendSinceOverride`, `TestScanAllDigestChains` (événement `digest.run` après `scan --all --digest`, absent sans le flag), `TestDigestNeverWritesUnderProject`.
- [ ] **Step 2: Lancer** `go test ./internal/digest/ ./internal/cli/ -run 'Compute|Digest|Title|Render|Toast|RunRoundTrip' -v` → FAIL.
- [ ] **Step 3: Implémenter** (`Compute`, gabarits texte/HTML EN et FR écrits à la main, repo, CLI, clés `digest.*`).
- [ ] **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** des gabarits `templates/fr/*.tmpl` et clés `digest.*` ; appliquer.
- [ ] **Step 6: Commit** `feat(digest): what changed since yesterday, text/html/json renderings, digest runs, michel digest`.

### Task 6: Secrets (`internal/secret`), `michel secret`, `egress.DialContext`

**Files:**
- Create: `internal/secret/secret.go` (interface + magasin fichier), `internal/secret/dpapi_windows.go`, `internal/secret/dpapi_other.go`, `internal/secret/secret_test.go`, `internal/cli/secret.go`, `internal/cli/secret_test.go`
- Modify: `internal/egress/gateway.go` (`DialContext`), `internal/egress/gateway_test.go`, `internal/egress/boundary_test.go` (déjà interdit `net.Dial` ailleurs : ajouter `net.DialTCP`, `tls.Dial`, `smtp.Dial` à la liste), `internal/cli/root.go`, `internal/i18n/catalog/{en,fr}.json` (`cli.secret.*`)

**Interfaces:**
- Produces:
  ```go
  package secret
  var ErrNotFound, ErrInvalidName error
  var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
  type Store interface { Set(name string, value []byte) error; Get(name string) ([]byte, error); Delete(name string) error; List() ([]string, error) }
  // Open returns the store of dataDir/secrets: DPAPI-protected files on Windows (user scope), 0600 plain files elsewhere.
  func Open(dataDir string) (Store, error)
  // Protected reports whether values are encrypted at rest on this OS (true on Windows).
  func Protected() bool
  const ReservedAPIToken = "api-token"
  // egress
  // DialContext opens a TCP connection to addr (host:port) for purpose, after the same allowlist check and audit record as HTTP.
  func (g *Gateway) DialContext(ctx context.Context, purpose, network, addr string) (net.Conn, error)
  ```
- DPAPI : `crypt32.dll` `CryptProtectData` / `CryptUnprotectData` via `syscall.NewLazyDLL`, `DATA_BLOB`, `CRYPTPROTECT_UI_FORBIDDEN`, libération par `LocalFree` ; entropie optionnelle fixe `"michel-secret-v1"`. Fichier `<dataDir>/secrets/<name>` ; dossier `0700`.
- CLI : `michel secret set <name>` (valeur sur stdin : `io.ReadAll` si non-TTY, sinon saisie masquée via `golang.org/x/term` — déjà dans le graphe ? sinon `term.ReadPassword` de `x/term` ajouté), `michel secret list`, `michel secret delete <name>`. Sur un OS sans protection : avertissement `cli.secret.plain_warning`. Audit `secret.set|delete` : `{name}` seulement. Jamais la valeur dans stdout/stderr/audit (test : la valeur `"hunter2-tok"` n'apparaît dans aucune sortie ni dans `audit_event`).

- [ ] **Step 1: Tests qui échouent** — secret : `TestSetGetDeleteRoundTrip`, `TestNameRules` (`Api-Token`, `a/b`, 65 caractères refusés), `TestFileIsNotPlainOnWindows` (`runtime.GOOS == "windows"` : le fichier ne contient pas la valeur), `TestFileMode0600Elsewhere` ; egress : `TestDialContextDeniedWithoutRule` (`ErrEgressDenied`, un `Attempt` enregistré `Allowed=false`), `TestDialContextAllowedReachesLoopbackListener` (règle `127.0.0.1` / `notify.email` ; un `net.Listen` de test reçoit la connexion), `TestDialContextFailsClosedWhenSinkFails`, boundary : `TestNoDirectDialOutsideEgress` (étendu) ; cli : `TestSecretSetFromStdinNeverPrintsValue`, `TestSecretListAndDelete`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: `go test ./...`** → PASS.
- [ ] **Step 5: Commit** `feat(secret,egress): local secret store (DPAPI on Windows), michel secret, audited DialContext`.

### Task 7: Canaux (`internal/notify`), section `notify` de la politique, `michel notify`, envoi depuis `digest --send`

**Files:**
- Create: `internal/notify/notify.go` (interface, `Build`, `SendAll`), `internal/notify/email.go`, `internal/notify/webhook.go`, `internal/notify/toast.go`, `internal/notify/toast_windows.go`, `internal/notify/toast_linux.go`, `internal/notify/toast_darwin.go`, `internal/notify/*_test.go`, `internal/cli/notify.go`, `internal/cli/notify_test.go`
- Modify: `internal/policy/policy.go` (`Notify NotifyConfig`), `internal/policy/validate.go`, `internal/policy/defaults.go`, `internal/policy/policy_test.go`, `config.example.yaml`, `internal/cli/digest.go` (`--send` envoie), `internal/cli/scan.go`, `internal/cli/root.go`, `internal/i18n/catalog/{en,fr}.json` (`notify.*`, `cli.notify.*`), `docs/security/network-egress.md` + `.fr.md` (Task 10 finalise)

**Interfaces:**
- Produces:
  ```go
  // policy
  type NotifyConfig struct { PageURL string `yaml:"page_url"` /* default http://127.0.0.1:7331/, never carries the token */; Channels []ChannelConfig `yaml:"channels"` }
  type ChannelConfig struct {
      Name string `yaml:"name"`; Type string `yaml:"type"` /* email|webhook|toast */; Enabled *bool `yaml:"enabled"` /* nil = true */
      Projects []string `yaml:"projects"`
      Host string `yaml:"host"`; Port int `yaml:"port"`; From string `yaml:"from"`; To []string `yaml:"to"`; Username string `yaml:"username"`; PasswordSecret string `yaml:"password_secret"`
      URL string `yaml:"url"`; Format string `yaml:"format"` /* generic|slack|discord, default generic */; Secret string `yaml:"secret"`
  }
  const ( PurposeEmail = "notify.email"; PurposeWebhook = "notify.webhook" )
  // ValidateNotify: unique names; known type; email needs host, port in {587,465}, from, to non-empty; webhook needs https url (http://127.0.0.1 allowed) and a secret name if url is not loopback; enabled email/webhook needs a network.allow rule (host, purpose) — error text names the exact rule to add.
  func ValidateNotify(n NotifyConfig, rules []AllowRule) error
  // notify
  type Notifier interface { Name() string; Type() string; Send(ctx context.Context, d digest.Digest) error; Test(ctx context.Context) error }
  type Deps struct { Gateway *egress.Gateway; Secrets secret.Store; Version string; Runner Runner; Now func() time.Time }
  // Runner executes a closed-list subprocess (toast). The default runs it; tests capture it.
  type Runner interface { Run(ctx context.Context, name string, args []string, stdin []byte) error }
  // Build returns one Notifier per enabled channel; an unknown type is a configuration error.
  func Build(cfg policy.NotifyConfig, deps Deps) ([]Notifier, error)
  // SendAll sends d to every notifier (filtered by Projects), never stops at the first failure, and returns one result per channel.
  func SendAll(ctx context.Context, ns []Notifier, d digest.Digest) []digest.ChannelResult
  var ErrSecretMissing error // "secret %q is not set: run michel secret set %s"
  ```
- Email : `net/smtp` ; 465 → `tls.Client(conn, &tls.Config{ServerName: host})` sur la connexion de `DialContext` ; 587 → `smtp.NewClient(conn, host)` + `StartTLS` obligatoire (échec si le serveur ne l'offre pas) ; `smtp.PlainAuth` seulement après TLS ; message `multipart/alternative` (texte + HTML), `Subject: Michel · <date> · N nouveautés` (via catalogue), `Date`, `Message-ID`. `Test` envoie un message fixe `notify.test.subject/body`.
- Webhook : corps selon `Format` ; en-têtes `Content-Type`, `User-Agent: michel/<version>`, `X-Michel-Timestamp`, `X-Michel-Signature: sha256=<hex HMAC-SHA256(secret, ts + "." + body)>` quand `Secret` ≠ "" ; `Discord` tronque à 1 900 runes ; 2xx = ok ; contexte 20 s.
- Toast Windows : `powershell.exe` résolu depuis `%SystemRoot%\System32\WindowsPowerShell\v1.0\` ; `-NoProfile -NonInteractive -EncodedCommand <UTF-16LE base64>` ; le script : charge `Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime`, `Windows.Data.Xml.Dom.XmlDocument`, XML `<toast><visual><binding template="ToastGeneric"><text>{title}</text><text>{body}</text></binding></visual></toast>` avec `title`/`body` échappés XML (`html.EscapeString` suffit pour `<>&"'`), `CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe').Show($toast)`. Linux : `notify-send Michel <body>` (`exec.LookPath`). macOS : `osascript -e 'display notification "<body>" with title "Michel"'` (guillemets échappés). Les textes viennent de `digest.ToastLines`.
- `digest --send` : `Build` → `SendAll` → `Run.Channels` → `Save` ; un canal en échec ⇒ exit 1 après avoir tout tenté ; message par canal « quoi / pourquoi / quoi faire » (règle d'allowlist manquante → la règle YAML exacte ; secret manquant → la commande `michel secret set`). Audit `notify.send` par canal : `{channel, type, host, result, bytes, run_id}` ; `notify.test` pour `michel notify test`.
- CLI : `michel notify list` (table name/type/enabled/host-or-url/projects), `michel notify test <name>`.

- [ ] **Step 1: Tests qui échouent** — policy : `TestValidateNotifyRules` (table : nom dupliqué, type inconnu, port 25, `to` vide, url http non loopback, email activé sans règle allow → message contient `host: smtp.example.org` et `purpose: notify.email`), `TestExampleConfigStillLoads` ; notify : `TestEmailSendsMultipartOverStartTLS` (serveur SMTP minimal de test sur loopback avec certificat auto-signé injecté via `Deps` ou `tls.Config` de test ; vérifie `EHLO`, `STARTTLS`, `AUTH PLAIN`, `From/To`, deux parties), `TestEmailDeniedByPolicySaysWhichRule` (Review Focus 4), `TestEmailMissingSecret`, `TestWebhookGenericSignature` (`httptest.Server` : recalcule l'HMAC, vérifie l'en-tête, le corps JSON `michel_digest == 1`), `TestWebhookSlackAndDiscordFormats`, `TestWebhookNon2xxIsError`, `TestToastWindowsScriptEscapesXML` (runner capturé : args contiennent `-EncodedCommand` ; le script décodé contient `&lt;b&gt;` et pas `<b>` pour un titre `<b>`), `TestToastLinuxUsesNotifySend`, `TestSendAllContinuesAfterFailure`, `TestSendAllFiltersProjects`, `TestNoBodyInAudit` ; cli : `TestDigestSendContinuesAfterChannelFailure` (Review Focus 4 : webhook ok + email sans secret → exit 1, `digest_run.channels` = `[ok, error]`, message dit `michel secret set`), `TestNotifyTestAndList`, `TestNotifyNeverLogsSecretValue`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: `go test ./...`** → PASS.
- [ ] **Step 5: Test manuel Windows** (poste de Kévin) : `michel notify test bureau` affiche un toast ; résultat noté au ledger (sans contenu).
- [ ] **Step 6: Relecture FR** des clés `notify.*`, `cli.notify.*` ; appliquer.
- [ ] **Step 7: Commit** `feat(notify): email over smtp, signed webhook, native toast; notify policy section, michel notify, digest --send`.

### Task 8: API locale (`internal/api`) et `michel serve`

**Files:**
- Create: `internal/api/server.go` (mux, middlewares, jeton), `internal/api/handlers.go`, `internal/api/views.go` (structures JSON sans chemin absolu ni commande), `internal/api/server_test.go`, `internal/api/handlers_test.go`, `internal/cli/serve.go`, `internal/cli/serve_test.go`
- Modify: `internal/cli/root.go`, `internal/i18n/catalog/{en,fr}.json` (`api.*`, `cli.serve.*`), `web/embed.go` + `web/dist/.gitkeep` (créés ici pour que `serve` compile ; Task 9 remplit)

**Interfaces:**
- Consumes: `digest.Compute`, `decide.Repo`, `scan.Repo`, `analyze.Repo`, `explain`, `project.Repo`, `secret.Store` (jeton), `audit.Logger`, `web.Dist() fs.FS`.
- Produces:
  ```go
  package api
  type Deps struct { Store *store.Store; Audit *audit.Logger; Policy policy.Policy; Secrets secret.Store; Now func() time.Time; Version string; OSVRoot string; Lang i18n.Lang; Web fs.FS /* nil = pas de front */ }
  // New builds the handler. Token is required on every /api/v1 route (Authorization: Bearer or, for the first page load only, ?token= on "/").
  func New(deps Deps, token string) http.Handler
  // LoadOrCreateToken returns the api token from the secret store (name secret.ReservedAPIToken), creating 32 random bytes (hex) if absent.
  func LoadOrCreateToken(s secret.Store) (string, error)
  // Views
  type ProjectView struct { Name, Classification string; FixLevel int; Open map[string]int; Decided map[string]int; Total int; LastScanAt, LastScanStatus string }
  type FindingView struct { scan.Finding (sans ProjectID) ; Analysis *analyze.Analysis ; Explanation explain.Explanation ; Decision *decide.Decision ; Glossary map[string]string }
  type DecisionRequest struct { Action string `json:"action"`; Why string `json:"why"`; Until string `json:"until"` /* YYYY-MM-DD */ }
  type ErrorBody struct { Error string `json:"error"`; Hint string `json:"hint,omitempty"` }
  // web
  package web
  func Dist() (fs.FS, bool) // sous-arbre dist ; false si index.html absent
  ```
- Routes (`/api/v1`) : `GET /meta`, `GET /today?lang=`, `GET /projects`, `GET /projects/{name}/findings?status=&severity=`, `GET /findings/{id}`, `POST /findings/{id}/decision`, `GET /digests?last=`. `GET /` sert `index.html` (ou la page texte « interface non construite : make web »), `/assets/*` depuis `Dist()`, `/manifest.webmanifest`, `/sw.js`. Mux `net/http` 1.22+ (`"GET /api/v1/findings/{id}"`).
- Middlewares : jeton (401 `ErrorBody`), `Cache-Control: no-store` sur `/api/`, `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'` (Vuetify injecte des styles), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, pas d'en-tête CORS, corps POST ≤ 64 KiB, `Content-Type` JSON exigé en POST. Écoute : `127.0.0.1:<port>` ou `[::1]` seulement ; une autre adresse est refusée (`cli.serve.loopback_only`).
- `FindingView` : chemins de points d'appel relatifs (déjà), `ProjectView` sans `Path`, `TestCmd`, `InstallCmd`. Test de minimisation : réponses de toutes les routes ne contiennent ni le chemin absolu du projet fixture, ni `test_cmd`, ni une commande déclarée `phpunit-secret-marker`.
- CLI : `michel serve [--listen 127.0.0.1:7331] [--open]` ; affiche une fois `http://127.0.0.1:7331/?token=…` ; `--open` lance le navigateur (`rundll32 url.dll,FileProtocolHandler` / `xdg-open` / `open`, liste fermée) ; `Ctrl+C` arrêt propre (`http.Server.Shutdown`, 5 s) ; audit `api.start` `{listen}` et `api.stop`. `SweepStale` au démarrage.

- [ ] **Step 1: Tests qui échouent** — `TestAPIRejectsMissingToken` (Review Focus 5 : 401, corps `{"error":…}` sans donnée), `TestAPIAcceptsBearerAndQueryOnRootOnly`, `TestTodayReturnsDigestInRequestedLang`, `TestProjectsAndFindingsViews`, `TestFindingDetailHasExplanationAndDecision`, `TestPostDecisionAppliesSameRulesAsCLI` (ignore sans why → 400 `hint` = clé catalogue ; defer sans until → 30 jours ; audit `decision.set` `author == "web"`), `TestAPIResponsesHaveNoAbsolutePathsNorCommands` (Review Focus 5), `TestSecurityHeadersAndNoCORS`, `TestServeRefusesNonLoopback`, `TestServeWithoutDistServesPlaceholder`, `TestLoadOrCreateTokenIsStable`, `TestServeNeverWritesUnderProject`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: `go test ./...`** → PASS.
- [ ] **Step 5: Commit** `feat(api): local token-protected JSON API and michel serve, embedded web placeholder`.

### Task 9: Front `web/` — page « Aujourd'hui », fiche, décision, réglages, PWA, embed, Vitest

**Files:**
- Create: `web/package.json`, `web/vite.config.js`, `web/index.html`, `web/public/manifest.webmanifest`, `web/public/sw.js`, `web/public/icons/{icon-192.png,icon-512.png}` (icône simple générée : lettre M), `web/src/main.js`, `web/src/App.vue`, `web/src/api.js`, `web/src/i18n/{fr,en}.json`, `web/src/i18n/index.js`, `web/src/lib/digestView.js` (fonctions pures), `web/src/components/{TodayPage,ProjectCard,PackageRow,FindingSheet,DecisionPanel,SettingsPanel,OsvBanner}.vue`, `web/src/lib/digestView.test.js`, `web/.gitignore`, `web/README.md` (3 lignes : `npm ci`, `npm run dev` avec proxy vers `michel serve`, `npm run build`)
- Modify: `Makefile` (`web`, `build` dépend de `web` si `npm` présent), `.gitignore` (garder `/web/dist/` ignoré **sauf** `.gitkeep`), `internal/i18n/tutoiement_test.go` (inclut `web/src/i18n/fr.json`), `docs/superpowers/sdd/…/progress.md` (vérification manuelle)

**Interfaces:**
- Consumes: routes de Task 8 ; `digest.Digest` JSON ; `FindingView` ; `DecisionRequest`.
- Produces (fonctions pures, testées par Vitest) :
  ```js
  // web/src/lib/digestView.js
  export function groupAttention(digest)        // → [{project, items:[{kind:'new'|'superseded'|'due', package, severity, text}]}] trié critical→low
  export function formatDate(iso, lang)          // 'fr' → 22/11/2026, 'en' → 2026-11-22
  export function decisionLabel(decision, lang)  // 'fix'|'defer 22/11/2026'|'ignore'|'' via i18n
  export function validateDecision({action, why, until}, now) // → {ok, errorKey} : mêmes règles que decide.Validate (ignore ⇒ why ; until ≥ aujourd'hui)
  // web/src/api.js
  export const api = { token, setToken(t), get(path), post(path, body) } // Authorization: Bearer ; 401 ⇒ événement 'unauthorized'
  ```
- Vuetify 4 (`vite-plugin-vuetify` autoImport), thème clair/sombre (`useTheme` non : Options API ⇒ `this.$vuetify.theme.global.name`), langue persistée `localStorage.michel.lang`, jeton `localStorage.michel.token` lu depuis `?token=` puis retiré de l'URL (`history.replaceState`).
- Écrans § 6.2 ; textes interface uniquement via `web/src/i18n/*.json` (helper `$t(key, params)` global, pluriel `.one/.other`) ; la voix de Michel (`digest.title`, `word`) vient de l'API déjà traduite.
- `sw.js` : précache `index.html` + `/assets/*` listés au build (plugin maison dans `vite.config.js` qui écrit `dist/sw-manifest.json`) ; `fetch` : `/api/` ⇒ réseau seulement, jamais de cache ; sinon cache-first ; hors ligne sur `/api/` ⇒ la page affiche `offline.hint` (« lance `michel serve` »).
- Build : `npm run build` ⇒ `web/dist/` ; `web/embed.go` `//go:embed all:dist` ; `make web` ; `make build: web? ; go build` (règle conditionnelle `ifneq ($(shell command -v npm),)`).
- Vérification manuelle (Chrome DevTools MCP ou navigateur) : page Aujourd'hui sur la fixture `demo`, décision `ignore` sans justification refusée, `defer` par défaut affiche la date, thème sombre, installation PWA proposée ; noté au ledger.

- [ ] **Step 1: Tests qui échouent** — Vitest : `groupAttention sorts critical first and keeps project order`, `formatDate per lang`, `decisionLabel`, `validateDecision mirrors decide rules` (ignore sans why ⇒ `errorKey === 'decision.why_required'` ; until hier ⇒ `'decision.until_past'` ; defer sans until ⇒ ok). Go : `TestDistEmbedsIndexAfterBuild` (skip si `web/dist/index.html` absent), tutoiement sur `web/src/i18n/fr.json`.
- [ ] **Step 2: Lancer** `cd web && npm ci && npx vitest run` → FAIL (fichiers absents).
- [ ] **Step 3: Implémenter** le front, le SW, le manifest, l'embed, le Makefile.
- [ ] **Step 4: Lancer** `npx vitest run` → PASS ; `npm run build` ; `go build ./... && go test ./...` → PASS ; `bin/michel serve` + vérification manuelle (captures non committées).
- [ ] **Step 5: Relecture FR** de `web/src/i18n/fr.json` ; appliquer.
- [ ] **Step 6: Commit** `feat(web): today page, finding sheet, decisions, settings, PWA shell embedded in the binary`.

### Task 10: Docs bilingues, run réel sur le projet de référence, hygiène, ledger

**Files:**
- Create: `docs/operations/daily-digest.md`, `docs/operations/daily-digest.fr.md` (décisions, digest, canaux, secrets, page, tâche planifiée à écrire soi-même en attendant `michel schedule`), `docs/superpowers/sdd/2026-10-23-michel-digest/progress.md`, `docs/superpowers/sdd/2026-10-23-michel-digest/deferred-and-rulings.md`
- Modify: `docs/operations/offline-installation.md` + `.fr.md` (nouvelles commandes, `--lang` auto, `project set --exclude`), `docs/security/network-egress.md` + `.fr.md` (purposes `notify.email`, `notify.webhook`, `DialContext`, toast = sous-processus local sans réseau), `README.md` + `README.fr.md` (statut plan 3, quick start `decide`, `digest --send`, `serve`), `config.example.yaml` (section `notify` commentée), `internal/hygiene/hygiene_test.go` (une empreinte de plus : SHA-256 des tokens joints, en minuscules, du dossier parent des projets de ce poste ; **le clair n'apparaît nulle part**, calculé hors dépôt avec `printf '%s' <tokens> | sha256sum`)

- [ ] **Step 1: Build** `make web && go build -o bin/michel.exe ./cmd/michel` ; `bin/michel.exe version`.
- [ ] **Step 2: Run réel** (config réelle, projet de référence) : `michel scan --all`, `michel decisions --project <ref>` (vide), `michel decide --project <ref> --package <pkg> defer --for 30d --why "…"` sur un paquet, `michel digest`, `michel digest --send` avec un canal `toast` et, si Kévin a fourni un SMTP de test, `email`, `michel serve` + page. **Ledger : agrégats seulement** (nombre de failles, de décisions, durée du digest, canaux ok/erreur), aucun nom de paquet ni de projet, projet dit « le projet de référence ».
- [ ] **Step 3: Vérifier** `michel audit verify` OK ; `michel audit list --last 60` : `decision.set`, `digest.run`, `notify.send`, `api.start` présents ; `egress.attempt` seulement pour les hôtes de canaux configurés ; `go test ./internal/hygiene/` vert ; relecture manuelle du ledger et des docs pour toute phrase décrivant la composition du projet privé.
- [ ] **Step 4: Docs** bilingues + relecture FR des `*.fr.md` touchés.
- [ ] **Step 5: Commit** `docs: decisions, daily digest, channels, secrets and today page; plan 3 ledger`.

---

## Self-review (2026-10-23)

- Arbitrages post-relecture builder (spec § 12, 11-14) : digest pur + `ExpireDue` dans `applyScan` et `digest --send` → T4/T5 ; textes stockés en anglais → T1 (`scan.error`), T7 (`channels[].error`) ; `assistant.lang: auto` → T2 ; fenêtre sans plafond → T5.
- Couverture spec plan 3 : § 3 décisions → T4 ; § 4 digest → T5 (+ T7 pour `--send`) ; § 5 canaux → T7, secrets → T6, `DialContext` → T6 ; § 6 page → T8 (API) + T9 (front) ; § 7 i18n → T2 (catalogue, gabarits, garde) + T3 (CLI) ; § 8 migration, persistance, `exclude`, balayage → T1 ; § 9 sécurité → tests nommés dans T6/T7/T8 + hygiène T10 ; § 10 ordre respecté.
- Types : `decide.Decision` (T4) ↔ `FindingView.Decision`, `DecisionRequest` (T8) ↔ `validateDecision` (T9) ; `digest.Digest`, `ChannelResult` (T5) ↔ `notify.SendAll` (T7) ↔ `/today` (T8) ↔ `groupAttention` (T9) ; `secret.Store` (T6) ↔ `notify.Deps.Secrets`, `api.LoadOrCreateToken` ; `egress.DialContext` (T6) ↔ email (T7) ; `scan.StatusDecided` (T4) ↔ `findings --status`, digest ; `i18n.Lang` (T2) ↔ `deps.Lang`, `digest.Compute`, `api.Deps`.
- Review Focus : 1 → T4 `TestDecidedFindingStaysDecidedWhenUnchanged` ; 2 → T4 + T5 ; 3 → T1 `TestSweepStaleLeavesRecentRunning` ; 4 → T7 ; 5 → T8.
- Proportion : 10 tâches, signatures et tests nommés, un seul bloc SQL complet (la migration est une donnée du plan, pas du code à inventer), pas de corps de fonction.
