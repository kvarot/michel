# Michel — Plan 2 : analyse déterministe et explications en langage courant

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pour chaque faille, calculer sans IA ni réseau tout ce qu'il faut pour décider : chemin de dépendance, version cible et saut de version, points d'appel dans le code de l'utilisateur, tests qui couvrent, extrait de changelog et breaking changes, score de risque et recommandation, puis les trois phrases d'explication (c'est quoi / ce qui pourrait arriver / ce que ça coûte) en français et en anglais.

**Architecture:** Un paquet `internal/analyze` (un fichier par source de faits, un `Analysis` par finding persisté dans une table `analysis`), un paquet `internal/explain` (gabarits `text/template` embarqués, `en` et `fr`, rendus à l'affichage à partir des faits, jamais stockés), et deux entrées CLI : `michel analyze` (recalcul) et `michel finding <id>` (fiche complète). `michel scan` enchaîne l'analyse sur les findings `new` / `pending` / reappeared. Tout est déterministe et hors ligne : les changelogs viennent de `vendor/` ou `node_modules/` locaux, sinon « indisponible hors ligne ».

**Tech Stack:** Go 1.27 ; `deps.dev/util/semver` (déjà dans go.sum via osv-scanner, sémantiques `semver.NPM` et `semver.Packagist`) ; `text/template` + `embed` ; SQLite via `internal/store` (migration `0002`). Aucune nouvelle dépendance réseau.

**Spec:** `docs/superpowers/specs/2026-10-22-michel-design.md` (§ 4.3 entité Analysis, § 4.4, § 4.11 trois phrases, § 5 langue) ; politique `docs/security/sovereignty-policy.md` (§ 4.1 hors ligne, § 8 minimisation).

## Global Constraints

- Mêmes contraintes que le plan 1 : module `github.com/kvarot/michel`, anglais dans le code et les messages CLI, `filepath` seul, UTC RFC 3339, `testing` standard, Windows et Linux bloquants, Conventional Commits avec le trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, aucun HTTP hors `internal/egress` (test AST en place : toute lecture de changelog se fait sur disque).
- **Aucun accès réseau dans ce plan.** Le changelog distant (design § 4.4.5, dépôt source du paquet) est hors périmètre : valeur `unavailable offline`.
- Lecture seule des dépôts de l'utilisateur ; aucun fichier écrit sous le projet.
- Minimisation (politique § 8) : les points d'appel stockés sont bornés à **200** par finding (`call_site_count` garde le total), les extraits de code ne sont **pas** stockés (le brief du plan 4 les lira à la demande), l'extrait de changelog est borné à **4 096** octets.
- Gabarits d'explication : `en` et `fr` écrits à la main, même structure, aucune traduction automatique ; le rendu ne contient jamais de secret ni de chemin absolu (chemins relatifs au projet).
- Score de risque (design § 4.4.6, règle publique) : saut majeur **+40**, breaking changes détectés **+25**, dépendance directe **+10**, plus de **N = 10** points d'appel **+15**, aucun test couvrant **+20**, paquet dans la liste « cœur » du projet **+20** ; plafonné à 100 ; seuils **< 30** `auto_fix`, **30–60** `handoff`, **> 60** `handoff` avec `warning: true`. Valeurs par défaut dans `policy.Risk`, surchargeables par projet (colonnes `risk_*`), **jamais par le modèle**.
- Langue : `--lang en|fr` persistant sur la racine, défaut = `assistant.lang` de la politique, défaut de la politique = `en` (le choix automatique selon le système arrive avec l'onboarding, plan 3).

## Review Focus

1. Lockfile Composer sans `composer.json` à côté (ou `package-lock.json` sans `package.json`) : le chemin de dépendance est calculé depuis le lock seul, `direct` vaut `unknown`, rien ne plante, et l'explication le dit. Test : Task 1.
2. Version installée non SemVer (`dev-master`, `1.0.x-dev`, `v7.4.0` avec préfixe, `2.0.0-beta.1`) : `v` retiré, pré-versions comparées selon l'écosystème, valeur inconnue → `jump = unknown`, score sans le terme majeur, explication honnête. Test : Task 2.
3. Projet sans `vendor/` ni `node_modules/` (dépôt fraîchement cloné) : namespaces PSR-4 inconnus → points d'appel par heuristique sur le nom du paquet, `call_sites_quality = low`, changelog `unavailable offline`. Test : Task 3 et Task 5.
4. Monorepo avec plusieurs lockfiles : les points d'appel d'une faille ne sont cherchés que dans le sous-arbre du manifeste, en excluant les sous-arbres des autres manifestes, `vendor/`, `node_modules/`, `.git/`, `dist/`, `build/`. Test : Task 3.
5. Paquet non présent dans `core_packages` mais sans aucun test couvrant et avec saut majeur : score 60 exactement = `handoff` sans avertissement (borne inclusive documentée). Test : Task 6.

---

### Task 1: Graphe de dépendances (Composer et npm)

**Files:**
- Create: `internal/analyze/deps.go`, `internal/analyze/deps_composer.go`, `internal/analyze/deps_npm.go`
- Test: `internal/analyze/deps_test.go`, `internal/analyze/testdata/deps/composer/{composer.json,composer.lock}`, `internal/analyze/testdata/deps/npm/{package.json,package-lock.json}`, `internal/analyze/testdata/deps/composer-nolockroot/composer.lock`

**Interfaces:**
- Produces:
  ```go
  type Directness string // "direct" | "transitive" | "unknown"
  type DepGraph struct { Ecosystem string; Root map[string]string /* direct deps: name -> constraint, "" if unknown */; Requires map[string][]string /* pkg -> deps */; HasRootManifest bool }
  func LoadDepGraph(manifestDir, ecosystem string) (*DepGraph, error) // ecosystem "Packagist" | "npm" ; lit <dir>/composer.{json,lock} ou <dir>/package{.json,-lock.json}
  type DepPath struct { Directness Directness; Via []string /* chemin depuis une dépendance directe jusqu'au paquet, exclu ; vide si direct */; Constraint string /* contrainte racine si direct */ }
  func (g *DepGraph) PathTo(pkg string) DepPath // BFS depuis Root ; plus court chemin ; "unknown" si HasRootManifest == false et pkg absent de Root
  ```
- Composer : `composer.lock` `packages[]` + `packages-dev[]` avec leurs `require` (ignorer `php`, `ext-*`, `lib-*`, `composer-plugin-api`) ; racine = `composer.json` `require` + `require-dev`. npm v3 : `packages` ; racine = `packages[""].dependencies` + `devDependencies` ; `Requires[name]` = clés `dependencies` + `optionalDependencies` de l'entrée `node_modules/<name>` (nom = dernier segment après `node_modules/`). Noms Composer comparés en minuscules.

- [ ] **Step 1: Tests qui échouent** — `TestComposerDirectAndTransitive` (fixture : racine requiert `acme/app` qui requiert `acme/lib` qui requiert `acme/vuln` ; `PathTo("acme/vuln")` → `transitive`, `Via == ["acme/app","acme/lib"]` ; `PathTo("acme/app")` → `direct`, `Constraint == "^1.0"`) ; `TestNpmDirectAndTransitive` (même forme avec `vuln-pkg` via `app-pkg`) ; `TestComposerWithoutRootManifestIsUnknown` (`HasRootManifest == false`, `PathTo` → `unknown`, `Via` vide) ; `TestComposerIgnoresPlatformRequires` ; `TestUnknownPackageIsUnknown`.
- [ ] **Step 2: Lancer** `go test ./internal/analyze/ -run 'Composer|Npm|Unknown' -v` → FAIL.
- [ ] **Step 3: Implémenter** les trois fichiers.
- [ ] **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): dependency graph and path for composer and npm lockfiles`.

### Task 2: Version cible, saut de version, contrainte

**Files:**
- Create: `internal/analyze/semver.go`
- Test: `internal/analyze/semver_test.go`

**Interfaces:**
- Produces:
  ```go
  type Jump string // "none" | "patch" | "minor" | "major" | "unknown"
  type Upgrade struct { Target string /* plus petite version corrigée > installée, "" si aucune */; Jump Jump; ConstraintAllows *bool /* nil si contrainte vide ou inconnue */ }
  func PlanUpgrade(ecosystem, installed string, fixed []string, constraint string) Upgrade
  func NormalizeVersion(ecosystem, v string) string // retire "v"/"V" en tête, trim ; renvoie "" si non parsable par deps.dev/util/semver pour l'écosystème
  ```
- Système semver : `semver.NPM` pour `npm`, `semver.Packagist` pour `Packagist` (`deps.dev/util/semver` : `sys.Parse`, `sys.ParseConstraint`, `c.Match(v)`, `v.Compare`). `Jump` = comparaison des composantes majeure/mineure/patch entre installée et cible ; pré-version ignorée pour le saut. `none` si `Target == ""` (aucune version corrigée) ; `unknown` si installée non parsable.

- [ ] **Step 1: Tests qui échouent** — table `TestPlanUpgrade` : (`Packagist`, `v7.4.0`, `["7.4.5","8.0.0"]`, `^7.4`) → `Target "7.4.5"`, `patch`, `allows true` ; (`npm`, `2.0.7`, `["2.0.9"]`, `~2.0.0`) → `patch`, `true` ; (`npm`, `1.2.0`, `["2.0.0"]`, `^1.2.0`) → `major`, `false` ; (`Packagist`, `1.2.0`, `["1.5.0"]`, `~1.2`) → `minor`, `true` (Composer `~1.2` = `>=1.2 <2.0`) ; (`npm`, `1.2.0`, `["1.5.0"]`, `~1.2`) → `minor`, `false` (npm `~1.2` = `<1.3`) ; (`Packagist`, `dev-master`, `["1.0.1"]`, `*`) → `unknown`, `allows nil` ; (`npm`, `1.0.0`, `[]`, `^1`) → `Target ""`, `none` ; (`npm`, `1.0.0`, `["0.9.0","1.0.0-beta.1","1.0.1"]`, `""`) → `Target "1.0.1"`, `allows nil` ; `TestNormalizeVersion` (`v1.2.3` → `1.2.3`, ` 1.2.3 ` → `1.2.3`, `dev-main` → `""`).
- [ ] **Step 2: Lancer** → FAIL.
- [ ] **Step 3: Implémenter** `semver.go` (import `deps.dev/util/semver` ; `go mod tidy` le promeut en dépendance directe).
- [ ] **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): upgrade target, semver jump and constraint check per ecosystem`.

### Task 3: Points d'appel dans le code de l'utilisateur

**Files:**
- Create: `internal/analyze/callsites.go`, `internal/analyze/callsites_php.go`, `internal/analyze/callsites_js.go`, `internal/analyze/walk.go`
- Test: `internal/analyze/callsites_test.go`, `internal/analyze/testdata/callsites/php/{composer.lock,vendor/acme/vuln/composer.json,src/Http.php,src/Other.php,tests/HttpTest.php,api/composer.lock,api/src/Api.php}`, `internal/analyze/testdata/callsites/js/{package-lock.json,src/a.js,src/b.ts,src/c.vue,node_modules/vuln-pkg/package.json}`

**Interfaces:**
- Produces:
  ```go
  type CallSite struct { File string /* relatif au projet, slash */; Line int; Snippet string /* la ligne, trim, max 160 chars ; non stocké en base */; IsTest bool }
  type CallSites struct { Sites []CallSite /* ≤ 200 */; Count int; Quality string /* "psr4" | "name" | "low" */; Namespaces []string }
  func FindCallSites(projectRoot, manifestRelPath, ecosystem, pkg string, exclude []string) (CallSites, error)
  ```
- Périmètre de recherche = sous-arbre du répertoire du manifeste, **moins** les répertoires contenant un autre `composer.lock` / `package-lock.json`, moins `vendor/`, `node_modules/`, `.git/`, `dist/`, `build/`, `.cache/`, plus les `exclude` du projet. Fichiers lus : PHP `*.php`, `*.phtml`, `*.twig` ; JS `*.js`, `*.mjs`, `*.cjs`, `*.ts`, `*.tsx`, `*.jsx`, `*.vue`, `*.svelte`. Fichiers > 2 MiB ignorés. Lecture séquentielle ligne par ligne (`bufio.Scanner`, buffer 1 MiB).
- PHP : namespaces depuis `vendor/<pkg>/composer.json` `autoload.psr-4` (et `psr-0`) si présent → motifs `use <NS>`, `\<NS>`, `<NS>\` (prefix match, insensible à la casse) → `Quality "psr4"` ; sinon motif sur le nom du paquet `vendor/name` → segments `name` en StudlyCase comme namespace probable → `Quality "name"` ; aucun résultat et pas de vendor → `"low"`. JS : `require('<pkg>')`, `require("<pkg>")`, `from '<pkg>'`, `from "<pkg>"`, `import('<pkg>')`, `import '<pkg>'`, et `<pkg>/` (sous-chemin) ; `Quality "psr4"` est remplacé par `"import"` pour npm.
- `IsTest` : chemin contient `/tests/`, `/test/`, `/__tests__/`, ou nom finit par `Test.php`, `.test.js|ts|jsx|tsx`, `.spec.js|ts|jsx|tsx`.

- [ ] **Step 1: Tests qui échouent** — `TestPhpCallSitesViaPsr4` (fixture vendor présent, `src/Http.php:3` `use Acme\Vuln\Client;`, `src/Http.php:9` `new Client(`, `tests/HttpTest.php` marqué test ; `Count == 3`, `Quality == "psr4"`, `api/src/Api.php` **absent** car sous un autre manifeste) ; `TestPhpCallSitesWithoutVendorFallsBackToName` (`Quality == "name"`) ; `TestJsCallSitesImportForms` (require, from, dynamic import, sous-chemin, dans `.js`, `.ts`, `.vue` ; `Count == 5`) ; `TestCallSitesCapAt200` (fichier généré avec 300 lignes `require('vuln-pkg')` → `len(Sites) == 200`, `Count == 300`) ; `TestCallSitesSkipNodeModulesAndDist`.
- [ ] **Step 2: Lancer** → FAIL.
- [ ] **Step 3: Implémenter** (walk partagé dans `walk.go` : `userFiles(root, manifestDir, otherManifestDirs, exclude, exts) ([]string, error)`).
- [ ] **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): call sites of a vulnerable package in user code (php psr-4, js imports)`.

### Task 4: Tests couvrants

**Files:**
- Create: `internal/analyze/tests.go`
- Modify: `internal/analyze/callsites_test.go` (réutilise les fixtures)
- Test: `internal/analyze/tests_test.go`

**Interfaces:**
- Consumes: `CallSites`, `userFiles`.
- Produces:
  ```go
  type Coverage struct { TestFiles []string /* relatifs, ≤ 50 */; Count int; Method string /* "callsite" | "reference" | "none" */ }
  func FindCoveringTests(projectRoot, manifestRelPath string, sites CallSites, ecosystem string, exclude []string) (Coverage, error)
  ```
- Règle : (1) tout `CallSite.IsTest` compte (`Method "callsite"`) ; (2) sinon, pour chaque fichier non-test des points d'appel, chercher les fichiers de test du périmètre qui mentionnent son nom de base sans extension (`Http` pour `src/Http.php`, mot entier) → `Method "reference"` ; (3) rien → `"none"`.

- [ ] **Step 1: Tests qui échouent** — `TestCoverageFromTestCallSite` (`tests/HttpTest.php` importe le paquet → `Method "callsite"`, `Count == 1`) ; `TestCoverageByReference` (fixture où seul `src/Http.php` appelle le paquet et `tests/HttpTest.php` mentionne `Http` → `"reference"`) ; `TestCoverageNone`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): covering tests heuristic`.

### Task 5: Extrait de changelog et breaking changes (hors ligne)

**Files:**
- Create: `internal/analyze/changelog.go`
- Test: `internal/analyze/changelog_test.go`, `internal/analyze/testdata/changelog/{keepachangelog.md,plain.md,breaking.md}`

**Interfaces:**
- Produces:
  ```go
  type Changelog struct { Source string /* chemin relatif au projet du fichier lu, ou "" */; Excerpt string /* ≤ 4096 octets, sections ]installed, target] */; Available bool; Breaking bool; BreakingLines []string /* ≤ 20 */ }
  func ReadChangelog(projectRoot, manifestRelPath, ecosystem, pkg, installed, target string) Changelog
  ```
- Fichiers cherchés dans `<manifestDir>/vendor/<pkg>/` ou `<manifestDir>/node_modules/<pkg>/` : `CHANGELOG*.md`, `CHANGES*.md`, `HISTORY*.md`, `CHANGELOG*` (insensible à la casse, premier trouvé). Sections = titres `#`/`##`/`###` contenant une version (`[1.2.3]`, `1.2.3`, `v1.2.3`, avec date éventuelle) ; garder celles dont la version est `> installed` et `<= target` (comparaison Task 2) ; si aucune version reconnue → `Excerpt` = les 4 096 premiers octets, `Breaking` calculé dessus. Breaking = ligne contenant (insensible à la casse) `breaking`, `BC break`, `removed`, `dropped support`, `no longer`, ou titre `### Breaking`/`### Removed`.

- [ ] **Step 1: Tests qui échouent** — `TestChangelogExcerptBetweenVersions` (keepachangelog : installed `1.0.0`, target `1.2.0` → contient `## [1.1.0]` et `## [1.2.0]`, pas `## [1.0.0]` ni `## [1.3.0]`) ; `TestChangelogDetectsBreaking` (`### Removed` → `Breaking true`, `BreakingLines` contient la ligne) ; `TestChangelogUnavailableWithoutVendor` (`Available false`, `Excerpt ""`) ; `TestChangelogCapAt4096`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): offline changelog excerpt and breaking-change detection`.

### Task 6: Score de risque, recommandation, politique et colonnes projet

**Files:**
- Create: `internal/analyze/risk.go`, `internal/store/migrations/0002_analysis.sql`, `docs/remediation-risk.md`, `docs/remediation-risk.fr.md`
- Modify: `internal/policy/policy.go` (section `Risk`, `Assistant.Lang`), `internal/policy/defaults.go`, `internal/policy/validate.go`, `config.example.yaml`, `internal/project/project.go` + `repo.go` (champs `CorePackages []string`, `RiskOverrides`), `internal/cli/project.go` (`--core-package` répétable, `--risk-*`)
- Test: `internal/analyze/risk_test.go`, `internal/policy/policy_test.go`, `internal/project/repo_test.go`

**Interfaces:**
- Produces:
  ```go
  // policy
  type RiskConfig struct { MajorJump, Breaking, Direct, ManyCallSites, NoTests, CorePackage int; ManyCallSitesThreshold int; AutoFixBelow, HandoffUpTo int } // défauts 40,25,10,15,20,20 ; 10 ; 30, 60
  // project : CorePackages []string (colonne core_packages TEXT '[]'), RiskOverrides map[string]int (colonne risk_overrides TEXT '{}', clés = noms des champs RiskConfig en snake_case)
  // analyze
  type Recommendation string // "auto_fix" | "handoff" | "report_only"
  type Risk struct { Score int; Recommendation Recommendation; Warning bool; Terms map[string]int /* terme -> points appliqués */ }
  func ScoreRisk(cfg policy.RiskConfig, overrides map[string]int, in RiskInput) Risk
  type RiskInput struct { Jump Jump; Breaking bool; Directness Directness; CallSiteCount int; TestCount int; IsCore bool; HasFix bool }
  ```
- Règles : `HasFix == false` → `report_only`, score calculé quand même ; `Jump == "unknown"` → terme majeur à 0 et `Terms["major_jump_unknown"] = 0` présent ; score ≤ `AutoFixBelow` exclu → `auto_fix` ; `[AutoFixBelow, HandoffUpTo]` inclus → `handoff` ; `> HandoffUpTo` → `handoff` + `Warning`. `Validate` : chaque terme 0..100, `AutoFixBelow < HandoffUpTo ≤ 100`, `Assistant.Lang ∈ {en, fr}`.
- `0002_analysis.sql` : `ALTER TABLE project ADD COLUMN core_packages TEXT NOT NULL DEFAULT '[]'`, `ADD COLUMN risk_overrides TEXT NOT NULL DEFAULT '{}'` ; `CREATE TABLE analysis (finding_id TEXT PRIMARY KEY, computed_at TEXT NOT NULL, michel_version TEXT NOT NULL, directness TEXT, via TEXT NOT NULL DEFAULT '[]', root_constraint TEXT NOT NULL DEFAULT '', has_root_manifest INTEGER NOT NULL DEFAULT 0, target_version TEXT NOT NULL DEFAULT '', jump TEXT NOT NULL DEFAULT 'unknown', constraint_allows INTEGER /* NULL=inconnu */, call_sites TEXT NOT NULL DEFAULT '[]' /* [{file,line,is_test}] ≤200, sans snippet */, call_site_count INTEGER NOT NULL DEFAULT 0, call_sites_quality TEXT NOT NULL DEFAULT 'low', namespaces TEXT NOT NULL DEFAULT '[]', test_files TEXT NOT NULL DEFAULT '[]', test_count INTEGER NOT NULL DEFAULT 0, test_method TEXT NOT NULL DEFAULT 'none', changelog_source TEXT NOT NULL DEFAULT '', changelog_excerpt TEXT NOT NULL DEFAULT '', changelog_available INTEGER NOT NULL DEFAULT 0, breaking INTEGER NOT NULL DEFAULT 0, breaking_lines TEXT NOT NULL DEFAULT '[]', risk_score INTEGER NOT NULL DEFAULT 0, risk_terms TEXT NOT NULL DEFAULT '{}', recommendation TEXT NOT NULL DEFAULT 'report_only', warning INTEGER NOT NULL DEFAULT 0)` + index `analysis(recommendation)`.
- `docs/remediation-risk.md` (+ `.fr.md`) : la règle publique, les termes, les seuils, les surcharges par projet, et la phrase « le modèle IA ne peut jamais modifier ces valeurs ».

- [ ] **Step 1: Tests qui échouent** — `TestScoreRiskTerms` (table : majeur + breaking + direct + 12 appels + 0 test + cœur → 130 plafonné 100, `handoff`, `Warning`) ; `TestScoreRiskThresholdsInclusive` (29 → `auto_fix` ; 30 → `handoff` sans warning ; 60 → `handoff` sans warning ; 61 → warning) ; `TestScoreRiskNoFixIsReportOnly` ; `TestScoreRiskUnknownJump` ; `TestProjectOverridesApply` (override `major_jump: 10`) ; policy : `TestRiskDefaults`, `TestValidateRejectsBadThresholds`, `TestAssistantLangDefaultEn`, `TestValidateRejectsUnknownLang` ; project : `TestCorePackagesRoundTrip`, `TestRiskOverridesRoundTrip` ; store : `TestMigration0002Applies` (ouvre une base 0001, applique, colonnes présentes).
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter** (migration, policy, project, CLI flags `project add --core-package <name>` répétable et `project set <name> --core-package ... --risk major_jump=10` ; pas de nouvelle sous-commande au-delà de `set`). **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze,policy,project): public risk score with per-project overrides`.

### Task 7: Orchestration, persistance, `michel analyze`, enchaînement après `scan`

**Files:**
- Create: `internal/analyze/analyze.go`, `internal/analyze/repo.go`, `internal/cli/analyze.go`
- Modify: `internal/cli/scan.go` (appel après le scan ; flag `--no-analyze`), `internal/scan/repo.go` (`ListFindings` accepte `status == "actionable"` = `new|pending`)
- Test: `internal/analyze/analyze_test.go` (fixture projet complet réutilisant Task 3), `internal/cli/analyze_test.go`

**Interfaces:**
- Consumes: Tasks 1–6, `scan.Finding`, `project.Project`, `audit.Logger`, `store.Store`.
- Produces:
  ```go
  type Analysis struct { FindingID string; ComputedAt time.Time; MichelVersion string; Path DepPath; HasRootManifest bool; Upgrade Upgrade; Calls CallSites /* Snippet vide une fois persisté */; Coverage Coverage; Changelog Changelog; Risk Risk }
  func Analyze(projectRoot string, p project.Project, f scan.Finding, cfg policy.RiskConfig, exclude []string) (Analysis, error) // pur, sans base
  type Repo struct{...}; func NewRepo(s *store.Store) *Repo
  func (r *Repo) Save(ctx, a Analysis) error ; func (r *Repo) Get(ctx, findingID string) (Analysis, bool, error)
  type RunResult struct { Analyzed, Skipped, Failed int; Errors []error; Duration time.Duration }
  func Run(ctx, deps Deps, p project.Project, findings []scan.Finding, opt Options) (RunResult, error) // Deps{Store, Audit, Version, Now, Risk policy.RiskConfig} ; Options{Force bool} ; un graphe de dépendances chargé une fois par manifeste ; `Skipped` = analyse existante plus récente que `last_seen_at` et pas Force
  ```
- Audit : `analyze.start` (Target projet, Evidence {findings}), `analyze.finish` (Evidence {analyzed, skipped, failed, duration_ms}) ; pas d'événement par finding.
- CLI : `michel analyze --project <name> | --all [--force]` → table `project  analyzed  skipped  failed  duration` + phrase de synthèse ; `michel scan` lance `analyze.Run` sur les findings `new`/`pending` du projet après un scan `ok` ou `partial`, sauf `--no-analyze` ; sa phrase de synthèse ajoute « , analyzed N findings ».

- [ ] **Step 1: Tests qui échouent** — `TestAnalyzeEndToEndPhp` (fixture : vendor présent, changelog présent, 2 points d'appel, 1 test → `Path.Directness == "direct"`, `Upgrade.Jump == "patch"`, `Changelog.Available`, `Risk.Recommendation == "auto_fix"`) ; `TestRunSkipsFreshAnalysis` (second Run → `Skipped == n`, `Force` → `Analyzed == n`) ; `TestSaveStripsSnippets` (colonne `call_sites` sans clé `snippet`) ; cli : `TestAnalyzeCommandTable`, `TestScanRunsAnalyzeUnlessDisabled` (événement `analyze.finish` présent après `scan`, absent avec `--no-analyze`).
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(analyze): persist per-finding analysis, michel analyze, run after scan`.

### Task 8: Explications en langage courant (en/fr) et fiche `michel finding <id>`

**Files:**
- Create: `internal/explain/explain.go`, `internal/explain/templates/en/{what,impact,cost}.tmpl`, `internal/explain/templates/fr/{what,impact,cost}.tmpl`, `internal/explain/glossary.go`, `internal/cli/finding.go`
- Modify: `internal/cli/root.go` (flag persistant `--lang`, résolution `flag > policy.Assistant.Lang > "en"`), `internal/cli/findings.go` (`--explain` : ajoute la phrase « what » sous chaque ligne)
- Test: `internal/explain/explain_test.go`, `internal/cli/finding_test.go`

**Interfaces:**
- Produces:
  ```go
  type Lang string // "en" | "fr"
  type Facts struct { Package, Ecosystem, OSVID, Summary, SeverityLabel string; CVSS float64; Installed, Target string; Jump analyze.Jump; Directness analyze.Directness; Via []string; CallSiteCount int; CallSitesQuality string; TestCount int; TestMethod string; ChangelogAvailable, Breaking bool; BreakingLines []string; Risk analyze.Risk; ManifestRelPath string; Certainty string /* "high" si psr4/import + tests, "medium" si name, "low" sinon */ }
  type Explanation struct { What, Impact, Cost string }
  func Render(lang Lang, f Facts) (Explanation, error) // text/template embarqués, FuncMap {plural, join, severityWord}
  func FactsFrom(fi scan.Finding, a analyze.Analysis, hasAnalysis bool) Facts
  func Term(lang Lang, key string) string // glossaire : cve, cvss, kev, transitive, lockfile, breaking, semver
  ```
- Contenu des gabarits (exigence § 4.11, une idée par phrase, pas de jargon sans mot du glossaire) :
  - **what** : paquet + version + où il est utilisé (`N places in your code, for example <file>:<line>`, ou `not found in your code (searched by name only)` quand `Quality == "name"|"low"`), résumé OSV en une phrase.
  - **impact** : sévérité en mot courant (`critical` → « could let an attacker take over », `high` → « serious », `medium`, `low`, `unknown` → « not rated yet »), + certitude (`Certainty`), + le fait qu'une dépendance transitive arrive via `<Via[0]>`.
  - **cost** : `Target` et `Jump` en mots (« a small patch update », « a minor update », « a major update that may change how the package works »), breaking changes (`None found in the changelog` / `Changelog not available offline` / `N breaking changes mentioned`), tests (`N tests cover the files that use it` / `No test covers them`), recommandation (« Michel can try this fix for you (level 2) » / « Best handed to you or your coding assistant with a brief » / « No fixed version yet: nothing to update, keep watching »).
  - Les deux langues écrites à la main ; les tests comparent des sous-chaînes clés dans chaque langue.
- CLI `michel finding <id-or-prefix>` : fiche complète (en-tête, trois phrases, faits : chemin, versions, contrainte, points d'appel (top 10, `file:line`), tests, changelog (extrait tronqué à 20 lignes), score et termes, recommandation) ; `--json` = `{finding, analysis, explanation}` ; sans analyse → les faits connus seulement et la phrase `Run "michel analyze --project <name>" to complete this view.` Préfixe d'id ambigu → erreur listant les candidats.

- [ ] **Step 1: Tests qui échouent** — `TestRenderEnglishThreeSentences` (facts direct/patch/2 call sites/1 test/auto_fix → `What` contient `2 places in your code`, `Cost` contient `small patch update` et `Michel can try this fix`) ; `TestRenderFrenchThreeSentences` (mêmes facts → `2 endroits de ton code`, `petite mise à jour corrective`, `Michel peut tenter cette correction`) ; `TestRenderUnknownJumpIsHonest` (`en` : `could not tell how big the update is`) ; `TestRenderNoFix` ; `TestRenderNeverContainsAbsolutePath` ; `TestGlossaryBothLangs` (chaque clé existe en `en` et `fr`) ; cli : `TestFindingDetailShowsExplanation`, `TestFindingDetailWithoutAnalysisHints`, `TestLangFlagOverridesPolicy`, `TestFindingPrefixAmbiguous`.
- [ ] **Step 2: Lancer** → FAIL. **Step 3: Implémenter.** **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(explain): plain-language what/impact/cost in English and French, michel finding detail`.

### Task 9: Run réel sur the reference project, docs, ledger

**Files:**
- Modify: `docs/operations/offline-installation.md` + `.fr.md` (sections `analyze`, `finding`, `--lang`, `project set`), `README.md` + `README.fr.md` (statut, une ligne sur l'analyse)
- Create: `docs/superpowers/sdd/2026-10-22-michel-analyse/progress.md` (ledger committé)

- [ ] **Step 1: Build** `go build -o bin/michel.exe ./cmd/michel`.
- [ ] **Step 2: Lancer** `michel analyze --project demo --force` puis `michel finding <id d'une critique>` en `en` et `--lang fr`, `michel findings --project demo --severity critical --explain`. Noter durée, compteurs `analyzed/skipped/failed`, répartition des recommandations (`auto_fix`/`handoff`/`report_only`), part des findings avec `call_sites_quality == psr4|import`, part avec changelog disponible. **Aucun nom de paquet, version, chemin de fichier the reference project ni phrase d'explication citant un paquet dans le ledger committé** (agrégats seulement).
- [ ] **Step 3: Vérifier** `michel audit list --last 30` : aucun `egress.attempt` ; `michel audit verify` OK.
- [ ] **Step 4: Docs** bilingues + ledger. **Step 5: Commit** `docs: analysis, finding detail and language switch; plan 2 ledger`.

---

## Self-review (2026-10-22)

- Couverture design § 4.4 : 1 chemin → T1 ; 2 saut + contrainte → T2 ; 3 points d'appel → T3 ; 4 tests → T4 ; 5 changelog (local seulement, distant hors plan) → T5 ; 6 score → T6. § 4.3 entité Analysis → T6/T7. § 4.11 trois phrases + glossaire → T8 ; onboarding, compteur de jours, « Michel parle » dans le digest → plan 3. § 5 langue : `--lang` + `assistant.lang` → T6/T8 ; catalogue CLI complet → plan 3.
- Types : `Directness`, `DepPath` (T1) ↔ `RiskInput.Directness`, `Facts.Directness` (T6, T8) ; `Jump`, `Upgrade` (T2) ↔ `RiskInput.Jump`, `Facts.Jump` ; `CallSites.Quality` valeurs `psr4|name|low|import` (T3) ↔ `Facts.CallSitesQuality` et `Certainty` (T8) ; `Coverage.Method` (T4) ↔ `test_method` (T6) ↔ `Facts.TestMethod` ; `Risk` (T6) ↔ `Analysis.Risk` (T7) ↔ `Facts.Risk`.
- Review Focus : 1 → T1 `TestComposerWithoutRootManifestIsUnknown` ; 2 → T2 `TestPlanUpgrade` lignes `dev-master`, `v7.4.0`, pré-version ; 3 → T3 `TestPhpCallSitesWithoutVendorFallsBackToName` + T5 `TestChangelogUnavailableWithoutVendor` ; 4 → T3 `TestPhpCallSitesViaPsr4` (autre manifeste exclu) ; 5 → T6 `TestScoreRiskThresholdsInclusive`.
- Proportion : 9 tâches, signatures et tests nommés, pas de corps de fonction.
