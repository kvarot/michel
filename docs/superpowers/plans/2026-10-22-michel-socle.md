# Michel — Plan 1 : socle (politique, egress, audit, store, scan hors ligne, CLI)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un binaire `michel` qui charge une politique `strict_local` validée, refuse toute sortie réseau non listée, journalise dans un audit chaîné, scanne hors ligne les lockfiles Composer et npm des projets enregistrés, et stocke des Findings stables par lockfile dans SQLite, avec un premier scan réel sur the reference project.

**Architecture:** Un module Go, un binaire, paquets `internal/*` à responsabilité unique. `osvscanner.DoScan` (osv-scanner v2.7.0) fait le scan avec `CompareOffline` et un `http.Client` fourni par la passerelle egress ; Michel télécharge lui-même les bases OSV via cette passerelle. Tout effet observable (démarrage, scan, refus réseau, mise à jour de base) produit un événement d'audit chaîné par SHA-256.

**Tech Stack:** Go 1.27.3 ; `github.com/google/osv-scanner/v2` v2.7.0 (`pkg/osvscanner`, `pkg/models`) ; `github.com/ossf/osv-schema/bindings/go/osvschema` ; `modernc.org/sqlite` ; `gopkg.in/yaml.v3` ; `github.com/spf13/cobra` ; `github.com/oklog/ulid/v2` ; `log/slog` ; tests `testing` + `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-10-22-michel-design.md` (§ 3, § 4.1-4.3, § 4.9, § 4.10 étapes 1-2) ; politique `docs/security/sovereignty-policy.md` (§ 4, § 4.1, § 4.2, § 7).

## Global Constraints

- Module `github.com/kvarot/michel`, `go 1.27`, licence Apache-2.0, code / identifiants / commits / README en anglais ; messages CLI en anglais.
- Binaire unique `michel` ; aucun sous-processus dans ce plan ; aucun cgo (`modernc.org/sqlite`).
- Mode par défaut `strict_local` ; démarrage refusé si la politique est invalide ou incohérente.
- Toute requête HTTP sortante passe par `egress.Gateway` ; aucun `http.DefaultClient`, aucun `http.Get` ailleurs (test de grep en CI).
- Aucune télémétrie, aucun rapport d'erreur distant.
- Identifiants : ULID (`oklog/ulid/v2`) pour les lignes ; `finding.id` = 16 premiers hex de SHA-256 de `project_id|manifest_rel_path|ecosystem|package|osv_id`.
- Horodatages en UTC RFC 3339.
- Windows et Linux bloquants : CI `go test ./...` sur `windows-latest` et `ubuntu-latest`. Chemins via `filepath`, jamais de `/` en dur.
- Exclusions de scan par défaut : `**/vendor/**`, `**/node_modules/**`, `**/.git/**`.
- Commits : Conventional Commits en anglais, suffixe `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Messages CLI (design § 4.11) : langage courant, une idée par phrase ; toute erreur dit *quoi*, *pourquoi*, *quoi faire ensuite* (ex. `Offline database missing for Packagist. Michel scans without network, so it needs a local copy. Run "michel db update" once from a connected machine.`) ; `michel scan` termine par une phrase de synthèse et la prochaine action suggérée.

## Review Focus

1. Fichier de politique absent : Michel démarre avec les défauts `strict_local` et le dit (`policy: defaults (no file at <path>)`), il ne plante pas. Test : Task 2.
2. Base OSV absente en `strict_local` : erreur explicite `offline database missing for Packagist: run "michel db update"`, zéro requête réseau. Test : Task 6.
3. Lockfile illisible ou corrompu dans un projet multi-manifestes : les autres manifestes sont scannés, l'erreur est stockée sur le `scan` et affichée, le code de sortie est non nul. Test : Task 7.
4. Chemin de projet inexistant ou non dossier à `project add` : refus avec message, aucun enregistrement, événement d'audit `project.add` résultat `denied`. Test : Task 5.
5. Événement d'audit modifié en base : `michel audit verify` nomme le premier événement cassé et sort avec code 2. Test : Task 4.

---

### Task 1: Squelette du module, CLI racine, CI

**Files:**
- Create: `go.mod`, `cmd/michel/main.go`, `internal/cli/root.go`, `internal/cli/version.go`, `internal/buildinfo/buildinfo.go`, `.github/workflows/ci.yml`, `Makefile`
- Test: `internal/cli/root_test.go`

**Interfaces:**
- Produces: `cli.NewRootCmd(deps *cli.Deps) *cobra.Command` ; `cli.Deps{Stdout, Stderr io.Writer; Now func() time.Time}` ; `buildinfo.Version string` (ldflags, défaut `dev`).

- [ ] **Step 1: Écrire le test qui échoue** — `TestRootVersion` : exécute `NewRootCmd(deps)` avec args `["version"]`, attend `Stdout` contenant `michel dev`.
- [ ] **Step 2: Lancer** `go test ./internal/cli/ -run TestRootVersion -v` → FAIL (paquet absent).
- [ ] **Step 3: Implémenter** `go mod init github.com/kvarot/michel`, `go get github.com/spf13/cobra@latest`, `main.go` appelle `cli.NewRootCmd(&cli.Deps{Stdout: os.Stdout, Stderr: os.Stderr, Now: time.Now}).Execute()`. Flags persistants racine : `--config <path>` (défaut `filepath.Join(os.UserConfigDir(), "michel", "config.yaml")`), `--data-dir <path>` (défaut `filepath.Join(os.UserConfigDir(), "michel")`), `--json` (sortie JSON).
- [ ] **Step 4: Lancer** le test → PASS.
- [ ] **Step 5: CI** `.github/workflows/ci.yml` : matrice `ubuntu-latest` / `windows-latest`, `actions/setup-go` avec `go-version: '1.27.x'`, `go vet ./...`, `go test ./...`. `Makefile` : `build`, `test`, `lint` (grep interdisant `http.DefaultClient|http\.Get\(|http\.Post\(` hors `internal/egress`).
- [ ] **Step 6: Commit** `feat: module skeleton, root CLI, CI matrix`.

### Task 2: Politique de souveraineté (YAML, défauts, validation)

**Files:**
- Create: `internal/policy/policy.go`, `internal/policy/defaults.go`, `internal/policy/validate.go`, `internal/policy/load.go`, `config.example.yaml`
- Test: `internal/policy/policy_test.go`, `internal/policy/testdata/*.yaml`

**Interfaces:**
- Produces:
  ```go
  type Mode string // "strict_local" | "standard"
  type Classification string // "public" | "internal" | "confidential" | "sensitive" | "health"
  type Policy struct {
      Sovereignty struct {
          Mode Mode; DataClassification Classification
          AI struct{ ProviderPolicy string; ExternalProvidersEnabled, ModelDownloadsEnabled, AutomaticModelUpdates bool }
          Network struct{ DefaultEgress string; TelemetryEnabled, RemoteErrorReporting bool; Allow []AllowRule }
          Audit struct{ Enabled bool; IntegrityProtection string; PromptContentRetention string }
          Remediation struct{ IsolatedExecutionRequired bool; ProductionDeploymentAllowed bool; HumanApprovalRequiredForMerge bool }
      }
      DB struct{ AutoUpdate bool; OSVPath string } // OSVPath défaut "<data-dir>/osv"
      Assistant struct{ Name string } // défaut "Michel"
  }
  type AllowRule struct{ Host string; Purpose string } // Host exact, ou "*.suffix"
  func Defaults() Policy
  func Load(path string, dataDir string) (Policy, Source, error) // Source: "file" | "defaults"
  func Validate(p Policy) error
  ```
- Valeurs pinnées : `Defaults()` = YAML § 4 de la politique, `Mode=strict_local`, `DefaultEgress="deny"`, `DB.AutoUpdate=false`, `Allow` vide, `Assistant.Name="Michel"`.

- [ ] **Step 1: Tests qui échouent** — `TestDefaultsAreStrictLocal` (tous les booléens réseau/IA à false, `DefaultEgress=="deny"`) ; `TestLoadMissingFileReturnsDefaults` (chemin inexistant → `Source=="defaults"`, pas d'erreur) ; `TestLoadFileOverrides` (`testdata/standard.yaml` avec `mode: standard`, `db.auto_update: true`) ; `TestValidateRejectsStrictLocalWithExternalProviders` (strict_local + `external_providers_enabled: true` → erreur contenant `strict_local forbids ai.external_providers_enabled`) ; `TestValidateRejectsUnknownMode` ; `TestValidateRejectsStrictLocalTelemetry` ; `TestValidateRejectsAllowRuleWithoutPurpose` ; `TestUnknownKeyIsError` (clé inconnue `foo:` → erreur via `yaml.Decoder.KnownFields(true)`).
- [ ] **Step 2: Lancer** `go test ./internal/policy/ -v` → FAIL.
- [ ] **Step 3: Implémenter** `Defaults`, `Load` (fichier absent → défauts ; présent → décodage strict puis fusion sur les défauts), `Validate` (règles : mode connu ; en `strict_local` : `ExternalProvidersEnabled`, `ModelDownloadsEnabled`, `AutomaticModelUpdates`, `TelemetryEnabled`, `RemoteErrorReporting` doivent être false, `DefaultEgress=="deny"` ; `ProductionDeploymentAllowed` toujours false ; chaque `AllowRule` a `Host` et `Purpose` non vides). `config.example.yaml` = défauts commentés.
- [ ] **Step 4: Lancer** les tests → PASS.
- [ ] **Step 5: Brancher** dans `cli.NewRootCmd` un `PersistentPreRunE` qui charge et valide, stocke `Policy` et `Source` dans `Deps`, et écrit sur Stderr `policy: file <path>` ou `policy: defaults (no file at <path>)` ; en cas d'erreur de validation, sortie code 3 avec le message. Test `TestRootRefusesInvalidPolicy` dans `internal/cli/root_test.go`.
- [ ] **Step 6: Commit** `feat(policy): sovereignty policy loading with strict_local defaults and validation`.

### Task 3: Passerelle egress (client HTTP unique, allowlist, journal des tentatives)

**Files:**
- Create: `internal/egress/gateway.go`, `internal/egress/transport.go`, `internal/egress/errors.go`
- Test: `internal/egress/gateway_test.go`

**Interfaces:**
- Consumes: `policy.Policy`, `policy.AllowRule`.
- Produces:
  ```go
  type Attempt struct{ Host, Purpose string; Allowed bool; At time.Time; Reason string }
  type Sink interface{ Record(Attempt) } // branché sur l'audit en Task 4
  type Gateway struct{ /* ... */ }
  func New(p policy.Policy, sink Sink) *Gateway
  func (g *Gateway) Client(purpose string) *http.Client // Transport = checkedTransport{purpose}
  func (g *Gateway) Allowed(host, purpose string) (bool, string) // reason
  func (g *Gateway) Attempts() []Attempt // copie, pour les tests
  var ErrEgressDenied = errors.New("egress denied by policy")
  ```
- Règles : `Allowed` vrai ssi une `AllowRule` matche `host` (exact, ou suffixe `*.x`) **et** `Purpose` égal. Loopback (`127.0.0.1`, `::1`, `localhost`) autorisé pour tout `purpose` commençant par `local.`. En `strict_local` les règles sont honorées (mode ne change pas l'algorithme ; c'est la validation qui a déjà interdit les purposes IA externes). Chaque appel `RoundTrip` enregistre une `Attempt` via `Sink` avant de laisser passer ou de retourner `ErrEgressDenied` (wrap avec host et purpose, sans query string ni headers).

- [ ] **Step 1: Tests qui échouent** — `TestDeniedHostReturnsErrEgressDenied` (httptest server, allowlist vide → `errors.Is(err, ErrEgressDenied)`, `Attempts()[0].Allowed==false`) ; `TestAllowedHostAndPurposePasses` (rule `{Host: "127.0.0.1", Purpose: "osv.db"}` → 200) ; `TestPurposeMismatchDenied` ; `TestWildcardSuffix` (`*.googleapis.com` matche `osv-vulnerabilities.storage.googleapis.com`, pas `googleapis.com.evil.net`) ; `TestLoopbackLocalPurposeAllowed` (`local.ollama` sur 127.0.0.1 sans règle) ; `TestAttemptNeverContainsQueryOrHeaders`.
- [ ] **Step 2: Lancer** `go test ./internal/egress/ -v` → FAIL.
- [ ] **Step 3: Implémenter** `checkedTransport` (embarque `http.Transport` clonée de `http.DefaultTransport.(*http.Transport).Clone()`, `Proxy: nil` pour ignorer les variables d'environnement, timeouts 30 s).
- [ ] **Step 4: Lancer** les tests → PASS.
- [ ] **Step 5: Commit** `feat(egress): single gateway http client with allowlist and attempt sink`.

### Task 4: Store SQLite, migrations, audit chaîné et `michel audit verify`

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrate.go`, `internal/store/migrations/0001_init.sql`, `internal/audit/audit.go`, `internal/audit/verify.go`, `internal/cli/audit.go`
- Test: `internal/store/store_test.go`, `internal/audit/audit_test.go`, `internal/cli/audit_test.go`

**Interfaces:**
- Produces:
  ```go
  // store
  func Open(path string) (*Store, error) // crée le dossier, PRAGMA journal_mode=WAL, foreign_keys=ON, applique les migrations
  func (s *Store) DB() *sql.DB ; func (s *Store) Close() error
  // audit
  type Event struct{ ID, TS, Actor, Action, Target, Result, CorrelationID string; Evidence map[string]any; PrevHash, Hash string }
  type Logger struct{ /* ... */ }
  func NewLogger(s *store.Store, now func() time.Time) *Logger
  func (l *Logger) Record(ctx context.Context, e Event) (Event, error) // remplit ID (ULID), TS, PrevHash, Hash ; insère
  func (l *Logger) EgressSink() egress.Sink // Action "egress.attempt", Target host, Result "allowed"|"denied", Evidence {purpose, reason}
  type VerifyResult struct{ Checked int; Broken *Event; Reason string }
  func Verify(ctx context.Context, s *store.Store) (VerifyResult, error)
  ```
- `Hash` = hex SHA-256 de `PrevHash + "\n" + JSON canonique (clés triées) de {ID, TS, Actor, Action, Target, Result, CorrelationID, Evidence}`. Premier événement : `PrevHash = ""`. Ordre de chaîne = ordre d'insertion (`rowid`).
- Schéma `0001_init.sql` : `schema_migrations(version int pk, applied_at text)`, `audit_event(rowid, id text unique, ts text, actor text, action text, target text, result text, correlation_id text, evidence text, prev_hash text, hash text unique)`, `project(id text pk, name text unique, source_type text, path text, classification text, fix_level int, test_cmd text, install_cmd text, active int, created_at text)`, `scan(id text pk, project_id text references project, started_at text, finished_at text, osv_db_version text, osv_db_fetched_at text, scanner_version text, status text, error text)`, `scan_manifest(scan_id text, rel_path text, ecosystem text, lock_sha256 text, package_count int, error text, primary key(scan_id, rel_path))`, `finding(id text pk, project_id text, manifest_rel_path text, ecosystem text, package text, osv_id text, aliases text, severity_label text, cvss_score real, installed_version text, fixed_versions text, dep_groups text, status text, first_seen_scan text, last_seen_scan text, first_seen_at text, last_seen_at text, summary text)`.

- [ ] **Step 1: Tests qui échouent** — store : `TestOpenAppliesMigrationsIdempotently` (deux `Open` sur le même fichier, `schema_migrations` a 1 ligne, `journal_mode` vaut `wal`) ; audit : `TestRecordChainsHashes` (3 événements, `e2.PrevHash==e1.Hash`, hash recalculé à la main égal) ; `TestVerifyCleanChain` ; `TestVerifyDetectsTamperedEvent` (`UPDATE audit_event SET result='allowed' WHERE id=?` sur le 2e → `Broken.ID==e2.ID`, `Reason=="hash mismatch"`) ; `TestVerifyDetectsDeletedEvent` (suppression du 2e → `Broken.ID==e3.ID`, `Reason=="prev_hash mismatch"`) ; `TestEgressSinkRecordsDeniedWithoutSecrets` ; cli : `TestAuditVerifyExitCode2OnTamper`.
- [ ] **Step 2: Lancer** `go test ./internal/store/ ./internal/audit/ -v` → FAIL.
- [ ] **Step 3: Implémenter** `store` (`modernc.org/sqlite`, driver `sqlite`, migrations via `embed.FS` triées par nom), `audit` (JSON canonique : `encoding/json` sur une `map[string]any` suffit, Go trie les clés de map), `cli` : `michel audit verify` imprime `audit: N events verified` (code 0) ou `audit: BROKEN at event <id>: <reason>` (code 2) ; `michel audit list --last N` (table `ts action target result`).
- [ ] **Step 4: Lancer** les tests → PASS.
- [ ] **Step 5: Brancher** : `cli.Deps` ouvre le store à `<data-dir>/michel.db` dans `PersistentPreRunE`, crée le `Logger`, enregistre `app.start` (Evidence : version, policy source, mode) et construit `egress.New(policy, logger.EgressSink())`. Test `TestRootRecordsAppStart`.
- [ ] **Step 6: Commit** `feat(store,audit): sqlite store with embedded migrations and hash-chained audit log`.

### Task 5: Projets (`project add|list|remove`)

**Files:**
- Create: `internal/project/project.go`, `internal/project/repo.go`, `internal/cli/project.go`
- Test: `internal/project/repo_test.go`, `internal/cli/project_test.go`

**Interfaces:**
- Produces:
  ```go
  type Project struct{ ID, Name, SourceType, Path string; Classification policy.Classification; FixLevel int; TestCmd, InstallCmd string; Active bool; CreatedAt time.Time }
  type Repo struct{ /* store */ }
  func NewRepo(s *store.Store) *Repo
  func (r *Repo) Add(ctx, p Project) (Project, error) // valide : Path absolu existant et dossier ; Name unique ; FixLevel 0..3 ; SourceType "local_path"
  func (r *Repo) List(ctx) ([]Project, error) ; Get(ctx, nameOrID string) (Project, error) ; Remove(ctx, nameOrID string) error
  var ErrNotADirectory, ErrDuplicateName error
  ```
- Défauts à l'ajout : `Classification = policy.Sovereignty.DataClassification`, `FixLevel = 1`, `Active = true`.

- [ ] **Step 1: Tests qui échouent** — `TestAddRejectsMissingPath` (`errors.Is(err, ErrNotADirectory)`) ; `TestAddDefaults` ; `TestAddRejectsDuplicateName` ; `TestRemoveByName` ; cli : `TestProjectAddDeniedIsAudited` (événement `project.add` `Result=="denied"`, aucune ligne `project`) ; `TestProjectListTable`.
- [ ] **Step 2: Lancer** → FAIL.
- [ ] **Step 3: Implémenter** `Repo` et commandes `michel project add <path> --name <n> [--classification c] [--fix-level n] [--test-cmd s] [--install-cmd s]`, `project list`, `project remove <name>`. Chaque commande écrit un événement d'audit `project.add|project.remove` (Target = nom, Evidence = {path, classification, fix_level}).
- [ ] **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(project): register local projects with audited add/list/remove`.

### Task 6: Bases OSV hors ligne (`michel db update|status`)

**Files:**
- Create: `internal/osvdb/osvdb.go`, `internal/osvdb/layout.go`, `internal/cli/db.go`
- Test: `internal/osvdb/osvdb_test.go`

**Interfaces:**
- Consumes: `egress.Gateway.Client("osv.db")`.
- Produces:
  ```go
  const Host = "osv-vulnerabilities.storage.googleapis.com"
  var Ecosystems = []string{"Packagist", "npm"}
  func ZipPath(root, ecosystem string) string // <root>/osv-scalibr/<ecosystem>/all.zip — vérifier contre le chemin attendu par osv-scalibr (localmatcher) dans le module vendorisé, et ajuster la constante si besoin
  type Status struct{ Ecosystem, Path string; Present bool; FetchedAt time.Time; SizeBytes int64 }
  func Statuses(root string) ([]Status, error)
  func Update(ctx, root string, client *http.Client, ecosystems []string, now func() time.Time) ([]Status, error) // GET https://<Host>/<eco>/all.zip → fichier temporaire → rename atomique ; écrit <root>/osv-scalibr/<eco>/fetched_at
  var ErrDatabaseMissing error // "offline database missing for <eco>: run \"michel db update\""
  func Require(root string, ecosystems []string) error // ErrDatabaseMissing nommant le premier absent
  ```

- [ ] **Step 1: Tests qui échouent** — `TestUpdateWritesZipViaGateway` (httptest sert un zip ; allowlist `{Host: "127.0.0.1", Purpose: "osv.db"}` ; `Update` avec `Host` surchargé par une variable de paquet `baseURL` pour le test ; fichier présent, `fetched_at` écrit) ; `TestUpdateDeniedWhenNotAllowlisted` (`errors.Is(err, egress.ErrEgressDenied)`, aucun fichier) ; `TestRequireNamesMissingEcosystem` ; `TestStatusesReportsFetchedAt`.
- [ ] **Step 2: Lancer** → FAIL.
- [ ] **Step 3: Implémenter** + CLI : `michel db update` (en `strict_local`, exige une règle `{Host: osvdb.Host, Purpose: "osv.db"}` dans la politique, sinon message `db update requires network.allow entry {host: osv-vulnerabilities.storage.googleapis.com, purpose: osv.db}` et code 3) ; `michel db status` (table écosystème / présent / date / taille / `STALE` si > 7 jours). Événement d'audit `osv.db.update` avec résultat et tailles.
- [ ] **Step 4: Lancer** → PASS.
- [ ] **Step 5: Commit** `feat(osvdb): offline OSV database download through egress gateway`.

### Task 7: Scan hors ligne et Findings

**Files:**
- Create: `internal/scan/scan.go`, `internal/scan/normalize.go`, `internal/scan/severity.go`, `internal/scan/repo.go`, `internal/cli/scan.go`, `internal/cli/findings.go`
- Test: `internal/scan/normalize_test.go`, `internal/scan/scan_test.go`, `internal/scan/testdata/project-a/composer.lock`, `internal/scan/testdata/project-a/web/package-lock.json`, `internal/scan/testdata/project-b/composer.lock` (JSON invalide), `internal/scan/testdata/osvdb/osv-scalibr/{Packagist,npm}/all.zip` (générés par un helper de test à partir de `testdata/advisories/*.json`)

**Interfaces:**
- Consumes: `project.Project`, `osvdb.Require/ZipPath`, `egress.Gateway.Client("osv.scan")`, `audit.Logger`, `osvscanner.DoScan`.
- Produces:
  ```go
  type Options struct{ OSVRoot string; Exclude []string } // Exclude défaut = contraintes globales
  type Result struct{ ScanID string; Manifests []ManifestResult; New, Still, Gone int; BySeverity map[string]int; Errors []error }
  type ManifestResult struct{ RelPath, Ecosystem, LockSHA256 string; Packages int; Findings int; Err error }
  func Run(ctx, deps Deps, p project.Project, opt Options) (Result, error) // Deps{Store, Audit, Gateway, Now, Version}
  // normalize
  type Finding struct{ ID, ProjectID, ManifestRelPath, Ecosystem, Package, OSVID string; Aliases []string; SeverityLabel string; CVSS float64; InstalledVersion string; FixedVersions []string; DepGroups []string; Summary string }
  func FindingID(projectID, manifestRelPath, ecosystem, pkg, osvID string) string
  func Normalize(projectID, projectRoot string, r models.VulnerabilityResults) ([]Finding, []ManifestResult)
  func SeverityLabel(maxSeverity string) (label string, score float64) // "" → "unknown",0 ; ≥9 critical ; ≥7 high ; ≥4 medium ; >0 low
  func FixedVersions(v *osvschema.Vulnerability, ecosystem, pkg string) []string // événements Fixed des ranges ECOSYSTEM/SEMVER du package concerné, dédupliqués, ordre d'apparition
  ```
- Appel `DoScan` : `ScannerActions{DirectoryPaths: []string{p.Path}, Recursive: true, CompareOffline: true, DownloadDatabases: false, LocalDBPath: opt.OSVRoot, PluginNetworkDisabled: true, ShowAllPackages: true, ExperimentalScannerActions: {ExcludePatterns: opt.Exclude, HTTPClient: gateway.Client("osv.scan")}}`. `ErrVulnerabilitiesFound` et `ErrNoPackagesFound` ne sont pas des échecs de scan. `osvscanner.SetLogger` branché sur `slog`.
- Transitions de statut à chaque scan du projet : finding présent et inconnu → `new` ; présent et déjà `new`/`pending` → `pending` ; présent et `gone` → `pending` (réapparition) ; absent et statut ≠ `gone` → `gone`. `first_seen_*` posés à la création, `last_seen_*` à chaque présence.
- `ManifestRelPath` = `filepath.ToSlash(rel(p.Path, Source.Path))`.
- Événements d'audit : `scan.start` (Target projet), `scan.manifest` par manifeste (Result `ok`|`error`), `scan.finish` (Evidence : compteurs).

- [ ] **Step 1: Tests qui échouent** — normalize : `TestFindingIDStable` (même entrée → même id ; manifeste différent → id différent) ; `TestSeverityLabel` (table : `""`→unknown/0, `"9.8"`→critical, `"7.5"`→high, `"5.3"`→medium, `"2.1"`→low) ; `TestFixedVersions` (advisory fixture avec deux ranges, un pour un autre package → ignoré) ; `TestNormalizeRelPathSlash` ; scan : `TestRunOfflineProducesZeroEgress` (project-a + osvdb fixture, allowlist vide, `len(gateway.Attempts())==0`, 2 manifestes, ≥1 finding par manifeste, `BySeverity` cohérent) ; `TestRunStatusTransitions` (scan 1 → `new` ; scan 2 → `pending` ; remplacer le lockfile par une version corrigée puis scan 3 → `gone` ; remettre l'original, scan 4 → `pending`) ; `TestRunMissingDatabaseFailsBeforeNetwork` (`errors.Is(err, osvdb.ErrDatabaseMissing)`, 0 attempts, aucun `scan` en base) ; `TestRunContinuesOnCorruptManifest` (project-b + project-a copié : résultat avec `Errors` non vide, l'autre manifeste scanné, `scan.status=="partial"`).
- [ ] **Step 2: Générer les fixtures** : helper `testdata/gen_osvdb_test.go` (tag `//go:build ignore` ou `TestMain`) qui zippe `advisories/*.json` en `all.zip` (une entrée `<id>.json` par advisory, format OSV : `id`, `summary`, `severity:[{type:"CVSS_V3", score:"CVSS:3.1/..."}]`, `affected:[{package:{ecosystem,name}, ranges:[{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"X"}]}]}]`). Vérifier le format d'entrée attendu par le localmatcher d'osv-scalibr dans le module vendorisé avant de figer. Lockfiles minimaux : `composer.lock` avec un paquet `acme/vuln` 1.0.0 et un sain ; `package-lock.json` v3 avec `node_modules/vuln-pkg` 1.0.0.
- [ ] **Step 3: Lancer** `go test ./internal/scan/ -v` → FAIL.
- [ ] **Step 4: Implémenter** `normalize.go`, `severity.go`, `repo.go` (upsert findings, transitions, `ListFindings(ctx, projectID, status string) ([]Finding, error)`), `scan.go`, CLI : `michel scan [--project name] [--all] [--osv-db path]` (table par projet : `project  manifests  packages  findings  critical/high/medium/low/unknown  new/gone` ; code 1 si `Errors` non vide, 0 sinon) et `michel findings --project name [--status s] [--severity s]` (table `severity  package  installed  fixed  osv_id  manifest  status`). `--json` sort la structure complète.
- [ ] **Step 5: Lancer** → PASS.
- [ ] **Step 6: Commit** `feat(scan): offline osv-scalibr scan with stable per-manifest findings and status transitions`.

### Task 8: Premier scan réel sur the reference project et documentation d'installation

**Files:**
- Create: `docs/operations/offline-installation.md`, `docs/security/network-egress.md`
- Modify: `README.md`

- [ ] **Step 1: Construire** `go build -o bin/michel.exe ./cmd/michel` (Windows) ; `bin/michel version`.
- [ ] **Step 2: Config de test** dans `%AppData%\michel\config.yaml` : défauts + `network.allow: [{host: osv-vulnerabilities.storage.googleapis.com, purpose: osv.db}]`, `db.osv_path: <osv-db-root>` (réutilise les zips déjà téléchargés ; vérifier via `michel db status` qu'ils sont vus, sinon `michel db update`).
- [ ] **Step 3: Enregistrer the reference project** : `michel project add <path to the reference project> --name demo --classification health`.
- [ ] **Step 4: Scanner** : `michel scan --project demo`. Attendu : ≥ 6 manifestes (sans ceux sous `vendor/`), un total de findings du même ordre que le rapport osv-scanner du 2026-10-22 (233 vulnérabilités sur 65 paquets, lockfiles vendor inclus ; l'écart doit s'expliquer par l'exclusion `vendor/`). Noter les chiffres réels dans le ledger. `michel audit verify` → 0. `michel audit list --last 20` ne montre **aucun** `egress.attempt`.
- [ ] **Step 5: Écrire** `docs/operations/offline-installation.md` (build, config, `db update` depuis une machine connectée, copie du dossier OSV vers une machine isolée, `scan`) et `docs/security/network-egress.md` (liste exhaustive des destinations et purposes de ce plan : `osv.db` vers `osv-vulnerabilities.storage.googleapis.com` uniquement ; `osv.scan` jamais utilisé en pratique, présent pour que toute requête inattendue d'osv-scalibr soit refusée et journalisée ; ce qui est testé vs déclaré). README : section « Quick start ».
- [ ] **Step 6: Commit** `docs: offline installation and network egress inventory for plan 1` ; ledger `docs/superpowers/sdd/2026-10-22-michel-socle/progress.md` avec les chiffres du scan the reference project.

---

## Self-review (fait le 2026-10-22)

- Couverture : design § 4.9 (strict_local, egress, audit chaîné, bases OSV opt-in) → Tasks 2, 3, 4, 6 ; § 4.3 Project/Scan/Finding → Tasks 4, 5, 7 ; § 4.10 étapes 1-2 → Tasks 1-8. Checkpoints Ed25519 signés, masquage des secrets, proxy local pour sous-processus : **hors plan 1** (plans remédiation et audit avancé), déclarés tels dans `network-egress.md`.
- Types : `policy.Policy` (T2) consommé par T3, T4, T5 ; `egress.Sink` (T3) implémenté par `audit.Logger.EgressSink` (T4) ; `osvdb.ErrDatabaseMissing` (T6) renvoyé par `scan.Run` (T7) ; `scan.Finding` lu par `findings` CLI (T7).
- Review Focus : 1 → T2 `TestLoadMissingFileReturnsDefaults` ; 2 → T7 `TestRunMissingDatabaseFailsBeforeNetwork` ; 3 → T7 `TestRunContinuesOnCorruptManifest` ; 4 → T5 `TestProjectAddDeniedIsAudited` ; 5 → T4 `TestVerifyDetectsTamperedEvent`.
- Points à vérifier par l'implémenteur dans le module vendorisé (deux endroits marqués) : disposition exacte `osv-scalibr/<eco>/all.zip` et format des entrées du zip.
