# Michel — Plan 4 : registre des sources

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Donner à l'utilisateur un registre unique de ses sources (bases OSV, enrichissements KEV/EPSS/CVE, veille « À lire », plugins, skills, serveurs MCP), géré depuis `michel source …` et la page « Sources », mis à jour chaque matin avant le scan, avec « exploitée activement » en tête du digest, et lire `yarn.lock` / `pnpm-lock.yaml`.

**Architecture:** Six paquets Go nouveaux : `internal/source` (registre, catalogue embarqué, accord, états), `internal/enrich` (KEV, EPSS, CVE à la demande, application aux findings), `internal/feed` (RSS/Atom, avis GitHub, page, technologies), `internal/gitrepo` (archives GitHub épinglées, aperçu, installation des skills, relevé, découverte), `internal/plugin` (interface `Provider`, lecteurs SARIF et Trivy JSON, Trivy/Semgrep à argv fermé, proxy de refus), `internal/sourceupdate` (orchestration quotidienne). Une migration `0005`, un écrivain de règle `network.allow` dans `internal/policy`, `Gateway.SetRules`, des colonnes dénormalisées sur `finding`, une page « Sources » dans `web/`.

**Tech Stack:** Go 1.27.3 ; stdlib (`encoding/xml`, `compress/gzip`, `archive/tar`, `encoding/csv`, `net/http` serveur pour le proxy de refus) ; `gopkg.in/yaml.v3` (catalogue, règle, lockfiles YAML) ; osv-scalibr déjà dans le graphe (`javascript/yarnlock`, `javascript/pnpmlock`) ; SQLite via `internal/store` ; Vue 3.5 + Vuetify 4.3, Options API, Vitest 5.

**Spec:** `docs/superpowers/specs/2026-10-26-michel-plan4-sources-design.md` (§ 3 registre, § 4 OSV et lockfiles, § 5 enrichissements, § 6 veille, § 7 plugins/skills/MCP, § 8 mise à jour et digest, § 9 sécurité, § 10 API et page, § 11 migration, § 13 arbitrages) ; catalogue `docs/superpowers/specs/2026-10-23-michel-sources-catalog.md` ; design v1 § 4.9, § 4.11 ; politique `docs/security/sovereignty-policy.md`.

## Global Constraints

- Module `github.com/kvarot/michel` ; code, identifiants, commits, aide Cobra en anglais ; messages imprimés via `internal/i18n` (EN référence, FR à la main, **tutoiement**, garde `tutoiement_test.go`) ; `testing` standard ; Windows et Linux bloquants ; Conventional Commits avec le trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Branche `feat/sources` créée depuis `main` au début de la Task 1, en place (ruling : rien d'autre en cours dans ce dépôt). Chaque tâche finit par `go test ./...` vert et un commit. `go` est dans `%LOCALAPPDATA%\Programs\go\bin` ; `git fetch/push` avec `-c http.sslBackend=schannel`.
- **Aucune trace des projets privés** : fixtures `demo`, `acme/lib`, `vuln-pkg`, dépôts `example/skill`, `example/mcp` ; `go test ./internal/hygiene/` vert ; ledger en agrégats seulement.
- **Jamais d'écriture sous `project.path`** (test `treeDigest` avant/après pour `scan`, `source run`, `analyze`) ; écritures hors dossier de données limitées au fichier de politique (règle `allow`, avec `.bak`) et à `~/.claude/skills/<nom>/` avec marqueur `.michel-source`.
- **SQL portable PostgreSQL** : pas de `rowid`, `AUTOINCREMENT`, `datetime()` ; `?`, `ON CONFLICT (…) DO UPDATE` ; `INTEGER` 0/1 ; `REAL` ; dates `TEXT` RFC 3339 UTC.
- **Tout réseau par `internal/egress`** : `Gateway.Client(purpose)` seulement ; `boundary_test.go` couvre les nouveaux paquets ; purposes `osv.db`, `source.enrich`, `source.feed`, `source.repo`, `source.discover`, `plugin.<key>` (jamais autorisé).
- **Données venues des sources = données non fiables** : `scan.SanitizeText`, bornes (KEV 50 Mo, EPSS 200 Mo décompressé, flux 5 Mo et 200 items, réponse à la demande 5 Mo, archive 50 Mo compressée / 200 Mo extraite / 5 000 fichiers), extraction sans traversée ni lien symbolique ni bit exécutable, jamais exécutées ni importées.
- **Minimisation** : canaux et API sans chemin absolu, commande, secret ni URL de rapport local ; requêtes GitHub portent seulement `owner/repo` ; enrichissements à la demande n'envoient que des identifiants CVE et sont désactivés par défaut.
- Secrets `github-token`, `nvd-api-key` par `michel secret set` ; jamais en argument, audit, erreur ou `--json`.
- Front : Options API, JS + JSDoc, textes dans `web/src/i18n/{fr,en}.json`, fetch seulement sur `/api/v1`.
- Relecture FR : toute tâche qui crée ou modifie un texte FR dispatche le relecteur francophone non spécialiste (consigne du plan 3 : « si une phrase demande une explication orale, propose une réécriture ») **avant** la revue de code et applique ses retours.

## Review Focus

1. Activer `enrich.kev` depuis la page alors que `config.yaml` n'existe pas : Michel crée un fichier minimal avec la seule règle, recharge, la passerelle de `serve` accepte la destination sans redémarrage, et l'audit porte `source.consent`. Test : Task 1 `TestEnableCreatesPolicyFileWhenAbsent`, `TestGatewaySetRulesTakesEffect`.
2. KEV ajoutée sur une faille `decided ignore` entre deux scans (par `source update`, pas par un scan) : décision `superseded(kev_changed)`, faille `pending`, digest « à revoir » **et** tête « exploitées activement ». Test : Task 3 `TestApplySupersedesIgnoreWhenKEVAppears`, `TestDigestHeadListsPendingKEV`.
3. Flux RSS hostile (10 Mo, 5 000 items, titres avec contrôle et HTML) : lecture tronquée à 5 Mo, 200 items, texte assaini, rien ne casse le digest ni la page. Test : Task 6 `TestRSSReaderCapsAndSanitizes`.
4. Archive de skill avec `../etc/x`, lien symbolique et fichier exécutable : extraction refusée pour les deux premiers, bit exécutable retiré, rien n'est écrit dans `~/.claude/skills`. Test : Task 7 `TestExtractRefusesTraversalAndSymlinks`, `TestInstallWritesNothingOnBadArchive`.
5. `source run plugin.trivy` avec un faux `trivy` qui tente `https://ghcr.io` et écrit dans le projet : la requête est refusée par le proxy et journalisée `plugin.trivy denied`, le test échoue si l'arbre du projet a changé (le faux outil écrit via `$TRIVY_OUT` seulement). Test : Task 8 `TestPluginRunDeniesEgressAndNeverWritesInProject`.

---

### Task 1: Migration `0005`, registre `internal/source`, accord et règle `allow`, `Gateway.SetRules`, `michel source` (gestion) et `michel tech`

**Files:**
- Create: `internal/store/migrations/0005_sources.sql`, `internal/source/source.go` (modèle, états), `internal/source/repo.go`, `internal/source/catalog.go` + `internal/source/catalog/catalog.yaml`, `internal/source/consent.go`, `internal/source/tech.go`, `internal/policy/write.go`, `internal/cli/source.go`, `internal/cli/tech.go`
- Modify: `internal/egress/gateway.go` (`SetRules`), `internal/policy/policy.go` (purposes), `internal/project/project.go` + `repo.go` (`Tech`, `TechAuto`), `internal/cli/project.go` (`--tech`), `internal/cli/root.go` (`AddCommand`, `source.Sync` après l'ouverture du store), `internal/i18n/catalog/{en,fr}.json`, `internal/i18n/keys_test.go` (`source.note.`, `source.state.`, `source.kind.` en `dynamicPrefixes`), `config.example.yaml` (commentaire sur les règles écrites par `source enable`)
- Test: `internal/store/store_test.go`, `internal/source/*_test.go`, `internal/policy/write_test.go`, `internal/egress/gateway_test.go`, `internal/cli/source_test.go`, `internal/cli/tech_test.go`, `internal/project/repo_test.go`

**Interfaces:**
- Produces:
  ```go
  // source
  type Kind string // KindOSV "osv", KindEnrichment "enrichment", KindFeed "feed", KindPlugin "plugin", KindSkill "skill", KindMCP "mcp", KindReference "reference"
  type Origin string // OriginCatalog "catalog", OriginUser "user"
  type State string  // StateOff "off", StateWaitingConsent "waiting_consent", StateOn "on", StateHidden "hidden"
  type Entry struct {
      ID, Key string; Kind Kind; Origin Origin; Name, URL string; Hosts []string; Purpose string
      Enabled, Hidden bool; Config Config; Tech []string; CatalogVersion int
      LastReadAt time.Time; LastReadResult, LastReadError string; LastReadItems int; LastReadETag string
      Status map[string]any; CreatedAt, UpdatedAt time.Time
  }
  type Config struct{ Catalog, User map[string]any } // Merged() map[string]any : User gagne ; Str(key) string ; Bool(key) bool ; List(key) []string
  func (e Entry) State(allowed func(host, purpose string) bool) State
  func ValidKey(k string) bool // ^(osv|enrich|feed|plugin|skill|mcp|ref|discover)\.[a-z0-9][a-z0-9-]{0,63}$
  func KeyFor(kind Kind, name string) string // préfixe + slug
  type Repo struct{ s *store.Store }
  func NewRepo(s *store.Store) *Repo
  func (r *Repo) List(ctx, kind Kind, includeHidden bool) ([]Entry, error)
  func (r *Repo) Get(ctx, key string) (Entry, error)            // ErrNotFound
  func (r *Repo) Upsert(ctx, e Entry) (Entry, error)             // ON CONFLICT (key) DO UPDATE
  func (r *Repo) SetEnabled(ctx, key string, on bool) error
  func (r *Repo) SetHidden(ctx, key string, hidden bool) error
  func (r *Repo) Delete(ctx, key string) error                    // user only: ErrCatalogEntry
  func (r *Repo) RecordRead(ctx, key string, at time.Time, result, errText string, items int, etag string) error
  func (r *Repo) SetStatus(ctx, key string, st map[string]any) error
  func (r *Repo) SetUserConfig(ctx, key string, user map[string]any) error
  // catalog
  const CatalogVersion = 1
  func Catalog() ([]Entry, []TechRule, error)                     // parse du YAML embarqué (cache)
  type TechRule struct{ Ecosystem, Package, Prefix, Tag string }  // Package exact ou Prefix ("symfony/")
  func Sync(ctx, r *Repo) (inserted, updated int, err error)      // § 3.2, ne touche ni enabled ni hidden ni tech ni Config.User
  func Reset(ctx, r *Repo, key string, all, purgeUser bool) (int, error)
  // consent
  type ConsentText struct{ Key, Host, Purpose string; What string } // What = clé i18n source.consent.<kind> rendue par l'appelant
  func ConsentNeeded(e Entry, allowed func(host, purpose string) bool) []ConsentText // vide si tous les couples sont déjà autorisés
  func Enable(ctx, deps Deps, key string, consent bool) (Entry, []ConsentText, error) // consent=false et besoin ⇒ ErrConsentRequired avec les textes ; sinon écrit la règle (policy.AddAllowRule), recharge (deps.Reload), audit source.consent, SetEnabled
  func Disable(ctx, deps Deps, key string, forget bool) error    // forget ⇒ RemoveAllowRule sauf si une autre entrée enabled partage le couple : ErrRuleShared{Key}
  type Deps struct{ Repo *Repo; Audit *audit.Logger; Gateway *egress.Gateway; PolicyPath string; Reload func() (policy.Policy, error); Now func() time.Time; Actor string }
  // tech
  func ListTech(ctx, s *store.Store) ([]string, error); func AddTech(ctx, s, tag string) error; func RemoveTech(ctx, s, tag string) error // tag ^[a-z0-9][a-z0-9.+-]{0,31}$
  func DeclaredTech(ctx, s *store.Store, p project.Project) []string // union project.Tech, project.TechAuto, globales ; trié, unique
  // policy
  func AddAllowRule(path string, r AllowRule) (added bool, err error)    // yaml.v3 nœuds, .bak, écriture atomique, crée le fichier minimal si absent ; added=false si déjà présente
  func RemoveAllowRule(path string, r AllowRule) (removed bool, err error)
  const PurposeEnrich = "source.enrich"; PurposeFeed = "source.feed"; PurposeRepo = "source.repo"; PurposeDiscover = "source.discover"; PurposeOSV = "osv.db"
  // egress
  func (g *Gateway) SetRules(rules []policy.AllowRule) // sous mutex ; Allowed lit sous le même mutex
  // project
  Project.Tech, Project.TechAuto []string `json:"tech"`, `json:"tech_auto"` (normalizeExtras : trié, unique, tag valide sinon ErrInvalidTech)
  ```
- Migration SQL exacte :
  ```sql
  CREATE TABLE source (
      id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, origin TEXT NOT NULL,
      name TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', hosts TEXT NOT NULL DEFAULT '[]', purpose TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0,
      config_catalog TEXT NOT NULL DEFAULT '{}', config_user TEXT NOT NULL DEFAULT '{}', tech TEXT NOT NULL DEFAULT '[]',
      catalog_version INTEGER NOT NULL DEFAULT 0,
      last_read_at TEXT NOT NULL DEFAULT '', last_read_result TEXT NOT NULL DEFAULT '', last_read_error TEXT NOT NULL DEFAULT '',
      last_read_items INTEGER NOT NULL DEFAULT 0, last_read_etag TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX idx_source_kind ON source(kind);
  CREATE TABLE tech (tag TEXT PRIMARY KEY, created_at TEXT NOT NULL);
  CREATE TABLE feed_item (
      id TEXT PRIMARY KEY, source_id TEXT NOT NULL, guid TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL DEFAULT '',
      published_at TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', tech TEXT NOT NULL DEFAULT '[]',
      seen_at TEXT NOT NULL, read_at TEXT NOT NULL DEFAULT '', UNIQUE (source_id, guid)
  );
  CREATE INDEX idx_feed_item_source ON feed_item(source_id, published_at);
  CREATE TABLE kev (cve TEXT PRIMARY KEY, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
      date_added TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '', ransomware TEXT NOT NULL DEFAULT '', notes_url TEXT NOT NULL DEFAULT '');
  CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL NOT NULL DEFAULT 0, percentile REAL NOT NULL DEFAULT 0, model_date TEXT NOT NULL DEFAULT '');
  CREATE TABLE cve_enrichment (cve TEXT PRIMARY KEY, cvss_score REAL NOT NULL DEFAULT 0, cvss_vector TEXT NOT NULL DEFAULT '',
      cvss_source TEXT NOT NULL DEFAULT '', ssvc_exploitation TEXT NOT NULL DEFAULT '', ssvc_automatable TEXT NOT NULL DEFAULT '',
      ssvc_technical_impact TEXT NOT NULL DEFAULT '', cwe TEXT NOT NULL DEFAULT '[]', fetched_at TEXT NOT NULL, source_key TEXT NOT NULL);
  CREATE TABLE plugin_run (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, project_id TEXT NOT NULL, started_at TEXT NOT NULL,
      finished_at TEXT NOT NULL DEFAULT '', tool_version TEXT NOT NULL DEFAULT '', report_path TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', findings INTEGER NOT NULL DEFAULT 0, log TEXT NOT NULL DEFAULT '');
  CREATE INDEX idx_plugin_run_project ON plugin_run(project_id, started_at);
  CREATE TABLE discovery (repo TEXT PRIMARY KEY, topic TEXT NOT NULL, stars INTEGER NOT NULL DEFAULT 0, description TEXT NOT NULL DEFAULT '',
      html_url TEXT NOT NULL DEFAULT '', first_seen_at TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new');
  ALTER TABLE finding ADD COLUMN kind TEXT NOT NULL DEFAULT 'dependency';
  ALTER TABLE finding ADD COLUMN source_key TEXT NOT NULL DEFAULT '';
  ALTER TABLE finding ADD COLUMN rule_id TEXT NOT NULL DEFAULT '';
  ALTER TABLE finding ADD COLUMN location TEXT NOT NULL DEFAULT '';
  ALTER TABLE finding ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
  ALTER TABLE finding ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE finding ADD COLUMN kev_added TEXT NOT NULL DEFAULT '';
  ALTER TABLE finding ADD COLUMN epss REAL NOT NULL DEFAULT 0;
  ALTER TABLE finding ADD COLUMN epss_percentile REAL NOT NULL DEFAULT 0;
  ALTER TABLE finding ADD COLUMN malicious INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE finding ADD COLUMN cvss_enriched REAL NOT NULL DEFAULT 0;
  CREATE INDEX idx_finding_kind ON finding(kind);
  CREATE INDEX idx_finding_kev ON finding(kev);
  ALTER TABLE decision ADD COLUMN seen_kev INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE project ADD COLUMN tech TEXT NOT NULL DEFAULT '[]';
  ALTER TABLE project ADD COLUMN tech_auto TEXT NOT NULL DEFAULT '[]';
  ```
- Catalogue `catalog.yaml` : `version: 1`, `entries:` (toutes les sources des § 4.1, § 5.1, § 6, § 7.3, § 7.4 du design et les références de sorte 4 du catalogue du 23/10, chacune avec `key`, `kind`, `name`, `url`, `hosts`, `purpose`, `enabled` (vrai pour `osv.packagist`, `osv.npm` seulement), `config`, `tech`, `note` = clé i18n), `tech_rules:` (liste du § 14). Les `hosts` des entrées `osv` valent `[osv-vulnerabilities.storage.googleapis.com]` avec purpose `osv.db`. Pour `skill` et `mcp` : `repo`, `path`, `pinned` (sha de tête relevé par le builder le jour de la tâche, en ouvrant le dépôt), `license`, `launch` (MCP) ; `license: unknown` si introuvable.
- CLI : `michel source list [--kind] [--all] [--json]`, `show <key>`, `enable <key> [--yes]` (sans `--yes` et besoin d'accord : affiche le texte, lit `y`/`N` sur stdin ; non-TTY sans `--yes` ⇒ refus avec le texte), `disable <key> [--forget]`, `add --kind … ` (validations : `feed` exige `--url https://` ou `--repo` avec `--format github_advisories` ; `osv` exige `--ecosystem` ; `plugin` exige `--format` ; `skill`/`mcp` exigent `--repo owner/name` et `--pin <sha 40 hex>`), `remove <key>` (skill installé ⇒ délègue à Task 7 `gitrepo.Uninstall`, en Task 1 : refus `ErrInstalled` si `config.installed_sha` non vide), `reset [<key>|--all [--purge-user]]`. `michel tech list|add|remove`. `michel project add|set --tech` (sémantique de remplacement comme `--exclude`). Audit : `source.enable`, `source.disable`, `source.consent`, `source.add`, `source.remove`, `source.reset`, `tech.set`, chacun avec `key` ou `tag`, jamais de contenu.

- [ ] **Step 1: Tests qui échouent** — store : `TestMigration0005Applies` (tables et colonnes présentes ; le SQL ne contient ni `rowid`, ni `AUTOINCREMENT`, ni `datetime(`). source : `TestCatalogParsesAndKeysAreValid` (chaque entrée : `ValidKey`, `kind` connu, `hosts` non vide ⇔ `purpose` non vide, `enabled` vrai pour exactement `osv.packagist` et `osv.npm`, `note` existe dans les deux catalogues i18n), `TestSyncInsertsThenKeepsUserChoices` (Sync, `SetEnabled("enrich.kev", true)`, `SetHidden("feed.nginx", true)`, re-Sync avec `name` modifié ⇒ nom mis à jour, `enabled`/`hidden` conservés), `TestStateWaitingConsentWithoutRule` (`enabled`, aucune règle ⇒ `waiting_consent` ; règle ⇒ `on` ; plugin sans hôte ⇒ `on`), `TestUpsertUserEntryAndDeleteCatalogRefused`, `TestResetRestoresCatalogAndKeepsUser`, `TestEnableWritesRuleRecordsConsentAndReloads` (politique dans un `t.TempDir()`, `Enable(consent=false)` ⇒ `ErrConsentRequired` avec un `ConsentText{Host:"www.cisa.gov", Purpose:"source.enrich"}` ; `Enable(consent=true)` ⇒ fichier contient la règle, `.bak` existe, audit `source.consent`, entrée `on`), `TestEnableCreatesPolicyFileWhenAbsent` (chemin inexistant ⇒ fichier créé, `policy.Load` + `Validate` passent, seules les clés `sovereignty.network.allow` y figurent), `TestEnableSharedRuleAsksNothing` (`osv.npm` activé après `osv.packagist` ⇒ `ConsentNeeded` vide, `source.consent` quand même écrit), `TestDisableForgetRefusedWhenShared` (`ErrRuleShared{Key:"osv.packagist"}`), `TestDeclaredTechMergesThreeOrigins`. policy : `TestAddAllowRuleKeepsCommentsAndOrder` (fichier avec commentaires et `risk:` ⇒ après ajout, commentaires présents, `allow` a une ligne de plus, `Validate` passe ; second ajout identique ⇒ `added=false`, fichier inchangé byte à byte), `TestAddAllowRuleRestoresOnInvalid` (fichier dont la relecture échoue ⇒ erreur, contenu d'origine conservé). egress : `TestGatewaySetRulesTakesEffect` (`Allowed` faux puis vrai après `SetRules`, sous `-race` avec un `Allowed` concurrent). project : `TestTechRoundTrip` (`["b","a","a"]` ⇒ `["a","b"]` ; `"Nginx!"` ⇒ `ErrInvalidTech`). cli : `TestSourceListShowsStateAndKind`, `TestSourceEnableNeedsYesWhenNotTTY` (exit code policy, texte d'accord sur stderr), `TestSourceEnableYesWritesRule`, `TestSourceAddFeedValidatesURL`, `TestSourceRemoveUserDeletesCatalogHides`, `TestTechAddListRemove`, `TestProjectSetTech`.
- [ ] **Step 2: Lancer** `go test ./internal/store/ ./internal/source/ ./internal/policy/ ./internal/egress/ ./internal/project/ ./internal/cli/ -run 'Migration0005|Catalog|Sync|State|Upsert|Reset|Enable|Disable|DeclaredTech|AddAllowRule|SetRules|TechRoundTrip|Source|Tech' -v` → FAIL (paquets absents).
- [ ] **Step 3: Implémenter** la migration, `internal/source` (fichiers listés), `policy/write.go` (lecture en `yaml.Node`, recherche ou création des nœuds `sovereignty` → `network` → `allow`, ajout d'un `MappingNode` `{host, purpose}`, `os.WriteFile` d'un `.tmp` puis `os.Rename` ; copie `.bak` avant), `Gateway.SetRules`, `Project.Tech/TechAuto` (colonnes `tech`, `tech_auto` dans `cols`, `insert`, `scan`, `Update`), `cli/source.go`, `cli/tech.go`, `--tech`, `source.Sync` dans `PersistentPreRunE` après `store.Open` (hors commandes `audit` et `version`), clés i18n EN/FR (`cli.source.*`, `source.kind.*`, `source.state.*`, `source.consent.*`, `source.note.*`).
- [ ] **Step 4: Relecture FR** du `fr.json` (clés `cli.source.*`, `source.consent.*`, `source.note.*`) par le relecteur francophone ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(source,policy,egress): sources registry, embedded catalog, consent with allow-rule writing, michel source and tech`.

### Task 2: Écosystèmes OSV dynamiques, `yarn.lock` et `pnpm-lock.yaml`, statut `empty`, drapeau `malicious`

**Files:**
- Create: `internal/analyze/deps_yarn.go`, `internal/analyze/deps_pnpm.go`, `internal/analyze/testdata/yarn-v1/`, `internal/analyze/testdata/yarn-berry/`, `internal/analyze/testdata/pnpm-v9/` (chaque dossier : lockfile + `package.json` avec `acme-direct` direct et `vuln-pkg` transitif via `acme-direct`)
- Modify: `internal/osvdb/layout.go` (`Ecosystems` supprimé au profit de `Enabled`), `internal/osvdb/osvdb.go` (`Statuses(root, ecosystems)`), `internal/scan/scan.go` (`lockfiles`, `scanPlugins`, `checkContent`, `ErrNoManifests`, `Require` ciblé, `ScanEmpty`, écosystème désactivé), `internal/scan/normalize.go` (`Finding.Malicious`, `Kind` par défaut), `internal/scan/repo.go` (colonnes `malicious`, `kind` à l'insertion et à la lecture), `internal/analyze/deps.go` (`LoadDepGraph(manifestDir, ecosystem, lockfileName)`), `internal/analyze/analyze.go` (passe `filepath.Base(f.ManifestRelPath)`), `internal/cli/db.go` (`Enabled`), `internal/cli/scan.go` (`empty` : exit 0 en `--all`, message `cli.scan.empty`), `internal/digest/digest.go` (`EmptyProjects`, `FailedScans` exclut `empty`, règle hebdomadaire), `internal/digest/templates/*/{text,html}.tmpl`, `internal/i18n/templates/*/what.tmpl` (variante `Malicious`), `internal/explain/explain.go` (`Facts.Malicious`), `internal/api/handlers.go` (`meta` : statuts des écosystèmes activés), i18n EN/FR
- Test: `internal/osvdb/osvdb_test.go`, `internal/scan/scan_test.go`, `internal/analyze/deps_test.go`, `internal/cli/scan_test.go`, `internal/digest/digest_test.go`, `internal/explain/explain_test.go`

**Interfaces:**
- Consumes: `source.Repo.List(ctx, source.KindOSV, false)`, `Entry.State`, `Entry.Config.Str("ecosystem")`.
- Produces:
  ```go
  // osvdb
  func Enabled(ctx context.Context, r *source.Repo, allowed func(host, purpose string) bool) ([]string, error) // écosystèmes des entrées osv à l'état on ; waiting_consent compte aussi (la règle manque, l'erreur du téléchargement le dira)
  func Statuses(root string, ecosystems []string) ([]Status, error)
  // scan
  var lockfiles = map[string]string{"composer.lock": "Packagist", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm"}
  var scanPlugins = []string{"php/composerlock", "javascript/packagelockjson", "javascript/yarnlock", "javascript/pnpmlock"}
  var ErrNoManifests = errors.New("no composer.lock, package-lock.json, yarn.lock or pnpm-lock.yaml found")
  const ScanEmpty = "empty"
  var ErrEcosystemDisabled = errors.New("ecosystem disabled") // ManifestResult.Err = fmt.Errorf("%w: enable osv.<slug>", …)
  Options.Ecosystems []string // écosystèmes activés ; nil = tous ceux des lockfiles trouvés (tests)
  Finding.Kind string `json:"kind"`; Finding.Malicious bool `json:"malicious"` // Normalize : Kind "dependency", Malicious = strings.HasPrefix(OSVID, "MAL-") ; gravité forcée "critical" si Malicious
  // analyze
  func LoadDepGraph(manifestDir, ecosystem, lockfileName string) (*DepGraph, error) // "yarn.lock" ⇒ loadYarn, "pnpm-lock.yaml" ⇒ loadPnpm
  // digest
  Digest.EmptyProjects int `json:"empty_projects"`; Digest.ShowEmpty bool `json:"show_empty"` // vrai si Since > 7 jours ou si le nombre diffère du dernier digest_run.summary["empty_projects"]
  // explain
  Facts.Malicious bool `json:"malicious"`
  ```
- Règles : `scan.Run` calcule `needed` = écosystèmes des lockfiles trouvés ; `osvdb.Require(root, needed ∩ opt.Ecosystems)` ; un lockfile dont l'écosystème ∉ `opt.Ecosystems` reçoit `ErrEcosystemDisabled` et est exclu de `DoScan` (`ExcludePatterns` + filtre), statut `partial`. Zéro lockfile ⇒ `UPDATE scan SET status='empty'`, `scan.finish result=empty evidence.reason=no_manifests`, retour `(Result{Status: ScanEmpty}, nil)` : plus d'erreur ; `cli/scan.go` imprime `cli.scan.empty` sur stdout, exit 1 seulement en `--project`. `checkContent(name, b)` : yarn v1 = première ligne non vide commence par `# THIS IS AN AUTOGENERATED FILE` ou contient `yarn lockfile v1` ⇒ vide si aucune ligne `^[^#\s].*:$` ; yarn berry et pnpm = YAML (`yaml.v3` en `map[string]any`) ⇒ berry : clé `__metadata`, vide si aucune autre clé ; pnpm : `lockfileVersion` présent, vide si `packages` et `importers` sans entrée ; sinon `unreadable`.
- Yarn v1 : blocs `"name@range", "name@range2":` puis `  version "x"` et `  dependencies:` indentées ; berry : `"name@npm:range":` → `version: x`, `dependencies:` map. pnpm v6/v9 : `importers['.'].dependencies[name].version` (racine, directes) ; `packages` clés `/name@version` (v6) ou `name@version` (v9) avec `dependencies` ; `snapshots` (v9) porte les `dependencies`. Racine directe = `package.json` (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`), sinon `importers` pnpm. Échec de parse ⇒ `(nil, err)` et `AnalyzeWith` note `lockfile format not understood` (chemin déjà existant pour `loadErr`).

- [ ] **Step 1: Tests qui échouent** — osvdb : `TestEnabledFollowsSourceEntries` (Packagist et npm par défaut ; `SetEnabled("osv.pypi", true)` ⇒ `PyPI` ajouté ; `SetEnabled("osv.npm", false)` ⇒ retiré). scan : `TestFindLockfilesSeesYarnAndPnpm`, `TestCheckContentYarnV1EmptyAndUnreadable`, `TestCheckContentPnpmAndBerry`, `TestRunScansYarnLockOffline` (fixture `demo-yarn` avec `yarn.lock` v1 contenant `vuln-pkg@1.0.0` et la base de test npm du `TestMain` ⇒ 1 finding, `ManifestRelPath == "yarn.lock"`), `TestRunScansPnpmLockOffline`, `TestRunEmptyIsNotAnError` (remplace `TestRunNoManifestsKeepsFindingsAndFails` : `Status == ScanEmpty`, `err == nil`, findings intacts, ligne `scan.status='empty'`), `TestRunDisabledEcosystemIsPartial` (`Options.Ecosystems = ["npm"]` sur un projet Composer + npm ⇒ `partial`, manifest `composer.lock` avec `ErrEcosystemDisabled`, findings Composer existants **non** passés `gone` : `unread` les protège), `TestNormalizeFlagsMaliciousAsCritical` (`MAL-2024-0001` ⇒ `Malicious`, `SeverityLabel == "critical"`). analyze : `TestYarnV1DirectAndTransitive`, `TestYarnBerryDirectAndTransitive`, `TestPnpmV9DirectAndTransitive` (mêmes assertions que `TestNpmDirectAndTransitive` : `acme-direct` `Direct`, `vuln-pkg` `Transitive` via `acme-direct`), `TestYarnGarbageIsError`. cli : `TestScanAllEmptyProjectExitZero` (dossier vide + projet valide ⇒ exit 0, stdout contient la phrase `cli.scan.empty`), `TestScanProjectEmptyExitOne`. digest : `TestDigestCountsEmptyApartFromFailed` (un `empty`, un `failed` ⇒ `FailedScans == 1`, `EmptyProjects == 1`, `ShowEmpty` vrai au premier digest, faux au second avec même compte dans la fenêtre d'une semaine). explain : `TestWhatSentenceForMaliciousPackage` (FR contient « paquet malveillant », EN « malicious package »).
- [ ] **Step 2: Lancer** les tests ciblés → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés). `digest.Compute` lit `summary["empty_projects"]` du dernier run (`Repo.Last`) pour `ShowEmpty`. Gabarit *what* : `{{if .Malicious}}` phrase dédiée, le reste inchangé (les phrases épinglées du plan 2 ne bougent pas : `plan2_golden_test.go` reste vert).
- [ ] **Step 4: Relecture FR** (`what.tmpl` FR, `cli.scan.empty`, phrase `digest.empty_projects`) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(scan,analyze,osvdb): yarn and pnpm lockfiles, enabled OSV ecosystems from the registry, empty scans, malicious packages`.

### Task 3: KEV et EPSS — lecteurs, application aux findings, gravité effective, `kev_changed`, digest, explication, risque

**Files:**
- Create: `internal/enrich/enrich.go` (types, `Apply`), `internal/enrich/kev.go`, `internal/enrich/epss.go`, `internal/enrich/repo.go`, `internal/enrich/testdata/kev.json`, `internal/enrich/testdata/epss.csv.gz`
- Modify: `internal/scan/normalize.go` + `repo.go` (`Finding.KEV`, `KEVAdded`, `EPSS`, `EPSSPercentile`, `CVSSEnriched` ; `EffectiveSeverity` ; `applyScan` remplit `kev`/`epss`/`malicious` via une `Lookup` passée en paramètre ; `seen_kev` dans `currentDecisions` et la supersession `ReasonKEVChanged`), `internal/decide/decide.go` + `repo.go` (`KEVChanged`, `SeenKEV`, `Set` écrit `seen_kev`), `internal/analyze/risk.go` (`RiskInput.Exploited`, `Terms["exploited"]`, `Risk.Urgency`), `internal/analyze/analyze.go` (`Exploited` depuis le finding), `internal/explain/explain.go` (`Facts.KEV`, `KEVAdded`, `EPSSPercentile`, `Urgent`), `internal/i18n/templates/*/{impact,cost}.tmpl`, `internal/i18n/catalog/*.json`, `internal/digest/digest.go` (`Exploited []Exploited`, `ExploitedDecided int`, `Attention`, titre), `internal/digest/templates/*/*.tmpl`, `internal/cli/findings.go` + `finding.go` (`[KEV]`, `kev: yes`), `internal/api/views.go` (`KEV`, `EPSS`, `Malicious`, `Kind`, `SeveritySource`), `docs/remediation-risk.md` + `.fr.md`, `internal/cli/root.go` (passe `enrich.Lookup` au scan)
- Test: `internal/enrich/*_test.go`, `internal/scan/scan_test.go`, `internal/decide/decide_test.go`, `internal/analyze/risk_test.go`, `internal/explain/explain_test.go`, `internal/digest/digest_test.go`, `internal/api/handlers_test.go`

**Interfaces:**
- Consumes: `source.Repo`, `Gateway.Client(policy.PurposeEnrich)`, `scan.Finding.Aliases`.
- Produces:
  ```go
  // enrich
  type Deps struct{ Store *store.Store; Audit *audit.Logger; Client *http.Client; Now func() time.Time }
  const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  const EPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
  const MaxKEVBytes int64 = 50 << 20; MaxEPSSBytes int64 = 200 << 20
  func ReadKEV(ctx, deps Deps, etag string) (items int, newETag string, err error)   // 304 ⇒ (0, etag, ErrNotModified) ; remplace la table kev en une transaction
  func ReadEPSS(ctx, deps Deps, etag string) (items int, newETag string, err error)  // csv.gz, lignes "#…" ignorées, colonnes cve,epss,percentile ; model_date depuis la ligne de commentaire
  type Lookup struct{ KEV map[string]KEVEntry; EPSS map[string]EPSSEntry; CVSS map[string]float64 } // chargé en mémoire : kev entier, epss et cve_enrichment filtrés sur les CVE demandés
  func LoadLookup(ctx, db *sql.DB, cves []string) (Lookup, error)
  func (l Lookup) Of(aliases []string) (kev bool, kevAdded string, epss, percentile, cvss float64) // premier alias CVE-… trouvé, max EPSS si plusieurs
  type ApplyResult struct{ Updated, NowKEV, Superseded int }
  func Apply(ctx, deps Deps) (ApplyResult, error) // tous les findings status ≠ gone : recalcule kev, kev_added, epss, epss_percentile, cvss_enriched ; si kev change sur une faille decided avec décision en vigueur ⇒ supersede(kev_changed), status pending, status_changed_at, audit decision.superseded ; même transaction
  // scan
  const ReasonKEVChanged = "kev_changed"
  func EffectiveSeverity(f Finding) (label string, source string) // "osv" ; "enrichment" quand SeverityLabel=="unknown" && CVSSEnriched>0 ; "malicious" ⇒ critical
  func SnapshotChanged(seenSeverity string, seenFixed []string, seenKEV bool, severity string, fixed []string, kev bool) (bool, string) // KEV comparé en dernier
  Options.Lookup *enrich.Lookup // nil = pas d'enrichissement (tests)
  // decide
  const KEVChanged Reason = scan.ReasonKEVChanged ; Decision.SeenKEV bool
  // analyze
  RiskInput.Exploited bool ; Risk.Urgency string `json:"urgency"` // "urgent" si Exploited, sinon "" ; Terms["exploited"] = 1/0 ; IsRiskFlag("exploited") == true
  // explain
  Facts.KEV bool; Facts.KEVAdded string; Facts.EPSSPercentile float64; Facts.Urgent bool
  // digest
  type Exploited struct{ Project, Package, Ecosystem, OSVID, FindingID, Installed, Target, Status string; Malicious bool; KEVAdded string }
  Digest.Exploited []Exploited `json:"exploited"`; Digest.ExploitedDecided int `json:"exploited_decided"`; Digest.ExploitedTotal int
  ```
- Règles : `Exploited` = findings `kev=1` ou `malicious=1` avec statut `new`, `pending`, ou `decided` dont la décision en vigueur est `fix` ; `ExploitedDecided` = même ensemble mais décision `defer` ou `ignore`. Titre : si `len(Exploited) > 0`, clé `digest.title.exploited` (« Michel a trouvé %d nouveautés cette nuit, %d exploitée(s) dans la nature »). `Attention` += KEV/malicious non décidées (toute gravité), sans double compte avec les critiques/élevées déjà comptées. Phrase *impact* : `{{if .KEV}}` « Cette faille est exploitée dans la nature (liste KEV de la CISA depuis le {{day .KEVAdded}}). » et `Certainty` forcée `high` ; `{{if ge .EPSSPercentile 0.5}}` « Probabilité d'exploitation sous 30 jours : X %, plus que Y % des failles connues. » ; *cost* : `{{if .Urgent}}` « À corriger en premier. ». `docs/remediation-risk*.md` : paragraphe « KEV ne change pas le score : il marque l'urgence ».

- [ ] **Step 1: Tests qui échouent** — enrich : `TestReadKEVReplacesTable` (serveur `httptest` servant `testdata/kev.json` à 3 entrées puis 2 ⇒ 3 puis 2 lignes), `TestReadKEVHonoursETag` (304 ⇒ `ErrNotModified`, table intacte), `TestReadKEVCapsBody` (`Content-Length` > cap ⇒ erreur, table intacte), `TestReadEPSSParsesGzipCSV` (4 lignes dont commentaire `#model_version:v2025.03.14,score_date:2026-10-25T00:00:00+0000` ⇒ `model_date == "2026-10-25"`), `TestLookupOfPicksCVEAlias` (`["GHSA-x", "CVE-2024-1"]`), `TestApplyFillsFindingColumns`, `TestApplySupersedesIgnoreWhenKEVAppears` (finding `decided ignore`, KEV absente ; insérer la CVE dans `kev` ; `Apply` ⇒ décision `superseded_reason == "kev_changed"`, finding `pending`, audit `decision.superseded` avec `reason kev_changed`), `TestApplyLeavesFixDecisionWhenKEVUnchanged`. scan : `TestApplyScanWritesKEVFromLookup`, `TestSnapshotChangedOnKEV`, `TestEffectiveSeverityUsesEnrichedCVSSOnlyWhenUnknown`. decide : `TestSetStoresSeenKEV`. analyze : `TestExploitedIsFlagNotPoints` (score identique avec et sans `Exploited`, `Terms["exploited"] == 1`, `Urgency == "urgent"`). explain : `TestImpactMentionsKEVAndEPSS` (FR et EN), `TestCostSaysFixFirstWhenUrgent`, golden plan 2 inchangé. digest : `TestDigestHeadListsPendingKEV` (KEV `pending` et KEV `decided fix` dans `Exploited`, KEV `defer` dans `ExploitedDecided` seulement, titre `digest.title.exploited`, `AttentionTotal` compte la KEV `low` pending), `TestRenderTextShowsExploitedFirst` (la section apparaît avant « Nouvelles failles »). api : `TestFindingViewCarriesKEVAndEPSS`.
- [ ] **Step 2: Lancer** les tests ciblés → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés). `cli/root.go` : après `store.Open`, `deps.Lookup` n'est pas chargé globalement ; `cli/scan.go` charge `enrich.LoadLookup` avec les CVE des findings normalisés juste avant `applyScan` (dans `scan.Run`, via `Options.Lookup` **ou** un `LookupFunc func(cves []string) (enrich.Lookup, error)` : choisir la fonction pour éviter de charger 300 000 lignes EPSS ; documenter dans `Options`).
- [ ] **Step 4: Relecture FR** (gabarits `impact`/`cost` FR, `digest.title.exploited`, section FR du digest, `docs/remediation-risk.fr.md`) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(enrich,scan,decide,digest,explain): CISA KEV and FIRST EPSS, exploited-in-the-wild head of the digest, kev_changed supersession, urgency flag`.

### Task 4: Enrichissements à la demande — Vulnrichment, NVD (clé optionnelle), CIRCL

**Files:**
- Create: `internal/enrich/ondemand.go`, `internal/enrich/vulnrichment.go`, `internal/enrich/nvd.go`, `internal/enrich/circl.go`, `internal/enrich/testdata/{vulnrichment,nvd,circl}-CVE-2024-0001.json`
- Modify: `internal/enrich/enrich.go` (`Apply` lit `cvss_enriched`), `internal/enrich/repo.go` (`cve_enrichment`)
- Test: `internal/enrich/ondemand_test.go`

**Interfaces:**
- Consumes: `secret.Store.Get("nvd-api-key")`, `Gateway.Client(policy.PurposeEnrich)`.
- Produces:
  ```go
  type OnDemand interface { Key() string; Fetch(ctx, client *http.Client, cve string) (CVERecord, error) } // ErrNotFound (404) ; ErrRateLimited (403/429)
  type CVERecord struct{ CVE string; CVSSScore float64; CVSSVector, SSVCExploitation, SSVCAutomatable, SSVCTechnicalImpact string; CWE []string }
  func Vulnrichment() OnDemand // GET https://raw.githubusercontent.com/cisagov/vulnrichment/develop/<YYYY>/<Nxxx>/<CVE>.json ; bloc = (numéro/1000)*1000 formaté "1xxx" ; lit containers.adp[].metrics[].cvssV3_1|cvssV4_0, ssvc
  func NVD(apiKey string) OnDemand // GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE> ; en-tête apiKey si non vide ; espacement 6 s sans clé, 0,6 s avec
  func CIRCL() OnDemand          // GET https://vulnerability.circl.lu/api/vulnerability/<CVE>
  const MaxOnDemandBytes int64 = 5 << 20; MaxVulnrichmentPerRun = 200; MaxNVDPerRun = 100; MaxCIRCLPerRun = 200
  func Candidates(ctx, db *sql.DB, limit int) ([]string, error) // CVE des findings non gone avec severity_label='unknown' et sans ligne cve_enrichment, par last_seen_at décroissant
  func RunOnDemand(ctx, deps Deps, src OnDemand, limit int) (fetched, notFound, failed int, err error) // écrit cve_enrichment(source_key = src.Key()) ; s'arrête à ErrRateLimited
  ```

- [ ] **Step 1: Tests qui échouent** — `TestVulnrichmentPathForCVE` (`CVE-2024-12345` ⇒ `/2024/12xxx/CVE-2024-12345.json`), `TestVulnrichmentParsesCVSSAndSSVC`, `TestNVDParsesMetricsAndSendsAPIKeyHeader` (en-tête `apiKey` présent avec clé, absent sans), `TestCIRCLParses`, `TestCandidatesOnlyUnknownSeverityWithoutRecord`, `TestRunOnDemandStopsAtRateLimit` (2e réponse 429 ⇒ `fetched == 1`, pas de 3e requête), `TestRunOnDemandCapsBody`, `TestApplyUsesEnrichedCVSSForUnknown` (finding `unknown` + `cve_enrichment` 8.1 ⇒ `cvss_enriched == 8.1`, `EffectiveSeverity` = `high`/`enrichment`).
- [ ] **Step 2: Lancer** `go test ./internal/enrich/ -run 'Vulnrichment|NVD|CIRCL|Candidates|OnDemand|EnrichedCVSS' -v` → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés) ; les URL de base sont des variables remplaçables en test (`SetBaseURLsForTest`, dans `export_test.go`).
- [ ] **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Commit** `feat(enrich): on-demand CVE enrichment from Vulnrichment, NVD and CIRCL with caps and rate limits`.

### Task 5: `michel source update`, `scan --all --update --digest`, ligne « catalogue », `decide --package` résumé, chaîne de supersessions

**Files:**
- Create: `internal/sourceupdate/update.go`, `internal/sourceupdate/update_test.go`, `internal/cli/source_update.go`
- Modify: `internal/cli/scan.go` (`--update`), `internal/cli/decide.go` (résumé, `--verbose`), `internal/digest/digest.go` (`Catalog`, dédoublonnage `Superseded`), `internal/digest/templates/*/*.tmpl`, `internal/digest/repo.go` (`summary` garde `empty_projects`, `catalog_failed`), `internal/osvdb/osvdb.go` (`Update` accepte un `etag` par écosystème ? non : garde `fetched_at`, ajoute `If-Modified-Since`), `docs/operations/daily-digest.md` + `.fr.md` (ligne planifiée), i18n EN/FR
- Test: `internal/cli/scan_test.go`, `internal/cli/decide_test.go`, `internal/digest/digest_test.go`

**Interfaces:**
- Consumes: `source.Repo`, `osvdb.Update`, `enrich.ReadKEV/ReadEPSS/RunOnDemand/Apply`, plus tard `feed.Read` (Task 6), `gitrepo.Status`/`Discover` (Task 7) : l'orchestrateur appelle des **readers enregistrés** pour ne pas dépendre des tâches suivantes.
- Produces:
  ```go
  // sourceupdate
  type Reader interface { Kinds() []source.Kind; Read(ctx, e source.Entry, deps Deps) (Result, error) }
  type Result struct{ Items int; ETag string; Status map[string]any; Skipped string } // Skipped = "rate budget" | "not_modified" | ""
  type Deps struct{ Store *store.Store; Repo *source.Repo; Audit *audit.Logger; Gateway *egress.Gateway; Secrets secret.Store; OSVRoot string; Now func() time.Time; Budget *Budget }
  type Budget struct{ Remaining int } // 50 sans github-token, 500 avec ; décrémenté par les readers GitHub
  func Register(r Reader) // appelé par enrich (Task 5), feed (6), gitrepo (7), dans des init() de paquets "adapters" : internal/sourceupdate/readers/{osv,enrich,feed,gitrepo}.go importés par cli
  type Report struct{ Updated, Skipped, WaitingConsent, Failed []string; Items map[string]int; NewVersions []NewVersion; DiscoverNew int }
  type NewVersion struct{ Key, Name, From, To string }
  func Run(ctx, deps Deps, keys []string, kind source.Kind) (Report, error) // ordre § 8.1 ; une erreur par entrée ⇒ RecordRead(error) + Failed, continue ; audit source.read par entrée ; enrich.Apply après la phase enrichment ; err final non nil si Failed non vide (ErrSomeFailed)
  // digest
  type Catalog struct{ Updated int; Failed, WaitingConsent, Unreachable []string; NewVersions []NewVersion; DiscoverNew int; UpdatedAt time.Time; Silent bool } // Silent = rien à dire
  Digest.Catalog Catalog `json:"catalog"` // Compute lit source : last_read_* de chaque entrée enabled, status.new_version, discovery state=new
  ```
- `michel source update [keys…] [--kind k] [--json]` : exit 1 si `Failed` non vide ; texte : une ligne par entrée (`✓ enrich.kev 1 532 items`, `✗ feed.nginx : timeout`, `· osv.pypi attend ton accord`). `scan --all --update --digest` : `sourceupdate.Run` d'abord ; un échec n'arrête pas les scans. `decide --package` : `cli.decide.package_summary` (« %d failles de %s décidées (%s) dans %s ; audit : %s → %s ») ; `--verbose` ⇒ anciennes lignes. Digest `Superseded` : grouper par `FindingID`, garder `SupersededAt` max.

- [ ] **Step 1: Tests qui échouent** — sourceupdate : `TestRunSkipsWaitingConsentWithoutNetwork` (Sink témoin : zéro `Attempt`), `TestRunContinuesAfterOneFailure` (reader qui échoue puis un qui réussit ⇒ `Failed == ["a"]`, `Updated == ["b"]`, deux `source.read`, `ErrSomeFailed`), `TestRunRespectsGitHubBudget` (budget 2, trois entrées repo ⇒ troisième `Skipped == "rate budget"`), `TestRunRecordsReadOnEntry` (`last_read_at`, `result`, `items`, `etag`). cli : `TestScanAllUpdateRunsSourceUpdateFirst` (ordre des événements d'audit : `source.read` avant `scan.start`), `TestSourceUpdateExitOneOnFailure`, `TestDecidePackagePrintsOneSummaryLine` (59 failles ⇒ une ligne stdout contenant `59`, et `--verbose` ⇒ 59 lignes). digest : `TestDigestCatalogLine` (une entrée `error`, une `waiting_consent`, un `status.new_version` ⇒ `Catalog.Failed`, `WaitingConsent`, `NewVersions` ; tout ok ⇒ `Silent`), `TestSupersededChainListsOnlyLatest` (A supersédée puis B décidée et supersédée dans la fenêtre ⇒ une seule ligne, `PreviousAction == B`).
- [ ] **Step 2: Lancer** les tests ciblés → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés) ; readers `osv` (appelle `osvdb.Update` pour l'écosystème de l'entrée, `fetched_at` ⇒ `last_read_at`) et `enrich` (kev, epss, on-demand par `config.format`) dans `internal/sourceupdate/readers/`. Doc `daily-digest` : `michel scan --all --update --digest` dans les trois planificateurs.
- [ ] **Step 4: Relecture FR** (`cli.source.update.*`, `cli.decide.package_summary`, section « catalogue » FR du digest, `daily-digest.fr.md`) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(sourceupdate,digest,cli): daily catalog update before the scan, catalog line in the digest, by-package decide summary, superseded chain`.

### Task 6: Veille « À lire » — lecteurs RSS/Atom, avis GitHub, page ; technologies ; items ; digest

**Files:**
- Create: `internal/feed/feed.go` (types, `Read`), `internal/feed/rss.go`, `internal/feed/github.go`, `internal/feed/page.go`, `internal/feed/repo.go`, `internal/feed/match.go`, `internal/feed/testdata/{rss,atom,advisories}.{xml,json}`, `internal/sourceupdate/readers/feed.go`, `internal/cli/source_items.go`
- Modify: `internal/scan/scan.go` (`project.tech_auto` recalculé à la fin du scan via `source.TechRules`), `internal/project/repo.go` (`UpdateTechAuto`), `internal/digest/digest.go` (`Reading []ReadingItem`), `internal/digest/templates/*/*.tmpl`, i18n EN/FR
- Test: `internal/feed/*_test.go`, `internal/scan/scan_test.go`, `internal/digest/digest_test.go`, `internal/cli/source_items_test.go`

**Interfaces:**
- Consumes: `source.Entry.Config.Str("format")`, `Str("repo")`, `Entry.Tech`, `source.DeclaredTech`, `secret.Store.Get("github-token")`, `Gateway.Client(policy.PurposeFeed)`.
- Produces:
  ```go
  // feed
  const MaxFeedBytes int64 = 5 << 20; MaxItemsPerRead = 200; MaxSummary = 500; Retention = 180 * 24 * time.Hour
  type Item struct{ ID, SourceID, GUID, Title, URL, PublishedAt, Summary string; Tech []string; SeenAt, ReadAt string }
  type Reader interface{ Parse(body []byte, e source.Entry) ([]Item, error) }
  func Detect(contentType string, body []byte) string // "rss" | "atom" | "" ; racine <rss> / <feed>
  func ReadEntry(ctx, deps Deps, e source.Entry, declared []string) (items int, etag string, err error) // GET avec If-None-Match ; format auto ⇒ Detect ; page ⇒ hash ; dédoublonne par (source_id, guid) ; Tech = étiquettes de l'entrée ∪ étiquettes déclarées trouvées dans le titre (mot entier, Fold) ; purge > Retention
  func StripHTML(s string) string // balises retirées, entités décodées, espaces réduits, puis scan.SanitizeText
  func MatchTech(title string, entryTech, declared []string) (matched []string, toRead bool)
  type Repo ; func (r *Repo) ListToRead(ctx, since time.Time, unreadOnly bool, tech []string) ([]Item, error) ; func (r *Repo) MarkRead(ctx, id string, at time.Time) error ; MarkAllRead
  // source
  func TechAuto(rules []TechRule, manifests []scan.ManifestResult, packages map[string][]string) []string // étiquettes depuis écosystèmes ("php" pour Packagist, "node" pour npm) et paquets
  // digest
  type ReadingItem struct{ Source, Title, URL, PublishedAt string; Tech []string }
  Digest.Reading []ReadingItem `json:"reading"` // max 10, non lus, published_at dans la fenêtre, toRead seulement
  ```
- Avis GitHub : `GET https://api.github.com/repos/{owner}/{repo}/security-advisories?state=published&per_page=50`, `Accept: application/vnd.github+json`, `Authorization: Bearer <token>` si présent ; item : `ghsa_id`, `summary`, `html_url`, `published_at`, `severity` ajouté au résumé. Page : item `guid = "page:" + sha256(texte)`, titre `feed.page_changed` (i18n à l'affichage : titre stocké `page changed`, traduit par clé).

- [ ] **Step 1: Tests qui échouent** — `TestDetectRSSAndAtom`, `TestRSSReaderCapsAndSanitizes` (corps 6 Mo tronqué ⇒ erreur `too large` et aucune écriture ; corps 1 Mo à 5 000 items ⇒ 200 items, titre `<b>x\x00</b>` ⇒ `x`), `TestAtomParses`, `TestGitHubAdvisoriesParsesAndSendsToken`, `TestPageChangeCreatesOneItemPerHash` (même contenu deux fois ⇒ 1 item), `TestReadEntryHonoursETag`, `TestMatchTechWholeWordFold` (`nginx` matche « Nginx 1.27 », pas « enginx »), `TestReadEntryPurgesOldItems`, `TestTechAutoFromRulesAndEcosystem` (`symfony/console` ⇒ `symfony`, `php`). scan : `TestScanWritesTechAuto`. digest : `TestDigestReadingListsUnreadMatchingItems` (11 items ⇒ 10 ; item lu exclu ; item sans match exclu). cli : `TestSourceItemsAndRead`.
- [ ] **Step 2: Lancer** les tests ciblés → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés) ; reader `feed` enregistré dans `sourceupdate`.
- [ ] **Step 4: Relecture FR** (section « À lire » FR, `cli.source.items.*`, `feed.page_changed`) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(feed,digest): vendor advisories to read, filtered by declared technologies; rss, atom, github advisories and page watchers`.

### Task 7: Skills et serveurs MCP — archive épinglée, aperçu, licence, installation avec marqueur, relevé GitHub, « À découvrir »

**Files:**
- Create: `internal/gitrepo/gitrepo.go` (types), `internal/gitrepo/fetch.go` (archive), `internal/gitrepo/extract.go`, `internal/gitrepo/license.go`, `internal/gitrepo/preview.go`, `internal/gitrepo/install.go`, `internal/gitrepo/status.go`, `internal/gitrepo/discover.go`, `internal/gitrepo/repo.go` (discovery), `internal/gitrepo/testdata/skill.tar.gz` (généré par un helper de test, pas committé : construit en mémoire), `internal/sourceupdate/readers/gitrepo.go`, `internal/cli/source_install.go`, `internal/cli/source_discover.go`
- Modify: `internal/cli/source.go` (`remove` délègue `Uninstall`), i18n EN/FR
- Test: `internal/gitrepo/*_test.go`, `internal/cli/source_install_test.go`

**Interfaces:**
- Consumes: `Gateway.Client(policy.PurposeRepo)`, `Gateway.Client(policy.PurposeDiscover)`, `secret.Store.Get("github-token")`, `sourceupdate.Budget`.
- Produces:
  ```go
  const MaxArchiveBytes int64 = 50 << 20; MaxExtractedBytes int64 = 200 << 20; MaxFiles = 5000
  func ArchiveURL(owner, repo, sha string) string // https://codeload.github.com/<owner>/<repo>/tar.gz/<sha>
  func Fetch(ctx, client *http.Client, dataDir, key, owner, repo, sha string) (dir string, err error) // <dataDir>/sources/repos/<key>/<sha>/ ; déjà présent ⇒ pas de réseau
  func Extract(r io.Reader, dst string) (files []FileInfo, err error) // ErrTraversal, ErrSymlink ; mode & 0o666 ; premier composant (<repo>-<sha>/) retiré
  type FileInfo struct{ Path string; Size int64 }
  type License struct{ SPDX, File string } // SPDX "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-3.0", "AGPL-3.0", "MPL-2.0", "unknown"
  func DetectLicense(dir string) License
  type Preview struct{ Key, Repo, SHA string; Files []FileInfo; License License; Head []string; Trust Trust; WillWrite string; Launch string }
  type Trust struct{ Stars int; PushedAt, Archived string; InCatalog bool }
  func PreviewInstall(ctx, deps Deps, e source.Entry, sha string) (Preview, error) // Head = 40 premières lignes de <path>/SKILL.md ou README.md ; WillWrite = chemin cible pour skill, "" pour mcp ; Launch = "claude mcp add --scope user <name> -- <command> <args…>" pour mcp
  type Deps struct{ Repo *source.Repo; Audit *audit.Logger; Client *http.Client; DataDir, SkillsDir string; Now func() time.Time } // SkillsDir défaut ~/.claude/skills
  func Install(ctx, deps Deps, e source.Entry, sha string) (installedTo string, err error) // skill : copie <path> vers SkillsDir/<name>/ (name = frontmatter name, sinon dossier) ; refus ErrForeignDir si existe sans .michel-source ; écrit .michel-source {key, sha, installed_at} ; mcp : rien hors dataDir ; met config.user installed_sha, install_dir ; audit source.install
  func Upgrade(ctx, deps Deps, e source.Entry, toSHA string) (Diff, error) // Fetch nouveau sha, Diff Added/Changed/Removed + SkillMDDiff (unified minimal) ; l'appelant confirme puis Install
  func Uninstall(ctx, deps Deps, e source.Entry) error // supprime SkillsDir/<name>/ si marqueur key correspond ; sinon ErrForeignDir ; audit source.remove
  type RepoStatus struct{ Stars int; PushedAt string; Archived bool; DefaultBranch, HeadSHA, LatestRelease string; CheckedAt string; NewVersion bool } // NewVersion = HeadSHA != pinned
  func Status(ctx, client *http.Client, token, owner, repo string, budget *sourceupdate.Budget) (RepoStatus, error) // 3 requêtes : /repos, /commits/<default_branch>, /releases/latest (404 toléré)
  func Discover(ctx, client *http.Client, token string, topics []string, budget *sourceupdate.Budget) ([]Discovery, error) // /search/repositories?q=topic:<t>&sort=stars&per_page=20
  type Discovery struct{ Repo, Topic string; Stars int; Description, HTMLURL, FirstSeenAt, State string }
  ```
- CLI : `source install <key> [--yes]` (aperçu puis `y/N`), `source upgrade <key> [--yes]`, `source discover [--add owner/repo --kind skill|mcp --pin <sha> | --ignore owner/repo]`, `source show` affiche `status`. Catalogue : le builder relève `pinned`, `license`, `launch` des 6 dépôts retenus (§ 7.3) le jour de la tâche.

- [ ] **Step 1: Tests qui échouent** — `TestExtractRefusesTraversalAndSymlinks` (archive en mémoire avec `../x`, un lien symbolique, un fichier `0o755` ⇒ `ErrTraversal`/`ErrSymlink` selon le cas, et pour une archive saine le mode est `0o644`), `TestExtractCapsFilesAndBytes`, `TestDetectLicenseSPDX` (MIT, Apache-2.0, GPL-3.0, aucun fichier ⇒ `unknown`), `TestPreviewShowsHeadLicenseAndTarget`, `TestInstallWritesMarkerAndRefusesForeignDir`, `TestInstallWritesNothingOnBadArchive` (archive traversante ⇒ `SkillsDir` vide après), `TestUninstallOnlyWithMatchingMarker`, `TestUpgradeDiffListsChanges`, `TestStatusUsesThreeRequestsAndBudget` (budget 3 ⇒ ok ; budget 2 ⇒ `ErrBudget` sans la troisième requête), `TestStatusFlagsNewVersion`, `TestDiscoverSkipsKnownRepos`, `TestMCPPreviewPrintsClaudeMCPAddLine`. cli : `TestSourceInstallNeedsYes`, `TestSourceInstallYesCopiesSkill` (`SkillsDir` = `t.TempDir()` par flag caché `--skills-dir` ou variable d'environnement `MICHEL_SKILLS_DIR` : choisir la variable, documentée pour les tests seulement), `TestSourceRemoveUninstallsSkill`.
- [ ] **Step 2: Lancer** `go test ./internal/gitrepo/ ./internal/cli/ -run 'Extract|License|Preview|Install|Uninstall|Upgrade|Status|Discover|MCP|SourceInstall|SourceRemove' -v` → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés) ; reader `gitrepo` dans `sourceupdate` (statut de chaque `skill`/`mcp`/`plugin` avec `repo`, puis `discover.github`) ; `source.Status` stocke `RepoStatus` en JSON.
- [ ] **Step 4: Relecture FR** (`cli.source.install.*`, `source.trust.*`, textes d'aperçu) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(gitrepo): pinned skills and mcp servers with preview, licence, marker install, daily repo status and discovery`.

### Task 8: Plugins — `Provider`, lecteurs SARIF et Trivy JSON, `source run`, proxy de refus, Trivy et Semgrep

**Files:**
- Create: `internal/plugin/plugin.go` (`Provider`, `ExternalFinding`, registre), `internal/plugin/sarif.go`, `internal/plugin/trivyjson.go`, `internal/plugin/trivy.go`, `internal/plugin/semgrep.go`, `internal/plugin/generic.go` (codeql, zap, generic : `Ingest` seul), `internal/plugin/run.go` (`Run`, sous-processus, `plugin_run`), `internal/plugin/repo.go`, `internal/plugin/testdata/{codeql,semgrep,trivy-misconfig}.{sarif,json}`, `internal/egress/denyproxy/denyproxy.go`, `internal/cli/source_run.go`
- Modify: `internal/scan/repo.go` (`ApplyExternal` : mêmes statuts, `gone` limité au `source_key` et projet du run), `internal/scan/normalize.go` (`Finding.SourceKey`, `RuleID`, `Location`, `Fingerprint`), `internal/i18n/templates/*/{what,impact,cost}.tmpl` (variantes par `Kind`), `internal/explain/explain.go` (`Facts.Kind`, `RuleID`, `Location`), `internal/cli/scan.go` (plugins `run=true` après le scan du projet), `internal/api/views.go` (`Kind`, `RuleID`, `Location`), `internal/egress/boundary_test.go` (exclut `internal/egress/denyproxy` comme `internal/egress`), i18n EN/FR
- Test: `internal/plugin/*_test.go`, `internal/egress/denyproxy/denyproxy_test.go`, `internal/scan/repo_test.go`, `internal/cli/source_run_test.go`, `internal/explain/explain_test.go`

**Interfaces:**
- Produces:
  ```go
  // plugin
  type ExternalFinding struct{ RuleID, Message, Location, Fingerprint, Severity string; CVSS float64; Kind string; Aliases []string }
  type Provider interface {
      Key() string; Tool() string; Kind() string
      Detect(ctx) (installed bool, version string)                       // exec.LookPath + "<tool> --version", 10 s
      Run(ctx, p project.Project, outDir string, env []string) (reportPath string, err error) // ErrNotRunnable pour codeql, zap, generic
      Ingest(ctx, reportPath string, p project.Project) ([]ExternalFinding, error)
  }
  func ForEntry(e source.Entry) (Provider, error) // config.tool ⇒ trivy | semgrep | codeql | zap | generic ; format sarif | trivy_json
  func ParseSARIF(r io.Reader, projectRoot string) ([]ExternalFinding, error) // level error→high, warning→medium, note→low ; properties["security-severity"] ⇒ CVSS + label ; location relative, SanitizeText ; fingerprint = partialFingerprints["primaryLocationLineHash"] sinon ""
  func ParseTrivyJSON(r io.Reader, knownCVEs map[string]bool) (findings []ExternalFinding, skippedKnown int, err error) // Misconfigurations ; Vulnerabilities ignorées si VulnerabilityID ∈ knownCVEs
  type RunDeps struct{ Store *store.Store; Audit *audit.Logger; Repo *source.Repo; DataDir string; Now func() time.Time; Exec func(ctx, name string, args, env []string, dir string) (stdout, stderr []byte, err error); Proxy func() (addr string, close func()) }
  func RunPlugin(ctx, deps RunDeps, e source.Entry, p project.Project, input string) (RunResult, error) // input ≠ "" ⇒ Ingest seul ; sinon Detect, proxy, Run (timeout 30 min, env = HTTP_PROXY/HTTPS_PROXY/ALL_PROXY=<proxy>, NO_PROXY="", TRIVY_SKIP_DB_UPDATE=true, SEMGREP_SEND_METRICS=off, PATH), Ingest, scan.ApplyExternal ; plugin_run ; audit plugin.run {key, project, tool_version, argv_hash, duration_ms, findings, result}
  type RunResult struct{ RunID string; New, Still, Gone, SkippedKnown int; ReportPath string }
  var TrivyArgs = func(out, projectPath, cacheDir string) []string // "fs","--scanners","misconfig","--format","sarif","--output",out,"--skip-db-update","--skip-java-db-update","--skip-check-update","--offline-scan","--cache-dir",cacheDir,projectPath
  var SemgrepArgs = func(out, projectPath, rulesDir string) []string // "scan","--sarif","--output",out,"--metrics=off","--disable-version-check","--config",rulesDir,projectPath
  // denyproxy
  func Listen(sink egress.Sink, purpose string) (addr string, close func(), err error) // 127.0.0.1:0 ; 403 à tout ; CONNECT fermé ; chaque requête ⇒ sink.Record(Attempt{Host, Purpose, Allowed:false, Reason:"plugin subprocess"})
  // scan
  func ApplyExternal(ctx, tx *sql.Tx, projectID, sourceKey, runID string, now time.Time, findings []Finding, current map[string]decisionView) (newN, still, gone int, superseded []Superseded, err error) // FindingID(projectID, sourceKey, "", ruleID, fingerprint ou location) ; gone = findings du même (project_id, source_key) absents
  ```
- Gabarits par `kind` : *what* `{{if ne .Kind "dependency"}}` « {{.Tool}} signale la règle {{.RuleID}} dans {{.Location}}. » ; *cost* « Corriger = modifier ton code, pas une dépendance. » ; les phrases `dependency` inchangées. `michel scan --project demo` : après l'analyse, pour chaque plugin `on` avec `run=true` et projet inclus, `RunPlugin` ; échec = avertissement stderr, pas d'exit 1 (comme l'analyse).

- [ ] **Step 1: Tests qui échouent** — `TestParseSARIFMapsLevelsAndSecuritySeverity` (fixture codeql : `error` ⇒ high ; semgrep avec `security-severity: 9.1` ⇒ critical, CVSS 9.1 ; chemin absolu `C:\x\src\a.php` ⇒ relatif `src/a.php` quand sous `projectRoot`, sinon ignoré), `TestParseTrivyJSONMisconfigAndSkipsKnownCVEs`, `TestDenyProxyRefusesAndRecords` (client via proxy : GET http ⇒ 403, CONNECT ⇒ erreur, deux `Attempt` `Allowed=false` purpose `plugin.trivy`), `TestPluginRunDeniesEgressAndNeverWritesInProject` (faux `trivy` = script Go compilé en `t.TempDir()` par `go build` d'un `testdata/faketool/main.go` : lit `HTTPS_PROXY`, tente `GET https://ghcr.io/` via ce proxy, écrit un SARIF dans `--output`, tente d'écrire `<project>/.trivyignore` et **doit** échouer ? non : le faux outil n'écrit pas dans le projet ; le test vérifie `treeDigest` identique et un `Attempt` refusé `ghcr.io`), `TestPluginRunIngestOnlyWithInput`, `TestPluginRunNotRunnableForZAP`, `TestApplyExternalGoneLimitedToSourceKey` (findings OSV du projet intacts après un run plugin qui ne les contient pas), `TestTrivyArgsAreMisconfigOnlyAndOffline`, `TestSemgrepArgsDisableMetrics`. explain : `TestWhatForCodeFinding`. cli : `TestSourceRunWithInput`, `TestScanRunsEnabledPluginsAfterAnalysis` (faux outil ; audit `plugin.run` après `analyze.finish`).
- [ ] **Step 2: Lancer** les tests ciblés → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés). `Exec` par défaut = `exec.CommandContext` avec `cmd.Dir = <data-dir>/plugins/<tool>/`, `cmd.Env = env` (jamais `os.Environ()` entier : `PATH`, `SystemRoot`, `TEMP`/`TMP`, `HOME`/`USERPROFILE` seulement, plus les variables listées), stdout/stderr tronqués à 64 Ko.
- [ ] **Step 4: Relecture FR** (gabarits `kind` FR, `cli.source.run.*`) ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(plugin,egress): findings providers (sarif, trivy json), trivy misconfig and semgrep runs behind a deny-all proxy, external findings in the same loop`.

### Task 9: API et page « Sources », ajouts « Aujourd'hui »

**Files:**
- Create: `internal/api/sources.go` (handlers), `internal/api/sources_test.go`, `web/src/components/SourcesPage.vue`, `web/src/components/SourceRow.vue`, `web/src/components/ConsentDialog.vue`, `web/src/components/InstallDialog.vue`, `web/src/components/AddSourceForm.vue`, `web/src/components/DiscoverList.vue`, `web/src/components/ReadingList.vue`, `web/src/components/ExploitedBanner.vue`, `web/src/lib/sourcesView.js` + `sourcesView.test.js`
- Modify: `internal/api/server.go` (routes § 10.1, `Deps.Sources`, `Deps.PolicyPath`, `Deps.Reload`), `internal/api/views.go` (`SourceView`, `ReadingView`, `CatalogView`), `internal/api/handlers.go` (`today` : `exploited`, `reading`, `catalog`, `discover`), `web/src/App.vue` (onglets `#/` et `#/sources`), `web/src/components/TodayPage.vue` (bandeau, « À lire », ligne catalogue), `web/src/components/PackageRow.vue` + `FindingSheet.vue` (chip KEV / malveillant / kind, EPSS), `web/src/api.js` (`del`), `web/src/i18n/{fr,en}.json`
- Test: `internal/api/sources_test.go`, `internal/api/handlers_test.go`, `web/src/lib/sourcesView.test.js`

**Interfaces:**
- Consumes: `source.Enable/Disable/Reset`, `source.Repo`, `feed.Repo`, `gitrepo.PreviewInstall/Install/Upgrade/Uninstall`, `plugin.RunPlugin`, `sourceupdate.Run` (une entrée).
- Produces: `SourceView{Key, Kind, Origin, Name, URL, Hosts, Purpose, State, Enabled, Hidden, Tech, Config (merged, sans *_secret), LastRead{At, Result, Error, Items}, Status, Badges []string, Note}` ; `POST /sources/{key}/enable` sans `consent:true` quand `ConsentNeeded` non vide ⇒ `409 {error, hint, consent: [{host, purpose, what, rule}]}` ; `GET /sources/{key}/preview` ⇒ `Preview` ; `POST /sources/{key}/run` ⇒ `202 {run_id}` puis `GET /plugin-runs/{id}` ; `GET /today` ajoute `exploited`, `exploited_decided`, `reading`, `catalog`, `discover_new`. Front : `sourcesView.js` exporte `groupByKind(sources)`, `stateLabelKey(state)`, `badgeKeys(source)`, `consentSentence(consent, t)`.
- Page : § 10.2 du design. Route par `location.hash` (`#/sources`), `App.vue` montre `SourcesPage` ou `TodayPage` ; onglets `v-tabs` dans l'en-tête.

- [ ] **Step 1: Tests qui échouent** — api : `TestSourcesListHidesSecretsAndPaths`, `TestEnableWithoutConsentIs409WithText`, `TestEnableWithConsentWritesRuleAndReloadsGateway` (`Deps.PolicyPath` temp ; après `POST`, une requête `Gateway.Allowed("www.cisa.gov","source.enrich")` vraie), `TestAddSourceValidates`, `TestDeleteCatalogHidesUserDeletes`, `TestPreviewAndInstallSkill` (serveur `httptest` d'archive, `MICHEL_SKILLS_DIR` temp), `TestRunPluginReturns202AndRunStatus`, `TestItemsReadAndDiscoverActions`, `TestTodayCarriesExploitedReadingCatalog`, `TestAPIResponsesHaveNoAbsolutePathsNorCommands` étendu aux nouvelles routes. web : `sourcesView.test.js` (`groupByKind` ordre fixe, `badgeKeys` pour `new_version`/`suggested`/`archived`, `consentSentence`).
- [ ] **Step 2: Lancer** `go test ./internal/api/ -run 'Sources|Enable|AddSource|Delete|Preview|RunPlugin|Items|Today|NoAbsolute' -v` et `cd web && npm run test` → FAIL.
- [ ] **Step 3: Implémenter** (fichiers listés) ; `npm run build` puis `go build ./...` ; vérification manuelle dans Chrome (page Sources, dialogue d'accord, « À lire », bandeau) notée au ledger.
- [ ] **Step 4: Relecture FR** du `web/src/i18n/fr.json` ; appliquer.
- [ ] **Step 5: Lancer** `go test ./...` et `cd web && npm run test` → PASS.
- [ ] **Step 6: Commit** `feat(api,web): sources page with consent and install dialogs, exploited banner, reading list and catalog line on the today page`.

### Task 10: Docs bilingues, run réel, hygiène, ledger

**Files:**
- Create: `docs/sources.md`, `docs/sources.fr.md`, `docs/superpowers/sdd/2026-10-26-michel-sources/progress.md`, `docs/superpowers/sdd/2026-10-26-michel-sources/deferred-and-rulings.md`
- Modify: `docs/security/network-egress.md` + `.fr.md` (purposes, proxy de refus, caps, « tested vs declared »), `docs/operations/offline-installation.md` + `.fr.md` (bases supplémentaires, KEV/EPSS hors ligne par copie), `docs/operations/daily-digest.md` + `.fr.md` (déjà la ligne `--update`), `README.md` + `README.fr.md` (section Sources), `internal/hygiene/hygiene_test.go` (ignore les chemins que `git check-ignore` ignore : lecture de `.gitignore` racine, au minimum `.idea/`, `.vscode/`, `*.db`), `config.example.yaml`
- Test: `internal/hygiene/hygiene_test.go`

- [ ] **Step 1: Hygiène** — `TestNoPrivateProjectTraces` saute les dossiers et fichiers listés dans `.gitignore` racine (parse simple : lignes non vides, non `#`, motifs de dossier `x/` et globs `*.ext`) ; test `TestHygieneSkipsGitignoredPaths` (fichier `.idea/x.xml` contenant un jeton haché ⇒ pas de violation). Lancer `go test ./internal/hygiene/` → PASS sur ce poste.
- [ ] **Step 2: Docs** — `docs/sources.md` (EN) + `.fr.md` : les six sortes, l'écran d'accord et la règle écrite, ce qui sort (tableau par source : hôte, ce qui est envoyé), KEV/EPSS et leur affichage, « À lire » et les technologies, plugins (Trivy misconfig, Semgrep et ses règles à placer, CodeQL/ZAP en lecture, proxy de refus = clôture journalisée, pas une garantie), skills et MCP (épinglage, aperçu, marqueur, `claude mcp add` à lancer soi-même), dépôts connus non proposés et pourquoi, `source update` et la ligne planifiée, dépannage (« attend ton accord », « rate budget », « base Trivy absente »). Mise à jour des autres docs listées. Relecture FR des `.fr.md`.
- [ ] **Step 3: Run réel** (contrôleur, sur le poste de Kévin, dossier de données jetable, projets enregistrés sous `refN`) : `michel source list`, `source enable osv.packagist osv.npm enrich.kev enrich.epss --yes`, `source update`, `scan --all --update --digest --json`, `source items`, `source show skill.trailofbits-code-audit`, `source install … ` jusqu'à l'aperçu (sans confirmer), `audit verify`. Noter dans `progress.md` **agrégats seulement** : nombre de sources par état, durée de `source update`, lignes KEV/EPSS chargées, nombre de findings KEV trouvés (compte), items « à lire », événements d'audit par action, `egress.attempt` par hôte (comptes), zéro écriture sous les projets (`treeDigest` manuel avant/après).
- [ ] **Step 4: Ledger** — `deferred-and-rulings.md` : rulings et `minor (deferred)` de chaque tâche, risques résiduels (proxy de refus contournable, Semgrep/Trivy mis à jour hors Michel, découverte limitée aux topics, licence détectée par heuristique, catalogue à sha fixe qui vieillit), relecture manuelle anti-trace.
- [ ] **Step 5: Lancer** `go test ./...`, `cd web && npm run test`, `go vet ./...` → PASS ; `git status` propre.
- [ ] **Step 6: Commit** `docs: sources guide, egress inventory, offline notes, plan 4 ledger and real-run aggregates` puis fusion dans `main` (`git merge --no-ff feat/sources`) et `git -c http.sslBackend=schannel push`.

## Self-review (2026-10-26)

- **Couverture du spec** : § 3 → Task 1 ; § 4.1–4.3 → Task 2 ; § 5.1–5.3 → Tasks 3 et 4 ; § 6 → Task 6 ; § 7.1–7.2 → Task 8 ; § 7.3–7.4 → Task 7 ; § 8.1–8.3 → Task 5 ; § 9 → réparti (boundary Task 8, SetRules Task 1, caps dans chaque lecteur, hygiène Task 10) ; § 10 → Task 9 ; § 11 → Task 1 ; § 13 arbitrages 12–16 → Tasks 3, 8, 7, 1.
- **Cohérence des types** : `source.Entry`, `source.Repo`, `sourceupdate.Reader/Budget`, `enrich.Lookup`, `scan.EffectiveSeverity`, `scan.ApplyExternal`, `gitrepo.Deps`, `plugin.RunDeps` nommés une fois et réutilisés tels quels.
- **Ordre** : Task 5 (orchestrateur) précède 6 et 7 grâce au registre de `Reader` ; Task 8 dépend de 1 et 3 (`Finding.Kind`, `Lookup` non requis) ; Task 9 dépend de toutes.
- **Review Focus** : 1 → Task 1 ; 2 → Task 3 ; 3 → Task 6 ; 4 → Task 7 ; 5 → Task 8 : chaque ligne a son test nommé dans la tâche.
- **Proportion** : plan ≈ 1,2 × le design ; les blocs sont des signatures, du SQL et des noms de tests, pas des corps.
