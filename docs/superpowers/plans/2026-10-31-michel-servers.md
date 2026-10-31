# Michel — Plan 6 : le serveur (voir si je suis touché, corriger sans casser)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Depuis la page de Michel, sans commande : trouver ses serveurs (HDS, VPS, mutualisé), lire en SSH ce qui y tourne (versions, réglages PHP), dire s'ils sont touchés (PHP2Shell en tête), prévenir (mail, notification, SMS pour l'urgent), puis corriger les réglages PHP et proposer les mises à jour par deux scripts `appliquer` / `annuler` faits d'actions sûres, validés par l'utilisateur, avec retour arrière automatique.

**Architecture:** Paquets nouveaux : `internal/target` (serveurs, liens projets, inventaire, découverte), `internal/sshx` (client SSH par la passerelle, agent SSH, clés d'hôte ; `sshx/sshtest` serveur de test en mémoire), `internal/collect` (commandes de lecture fermées, parseurs, masquage avant stockage), `internal/serverrules` (règles embarquées versionnées : réglages PHP, PHP amont), `internal/vulnmatch` (paquets du système contre les bases OSV des distributions), `internal/serverfix` (grammaire d'actions, rendu des scripts, empreinte, exécution, retour arrière). `internal/fix` étendu aux findings serveur ; outil MCP `propose_server_fix`. Migration `0011_targets.sql`. Routes `/api/v1/targets…` ; page « Serveurs » et page « Corriger » étendue.

**Tech Stack:** Go 1.27.3 ; nouvelle dépendance directe `golang.org/x/crypto` (`ssh`, `ssh/agent`, `ssh/knownhosts`, déjà présent en indirect v0.58.0) et `github.com/Microsoft/go-winio` (tube nommé de l'agent OpenSSH Windows, déjà indirect) ; comparaison de versions des distributions par `github.com/google/osv-scalibr/semantic` (déjà dans le graphe via osv-scanner ; le builder vérifie) ; SQLite via `internal/store` ; Vue 3.5 + Vuetify 4.3, Options API, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-31-michel-plan6-servers-design.md` (§ 3 décisions, § 4 Target et découverte, § 5 SSH, § 6 collecte, § 7 touché ?, § 7.2 PHP2Shell, § 8 scripts, § 8.1 bis précisions, § 9 niveaux, § 10 alertes, § 11 pages, § 12 API/CLI/migration/audit, § 13 arbitrages) ; plan 5 `2026-10-30-michel-plan5-fix-agent-design.md` § 7-9 ; design v1 § 4.9, § 4.12 ; politique `docs/security/sovereignty-policy.md`.

## Global Constraints

- Mêmes règles que le plan 5 (`docs/superpowers/plans/2026-10-30-michel-fix-agent.md`, Global Constraints) : module `github.com/kvarot/michel` ; anglais pour code/commits/CLI ; textes via `internal/i18n` (EN référence, FR à la main, **tutoiement**, `tutoiement_test.go`, `keys_test.go` : préfixes dynamiques à ajouter dans `dynamicPrefixes`) ; Windows et Linux bloquants ; Conventional Commits + trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` ; SQL portable PostgreSQL ; ULID ; sous-processus en argv fermé ; minimisation (aucun chemin absolu du poste, secret ni contenu de config dans API, canaux, audit).
- Branche `feat/servers` créée au début de la Task 1 depuis la pointe de `docs/plan6-design`. Chaque tâche finit par `go test ./...` vert, un commit, un push (`git -c http.sslBackend=schannel push`), et la copie du ledger dans `docs/superpowers/sdd/2026-10-31-michel-servers/ledger.md`. `go` dans `%LOCALAPPDATA%\Programs\go\bin`.
- **Aucune trace des projets ou serveurs privés** : fixtures `demo`, `srv-demo`, `example.test`, IP de documentation (`192.0.2.0/24`, `198.51.100.0/24`) ; `go test ./internal/hygiene/` vert ; ledger en agrégats.
- **Jamais de vrai serveur dans les tests automatiques** : tout passe par `sshx/sshtest` (serveur SSH en mémoire, système de fichiers et commandes simulés). Jamais le vrai `~/.ssh` ni le vrai agent SSH dans les tests (HOME et socket/tube temporaires).
- **Réseau** : SSH par `egress.Gateway.DialContext(ctx, "target.ssh", "tcp", addr)` puis `ssh.NewClientConn` — jamais `ssh.Dial`, jamais `net.Dialer{}` ; GET du site par `Gateway.Client("target.http")` ; SMS par `Gateway.Client("notify.sms")`. Purposes ajoutés à `internal/policy` ; `boundary_test.go` liste aussi `internal/sshx`, `internal/collect`, `internal/serverfix`.
- **Écritures sur le poste** : dossier de données de Michel seulement (sauvegardes chiffrées `secret.Protect`), plus le fichier de politique (règles `allow`) ; lecture seule de `~/.ssh/config`, `~/.ssh/known_hosts` et des `.idea/*.xml` des projets suivis — jamais d'écriture dans un projet ni dans `~/.ssh`.
- **Écritures sur un serveur** : uniquement par un script validé (empreinte) ; seules actions : `backup_file`, `set_directive`, `test_config`, `reload_service`, `package_upgrade` (+ `check_site` côté poste) ; **aucune suppression** ; fichiers cibles : `php.ini` chargé, pool PHP-FPM, `.user.ini` (décision Kévin, spec § 3.11) ; sauvegardes dans `~/.michel/backups/<correction>/`.
- **L'agent n'a jamais d'accès SSH**, ne voit que l'inventaire masqué, propose des actions typées ; `health` (serveurs `hds`) ⇒ agent refusé.
- Plafonds : session SSH 60 s par commande, 5 min par collecte ; sortie 1 Mio par commande ; fichier de config lu ≤ 256 Kio ; SMS ≤ 3 par jour ; rétention des sauvegardes sur le poste 90 jours ; `check_interval` défaut 24 h.
- Front : Options API, JS + JSDoc, `web/src/i18n/{fr,en}.json`, fetch seulement `/api/v1`.
- Relecture FR : toute tâche qui crée ou modifie un texte FR dispatche le relecteur francophone non spécialiste **avant** la revue de code.

## Review Focus

1. Clé d'hôte qui change entre deux connexions (serveur réinstallé ou attaque) : connexion bloquée avant toute commande, message clair, rien d'exécuté. Test : Task 2 `TestChangedHostKeyBlocksBeforeAnyCommand`.
2. Valeur ou chemin hostile dans une proposition (agent manipulé : `Off'; rm -rf / #`, retour à la ligne, `$(…)`, chemin `../../etc/passwd`, chemin non collecté) : action refusée ou valeur échappée ; aucun script produit ne contient de commande hors grammaire. Tests : Task 9 `TestRenderEscapesHostileValues`, `TestRejectPathNotInInventory`, `FuzzRenderedScriptStaysInGrammar`.
3. Site qui ne répond plus après le rechargement : `annuler` lancé tout de suite, site revérifié, alerte urgente ; avec `executor: user`, alerte « lance annuler maintenant ». Test : Task 10 `TestSiteDownTriggersRollback`, `TestUserExecutorSiteDownAlerts`.
4. Config collectée contenant un mot de passe de base (`mysqli.default_pw`, DSN dans un pool FPM `env[DATABASE_URL]`) : jamais en base en clair, jamais dans l'API, jamais montrée à l'agent. Tests : Task 4 `TestCollectedSecretsNeverStored`, Task 11 `TestInventoryResponseHasNoSecret`.
5. PHP de la ligne de commande différent de celui du site (FPM 8.2 vs CLI 8.3, `.user.ini`) : les deux sont lus et jugés séparément ; si seul le CLI est vu, la fiche le dit. Test : Task 4 `TestCLIAndFPMReportedSeparately`, Task 5 `TestFPMVersionJudgedNotCLI`.

---

### Task 1: Migration `0011`, modèle `target`, purposes

**Files:**
- Create: `internal/store/migrations/0011_targets.sql`, `internal/target/target.go`, `internal/target/repo.go`, `internal/target/repo_test.go`
- Modify: `internal/project/project.go` + `repo.go` (retrait de `ServerFixLevel`), `internal/api/views.go` + `handlers.go` (`PATCH /projects/{name}` sans `server_fix_level`), `internal/cli/project.go` (retrait `--server-fix-level`), `internal/policy/policy.go` (purposes), `internal/egress/boundary_test.go` (dossiers parcourus)

**Interfaces:**
- Produces: `target.Kind` (`KindHDS="hds"`, `KindVPS="vps"`, `KindShared="shared"`) ; `target.Env` (`EnvProd="prod"`, `EnvPreprod="preprod"`, `EnvDev="dev"`) ; `target.Executor` (`ExecUser="user"`, `ExecMichel="michel"`) ; `target.SudoMode` (`SudoNone="none"`, `SudoNopasswd="nopasswd"`) ; `target.Target{ID, Name, Host string; Port int; User, Alias, HostKey string; Kind Kind; Env Env; Classification policy.Classification; FixLevel int; CheckInterval time.Duration; PreprodID string; Executor Executor; Sudo SudoMode; SiteURL string; AutoConfig bool; Active bool; LastCheckAt time.Time; CreatedAt time.Time}` (Kind `hds` ⇒ Classification `health`, refus de toute autre valeur : `ErrHDSIsHealth`) ; `target.Link{TargetID, ProjectID, RemoteDir string}` ; `target.Inventory{TargetID string; At time.Time; OS OSInfo; PHP []PHPRuntime; Web []WebServer; Packages []Package; Directives []Directive; Files []FileSeen; Unseen []Unseen}` (types détaillés Task 4) ; `target.NewRepo(s) *Repo` avec `Add`, `Get(ctx, idOrName)`, `List`, `Update`, `Remove`, `SetHostKey(ctx, id, fp string)`, `Link(ctx, Link)`, `Unlink`, `Links(ctx, targetID)`, `TargetsOfProject(ctx, projectID)`, `SaveInventory(ctx, Inventory) error`, `LatestInventory(ctx, targetID) (Inventory, bool, error)`, `Due(ctx, now) ([]Target, error)` (actifs dont `LastCheckAt+CheckInterval ≤ now`, `CheckInterval=0` = à la main seulement).
- Produces: `policy.PurposeTargetSSH="target.ssh"`, `policy.PurposeTargetHTTP="target.http"`, `policy.PurposeNotifySMS="notify.sms"`.
- **Ruling de schéma** (spec § 4) : un finding serveur garde `finding.project_id = target.id` (colonne NOT NULL existante ; les ULID ne se chevauchent pas) et `finding.kind ∈ {server_package, server_config}` ; idem `fix_attempt.project_id`. `target.IsTargetID(ctx, id) bool` sert aux lectures pour ne jamais mélanger projet et serveur (les listes de projets filtrent `kind NOT LIKE 'server_%'`).
- `0011_targets.sql` : `target`, `target_project (target_id, project_id, remote_dir, PK(target_id, project_id))`, `target_inventory (target_id, at, body TEXT JSON sans secret)`, `server_backup (id, attempt_id, target_id, remote_path, sha256, blob TEXT chiffré base64, created_at)`, `server_snapshot_ack (attempt_id PK, at, actor)`, colonne `fix_proposal.scripts TEXT NOT NULL DEFAULT ''` (JSON `serverfix.Bundle`, Task 9) ; `ALTER TABLE project DROP COLUMN server_fix_level`.

- [ ] **Step 1: Branche** `git checkout docs/plan6-design && git checkout -b feat/servers && git -c http.sslBackend=schannel push -u origin feat/servers`.
- [ ] **Step 2: Tests** `TestTargetHDSForcesHealth` (Kind hds + Classification sensitive ⇒ `ErrHDSIsHealth` ; Kind hds sans classification ⇒ health), `TestTargetFixLevelRange` (4 ⇒ `ErrInvalidFixLevel`), `TestLinkTargetProject`, `TestInventoryRoundTrip`, `TestDueRespectsInterval` (24 h, 0 = jamais), `TestProjectListIgnoresServerFindings`, `TestMigration0011DropsServerFixLevel`, API `TestPatchProjectRejectsServerFixLevel` (champ inconnu ⇒ 400).
- [ ] **Step 3: Lancer** `go test ./internal/target/ ./internal/project/ ./internal/api/` → FAIL ; **Step 4: Implémenter** ; **Step 5: Lancer** `go test ./...` → PASS.
- [ ] **Step 6: Commit** `feat(target): servers model, project links, inventory storage, ssh/http/sms purposes`.

### Task 2: `internal/sshx` — client SSH par la passerelle, agent, clés d'hôte ; `sshx/sshtest`

**Files:**
- Create: `internal/sshx/client.go`, `internal/sshx/agent_windows.go`, `internal/sshx/agent_other.go`, `internal/sshx/hostkey.go`, `internal/sshx/client_test.go`, `internal/sshx/sshtest/server.go` (+ test)
- Modify: `go.mod` / `go.sum` (`golang.org/x/crypto`, `github.com/Microsoft/go-winio` en direct)

**Interfaces:**
- Produces: `sshx.Deps{Gateway *egress.Gateway; Audit *audit.Logger; KnownHosts string (chemin, défaut ~/.ssh/known_hosts); Agent func() (agent.ExtendedAgent, io.Closer, error); Now func() time.Time}` ; `sshx.Dial(ctx, d Deps, t target.Target) (*Client, error)` ; erreurs typées `ErrHostKeyUnknown{Fingerprint string}` (empreinte SHA256 à confirmer), `ErrHostKeyChanged{Want, Got string}`, `ErrNoAgent`, `ErrNoKeyAccepted` (serveur qui n'accepte que le mot de passe), `ErrDenied` (passerelle) ; `sshx.Fingerprint(ctx, d, t) (string, error)` (lit la clé d'hôte sans authentification, pour la confirmation) ; `(*Client).Run(ctx, argv []string, stdin io.Reader) (Result, error)` avec `Result{Stdout, Stderr []byte; Exit int; Truncated bool}` — `argv` quoté par `sshx.Quote` (POSIX, apostrophes), plafonds 1 Mio et 60 s ; `(*Client).Close()` ; audit `target.connect` (cible, utilisateur, empreinte, durée, résultat) à la fermeture.
- Agent : Windows `\\.\pipe\openssh-ssh-agent` par go-winio (chemin réglable `ssh.agent_pipe` pour Pageant en mode OpenSSH) ; ailleurs `SSH_AUTH_SOCK`. Aucune clé privée lue.
- Clé d'hôte : acceptée si `t.HostKey` (empreinte confirmée) ou présente dans `known_hosts` ; inconnue ⇒ `ErrHostKeyUnknown` ; différente ⇒ `ErrHostKeyChanged`, jamais d'acceptation silencieuse.
- `sshtest.New(t *testing.T, opts Options) *Server` : écoute sur `127.0.0.1:0`, clé d'hôte générée, clés clientes acceptées, `Options{Files map[string]string; Commands map[string]Handler; Writable map[string]bool; Sudo bool}` ; exécute `sh -s` sur un mini-interpréteur limité à la grammaire de Task 9 (pour les tests d'exécution) ; journalise chaque commande reçue (`(*Server).Log() []string`) ; `(*Server).Addr()`, `HostKeyFingerprint()`, `NewAgent(t) ` (agent en mémoire + clé cliente).

- [ ] **Step 1: Tests** `TestDialThroughGateway` (règle `allow` `127.0.0.1`/`target.ssh` ⇒ OK ; sans règle ⇒ `ErrDenied`, aucune connexion TCP), `TestUnknownHostKeyReturnsFingerprint`, `TestChangedHostKeyBlocksBeforeAnyCommand` (log du serveur vide), `TestKnownHostsAccepted`, `TestNoAgentIsClear`, `TestPasswordOnlyServer` ⇒ `ErrNoKeyAccepted`, `TestRunQuotesArgv` (argument `a'b; rm x` reçu intact comme un seul argument), `TestRunCapsOutput`, `TestRunTimeout`, `TestConnectAudited` (aucune donnée de sortie dans l'événement).
- [ ] **Step 2: Lancer** `go test ./internal/sshx/...` → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS (dont `boundary_test.go`).
- [ ] **Step 5: Commit** `feat(sshx): ssh client through the egress gateway, agent auth, strict host keys, test server`.

### Task 3: Découverte des serveurs

**Files:**
- Create: `internal/target/discover.go`, `internal/target/sshconfig.go`, `internal/target/phpstorm.go`, `internal/target/discover_test.go`, fixtures `internal/target/testdata/{ssh_config,deployment.xml,webServers.xml}` (hôtes `example.test`, `192.0.2.10`)

**Interfaces:**
- Produces: `target.Candidate{Alias, Host string; Port int; User string; IdentityFile string (chemin relatif à HOME, jamais le contenu); From []string ("ssh_config"|"phpstorm"); Projects []CandidateLink; Known bool (déjà suivi)}` ; `target.CandidateLink{ProjectID, RemoteDir string}` ; `target.Discover(ctx, home string, projects []project.Project, existing []Target) ([]Candidate, error)` ; `target.ParseSSHConfig(r io.Reader) ([]Candidate, error)` (`Host` sans joker, `HostName`, `User`, `Port`, `IdentityFile`, `Include` relatif suivi une fois, profondeur 2) ; `target.ParsePhpStorm(projectRoot string) ([]Candidate, error)` (lit `.idea/webServers.xml` : `webServer` SFTP host/port/user ; `.idea/deployment.xml` : correspondances `deploy` → dossier distant ; aucun mot de passe cherché ; fichier absent = rien).
- Fusion : même `host:port:user` ⇒ un candidat, sources cumulées, liens projets cumulés ; un candidat déjà suivi est `Known`.

- [ ] **Step 1: Tests** `TestParseSSHConfigSkipsWildcards`, `TestParseSSHConfigInclude`, `TestParsePhpStormSFTPAndMappings`, `TestDiscoverMergesSources`, `TestDiscoverMarksKnown`, `TestDiscoverNeverWrites` (`treeDigest` des projets et du HOME de test inchangé), `TestDiscoverIgnoresPasswordFields` (XML avec `password` ⇒ aucune valeur dans le résultat).
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Commit** `feat(target): discover servers from ssh config and phpstorm deployments`.

### Task 4: `internal/collect` — lecture du serveur

**Files:**
- Create: `internal/collect/collect.go`, `internal/collect/commands.go`, `internal/collect/parse.go`, `internal/collect/files.go`, `internal/collect/collect_test.go`, fixtures `internal/collect/testdata/` (sorties `php -v`, `php -i`, `php --ini`, `php-fpm8.2 -i`, `os-release` Debian 12 / Ubuntu 22.04 / Alpine / AlmaLinux, `dpkg-query`, `rpm -qa`, `apk info -v`, `nginx -v`, `apache2 -v`)
- Modify: `internal/target/target.go` (types d'inventaire)

**Interfaces:**
- Produces (dans `target`) : `OSInfo{ID, VersionID, Pretty string}` ; `PHPRuntime{SAPI ("cli"|"fpm"), Binary, Version string; FromPackage string (paquet de distribution propriétaire du binaire, vide si compilé ou mutualisé); Modules []string; LoadedIni string; ScannedDir string; ScannedFiles []string; PoolFiles []string}` ; `WebServer{Name, Version string}` ; `Package{Name, Source, Version, Arch string}` ; `Directive{SAPI, Name, Value, File string; Line int; Secret bool}` (valeur remplacée par `[masqué]` si `Secret`) ; `FileSeen{Path, SHA256 string; Size int}` ; `Unseen{What, Reason string}` (clés i18n `collect.unseen.*`).
- Produces: `collect.Deps{Now func() time.Time; Audit *audit.Logger; Gateway *egress.Gateway}` ; `collect.Run(ctx, d Deps, c Runner, t target.Target, links []target.Link) (target.Inventory, error)` avec `collect.Runner interface{ Run(ctx, argv []string, stdin io.Reader) (sshx.Result, error) }` ; `collect.Commands(t target.Target) [][]string` (liste fermée ; aucun `sudo`) ; audit `target.collect` (comptes : paquets, directives, fichiers, non vus ; empreinte de l'inventaire).
- Commandes (liste fermée, chacune facultative : échec ⇒ `Unseen`) : `cat /etc/os-release`, `uname -r`, `command -v php php-fpm php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5`, `php -v`, `php -m`, `php --ini`, `php -r <script qui sort ini_get_all() en JSON>`, pour chaque FPM trouvé `<fpm> -v` / `<fpm> -i`, `nginx -v`, `apache2 -v`, `httpd -v`, `dpkg-query -W -f '${Package}\t${source:Package}\t${Version}\t${Architecture}\n'`, `rpm -qa --qf '%{NAME}\t%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'`, `apk info -v`, `dpkg -S <binaire php>` / `rpm -qf <binaire>` (propriétaire), `cat <fichier>` pour chaque fichier autorisé.
- Fichiers autorisés : `LoadedIni`, `ScannedFiles`, pools FPM (`/etc/php/*/fpm/pool.d/*.conf` vus par `<fpm> -i` ou `php-fpm -tt`), `<RemoteDir>/.user.ini` et `<RemoteDir>/public/.user.ini` des liens ; plus les chemins ajoutés par l'utilisateur **sauf** cible `health` (refus : `ErrHealthPath`) ; ≤ 256 Kio ; jamais de journaux, de bases, de dossiers.
- Secrets : directives `*password*`, `*_pw`, `*secret*`, `*key*` (hors liste blanche `session.*`, `opcache.*`…), `env[...]` des pools, DSN ⇒ `Secret=true`, valeur non stockée ; contenu des fichiers jamais stocké (empreinte seulement) ; `mask` appliqué à tout texte libre.

- [ ] **Step 1: Tests** (avec `sshtest`) `TestCollectDebianPHPFPM` (Debian 12, PHP CLI 8.2.20 + FPM 8.2.20 paquet `php8.2-fpm`, directives lues), `TestCollectSharedHostingNoPackages` (pas de `dpkg`, PHP compilé ⇒ `FromPackage=""`, `Unseen` « paquets »), `TestCLIAndFPMReportedSeparately` (CLI 8.3.35, FPM 8.2.20 ⇒ deux `PHPRuntime`), `TestOnlyCLISeenIsSaid` (aucun FPM ⇒ `Unseen{collect.unseen.fpm}`), `TestUnreadableIniIsUnseen` (permission ⇒ `Unseen`, aucune autre tentative, aucun `sudo` dans le log du serveur), `TestCollectedSecretsNeverStored` (`mysqli.default_pw=hunter2-demo`, `env[DATABASE_URL]=mysql://u:p@db/x` ⇒ ni `hunter2-demo` ni `u:p` dans l'inventaire JSON ni l'audit), `TestHealthTargetRefusesNonConfigPath`, `TestCommandsAreClosedList` (aucune commande hors liste dans le log), `TestFileSizeCap`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** (`collect.unseen.*`) ; **Step 6: Commit** `feat(collect): read-only server collection with closed commands and masking at source`.

### Task 5: `internal/serverrules` — règles PHP embarquées (réglages, PHP amont, PHP2Shell)

**Files:**
- Create: `internal/serverrules/rules.yaml`, `internal/serverrules/rules.go`, `internal/serverrules/eval.go`, `internal/serverrules/rules_test.go`
- Modify: `internal/scan/normalize.go` (`KindServerPackage="server_package"`, `KindServerConfig="server_config"`, champ `Mitigation bool`, `SAPI string`), `internal/i18n/catalog/{en,fr}.json` (`serverrules.*`, préfixe dynamique)

**Interfaces:**
- Produces: `serverrules.Version` (entier, comme `CatalogVersion`) ; `serverrules.Rules() (Set, error)` ; `Set{Config []ConfigRule; Upstream []UpstreamAdvisory; EOL []Branch}` ; `ConfigRule{ID, Directive, Risky, Advised, Severity string; Context []string ("prod"|"shared"|"https"|"sapi:fpm"…); Mitigates []string (CVE atténuées); Key string (i18n)}` ; `UpstreamAdvisory{ID string; Aliases []string; Severity string; CVSS float64; Branches []BranchFix{Branch, Fixed string}; Mitigations []string (IDs de ConfigRule)}` ; `serverrules.Evaluate(t target.Target, inv target.Inventory, s Set) []scan.Finding` (un finding par runtime et par règle ; `ID = scan.FindingID(t.ID, "<sapi>:<binaire>", "php-upstream"|"php-config", directive|"php", advisoryID|ruleID)`).
- Contenu initial (valeurs revérifiées par le builder au moment de la tâche, spec § 7.2) : PHP2Shell `CVE-2026-109618` et `CVE-2026-109619`, branches 8.2 → 8.2.35, 8.3 → 8.3.36, 8.4 → 8.4.27, 8.5 → 8.5.12, sévérité critique, CVSS 9.2, mitigations `session_upload_progress_off` (et `fatal_error_backtraces_off` pour 8.5) ; règles `display_errors_prod` (On en prod), `expose_php` (On), `allow_url_include` (On), `open_basedir_shared` (vide en mutualisé), `session_cookie_secure` (Off avec `site_url` https), `session_upload_progress_off` (On ⇒ conseillé 0, `Mitigates` PHP2Shell, `Mitigation: true`) ; branches en fin de support. **Jamais `memory_limit=-1`** (test).
- Règle : un runtime avec `FromPackage ≠ ""` n'est **pas** jugé par `Upstream` (les distributions corrigent sans changer le numéro amont : c'est `vulnmatch`, Task 6) ; un runtime compilé/mutualisé l'est.
- KEV/EPSS : les findings portent les CVE en `Aliases` ; l'enrichissement existant (plan 4) les marque KEV.

- [ ] **Step 1: Tests** `TestPHP2ShellUpstreamVulnerable` (8.3.35 compilé ⇒ finding `server_package` critique, alias les deux CVE), `TestPHP2ShellFixed` (8.3.36 ⇒ rien), `TestDistroPHPNotJudgedUpstream` (`FromPackage=php8.3-fpm` ⇒ aucun finding amont), `TestFPMVersionJudgedNotCLI` (CLI 8.3.36, FPM compilé 8.2.34 ⇒ finding sur `fpm`), `TestDisplayErrorsOnlyInProd`, `TestUploadProgressIsMitigationOnly` (finding `server_config` avec `Mitigation=true`, la faille amont reste ouverte), `TestNeverAdvisesMemoryLimitMinusOne` (aucune règle `Advised: "-1"` sur `memory_limit`), `TestRulesYAMLVersionMatches`, `TestEveryRuleHasEnAndFrText`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** (explications des règles) ; **Step 6: Commit** `feat(serverrules): embedded php config and upstream rules, php2shell`.

### Task 6: `internal/vulnmatch` — paquets du système contre OSV des distributions

**Files:**
- Create: `internal/vulnmatch/match.go`, `internal/vulnmatch/ecosystem.go`, `internal/vulnmatch/match_test.go`, fixture `internal/vulnmatch/testdata/osv/Debian/all.zip` (2-3 avis fabriqués, `DSA-0000-1` sur `php8.2`)

**Interfaces:**
- Consumes: `osvdb.ZipPath(root, ecosystem)`, `osvdb.Enabled`, `source.Repo.SetEnabled`.
- Produces: `vulnmatch.Ecosystem(os target.OSInfo) (eco string, ok bool)` (`debian` 12 ⇒ `"Debian:12"`, `ubuntu` 22.04 ⇒ `"Ubuntu:22.04:LTS"`, `alpine` 3.19.1 ⇒ `"Alpine:v3.19"`, `almalinux` 9 ⇒ `"AlmaLinux:9"`, `rocky` ⇒ `"Rocky Linux:9"`) ; `vulnmatch.CatalogKey(eco string) string` (`"Debian:12"` ⇒ `"osv.debian"`) ; `vulnmatch.Match(ctx, osvRoot, eco string, pkgs []target.Package) ([]Hit, error)` avec `Hit{Package target.Package; OSVID string; Aliases []string; Severity string; CVSS float64; Fixed string}` — lecture des avis du zip, plages `ECOSYSTEM` comparées par `osv-scalibr/semantic` selon l'écosystème, par paquet **source** quand l'avis le demande ; `vulnmatch.Findings(t target.Target, hits []Hit) []scan.Finding` (`KindServerPackage`).
- Base absente ou source désactivée : `ErrSourceDisabled{Key}` — la fiche serveur propose d'activer la source (écran d'accord existant du plan 4).

- [ ] **Step 1: Tests** `TestEcosystemFromOSRelease` (table), `TestMatchDebianSourcePackage`, `TestMatchFixedVersionNotReported`, `TestDebianEpochComparison` (`1:8.2.20-1` > `8.2.99`), `TestMissingDatabaseIsSourceDisabled`, `TestFindingsAreServerPackage`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Commit** `feat(vulnmatch): match server os packages against distribution osv databases`.

### Task 7: Vérification d'un serveur, statuts, planification, recomparaison hors ligne

**Files:**
- Create: `internal/target/check.go`, `internal/target/findings.go`, `internal/target/schedule.go`, `internal/target/check_test.go`
- Modify: `internal/scan/repo.go` (fonction exportée `ApplyServerFindings(ctx, tx, targetID, runID string, now time.Time, fs []Finding) (newN, still, gone int, err error)` qui réutilise la logique `apply` des statuts du plan 3), `internal/sourceupdate` (après mise à jour d'une base OSV : `target.Rematch`), `internal/cli/serve.go` (planificateur)

**Interfaces:**
- Produces: `target.CheckDeps{Repo *Repo; Store *store.Store; SSH sshx.Deps; Collect collect.Deps; OSVRoot string; Sources *source.Repo; Rules func() (serverrules.Set, error); Alert func(ctx, AlertInput); Now func() time.Time}` ; `target.Check(ctx, d CheckDeps, targetID string) (CheckResult, error)` (connexion, collecte, `Evaluate`, `vulnmatch`, `ApplyServerFindings`, `LastCheckAt`) ; `CheckResult{New, Still, Gone int; Unseen int; SourceToEnable string; Touched bool}` ; `target.Rematch(ctx, d CheckDeps) (int, error)` (sur le dernier inventaire stocké de chaque serveur, **sans connexion** ; nouveaux findings graves ⇒ `Alert`) ; `target.Scheduler(ctx, d CheckDeps, every time.Duration)` (boucle : `Due` puis `Check`, un serveur à la fois) ; `target.AlertInput{Target Target; New []scan.Finding; Urgent bool; Kind ("new"|"rollback_failed"|"rolled_back"|"applied_auto")}` ; `target.Urgent(t Target, f scan.Finding) bool` (`t.Env == prod` et (`f.KEV` ou sévérité critique)).
- Statuts : mêmes que le code (plan 3) ; `gone` quand une collecte ne voit plus le problème sans correction de Michel ; `proven_fixed` posé par Task 10.

- [ ] **Step 1: Tests** (sshtest + règles de test) `TestCheckCreatesFindingsAndAlertsUrgent` (prod + PHP2Shell ⇒ `Urgent`), `TestCheckPreprodNotUrgent`, `TestSecondCheckKeepsStatuses` (`new` → `pending`, pas de doublon), `TestFindingGoneWhenFixedOutsideMichel`, `TestRematchWithoutConnection` (aucune connexion dans l'audit), `TestSchedulerRunsDueOnly`, `TestHostKeyChangedCheckFailsClearly` (aucun finding changé), `TestCheckProposesDistroSource`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Commit** `feat(target): server check, finding statuses, schedule and offline rematch`.

### Task 8: Alertes serveur et canal SMS

**Files:**
- Create: `internal/notify/sms.go`, `internal/notify/server.go`, `internal/notify/sms_test.go`
- Modify: `internal/policy/policy.go` + `validate.go` (`ChannelSMS="sms"`, `ChannelConfig.Provider ("freemobile"|"generic")`, `User`, `URL`, `Secret` ; `Urgent bool` par canal ; `NotifyConfig.SMSPerDay` défaut 3), `internal/notify/notify.go` (`New` construit le canal SMS), `internal/digest` (section « Serveurs » : touchés, corrigés, annulés), `internal/i18n/catalog/{en,fr}.json`, `config.example.yaml`

**Interfaces:**
- Produces: `notify.SendServerAlert(ctx, ns []Notifier, in target.AlertInput, pageURL string, now time.Time) []Delivery` (texte court : « Serveur <nom> : 1 faille grave », lien ; jamais de version, chemin ni réglage) ; SMS envoyé seulement si `in.Urgent` ou `Kind=rollback_failed`, et canal `Urgent` vrai, et compteur du jour < `SMSPerDay` (compteur dans le store) ; Free Mobile : `GET https://smsapi.free-mobile.fr/sendmsg?user=…&pass=…&msg=…` (identifiants depuis `secret.Store`, jamais journalisés ; l'URL avec secret n'apparaît ni dans l'audit ni dans les erreurs) ; générique : `POST` JSON `{text}` sur `URL` avec HMAC comme le webhook ; purpose `notify.sms`.

- [ ] **Step 1: Tests** `TestSMSOnlyWhenUrgent`, `TestSMSDailyCap`, `TestFreeMobileSecretNeverInErrorOrAudit` (serveur HTTP de test qui renvoie 500 ⇒ l'erreur ne contient pas le mot de passe), `TestServerAlertHasNoDetail`, `TestDigestServersSection`, `TestSMSChannelValidation`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** ; **Step 6: Commit** `feat(notify): server alerts and sms channel for urgent cases`.

### Task 9: `internal/serverfix` — actions, scripts, empreinte

**Files:**
- Create: `internal/serverfix/action.go`, `internal/serverfix/validate.go`, `internal/serverfix/render.go`, `internal/serverfix/ini.go`, `internal/serverfix/simulate.go`, `internal/serverfix/serverfix_test.go`, `internal/serverfix/fuzz_test.go`

**Interfaces:**
- Produces: `serverfix.Op` (`OpBackup="backup_file"`, `OpSetDirective="set_directive"`, `OpTestConfig="test_config"`, `OpReload="reload_service"`, `OpPackageUpgrade="package_upgrade"`, `OpCheckSite="check_site"`) ; `serverfix.Action{Op Op; Path, Directive, Value, Service, Package, Version, SAPI string}` ; `serverfix.Plan{TargetID, FindingID string; Actions []Action; Mitigation bool; NeedsSnapshot bool}` ; `serverfix.Validate(p Plan, t target.Target, inv target.Inventory) (Plan, error)` (normalise ; ajoute `backup_file` avant chaque écriture, `test_config` et `reload_service` après ; refus typés `ErrPathNotAllowed` (chemin hors `LoadedIni`/`ScannedFiles`/pools/`.user.ini` des liens, ou `..`), `ErrBadValue` (caractères de contrôle, retour à la ligne, `;` de commentaire ini non échappable), `ErrUnknownDirective`, `ErrUnknownService`, `ErrUnknownPackage`, `ErrMajorUpgrade` (changement de branche PHP ⇒ proposition seulement)) ; `serverfix.Place(inv, sapi, directive string) (path string, line int, appendLine bool)` (fichier où PHP lit la directive, sinon ajout à la fin du `php.ini` chargé ou du `.user.ini`, jamais nouveau fichier dans `conf.d`) ; `serverfix.Render(p Plan, t target.Target, correctionID string) (Bundle, error)` ; `Bundle{Apply, Undo, Explain string; Checks []Action (check_site…); Hash string}` (`Hash` = SHA-256 de `Apply`+`Undo`+`Checks` canoniques) ; `serverfix.ParseSimulation(manager, out string) (SimResult, error)` avec `SimResult{Upgrades []string; Removes []string; Installs []string}` ; `ErrWouldRemove{Packages []string}`.
- Rendu (`Apply`) : `#!/bin/sh`, `set -eu`, dossier `$HOME/.michel/backups/<correctionID>` (`mkdir -p`), vérification d'écriture de chaque fichier avant toute modification (sinon `echo "lance ce script en root" >&2; exit 3`), `trap` qui remet les sauvegardes et recharge si une étape échoue après modification, modification de directive par `sed` d'une ligne exacte ou `printf >>` (valeurs échappées en apostrophes POSIX), test de config, `sudo -n` en préfixe seulement si `t.Sudo == nopasswd`. `Undo` : remise des fichiers sauvegardés (`cp`), test, rechargement ; pour `package_upgrade` : message « retour par ton snapshot », aucun déclassement. Aucun `rm`, `mv` hors sauvegarde, `>` sur un fichier non sauvegardé, `dd`, `truncate`, `find -delete`.
- **Grammaire** : `serverfix.Lint(script string) error` vérifie que chaque ligne non vide correspond à un gabarit de la grammaire ; `Render` l'appelle et échoue sinon.

- [ ] **Step 1: Tests** `TestValidateAddsBackupTestReload`, `TestRejectPathNotInInventory`, `TestRejectDotDotPath`, `TestRenderEscapesHostileValues` (valeur `Off'; rm -rf / #` ⇒ `ErrBadValue` ou présente seulement entre apostrophes échappées ; `Lint` OK ; aucune ligne `rm`), `TestPlaceDirectiveWhereEffective`, `TestPlaceAppendsWhenAbsent`, `TestNoConfDFileCreated`, `TestSudoPrefixOnlyWhenNopasswd`, `TestScriptStopsBeforeChangeWhenNotWritable`, `TestUndoRestoresBackups`, `TestPackageUndoSaysSnapshot`, `TestSimulationWithRemovalIsRefused` (sortie `apt-get -s` avec `Remv` ⇒ `ErrWouldRemove`), `TestMajorUpgradeIsProposalOnly`, `TestHashCoversBothScriptsAndChecks`, `FuzzRenderedScriptStaysInGrammar` (valeurs aléatoires ⇒ soit erreur, soit `Lint` OK et aucune commande de suppression), `TestScriptsRunOnSSHTest` (exécution réelle de `Apply` puis `Undo` sur `sshtest` : fichier modifié puis restauré à l'identique).
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./internal/serverfix/ && go test -run=^$ -fuzz=FuzzRenderedScriptStaysInGrammar -fuzztime=30s ./internal/serverfix/` → PASS ; `go test ./...` → PASS.
- [ ] **Step 5: Commit** `feat(serverfix): typed safe actions, apply and undo scripts, grammar lint, hash`.

### Task 10: Correction serveur préparée par Michel : proposer, valider, exécuter, annuler, prouver

**Files:**
- Create: `internal/fix/server.go`, `internal/fix/server_exec.go`, `internal/fix/server_test.go`
- Modify: `internal/fix/service.go` (aiguillage `Start`/`Approve`/`Apply` selon `finding.kind`), `internal/fix/fix.go` (`Proposal.Scripts *serverfix.Bundle`, `Proposal.Steps []StepResult`), `internal/fix/repo.go` (sauvegardes, accusé snapshot), `internal/i18n/catalog/{en,fr}.json` (`fix.server.*`)

**Interfaces:**
- Consumes: Tasks 1, 2, 4, 7, 9.
- Produces: `fix.Deps` étendu : `Targets *target.Repo; SSH sshx.Deps; CheckServer func(ctx, targetID string) (target.CheckResult, error); SiteCheck func(ctx, url string) error (GET par target.http, 2xx/3xx et corps non vide); Alert func(ctx, target.AlertInput)` ; `fix.StartServer(ctx, d, findingID string) (Attempt, error)` (Michel construit le `serverfix.Plan` depuis la règle ou l'avis ; mise à jour de paquet : simulation par SSH d'abord ; propose ; `ErrNeedsAgent` si aucune correction déterministe) ; `fix.SnapshotDone(ctx, d, attemptID, actor string) error` (audit `server_fix.snapshot_done`) ; `fix.Approve` refuse un plan `NeedsSnapshot` sans accusé (`ErrSnapshotRequired`) ; exécution `executor: michel` : `serverfix.Bundle.Hash` revérifié juste avant l'envoi, `Apply` par `sh -s` sur l'entrée standard, `StepResult{Op, OK bool, Detail string}` en flux, puis `Checks` depuis le poste, puis `CheckServer` ; site KO ⇒ `Undo` immédiat, `SiteCheck` à nouveau, état `failed` cause `fix.server.rolled_back`, `Alert{Kind: rolled_back}` ; `Undo` KO ⇒ `Alert{Kind: rollback_failed, Urgent: true}` avec la liste des sauvegardes ; `executor: user` : état `approved` en attente, `fix.AppliedByMe(ctx, d, attemptID) error` lance `Checks` + `CheckServer` ; site KO ⇒ alerte urgente « lance annuler maintenant » ; sauvegardes rapatriées (`cat` des fichiers de `~/.michel/backups/<id>/`) et stockées chiffrées (`server_backup`), purge > 90 jours ; preuve : `proven_fixed` si la collecte ne voit plus le finding **et** site OK (si `SiteURL`), sinon `inconclusive`. Audit : `server_fix.propose`, `server_fix.approve`, `server_fix.apply`, `server_fix.rollback`, `server_fix.proven` (empreintes, jamais de contenu).
- **Préprod d'abord** : `t.PreprodID ≠ ""` ⇒ `StartServer` crée la correction sur la préprod ; à `proven_fixed` en préprod, Michel crée la correction de la prod reconstruite depuis l'inventaire de la prod (nouvelle empreinte), qui attend sa propre validation.

- [ ] **Step 1: Tests** (sshtest) `TestServerConfigFixEndToEnd` (`expose_php` On ⇒ proposition, Valider, script exécuté, collecte ⇒ `proven_fixed`, fichier serveur modifié, sauvegarde stockée chiffrée), `TestApproveNeedsSnapshotForPackages`, `TestHashRecheckedBeforeSend` (bundle modifié en base ⇒ refus, rien envoyé), `TestSiteDownTriggersRollback` (fichier restauré à l'identique, état `failed`, alerte `rolled_back`), `TestRollbackFailureAlertsUrgent`, `TestUserExecutorWaitsForAppliedByMe`, `TestUserExecutorSiteDownAlerts`, `TestPreprodFirstThenProdRebuilt` (chemins différents en prod ⇒ nouvelle empreinte, prod non exécutée sans Valider), `TestMitigationKeepsUpstreamOpen` (PHP2Shell : `session.upload_progress.enabled=0` appliqué ⇒ finding de config `proven_fixed`, finding amont toujours ouvert), `TestSimulationRemovalRefusesPlan`, `TestBackupsPurgedAfter90Days`, `TestServerAuditHasNoConfigContent`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** ; **Step 6: Commit** `feat(fix): deterministic server fixes with validated scripts, rollback and proof`.

### Task 11: Agent pour le serveur, `propose_server_fix`, accord par serveur, niveaux 2 et 3

**Files:**
- Create: `internal/fix/server_agent.go`, `internal/fix/server_auto.go`, `internal/fix/server_agent_test.go`
- Modify: `internal/mcp/tools.go` (+ `mcp_test.go`), `internal/fix/consent.go` (accord par serveur), `internal/fix/prompt.go` (consigne serveur : inventaire masqué fourni comme données non fiables), `internal/fix/queue.go` (éligibilité serveur), `internal/i18n/catalog/{en,fr}.json`

**Interfaces:**
- Produces: outil MCP `propose_server_fix` (schéma : `summary`, `actions[]` avec les seuls champs de `serverfix.Action`, `mitigation`) lié au jeton de tentative comme `propose_fix`, disponible seulement pour une tentative serveur ; `get_server_inventory` (inventaire masqué de la cible de la tentative ; jamais de valeur `Secret`, jamais de chemin du poste) ; `fix.StartServerAgent(ctx, d, findingID string) (Attempt, error)` (refus typés `ErrHealthForbidden` pour `hds`/`health`, `ErrConsentRequired`) ; `fix.ProposeServer(ctx, d, attemptID string, in ServerProposeInput) (Proposal, error)` (Michel passe par `serverfix.Validate` + `Render` ; une action refusée ⇒ message à l'agent, pas de proposition) ; `fix.ServerConsentNeeded(t target.Target, pol policy.Policy, consented bool) []ConsentText` (« versions et réglages masqués de ce serveur ») ; `fix.EligibleServer(f scan.Finding, t target.Target, decided func(string) string) bool` (niveau ≥ 2) ; `fix.AutoApplicableServer(t target.Target, p serverfix.Plan, origin string) bool` (toutes requises : `t.FixLevel==3`, `t.AutoConfig`, `t.Executor==michel`, `origin==manual` (Michel, pas l'agent), uniquement `set_directive` issus de `serverrules`, aucun `package_upgrade`, `SiteURL` renseigné, préprod `proven_fixed` si `PreprodID`).
- La vue « agent » n'a aucun outil d'approbation, d'exécution ou de réglage (test existant étendu).

- [ ] **Step 1: Tests** `TestHealthTargetRefusesAgent`, `TestProposeServerRejectsHostileAction` (action avec chemin hors inventaire ⇒ aucune proposition, message à l'agent), `TestInventoryToolHasNoSecret`, `TestServerToolsOnlyForServerAttempts`, `TestMCPStillHasNoApprovalTool`, `TestAutoApplicableServerRules` (table : chaque condition fausse ⇒ faux), `TestLevel2QueuesServerFindings`, `TestPackageUpgradeNeverAuto`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** ; **Step 6: Commit** `feat(fix,mcp): agent-assisted server fixes, per-server consent, levels 2 and 3`.

### Task 12: API et CLI serveurs

**Files:**
- Create: `internal/api/targets.go`, `internal/api/targets_test.go`, `internal/cli/target.go` (+ test)
- Modify: `internal/api/server.go` (`s.targetRoutes()` avant le catch-all ; `target.Scheduler` lancé par `goBackground` avec `serve`), `internal/api/fix.go` (routes snapshot / applied-by-me, vues serveur), `internal/cli/serve.go`, `internal/cli/root.go`

**Interfaces:**
- Produces routes (`/api/v1`, jeton) : `GET /targets`, `POST /targets` (ajout depuis un candidat ou manuel), `GET /targets/{id}` (`TargetView` : réglages, état en une phrase, failles, non vus, projets liés, historique, taille des sauvegardes serveur si connue), `PATCH /targets/{id}`, `DELETE /targets/{id}` (retire le serveur de Michel ; rien sur le serveur), `POST /targets/discover` → candidats, `GET /targets/{id}/hostkey` (empreinte à confirmer), `POST /targets/{id}/hostkey {fingerprint}`, `POST /targets/{id}/check` → 202, `GET /targets/{id}/inventory` (sans secret, sans chemin du poste), `POST /fix/{attempt}/snapshot-done`, `POST /fix/{attempt}/applied-by-me`, `GET /targets/{id}/ai-consent` + `POST`. Erreurs typées (Tasks 2, 4, 9, 10, 11) → messages i18n en clair.
- Produces CLI : `michel target list`, `michel target discover`, `michel target add <alias|host> [--user --port --kind --env]`, `michel target trust <id> --fingerprint`, `michel target check <id>`, `michel target set <id> [--level --executor --sudo --site-url --interval --preprod]`.

- [ ] **Step 1: Tests** `TestTargetRoutesNeedToken`, `TestDiscoverReturnsCandidates`, `TestHostKeyConfirmFlow` (empreinte fausse ⇒ 409), `TestCheckReturns202`, `TestInventoryResponseHasNoSecret`, `TestTargetResponsesHaveNoLocalPaths`, `TestSnapshotDoneThenApprove`, `TestServerRefusalsAreTranslated`, CLI `TestTargetDiscoverAndAdd`, `TestTargetTrustFingerprint`.
- [ ] **Step 2: Lancer** → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `go test ./...` → PASS.
- [ ] **Step 5: Relecture FR** ; **Step 6: Commit** `feat(api,cli): server routes, discovery, host key trust, checks`.

### Task 13: Pages « Serveurs » et « Corriger » pour un serveur

**Files:**
- Create: `internal/sshx/sshtest/cmd/demo/main.go` (serveur de démo : `sshtest` sur un port local, clé cliente ajoutée à un agent de test dont il imprime le chemin, site HTTP local qu'on peut couper), `web/src/components/ServersPage.vue`, `web/src/components/ServerSheet.vue`, `web/src/components/DiscoverServersDialog.vue`, `web/src/components/HostKeyDialog.vue`, `web/src/components/ServerProposal.vue`, `web/src/lib/serversView.js` (+ test)
- Modify: `web/src/App.vue` (`#/servers`, `#/servers/<id>`), `web/src/components/FixPage.vue` (panneau droit serveur), `FixSettings.vue` / `ProjectCard.vue` (retrait de « Corriger le serveur » grisé ; lien vers les serveurs liés), `TodayPage.vue` (serveurs touchés en tête), `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: routes Task 12.
- Produces : page « Serveurs » (spec § 11.1 : liste nom / type / environnement / état en une phrase ; « Trouver mes serveurs » ; fiche : vu, non vu, failles avec « Corriger », historique, réglages en phrases : niveau, qui exécute, préprod, fréquence, `sudo`, adresse du site) ; `ServerProposal` (spec § 11.2 : proposition en clair, étape « Snapshot fait » si besoin, « réduit le risque, ne corrige pas » pour une mitigation, Valider / Refuser, « Voir les scripts » replié avec « Copier », « J'ai appliqué » en `executor: user`, étapes en une ligne pendant l'exécution, retour arrière dit en clair). `serversView.js` : `stateSentence(target, lang)`, `kindLabel`, `envLabel`, `levelLabel`, `stepLine(step, lang)`, `needsSnapshot(proposal)`, `canApproveServer(attempt, proposal)` (faux sans accusé snapshot).
- États vides et erreurs (pas d'agent SSH, clé d'hôte inconnue ou changée, mot de passe seulement, droits insuffisants, source de distribution à activer) : une phrase + quoi faire.

- [ ] **Step 1: Tests vitest** `stateSentence` (touché / rien de connu / pas pu tout voir), `needsSnapshot`, `canApproveServer`, `stepLine` (FR/EN), `levelLabel`.
- [ ] **Step 2: Lancer** `cd web && npm test` → FAIL ; **Step 3: Implémenter** ; **Step 4: Lancer** `npm test` et `npm run build` → PASS ; `go test ./...` → PASS.
- [ ] **Step 5: Vérification manuelle** dans le navigateur intégré : `michel serve` avec un serveur `sshtest` lancé par une commande de démo de test (`go run ./internal/sshx/sshtest/cmd/demo`, Debian 12 + PHP compilé 8.3.35 + `expose_php=On`, site de test local) : trouver, confirmer l'empreinte, vérifier ⇒ PHP2Shell urgent ; corriger `expose_php` ⇒ `proven_fixed` ; site coupé ⇒ retour arrière affiché ; captures notées dans le rapport.
- [ ] **Step 6: Relecture FR** ; **Step 7: Commit** `feat(web): servers page, server sheet, server fix proposal`.

### Task 14: Docs bilingues, run de démonstration, hygiène, ledger

**Files:**
- Create: `docs/servers.md`, `docs/servers.fr.md`, `docs/superpowers/sdd/2026-10-31-michel-servers/{ledger.md,deferred-and-rulings.md}`
- Modify: `docs/security/network-egress.md` + `.fr.md` (`target.ssh`, `target.http`, `notify.sms`), `README.md` + `README.fr.md` (section « Serveurs »), `docs/fix.md` + `.fr.md` (corrections serveur), `config.example.yaml`

- [ ] **Step 1: Docs** — `docs/servers.md` + `.fr.md` : trouver ses serveurs, préparer un utilisateur SSH et une clé pour Michel (agent Windows, Pageant), confirmer l'empreinte, ce que Michel lit et ne lit jamais (HDS), PHP CLI vs FPM, « touché ? » et les sources (OSV des distributions, règles PHP, PHP2Shell), les scripts `appliquer`/`annuler` et la liste des actions (aucune suppression), qui exécute, `sudo`, préprod, snapshot, sauvegardes (et comment les vider soi-même), niveaux, alertes et SMS, dépannage. Relecture FR.
- [ ] **Step 2: Run de démonstration** (contrôleur, dossier de données jetable, serveur `sshtest` de démo et vrai binaire `michel serve`, jamais un serveur réel ni le vrai `~/.ssh`) : découverte, empreinte, vérification, PHP2Shell détecté, alerte (canal de test), correction de config validée et prouvée, retour arrière sur site coupé, `audit verify`. Agrégats seulement dans le ledger. Le run sur un vrai serveur de test de Kévin est noté comme à faire par lui (risque résiduel).
- [ ] **Step 3: Ledger** — rulings, minors différés, risques résiduels (PHP CLI ≠ site non détectable partout, liste PHP amont embarquée à jour seulement avec Michel, agent Pageant non testé, scripts lancés par l'utilisateur hors du contrôle de Michel, nginx/apache seulement signalés).
- [ ] **Step 4: Lancer** `go test ./...`, `go vet ./...`, `cd web && npm test` → PASS ; `git status` propre.
- [ ] **Step 5: Commit** `docs: servers guide, egress inventory, plan 6 ledger and demo-run aggregates`. La fusion dans `main` vient après la revue de branche finale.

## Self-review (2026-10-31)

- **Couverture du spec** : § 4 → Tasks 1, 3 ; § 4.1 → Task 3 ; § 5 → Task 2 ; § 5.3 → Tasks 2, 4, 9 ; § 6 → Task 4 ; § 6.4 → Task 7 ; § 7.1 → Tasks 5, 6 ; § 7.2 PHP2Shell → Tasks 5, 10 ; § 7.3 → Task 7 ; § 8.1 + 8.1 bis → Task 9 ; § 8.2 → Tasks 10, 11 ; § 8.3 → Task 10 ; § 8.4 → Tasks 9, 10 ; § 8.5 → Task 10 ; § 9 → Task 11 ; § 10 → Task 8 ; § 11 → Task 13 ; § 12 → Tasks 1, 12, 14 ; § 13 arbitrages 1-14 → Tasks 4 (1), 2 (2), 1 (3), 3 (4), 10-11 (5), 9 (6, 13), 10 (7, 8, 10), 9-10 (9), 7 (11), 8 (12), 5 (14).
- **Cohérence des types** : `target.Target/Inventory/Candidate`, `sshx.Client/Result`, `collect.Runner`, `serverrules.Set`, `vulnmatch.Hit`, `serverfix.Action/Plan/Bundle`, `fix.StartServer/ProposeServer` définis une fois.
- **Ordre** : 1 (modèle) → 2 (SSH) → 3 (découverte) → 4 (collecte) → 5 (règles) → 6 (paquets OS) → 7 (vérification) → 8 (alertes) → 9 (scripts) → 10 (correction déterministe) → 11 (agent, niveaux) → 12 (API/CLI) → 13 (pages) → 14.
- **Review Focus** : 1 → Task 2 ; 2 → Task 9 ; 3 → Task 10 ; 4 → Tasks 4, 12 ; 5 → Tasks 4, 5.
- **Proportion** : signatures, noms de tests, valeurs du spec ; pas de corps.
