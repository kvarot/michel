# Michel — Plan 7 : les erreurs des serveurs (être prévenu sans copier les journaux)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Michel lit à intervalle régulier, en SSH et sans rien installer, les journaux PHP, PostgreSQL et applicatifs déclarés pour chaque serveur, et prévient de lui-même selon les règles de l'utilisateur ; par défaut, aucun contenu de journal ne quitte le serveur.

**Architecture:** Nouveau paquet `internal/serverlog` : sources, position par fichier, script de filtre généré (`sh` + `awk`) qui trie sur le serveur, revalidation stricte sur le poste, signatures et comptes par heure, règles d'alerte, planificateur. `internal/notify` et `internal/digest` gagnent l'alerte et la section des journaux ; `michel serve` envoie le digest.

**Tech Stack:** Go 1.27.3, aucune nouvelle dépendance ; `sh` et `awk` POSIX côté serveur ; Vue 3 Options API côté page.

**Spec:** `docs/superpowers/specs/2026-11-02-michel-plan7-server-logs-design.md`.

## Global Constraints

- **Démarrage** : exécution seulement après le premier run réel du plan 6 (spec § 12). Branche `feat/server-logs` depuis `main`. Chaque tâche finit par `go test ./...` vert, un commit, un push (`git -c http.sslBackend=schannel push`) et la copie du ledger dans `docs/superpowers/sdd/2026-11-02-michel-server-logs/`.
- Module `github.com/kvarot/michel` ; anglais pour code, commits, CLI ; design et ledger en français.
- **Aucune trace de projet ou serveur privé** : fixtures `demo`, `srv-demo`, `example.test`, IP de documentation ; `go test ./internal/hygiene/` vert ; ledger en agrégats.
- **SQL portable PostgreSQL** : pas de `rowid`, `AUTOINCREMENT`, `datetime()` ; `?` et `ON CONFLICT` ; dates RFC 3339 en `TEXT`.
- **Textes** par `internal/i18n` et `web/src/i18n/{fr,en}.json`, EN référence, FR au **tutoiement**. Toute tâche qui crée ou modifie un texte FR dispatche le relecteur francophone non spécialiste **avant** la revue de code.
- **Réseau** : uniquement par `internal/egress` ; lecture par `sshx.Dial` (purpose `target.ssh`) ; aucun nouveau purpose. **Aucune écriture dans un projet scanné.**
- **Aucune écriture sur un serveur** : le script n'a ni redirection vers un fichier, ni `system`, ni commande `getline`, ni `rm`, ni fichier temporaire. **Jamais de `sudo` pour lire.** Fichier illisible = « non vu ».
- **Jamais de ligne brute** stockée, envoyée, journalisée ou renvoyée par l'API, avec aucun réglage. Jamais d'IP, d'identifiant, d'email, d'URL avec paramètres, même avec le texte nettoyé activé (valeurs remplacées, spec § 7.3).
- **Aucune donnée de journal vers un agent**, sur aucun serveur.
- **Jamais de vrai serveur dans les tests automatiques**. Les tests du filtre exécutent le vrai `sh` et le vrai `awk` sur des fichiers temporaires (`exec.LookPath`, `t.Skip` s'ils manquent) ; `sshx/sshtest` sert aux tests de connexion, avec `Options.Commands` qui délègue au vrai `sh`.
- **Valeurs de la spec** : `log_interval` défaut 5 min, bornes 1 min à 24 h ou `manual` ; plafonds par source et par passage 5 Mio et 30 s, réglables ; alerte « je ne lis plus » après 3 échecs de suite et 30 min ; `resolved` après 7 jours, réglable ; conservation 90 jours, de 7 à 365, jamais sous le délai de `resolved` ; réalerte à 10 fois l'heure précédente et au moins 100 occurrences ; 10 alertes par heure et par serveur ; texte nettoyé plafonné à 200 caractères ; digest à 08:00 par défaut.
- Choix de ce plan, à signaler au ledger : au plus 50 fichiers par source avec joker ; `LC_ALL=C` dans le script ; regroupement `critical/error/warning/info`.
- Front : Options API, JS + JSDoc, fetch seulement `/api/v1`.

## Review Focus

1. **Ligne hostile écrite dans un journal** (un visiteur contrôle une partie du message : tabulation, retour à la ligne, faux `PHP Fatal error`, séquences d'échappement, email dans un faux chemin) : aucun enregistrement forgé n'est accepté, aucune valeur hors schéma n'est stockée. Test : Task 2 `TestForgedLineCannotInjectRecord`.
2. **Journal énorme, ligne sans fin, contenu binaire** : plafond respecté, `awk` ne plante pas, position cohérente, volume non lu signalé. Test : Task 3 `TestHugeLineAndBinaryRespectCap`.
3. **Retour après trois jours de poste éteint** : plafond respecté, trou noté, une seule alerte groupée, aucune rafale. Test : Task 5 `TestReturnAfterDaysOffIsOneAlertAndOneGap`.
4. **Joker et rotation pendant la lecture** (fichier remplacé, tronqué, supprimé, lien symbolique posé à sa place, 5 000 fichiers qui correspondent) : rien hors déclaration n'est lu, l'écart est dit. Test : Task 3 `TestFileSwappedOrTruncatedBetweenReads`, `TestWildcardCapIsReported`.
5. **Digest non livré** (aucun canal, tous les canaux en échec, `serve` et la tâche planifiée en même temps) : la fenêtre « depuis le dernier digest » n'avance pas sans livraison ; aucun élément perdu ni envoyé deux fois. Test : Task 7 `TestServeDigestKeepsWindowWithoutDelivery`, `TestServeAndScheduledTaskSendOnce`.

---

### Task 1: Migration et modèle `serverlog`

**Files:**
- Create: `internal/store/migrations/0018_server_logs.sql`, `internal/serverlog/serverlog.go`, `internal/serverlog/repo.go`, `internal/serverlog/repo_test.go`

**Interfaces:**
- Produces: `Format` (`FormatPHP="php"`, `FormatPostgres="postgres"`, `FormatMonolog="monolog"`, `FormatJSON="json"`, `FormatText="text"`) ; `Level` (`LevelCritical`, `LevelError`, `LevelWarning`, `LevelInfo`) ; `Status` (`new`, `seen`, `resolved`, `reopened`, `ignored`) ; `Route` (`immediate`, `digest`, `ignored`).
- Produces: `Source{ID, TargetID, Path string; Format Format; LevelField, ChannelField, Pattern string; Active bool; CreatedAt time.Time}` ; `Cursor{SourceID, File, FileID string; Offset int64; ReadAt time.Time}` ; `Signature{ID, TargetID, SourceID string; Level Level; Type, Location, Channel string; Status Status; FirstAt, LastAt, LastAlertAt time.Time; Total int64}` ; `Record{Level Level; Type, Location, Channel, Text string; Hour time.Time; Count int64}` ; `Note{TargetID, SourceID, Kind string; From, To time.Time; Amount int64}` avec `Kind` = `gap`, `skipped`, `rotated`, `unseen`, `rejected`, `too_many_files`.
- Produces: `Settings{TargetID string; Interval time.Duration; StoreText, AlertText bool; RetentionDays int; ResolveAfter time.Duration; ReadCap int64; ReadTimeout time.Duration; MaxAlertsPerHour int; SMS bool; Routes map[Level]Route}` ; `DefaultSettings(env target.Env) Settings`.
- Produces: `NewRepo(*store.Store) *Repo` avec `AddSource`, `UpdateSource`, `DeleteSource`, `Sources(ctx, targetID)`, `Cursors`, `SaveCursors`, `Settings`, `SaveSettings`, `Apply(ctx, src Source, recs []Record, now time.Time) (fresh, reopened, spiked []Signature, err error)`, `Signatures(ctx, targetID)`, `SetStatus`, `Resolve(ctx, now)`, `AddNote`, `Notes`, `Purge(ctx, now)`, `EraseTarget(ctx, targetID)`, `EraseText(ctx, targetID)`.

- [ ] **Step 1: Tests `repo_test.go`** : `TestDefaultSettingsMatchSpec` (`prod` : `critical` immédiat, `error` digest, `warning` et `info` ignorés ; `preprod`, `dev` : `critical` et `error` digest ; 5 min, 90 j, 7 j, 5 Mio, 30 s, 10, SMS faux, textes faux) ; `TestSignatureDoesNotDependOnText` (deux `Record` qui ne diffèrent que par `Text` donnent une signature) ; `TestApplyLifecycle` (`new`, puis `resolved` après `ResolveAfter`, puis `reopened` ; un `ignored` reste `ignored` et compte toujours) ; `TestApplySpike` (9 fois l'heure d'avant non, 10 fois avec 99 non, 10 fois avec 100 oui) ; `TestPurgeKeepsIgnoredRowsOnly` ; `TestEraseTargetRemovesEverything`, `ignored` compris ; `TestRetentionFloor` (`SaveSettings` refuse 6 et 366 jours, et une conservation sous `ResolveAfter`).
- [ ] **Step 2: Vérifier l'échec** : `go test ./internal/serverlog/` échoue, paquet absent.
- [ ] **Step 3: Écrire** `0018_server_logs.sql` : `log_source`, `log_cursor` (clé `source_id, file`), `log_settings`, `log_signature` (texte chiffré en `BLOB`, colonne `text_enc`), `log_bucket` (clé `signature_id, hour`), `log_note`, puis modèle et repo. Signature = SHA-256 de (`source_id`, niveau, type, emplacement, canal).
- [ ] **Step 4: Vérifier** : `go test ./internal/serverlog/ ./internal/store/ ./internal/hygiene/` OK.
- [ ] **Step 5: Commit** `feat: server log model and storage`.

### Task 2: Le filtre et sa revalidation

**Files:**
- Create: `internal/serverlog/filter.go`, `internal/serverlog/filter_test.go`, `internal/serverlog/parse.go`, `internal/serverlog/parse_test.go`, `internal/serverlog/testdata/*.log` (corpus fictif, piégé)

**Interfaces:**
- Consumes: Task 1.
- Produces: `FilterOptions{Text bool; RemoteDirs []string; ReadCap int64; MaxFiles int}` ; `Script(src Source, cursors []Cursor, o FilterOptions) (string, error)` ; `FileState{File, FileID string; Offset, Skipped int64; Rotated, First bool}` ; `Output{Files []FileState; Records []Record; Rejected int; Unseen []string; TooManyFiles bool}` ; `ParseOutput(out []byte, src Source, o FilterOptions, now time.Time) Output`.

- [ ] **Step 1: Tests du script** (vrai `sh`, vrai `awk`) par format, avec la table de la spec § 6 :
  - `TestPHPExtractsLevelTypeLocation` : `PHP Fatal error:  Uncaught PDOException: secret in /var/www/demo/app/Invoice.php:42` avec `RemoteDirs` `/var/www/demo` donne `critical`, `PDOException`, `app/Invoice.php:42` ; hors dossier lié, `Invoice.php:42`.
  - `TestPostgresKeepsSeverityAndSqlstateOnly` : avec `%e`, `ERROR`, `23505` ; sans `%e`, sévérité seule ; `DETAIL`, `STATEMENT`, `HINT`, `CONTEXT` ne produisent aucun enregistrement.
  - `TestMonologReadsAnchoredContextOnly` : `[object] (App\Foo(code: 0): valeur at /var/www/demo/src/Foo.php:7)` donne la classe et `src/Foo.php:7`, jamais `valeur`.
  - `TestJSONUsesDeclaredFieldsOnly` et `TestTextCountsByLevelOnly`.
  - `TestDefaultScriptCannotEmitText` : avec `Text=false`, le script ne contient pas `$0` dans un `print`/`printf`, ni le bloc de nettoyage.
  - `TestScriptGrammar` : pour tous les formats, avec et sans texte, aucun `system`, `| getline`, `> `, `>>`, `rm`, `mktemp`, `sudo`, `ssh`, `curl`, `wget`.
  - `TestScriptQuotesHostilePaths` : un chemin avec `'`, `$(…)`, retour à la ligne ou `..` est refusé par `Script` ou correctement échappé.
- [ ] **Step 2: Test du corpus, le test le plus important** : `TestTrapCorpusLeavesNoTrace` : `testdata/trap.log` place noms, emails, IP, numéros de sécurité sociale fictifs, requêtes SQL avec valeurs, jetons et URL avec paramètres dans chaque format. Avec les réglages par défaut, aucun marqueur n'apparaît dans la sortie brute du filtre, ni dans `Output`. `TestCleanedTextRemovesValues` : avec `Text=true`, chaînes entre guillemets, nombres, adresses, emails, URL sont remplacés, longueur ≤ 200.
- [ ] **Step 3: Tests de revalidation** : `TestForgedLineCannotInjectRecord` (tabulation, retour à la ligne, faux enregistrement, séquences ANSI dans une ligne, email dans un faux chemin) ; `TestParseRejectsOutOfSchema` (niveau inconnu, type hors `^[A-Za-z_\\][A-Za-z0-9_\\]{0,127}$`, emplacement absolu, avec `@`, `?`, ou `..`, canal de plus de 64 caractères, nombre négatif, heure à plus de 24 h dans le futur) : ligne jetée, `Rejected` incrémenté, contenu jamais dans `Output`, l'erreur, ni le journal.
- [ ] **Step 4: Vérifier l'échec**, puis **écrire** `Script` et `ParseOutput`. Le script fixe `LC_ALL=C`, vérifie `[ -f ]` et `[ ! -L ]`, lit `ls -di` et `wc -c`, lit par `tail -c +N | head -c MAX`, ne consomme que jusqu'au dernier retour à la ligne, regroupe par (niveau, type, emplacement, canal, heure). Le bloc de nettoyage n'entre dans le script que si `Text`.
- [ ] **Step 5: Vérifier** : `go test ./internal/serverlog/` OK, puis, si présents, avec `dash`, `busybox sh`, `mawk`, `gawk`, `busybox awk` (`TestFilterVariants`, sous-tests sautés si absents, nombre sauté noté au ledger).
- [ ] **Step 6: Commit** `feat: server-side log filter with strict revalidation`.

### Task 3: Lire une source et trouver les journaux

**Files:**
- Create: `internal/serverlog/read.go`, `internal/serverlog/read_test.go`, `internal/serverlog/discover.go`, `internal/serverlog/discover_test.go`, `internal/serverlog/validate.go`, `internal/serverlog/validate_test.go`

**Interfaces:**
- Consumes: `sshx.Client.RunWith`, `target.Repo`, inventaire du plan 6, Task 2.
- Produces: `ValidatePath(p string) error` ; `Candidate{Path string; Format Format; Why string}` ; `Discover(ctx, repo *target.Repo, t target.Target) ([]Candidate, error)` ; `Read(ctx, c *sshx.Client, src Source, cursors []Cursor, o FilterOptions, timeout time.Duration, now time.Time) (Output, []Cursor, error)` ; `Try(ctx, c, src, o, timeout, now) (Output, error)` (ne stocke rien et ne déplace aucune position).

- [ ] **Step 1: Tests** :
  - `TestValidatePathRefusals` : relatif, `..`, joker hors du dernier segment, vide, retour à la ligne.
  - `TestFirstReadStartsAtEnd` : à l'activation, aucun enregistrement de l'historique ; une ligne ajoutée ensuite est lue. Un fichier apparu après l'activation est lu depuis son début.
  - `TestPartialLineWaitsForNextRead`.
  - `TestHugeLineAndBinaryRespectCap` : 20 Mio sans retour à la ligne, octets NUL : `Skipped` > 0, position cohérente.
  - `TestFileSwappedOrTruncatedBetweenReads` : inode changé ou fichier plus court : lecture depuis le début, `Rotated` ; lien symbolique posé à la place ou fichier supprimé : `Unseen`, rien lu.
  - `TestWildcardReadsAllWithOneCursorEach` et `TestWildcardCapIsReported` (51 fichiers : 50 lus, `TooManyFiles`).
  - `TestDeniedFileIsUnseenWithoutSudo` : aucune commande avec `sudo` au journal de `sshtest`.
  - `TestAwkMissingIsUnseen` : aucun repli vers `cat`.
  - `TestTryStoresNothing`.
  - `TestDiscoverProposes` : `error_log` CLI et pools FPM depuis l'inventaire, `/var/log/postgresql/`, `storage/logs/` et `var/log/` sous `target_project`, jamais de source créée.
- [ ] **Step 2: Vérifier l'échec, écrire, vérifier** : `go test ./internal/serverlog/` OK.
- [ ] **Step 3: Commit** `feat: read a declared log source over SSH and propose sources`.

### Task 4: Confidentialité : texte, conservation, écarts

**Files:**
- Create: `internal/serverlog/privacy.go`, `internal/serverlog/privacy_test.go`
- Modify: `internal/serverlog/repo.go`

**Interfaces:**
- Consumes: `mask` (détecteurs), `secret.Protect`, `secret.Unprotect`, Task 1.
- Produces: `Deviations(s Settings) []string` (clés stables : `store_text`, `alert_text`, `retention`) ; `ChangeSettings(ctx, repo *Repo, log *audit.Logger, t target.Target, next Settings, confirmed bool) error` ; `ErrConfirmationNeeded` ; `Purge` et `EraseText` audités (`log.purge`).

- [ ] **Step 1: Tests** : `TestDeviationNeedsConfirmation` ; `TestHDSCanDeviateWithConfirmation` (décision 6 : aucun blocage, `health` dans l'audit) ; `TestAlertTextRequiresStoreText` ; `TestBackToNoneErasesStoredTextNow` (aucun octet de `text_enc`, audit `log.settings` et `log.purge`) ; `TestStoredTextIsEncryptedAndMasked` (un jeton passé dans le texte est masqué, le clair n'est pas en base) ; `TestPurgeAtRetention` ; `TestAuditCarriesNoContent`.
- [ ] **Step 2: Vérifier l'échec, écrire, vérifier** : `go test ./internal/serverlog/` OK.
- [ ] **Step 3: Commit** `feat: server log privacy settings, encrypted text and purge`.

### Task 5: Passage, règles d'alerte, planificateur

**Files:**
- Create: `internal/serverlog/pass.go`, `internal/serverlog/pass_test.go`, `internal/serverlog/schedule.go`, `internal/serverlog/schedule_test.go`
- Modify: `internal/cli/serve.go`, `internal/cli/serve_test.go`

**Interfaces:**
- Consumes: `sshx.Deps`, `target.Repo`, Tasks 1 à 4.
- Produces: `AlertKind` (`AlertNew`, `AlertReopened`, `AlertSpike`, `AlertVolume`, `AlertNotReading`, `AlertCapReached`) ; `AlertInput{Target target.Target; Kind AlertKind; Items []AlertItem; Reason string}` ; `AlertItem{Level Level; Type, Location, Text string; Count int64}` ; `Deps{Repo *Repo; Targets *target.Repo; Audit *audit.Logger; SSH sshx.Deps; Alert func(context.Context, AlertInput); Now func() time.Time}` ; `PassResult{Records, Rejected, Alerts int; Reason string}` ; `Pass(ctx, d Deps, targetID string) (PassResult, error)` ; `Scheduler(ctx, d Deps, every time.Duration)`.

- [ ] **Step 1: Tests de `Pass`** : `TestPassAppliesRoutes` (`critical` en `prod` alerte, `error` non) ; `TestPerSignatureIgnoredStaysSilent` ; `TestNewSignaturesGroupedInOneAlert` ; `TestSpikeRealerts` ; `TestHourlyCapThenOneMessage` (10 puis un `AlertCapReached`) ; `TestAuditLogReadHasNoContent` (`log.read` : serveur, source, fenêtre, volume, enregistrements, empreinte) ; `TestAlertTextOnlyWhenAllowed`.
- [ ] **Step 2: Tests de lecture manquée** : `TestNotReadingAfterThreeFailuresAnd30Min` (2 échecs non, 3 échecs en 20 min non, une alerte ensuite, une seule par incident, nouvel incident après une réussite) ; `TestNotReadingRouteByEnv` (immédiat `prod`, digest ailleurs) ; `TestNotReadingIgnoresHourlyCap` ; `TestLockedAgentIsOneAlert` (`no_agent` sur 3 serveurs = une alerte) ; `TestVolumeFollowsErrorRoute` ; `TestReturnAfterDaysOffIsOneAlertAndOneGap`.
- [ ] **Step 3: Tests du planificateur** : `TestSchedulerRespectsInterval` et `manual` ; `TestNoSourceNoConnection` (`sshtest.Accepted()` à 0) ; `TestInactiveTargetSkipped` ; `TestSameServerNeverTwiceAtOnce` ; `TestSlowServerDoesNotBlockOthers` (au plus 4 en parallèle) ; `TestServeStartsAndStopsLogScheduler` dans `internal/cli/serve_test.go`.
- [ ] **Step 4: Vérifier l'échec, écrire, vérifier** : `go test ./internal/serverlog/ ./internal/cli/` OK.
- [ ] **Step 5: Commit** `feat: server log passes, alert rules and scheduler`.

### Task 6: Alertes sur les canaux

**Files:**
- Create: `internal/notify/serverlog.go`, `internal/notify/serverlog_test.go`
- Modify: `internal/cli/serve.go`, catalogue `internal/i18n`

**Interfaces:**
- Consumes: `serverlog.AlertInput`, `Notifier`, `Scoped`, `messenger`, `webhook.marked`, `sms.alert`.
- Produces: `SendLogAlert(ctx, ns []Notifier, in serverlog.AlertInput, smsAllowed bool, pageURL string, now time.Time) []Delivery`. Marqueur webhook `michel_server_log_alert`.

- [ ] **Step 1: Tests** : `TestLogAlertExactDefaultBody` contient `PDOException`, `Invoice.php:42`, `37`, le nom du serveur et le lien ; `TestLogAlertNoTextByDefault` ; `TestLogAlertTextWhenAllowed` ; `TestLogSMSOffByDefault` ; `TestLogSMSRespectsDailyCap` ; `TestScopedChannelSkipped` ; `TestWebhookMarker` ; `TestNotReadingMessageSaysWhy`, sans hôte ni utilisateur SSH. Audit `notify.send` comme pour `SendServerAlert`.
- [ ] **Step 2: Vérifier l'échec, écrire, relecture FR, vérifier** : `go test ./internal/notify/ ./internal/i18n/` OK.
- [ ] **Step 3: Commit** `feat: server log alerts on the notify channels`.

### Task 7: `serve` envoie le digest, section des journaux

**Files:**
- Create: `internal/cli/digest_schedule.go`, `internal/cli/digest_schedule_test.go`, `internal/digest/serverlogs.go`, `internal/digest/serverlogs_test.go`
- Modify: `internal/cli/digest.go`, `internal/cli/serve.go`, `internal/cli/scan.go`, `internal/policy/policy.go`, `config.example.yaml`, `internal/digest/digest.go`, `internal/digest/render.go`, `internal/digest/templates/*`

**Interfaces:**
- Consumes: `sendDigest`, `digest.Repo.Last`, `serverlog.Repo`.
- Produces: `policy.NotifyConfig.DigestAt string` (yaml `digest_at`, `"08:00"` par défaut, `"off"` coupe l'envoi par `serve`) ; `digestDue(last digest.Run, hasLast bool, now time.Time, at string) bool` ; `runDigestLoop(ctx, cmd, deps, every time.Duration)` ; `sendDigest` ne fait pas avancer la fenêtre sans livraison réussie, quand il est appelé par la boucle ou par `scan --digest` ; `digest.ServerLogDigest{Name string; New, Reopened int; Top []serverlog.AlertItem; Gaps []serverlog.Note; Deviations []string}` dans `Digest`.

Décision de ce plan : `michel digest --send` lancé à la main envoie toujours (la fenêtre partagée évite le doublon de contenu) ; `scan --digest` et la boucle de `serve` sautent si un digest est déjà parti dans la journée locale.

- [ ] **Step 1: Tests de l'envoi** : `TestDigestDueAtHour` (avant 08:00 non, après oui, une fois par jour, heure réglable, `off` jamais) ; `TestDigestCatchesUpAfterStart` (poste éteint à 08:00, envoi au démarrage) ; `TestServeDigestKeepsWindowWithoutDelivery` (aucun canal, ou tous en échec : aucun `digest_run`, éléments encore présents au prochain) ; `TestServeAndScheduledTaskSendOnce` ; `TestManualDigestStillSends` ; `TestExistingScheduledLineStillWorks`.
- [ ] **Step 2: Tests de la section** : `TestDigestListsNewAndFrequentErrors` ; `TestDigestShowsReadGap` (de quand à quand) ; `TestDigestNoTextByDefault` et `TestDigestTextFollowsAlertSetting` ; `TestDeviationRemindedWeekly` ; `TestDigestRespectsScopedChannels` (`ForChannel`, `Filter`) ; mêmes contrôles en texte et HTML.
- [ ] **Step 3: Vérifier l'échec, écrire, relecture FR, vérifier** : `go test ./internal/cli/ ./internal/digest/ ./internal/policy/ ./internal/i18n/` OK.
- [ ] **Step 4: Commit** `feat: serve sends the digest, with server log errors`.

### Task 8: API et CLI

**Files:**
- Create: `internal/api/serverlogs.go`, `internal/api/serverlogs_test.go`, `internal/cli/target_logs.go`, `internal/cli/target_logs_test.go`
- Modify: `internal/api/targets.go`, `internal/api/server.go` (`Deps`), `internal/cli/target.go`, `internal/cli/serve.go`

**Interfaces:**
- Consumes: Tasks 1 à 5.
- Produces, sous `/api/v1/targets/{id}/logs` : `GET,POST /sources` ; `PATCH,DELETE /sources/{source}` ; `POST /sources/discover` ; `POST /sources/try` ; `GET /errors` ; `PATCH /errors/{signature}` (`seen`, `ignored`) ; `GET,PATCH /settings` ; `POST /purge`. `TargetView` gagne `log_new int`, `log_deviations []string`, `log_no_channel bool`. CLI `michel target logs list|read <server>`.

- [ ] **Step 1: Tests** : `TestLogsAPIRoundTrip` ; `TestSettingsDeviationNeedsConfirm` (`409` et code `logs.confirm_needed` sans `confirmed: true`, puis OK, y compris `hds`) ; `TestTryReturnsExactlyWhatWouldComeBack` et n'écrit rien ; `TestSourceDeleteTouchesNothingRemote` ; `TestErrorsHaveDetailCommand` (commande SSH à copier avec fichier et date, sans contenu) ; `TestErrorsNeverCarryAbsolutePosteOrRawLine` ; `TestTextDecryptedOnlyWhenAllowed` ; `TestNoChannelFlag` ; `TestAuthRequired`.
- [ ] **Step 2: Vérifier l'échec, écrire, vérifier** : `go test ./internal/api/ ./internal/cli/` OK.
- [ ] **Step 3: Commit** `feat: server logs API and CLI`.

### Task 9: Bloc « Journaux » de la fiche serveur

**Files:**
- Create: `web/src/components/ServerLogs.vue`, `web/src/lib/serverLogsView.js`, `web/src/lib/serverLogsView.test.js`
- Modify: `web/src/components/ServerSheet.vue` (nouvelle `<section>` après `srv-${id}-flaws`), liste des serveurs (`log_new`, badge), `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: API de la Task 8.
- Produces: `serverLogsView` : `privacyChoices(settings, kind)` (choix recommandé en premier, marqué), `deviationWarning(key, kind)`, `intervalNote(duration)`, `readState(source, now)`.

- [ ] **Step 1: Tests Vitest** : `recommended option comes first` ; `hds warning names health data and hosting` ; `interval above 10 minutes warns` ; `last read and unseen wording` ; `no channel warning`.
- [ ] **Step 2: Écrire** le bloc de la spec § 10 : sources cochées, dernière lecture, « non vu », « Essayer » avant activation, erreurs groupées, « Voir le détail » avec bouton Copier, réglages en phrases, confirmation d'écart, badge, « Effacer les données de journaux de ce serveur ». Accessibilité alignée sur les sections voisines.
- [ ] **Step 3: Relecture FR, vérifier** : `npx vitest run` et `npm run build` dans `web/`, puis `go test ./web ./internal/hygiene/` OK. Vérifier la page dans le navigateur intégré sur un serveur `sshtest` de démonstration, en thème clair et sombre.
- [ ] **Step 4: Commit** `feat: server logs block on the server sheet`.

### Task 10: Docs, conteneur de test, run réel

**Files:**
- Modify: `docs/servers.md`, `docs/servers.fr.md`, `docs/operations/daily-digest.md`, `docs/operations/daily-digest.fr.md`, `docs/security/network-egress.md`, `docs/security/network-egress.fr.md`, `README.md`, `config.example.yaml`, `test/docker-server/Dockerfile`
- Create: `docs/superpowers/sdd/2026-11-02-michel-server-logs/real-run-checklist.md`

- [ ] **Step 1: Écrire les docs** : ce qui est lu, ce qui sort, conservation, recommandations et écarts, limite « poste allumé », groupes de lecture sans `sudo`, `%e` dans `log_line_prefix`, « ce n'est pas un avis juridique, fais valider par ton DPO », aide au registre des traitements, heure du digest. **Relecture FR.**
- [ ] **Step 2: Compléter le conteneur** : PostgreSQL et page PHP qui provoque une erreur.
- [ ] **Step 3: Run réel sur le conteneur** : journal piégé, erreurs PHP, PostgreSQL, Monolog ; aucun marqueur en base, dans l'audit ou dans l'alerte (`grep` sur la base et sur les messages) ; délai réel jusqu'à l'alerte sous 10 min ; poste coupé puis repris ; rotation réelle (`logrotate`). Chiffres seulement au ledger.
- [ ] **Step 4: Vérifier et faire la revue finale** : `go test ./...`, `npx vitest run`, `go test ./internal/hygiene/`. Revue de toute la branche.
- [ ] **Step 5: Commit** `docs: server logs guide, egress inventory and real run`.

## Self-review (2026-11-02)

Couverture de la spec : § 4 Tasks 1, 3 ; § 5 Tasks 2, 3, 5 ; § 6 Task 2 ; § 7 Tasks 2, 4, 6, 7, 9, 10 ; § 8 Tasks 1, 5, 6, 7 ; § 9 Task 1 ; § 10 Tasks 8, 9 ; § 11 Tasks 1, 4, 8 ; § 12 Tasks 2, 3, 10. Noms croisés vérifiés entre les blocs Interfaces.
