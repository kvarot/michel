# Michel : interface guidée, plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Une personne novice fait seule, en dix minutes, les trois parcours (faille de projet, faille de serveur, exposition d'un serveur), dans une interface d'allure professionnelle où rien de ce qui existe n'est retiré.

**Architecture:** Une coquille de navigation (`App.vue`, `lib/navView.js`) et un thème (`lib/theme.js`) ; le mode avancé vit dans `$ui.advanced`, sur les mêmes pages. Trois modules de logique pure : `lib/todoView.js` (À faire, Résolu), `lib/pathView.js` (le chemin de la faille et le texte vrai de « ce qui va se passer »), `lib/exposureView.js`. Côté Go : une commande de plus dans la liste fermée de `internal/collect`, des règles déterministes dans `internal/serverrules`, un genre de faille `server_exposure` que le service de correction refuse, et deux routes pour ajouter et contrôler un projet depuis la page.

**Tech Stack:** Go 1.27.3, Vue 3.5 Options API, JS et JSDoc, Vuetify 4.3, Vite, Vitest (fonctions pures, environnement `node`). Aucune nouvelle dépendance.

**Spec:** `docs/superpowers/specs/2026-11-03-michel-ui-guided-design.md`. Apparence de référence : `docs/superpowers/specs/2026-11-03-michel-ui-guided-mockup.html`, avec les corrections de texte de la règle R3.

## Global Constraints

- Branche `feat/ui-guided`. Module `github.com/kvarot/michel`. Anglais pour code, commits, CLI ; français pour ce plan et le ledger (`docs/superpowers/sdd/2026-11-03-michel-ui-guided/`, en agrégats).
- Commandes Bash : `export PATH="$LOCALAPPDATA/Programs/go/bin:$PATH"`. Pas de python, pas de gcc (donc pas de `-race` ici). Docker seulement dans WSL (`wsl -d Ubuntu -- docker`).
- **Porte de chaque tâche front** : `cd web && npx vitest run && npm run build`, puis `go test ./web ./internal/hygiene/`. **Porte de chaque tâche Go** : `go test ./...` et `go vet ./...`. Les échecs `example/mcp` de `internal/api` sont environnementaux (ruling R7 du plan 7) : les citer, ne pas les corriger.
- Vue 3 Options API, JS et JSDoc, Vuetify 4. Logique testable dans `web/src/lib/*View.js`, sans DOM. Vitest reste sur `node` : pas de test de composant, pas de `@vue/test-utils` (aucune dépendance ajoutée) ; ce qu'un composant décide passe par une fonction de `lib/`.
- **CSP inchangée** : ni police téléchargée ni ressource externe. `--m-voice` (serif déjà en place) pour les phrases de Michel et les titres-verdicts, `--m-ui` pour l'interface. Icônes : chemins SVG écrits dans le code, comme `checkPath` dans `ProjectCard.vue`.
- **Une gravité est toujours une couleur et un mot.** Contraste AA, clavier, `prefers-reduced-motion`, 16 px de marge sur téléphone, aucun défilement horizontal à 375 px.
- **Textes** : `web/src/i18n/{fr,en}.json`, à égalité, FR au tutoiement ; `internal/i18n/catalog/{fr,en}.json` pour ce qui vient de Go. **Tout texte français passe un lecteur non spécialiste avant la revue de code** : c'est une étape de chaque tâche qui en crée ou en change.
- **Jargon** : pas de CVE, CVSS, port, paquet ni SSH en mode simple sans explication (test de la Task 3).
- **Rien ne s'affaiblit** (plans 5 à 7) : aucune confirmation retirée ni cachée par le mode simple (accord IA, `Valider` par empreinte, refus, snapshot, empreinte de serveur, retrait d'un serveur, écarts de confidentialité des journaux, purge) ; masquage (`MaskedText`, `splitMasked`) conservé ; pas de ligne de journal brute affichée ; aucune donnée de journal vers un agent ; jeton et en-têtes inchangés.
- **Serveurs** : jamais de vrai serveur dans les tests (`sshx/sshtest`, conteneur `test/docker-server`). Ne jamais changer le service `ssh-agent` de Windows : agent de test en espace utilisateur (`ssh.agent_pipe`), hors du dépôt. Toute lecture reste dans la liste fermée, sans `sudo`, sans écriture, sans second moyen.
- **Aucun nom ni chemin de projet privé** : fixtures `demo`, `srv-demo`, `example.test`, adresses de documentation (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`, `2001:db8::`) ; `go test ./internal/hygiene/` vert.
- **Valeurs de la spec** : chemin `Trouvée, Solution proposée, Ton accord, Corrigée, Vérifiée` ; colonnes `Ouvert à tous`, `Réservé`, `Non vérifié` ; titre `joignable si aucun pare-feu ne le bloque` ; 80, 443 site web, normal ; 22 connexion d'administration, normal ; 3306, 5432, 6379, 11211, 27017, 9200 bases et caches, `à fermer` ; le reste `service non reconnu, à vérifier` ; palette de la Task 1. Ports vérifiés : MySQL 3306, PostgreSQL 5432, Redis 6379, Memcached 11211, MongoDB 27017, Elasticsearch 9200.

## Rulings

Le propriétaire a demandé de suivre les recommandations et d'ajuster ensuite. Ces règles tranchent ce que la spec laisse ouvert ou ce que le code contredit. Chacune dit ce qu'elle coûte si elle est fausse.

- **R1, « Ce que l'IA va faire » n'est pas un seul texte.** Projet : vrai pour la copie et l'accord, faux si « tests lancés » est dit sans condition. Serveur : il n'y a **ni copie ni IA** pour les corrections courantes (`OriginServer`, `fix.intro_server`). Le titre devient « Ce que Michel va faire » sur un serveur, et le bouton « Préparer la correction » (rien n'y est lancé) ; « Lancer la correction » reste sur un projet. Table exacte en Task 8 et Task 9. Coût : deux titres au lieu d'un.
- **R2, « Vérifiée ».** `rescan_clean` est le nouveau scan de la **copie**, connu dès `proposed` (`service.go:1172`), avant l'accord : il ne peut pas seul allumer une étape placée après « Corrigée ». Projet : `verified` = état `proven_fixed` **et** `proposal.rescan_clean === true`. Serveur, l'équivalent : état `proven_fixed` (posé par `server_exec.go:865`, seulement quand une lecture complète ne voit plus la faille et que le contrôle du site, s'il a une adresse, a réussi). `inconclusive` n'est jamais vérifiée. Exposition : faille `gone` après une lecture complète. Un `proven_fixed` de projet avec `rescan_clean` faux s'arrête à « Corrigée », avec sa phrase. Coût : un cas rare moins vert que le fait.
- **R3, la maquette dit parfois plus que Michel ne sait.** On garde ses formes, pas ces mots : « 3 portes ouvertes vers l'extérieur », « répond à tout le monde », « Le reste va bien », « Injoignable de l'extérieur » (sur une adresse privée). Remplacés par les textes des Tasks 6 et 13. Coût : un titre plus long.
- **R4, ajouter et contrôler un projet depuis la page.** Aujourd'hui rien ne le permet (`today.no_projects_hint` renvoie à la ligne de commande, aucune route `POST /projects` ni scan). Sans cela, ni le guide ni « voir résolu » ne marchent : `fix.Prove` ne tourne qu'après un scan. Task 14 ajoute deux routes. Coût : deux routes à maintenir.
- **R5, `SourcesPage` n'est pas « Mes projets ».** Elle gère les sources d'information. « Mes projets » est une nouvelle page sur `ProjectCard` ; `SourcesPage` reste à `#/sources`, joignable depuis Réglages. Coût : aucun.
- **R6, Michel ne fusionne toujours pas.** Le dernier pas du parcours projet reste à la personne : la page dit quoi faire et donne la commande à copier. C'est la seule étape où une personne sans Git peut bloquer ; l'essai de la Task 16 le mesure et le rapporte, il ne le contourne pas. Coût : l'objectif 1 de la spec n'est pas tenu à 100 % pour qui n'a jamais utilisé Git.
- **R7, lecture d'exposition.** `ss -tln`, puis `/usr/sbin/ss -tln` seulement si la première répond 127 : c'est le même programme, placé ailleurs selon la distribution, comme `cmdFindSbin` pour FPM. Ce n'est pas « un autre moyen » ; aucun repli vers `netstat` ou `/proc`. TCP seulement : **UDP n'est pas lu**, et la colonne « Non vérifié » le dit. Coût : Memcached en UDP reste invisible, dit en clair.
- **R8, `hds`.** Rien n'interdit cette commande sur `hds` ni sur un autre type : les limites `hds` portent sur les chemins ajoutés (`CheckPath`, `ErrHealthPath`) et les agents (`healthTarget`), et `ss -tln` ne lit aucun fichier ni aucun contenu. Elle tourne donc partout. Le serveur `hds` garde « jamais d'agent ». Sur `shared`, les services peuvent être ceux de l'hébergeur ou d'un autre client : ils s'affichent avec une phrase qui le dit, mais **aucune faille** n'est créée. Coût : une base réellement exposée sur un mutualisé n'entre pas dans À faire.
- **R9, gravité d'un service à fermer : `medium`.** Michel ne sait pas si le service est joignable : pas d'alerte mail ni SMS (`grave` exige `high`), une ligne « À regarder » en À faire, comme la maquette. Coût : pas de message si une base est réellement ouverte ; à revoir quand l'essai extérieur existera.
- **R10, le port de connexion.** `target.Port` compte comme connexion d'administration, même s'il n'est pas 22. Coût : aucun, Michel vient de s'y connecter.
- **R11, classement d'adresse.** `127.0.0.0/8`, `::1` : réservé au serveur. RFC 1918, `fc00::/7`, `fe80::/10`, `100.64.0.0/10` : réservé au réseau privé. `0.0.0.0`, `::`, `*`, et toute autre adresse : ouvert à tous. Une adresse IPv4 dans IPv6 est d'abord dépliée. Une écoute limitée à une interface (`0.0.0.0%eth0`) reste « ouvert à tous » : Michel ne sait pas ce que l'interface joint. Coût : un faux « ouvert » sur une interface interne.
- **R12, « Je sais, c'est bloqué ou voulu ».** Michel ne voit pas le pare-feu de l'hébergeur : sans issue, une base bloquée resterait à faire pour toujours. Une faille d'exposition reçoit une décision `ignore` avec justification obligatoire (Task 13), affichée « Tu as indiqué : … Michel ne l'a pas vérifié », et le service reste dans sa colonne. Pas d'annulation depuis la page en première version : `michel decide`. Coût : une décision erronée demande la ligne de commande.
- **R13, commande de test.** `test_cmd` reste en ligne de commande : l'ouvrir à la page permettrait d'exécuter une commande avec le seul jeton. La page expose seulement `has_test_cmd`, et dit la vérité. Coût : un projet sans tests déclarés le reste pour un novice.
- **R14, niveau 0 d'un projet.** `POST /findings/{id}/fix` ne regarde pas `fix_level` (le serveur, si : `ErrReportOnly`). La page guidée n'offre pas le bouton au niveau 0 et le dit ; l'API n'est pas touchée, le mode avancé garde `FindingSheet`. À signaler au propriétaire. Coût : l'incohérence d'API reste.
- **R15, liste À faire.** Aucune route ne donne les failles de tous les serveurs ; la page lit `GET /targets`, puis `GET /targets/{id}` pour chaque serveur avec `open_findings > 0` (au plus 20, le reste en une ligne « et N autres serveurs »). Coût : quelques requêtes locales.
- **R16, Réglages en page.** `#/settings` remplace la boîte de dialogue ; `SettingsPanel` garde ses événements. `FixPage` sort de la navigation (`#/fix…` reste, et la page reste joignable). `ExploitedBanner` et `ReadingList` passent en mode avancé : une faille exploitée reste une ligne `Urgent` en tête d'À faire. Coût : un clic de plus pour décider en lot.
- **R17, gravité `high`.** La palette de la spec n'a pas d'orange : `high` garde `#B4501A` (4,76 sur `#F4F7FA`). Coût : une couleur de plus.
- **R18, Task 16.** Les trois parcours complets sur ordinateur en clair et téléphone en sombre ; sur les deux autres combinaisons, chaque écran une fois. Agent de correction : le faux agent (`internal/agent/testdata/fakeclaude`), pour qu'aucun code ne parte et que l'essai se rejoue. Le vrai agent a son run au plan 5 ; le rapport le dit. Coût : la conversation réelle n'est pas revue par la personne fictive.

## Review Focus

1. **Sortie hostile ou inattendue de `ss`** (tabulation, adresse forgée, port 70000, `%zone`, pas d'en-tête, liste coupée, sortie vide avec code 0) : rien hors schéma n'est gardé, le doute devient « non vu », jamais « rien d'ouvert ». Test : Task 10 `TestParseListenersRefusesForged`, `TestNoHeaderIsNotRead`.
2. **Lecture absente ou ancienne** (`ss` manquant, inventaire d'avant cette version, `Rematch` sans connexion) : une faille d'exposition déjà ouverte le reste, l'écran dit « pas encore lu ». Tests : Task 11 `TestUnreadListenersKeepExposureOpen`, Task 13 `not read says so and keeps the firewall row`.
3. **Liste À faire vide alors que Michel n'a rien vu** (aucun scan, scan échoué, serveur jamais vérifié, base de failles absente) : jamais de phrase rassurante. Test : Task 6 `an empty list never reassures when something was not seen`.
4. **États qui ne prouvent rien** (`inconclusive`, `unknown`, `failed`, `proven_fixed` sans `rescan_clean`, `applied` jamais fusionné) : jamais « Vérifiée », et la faille reste à faire quand elle l'est. Test : Task 8 `verified table`.
5. **Stockage bloqué ou effacé** (fenêtre privée, `localStorage` qui lève) : la page marche, le mode revient à simple, le guide reprend d'après les données et non d'après le stockage. Test : Task 15 `guide resumes from data when storage is empty`, Task 3 `advanced defaults to off`.

---

### Task 1: Thème et palette

**Files:**
- Create: `web/src/lib/theme.js`, `web/src/lib/theme.test.js`
- Modify: `web/src/main.js` (remplace `shared`), `web/src/styles.css`

**Interfaces:**
- Produces: `themes = {light, dark}` (couleurs Vuetify) ; `contrast(a: string, b: string): number`.

- [ ] **Step 1: Test** `every text color reaches AA on its backgrounds` : pour `on-background`, `primary`, `success`, `warning`, `error`, `critical`, `high`, `medium`, `low`, `unknown`, `secondary` sur `background` et `surface`, puis `on-primary` sur `primary`, `on-nav` sur `nav` et `nav-active`, dans les deux thèmes : `contrast >= 4.5`.
- [ ] **Step 2: Vérifier l'échec** : `npx vitest run src/lib/theme.test.js`, module absent.
- [ ] **Step 3: Écrire** `theme.js` avec ces valeurs exactes.

| Jeton | Clair | Sombre |
|---|---|---|
| `background` | `#F4F7FA` | `#0F1C2B` |
| `surface` | `#FFFFFF` | `#172737` |
| `surface-variant` | `#E6EEF6` | `#22364A` |
| `on-background`, `on-surface`, `on-surface-variant` | `#14304F` | `#E6EEF6` |
| `primary`, `info`, `low` | `#1B62B5` | `#8FBDF0` |
| `on-primary` | `#FFFFFF` | `#0F1C2B` |
| `secondary`, `unknown` | `#566879` | `#A9BCCC` |
| `success` | `#0F6B52` | `#6FD3B5` |
| `warning`, `medium` | `#9A5B00` | `#E9B860` |
| `error`, `critical` | `#B3261E` | `#FF9A90` |
| `high` | `#B4501A` | `#FFB074` |
| `nav` | `#14304F` | `#0A1521` |
| `on-nav` | `#FFFFFF` | `#E6EEF6` |
| `nav-active` | `#264A70` | `#22364A` |
| `line` | `#D3DDE8` | `#2E4459` |

- [ ] **Step 4: `styles.css`** : `--m-line: rgb(var(--v-theme-line))` ; classes `.m-tag--urgent`, `--look`, `--done`, `--info` (mot en gras sur fond teinté à 12 %, valeurs de la maquette `.tag`) ; `.m-panel` (surface, filet, rayon 8 px) ; `.m-verdict` (`--m-voice`, 600, `clamp(1.5rem, 1.2rem + 1.4vw, 1.9rem)`, `max-width: 30ch`).
- [ ] **Step 5: Vérifier** la porte front, puis ouvrir la page existante en clair et en sombre : rien d'illisible dans les pages non retouchées.
- [ ] **Step 6: Commit** `feat: guided interface palette, light and dark`.

### Task 2: Navigation et pages

**Files:**
- Create: `web/src/lib/navView.js`, `web/src/lib/navView.test.js`, `web/src/components/AppNav.vue`, `web/src/components/ProjectsPage.vue`, `web/src/components/ResolvedPage.vue` (vide jusqu'à la Task 7)
- Modify: `web/src/App.vue`, `web/src/components/TodayPage.vue` (les cartes de projet partent), `web/src/components/SettingsPanel.vue` (bouton de fermeture seulement dans une boîte), `web/src/lib/serversView.js`, `web/src/lib/serversView.test.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `navEntries: {page, hash, key, shortKey, icon}[]`, pages `todo` (`#/`), `projects` (`#/projects`), `servers` (`#/servers`), `resolved` (`#/resolved`), `settings` (`#/settings`) ; `pageOf(hash): 'todo'|'projects'|'servers'|'resolved'|'settings'|'sources'|'fix'` ; `activeEntry(page)` : `fix` donne `todo`, `sources` donne `settings`.
- Produces: `serversRoute(hash)` lit aussi `#/servers/<id>?finding=<fid>` et rend `{id, finding}` ; `serversHash(id, finding = '')`.
- Consumes: `fixRoute`.

- [ ] **Step 1: Tests** : `pageOf reads every hash`, y compris `#/fix/abc`, `#/fix?finding=x`, `#/servers/a?finding=b`, un hash inconnu donne `todo` ; `activeEntry highlights the parent` ; `serversRoute keeps old addresses` et `decodes finding`.
- [ ] **Step 2: Vérifier l'échec, écrire** `navView.js`.
- [ ] **Step 3: `AppNav.vue`** : `<nav :aria-label>` de liens `<a :href>`, `aria-current="page"` sur l'entrée active. À partir de 960 px (`$vuetify.display.mdAndUp`), `v-navigation-drawer` permanent de 200 px sur `nav`, nom d'assistant en `--m-voice`, puis l'entrée « Besoin d'aide ? Revoir le guide » vers `#/settings`. En dessous, `v-bottom-navigation` à cinq entrées, icône et mot court. Mots : `nav.todo` « À faire », `nav.projects` « Mes projets », `nav.servers` « Mes serveurs », `nav.resolved` « Résolu », `nav.settings` « Réglages, aide » ; courts : « À faire », « Projets », « Serveurs », « Résolu », « Réglages ». EN à égalité. Aucune couleur seule : `aria-current` et graisse.
- [ ] **Step 4: `App.vue`** : retire `v-tabs` et `settingsOpen`. Garde `state`, `load`, le lien d'évitement, `unauthorized`, `offline`, `error`. La nav n'apparaît qu'en `ready`. Branche `ProjectsPage` (reçoit `digest`, reprend `groupAttention` et `ProjectCard`, `@decided`), `SettingsPanel` en page, `SourcesPage` à `#/sources`, et `ResolvedPage`. `stale` recharge le digest en revenant sur `todo` ou `projects`.
- [ ] **Step 5: Relecture FR, vérifier** la porte front et, au navigateur à 375 et 1280 px : chaque entrée, retour arrière, tabulation clavier, aucun défilement horizontal.
- [ ] **Step 6: Commit** `feat: side and bottom navigation, projects and settings pages`.

### Task 3: Mode avancé

**Files:**
- Create: `web/src/lib/modeView.js`, `web/src/lib/modeView.test.js`, `web/src/i18n/jargon.test.js`
- Modify: `web/src/lib/storage.js`, `web/src/main.js`, `web/src/components/SettingsPanel.vue`, `web/src/components/FindingSheet.vue`, `web/src/components/PackageRow.vue`, `web/src/components/ProjectCard.vue`, `web/src/components/ServerSheet.vue`, `web/src/components/ServerLogs.vue`, `web/src/components/ServerProposal.vue`, `web/src/components/FixProposal.vue`, `web/src/components/TodayPage.vue`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `keys.advanced = 'michel.advanced'` ; `readAdvanced(load): boolean` (vrai seulement pour `'1'`) ; `$ui.advanced` réactif ; `stripTechnicalIds(text): string` retire `CVE-…`, `GHSA-…`, `PHP2Shell` reste.

- [ ] **Step 1: Tests** : `advanced defaults to off` (vide, valeur inconnue, `load` qui lève) ; `stripTechnicalIds removes ids and keeps the sentence` ; `jargon.test.js` : `no unexplained jargon in simple texts`, pour les familles `nav.`, `todo.`, `resolved.`, `path.`, `plan.`, `expo.`, `guide.`, `empty.`, `help.`, regex `/\b(CVE|CVSS|GHSA|EPSS|KEV)\b/` interdite partout en FR, et `/\b(port|paquet|SSH)\b/i` permise seulement si la même phrase donne son explication (liste d'exceptions écrite dans le test, clé par clé) ; `i18n catalogs have the same keys` dans `texts.test.js`.
- [ ] **Step 2: Vérifier l'échec, écrire**, ajouter l'interrupteur à `SettingsPanel` (`settings.advanced` « Mode avancé », éteint par défaut, `save` et `$ui.advanced`).
- [ ] **Step 3: Appliquer cette table**, avec `v-if="$ui.advanced"` :

| Composant | Caché en mode simple | Reste toujours |
|---|---|---|
| `FindingSheet` | identifiant, faits, détail technique, glossaire | les phrases, `Corriger`, `DecisionPanel` |
| `PackageRow`, `ProjectCard` | versions, EPSS, identifiants, comptes par décision | nom du composant, gravité (mot), état du scan |
| `ServerSheet` | `user@host:port`, inventaire vu, directives, historique détaillé, sauvegardes | état, failles, **liste « non vu »**, réglages en phrases, accord IA, retrait, empreinte |
| `ServerLogs` | format, champs, fenêtre de détail, commande à copier | erreurs groupées, écarts, confirmations, purge |
| `ServerProposal`, `FixProposal` | empreinte courte, diff, sortie des tests, commandes, scripts dépliables | résumé, `Valider`, `Refuser`, snapshot, avertissements, retour arrière, **lignes `steps_server`** |
| `TodayPage` | `ExploitedBanner`, `ReadingList`, ligne de catalogue | ce que la Task 6 y met |

Un script reste lisible en mode simple par un lien « Voir le script » qui bascule localement l'affichage : on ne valide jamais sans pouvoir voir.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, et au navigateur les deux modes sur une fiche serveur de démonstration. Vérifier qu'aucun `v-dialog` n'est sous un `v-if` lié au mode (`grep`).
- [ ] **Step 5: Commit** `feat: advanced mode, off by default, same pages`.

### Task 4: Aide au champ

**Files:**
- Create: `web/src/components/FieldHelp.vue`, `web/src/lib/helpView.js`, `web/src/lib/helpView.test.js`
- Modify: `web/src/components/DiscoverServersDialog.vue`, `HostKeyDialog.vue`, `ServerSheet.vue`, `FixSettings.vue`, `DecisionPanel.vue`, `ServerLogs.vue`, `ServerProposal.vue`, `FixProposal.vue`, `SettingsPanel.vue`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `helpIds: string[]` ; `<FieldHelp id="server.host" />`, texte `help.<id>`.

- [ ] **Step 1: Tests** : `every help id has fr and en text` ; `help stays short` (au plus 280 caractères) ; `every FieldHelp in the components is listed` et l'inverse, en lisant `import.meta.glob('../components/*.vue', { query: '?raw', eager: true })`.
- [ ] **Step 2: Écrire** `FieldHelp.vue` : un vrai `<button type="button">` « ? » de 24 px (zone de 44 px sur téléphone), `aria-expanded`, `aria-controls`, nom accessible `help.label` « Aide : {champ} », texte **en ligne sous le champ** (pas au survol : il marche au doigt, et ne masque rien). `Échap` referme.
- [ ] **Step 3: Écrire les textes**, trois idées par clé : à quoi ça sert, quoi mettre, ce qui se passe si on se trompe. Identifiants : `server.host`, `server.user`, `server.port`, `server.name`, `server.site`, `server.kind`, `server.env`, `server.level`, `server.auto`, `server.executor`, `server.sudo`, `server.interval`, `server.preprod`, `server.active`, `server.fingerprint`, `server.check`, `server.snapshot`, `project.level`, `project.auto`, `project.ai`, `decision.action`, `decision.until`, `decision.why`, `logs.path`, `logs.format`, `logs.try`, `logs.interval`, `logs.store_text`, `logs.alert_text`, `logs.retention`, `logs.sms`, `fix.approve`, `fix.refuse`, `settings.token`, `settings.advanced`, `settings.theme`, `settings.lang`. Les Tasks 13 et 14 ajoutent `exposure.decision`, `project.path`, `project.name` avec leurs champs. Le texte se vérifie dans le code : ex. `server.executor` dit qui lance le script, `server.sudo` que Michel n'utilise `sudo` que pour lancer un script validé, jamais pour lire.
- [ ] **Step 4: Relecture FR, vérifier** la porte front ; au navigateur, clavier seul, puis 375 px.
- [ ] **Step 5: Commit** `feat: plain help on every field and action`.

### Task 5: Remarques reportées du plan 7, tâche 9

**Files:**
- Modify: `web/src/components/ServerLogs.vue`, `web/src/lib/serverLogsView.js`, `web/src/lib/serverLogsView.test.js`, `web/src/components/ServerSheet.vue`

**Interfaces:**
- Produces: `domId(text): string` (identifiant sûr, stable, sans espace) ; `intervalNote` remplacée par le champ `interval_note` de l'API, repli local si absent ; `settingsSaveOutcome(err): {kind: 'confirm'|'error'|'ok', ...}`.

Le registre du plan 7 liste ces points, à reprendre un par un.

- [ ] **Step 1: Tests** : `domId has no space and differs for different paths` ; `settingsSaveOutcome reads the 409 logs.confirm_needed` (le flux 409 sans test de composant passe ainsi par une fonction) ; `api interval note wins over the local one`.
- [ ] **Step 2: Corriger** : `candKey` dans les `id` (`aria-describedby` cassé sur un chemin avec espace) ; `now` figé à l'ouverture (rafraîchir chaque minute, minuteur arrêté à `beforeUnmount`) ; `load()` sans séquence (ignorer la réponse d'un appel dépassé, comme `acceptResult`) ; `refreshView` qui avale son erreur dans `ServerSheet` (la montrer) ; `c.strong` calculé et non lu (retirer) ; phrase de l'intervalle `manual` : elle promet « quand tu le demandes » sans bouton, dire « avec la commande `michel target logs read` » en mode avancé et « seulement quand tu le demandes en ligne de commande » en simple.
- [ ] **Step 3: Relecture FR, vérifier** la porte front, puis le bloc Journaux **en sombre** (jamais revu après le dernier commit du plan 7) et le contenu réel copié par « Copier ».
- [ ] **Step 4: Commit** `fix: deferred server logs minors from plan 7`.

### Task 6: À faire

**Files:**
- Create: `web/src/lib/todoView.js`, `web/src/lib/todoView.test.js`
- Modify: `web/src/components/TodayPage.vue` (reste le composant de `#/`), `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: `groupAttention`, `findingTitle`, `fixHash`, `serversHash(id, finding)`, `GET /today`, `GET /fixes`, `GET /targets`, `GET /targets/{id}`.
- Produces: `buildTodo({digest, attempts, servers, details, lang, now, advanced}): {head, sub, lines, unseen}` ; une ligne vaut `{id, tone: 'urgent'|'look'|'info', word, title, where, action: {label, href}|null, rank}`.

Règles exactes :

| Rang | Ligne | Mot | Action |
|---|---|---|---|
| 0 | Malveillant, exploitée (`kev`), `urgent` serveur, tentative `unknown`, restauration de snapshot | `Urgent` | `Voir la solution`, `Vérifier le serveur` |
| 1 | Critique | `Urgent` | `Voir la solution` |
| 2 | Tentative `proposed` | `À valider` | `Lire et valider` |
| 3 | Élevée | `Important` | `Voir la solution` |
| 4 | Service `à fermer`, moyenne, tentative `inconclusive` ou `failed` non remplacée | `À regarder` | `Comprendre` |
| 5 | Faible, non notée ; `log_new > 0` (« {n} nouvelles erreurs sur {serveur} », jamais de texte de journal) ; empreinte à confirmer ; vérification échouée ; scan échoué | `À regarder` | action nommée par son effet |

À rang égal, l'ordre d'arrivée, serveurs et projets mêlés. Une seule action par ligne. Un composant dont la décision est `ignore` ou `defer` n'a pas de ligne tant qu'il n'est pas dû. Une tentative `applied` donne une ligne « La correction est prête : à toi de la fusionner » (rang 2). En mode simple, `stripTechnicalIds` sur tout titre ; le titre d'un `server_package` en simple est `todo.server_package` : « Un logiciel installé sur {serveur} a une faille connue ».

Textes de tête (R3) : `todo.head.one` « Bonjour. Une chose demande ton attention. », `todo.head.other` « Bonjour. {n} choses demandent ton attention. », sous-titre comptant projets et serveurs, **sans jamais « Le reste va bien »**. Liste vide : `todo.head.none` « Rien à faire pour l'instant, d'après ce que Michel a pu voir. », suivi de ce qui n'a pas été vu.

- [ ] **Step 1: Tests** : `urgent first, projects and servers mixed` ; `one action per line` ; `an empty list never reassures when something was not seen` (aucun scan, `failed_scans > 0`, `never_checked`, `unread`, `osv_stale`, base absente : `unseen` non vide, et aucun texte du résultat ne contient « va bien », « protégé », « sécurisé », `safe`, `protected`) ; `simple mode removes ids` ; `no raw log text` (une fixture d'erreur de journal avec marqueur ne laisse aucune trace) ; `more than 20 servers makes one line` ; `exposure line says firewall` : son titre vaut `todo.exposure` « Ta base de données écoute sur toutes les adresses : joignable si aucun pare-feu ne la bloque ».
- [ ] **Step 2: Vérifier l'échec, écrire.**
- [ ] **Step 3: `TodayPage.vue`** : `.m-verdict`, sous-titre, `.m-panel` de lignes, chaque ligne : mot-gravité, titre, où, un bouton. Sur téléphone, le bouton passe sous le texte, pleine largeur. Garde `failed_scans`, `OsvBanner`. Charge les détails au `watch digest` avec un compteur de séquence. Bouton `Actualiser` déplacé ici.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes.
- [ ] **Step 5: Commit** `feat: one to-do list, most urgent first`.

### Task 7: Résolu

**Files:**
- Create: `web/src/lib/pathView.js`
- Modify: `web/src/components/ResolvedPage.vue`, `web/src/lib/todoView.js`, `web/src/lib/todoView.test.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: `GET /fixes?state=proven_fixed`, `isVerified` (Task 8 l'écrit, cette tâche l'importe depuis `lib/pathView.js` : créer le fichier ici avec cette seule fonction, signature `isVerified(attempt): boolean`), `formatDate`.
- Produces: `resolvedLines(attempts, exposures, lang): {at, title, where, verified, href}[]`, le plus récent en haut.

- [ ] **Step 1: Tests** : `only verified attempts are listed as verified` (projet sans `rescan_clean` : ligne « Corrigée, non confirmée » séparée, jamais dans « Vérifiée ») ; `date from updated_at` ; `empty list says what it means`.
- [ ] **Step 2: Écrire**, avec `empty.resolved` : « Rien de résolu pour l'instant. Une faille apparaît ici quand un nouveau contrôle a confirmé sa correction. » et un bouton vers `#/`. Un projet ajoute `resolved.deploy` : « Corrigée dans ton code. Pense à déployer : Michel ne sait pas si ton site est à jour. »
- [ ] **Step 3: Relecture FR, vérifier, commit** `feat: resolved page, verified fixes with dates`.

### Task 8: Chemin de la faille, projets

**Files:**
- Create: `web/src/components/FailurePath.vue`, `web/src/components/FailureGuide.vue`, `web/src/lib/pathView.test.js`
- Modify: `web/src/lib/pathView.js`, `web/src/lib/fixView.js` (`stateLine`), `web/src/components/FixPage.vue`, `web/src/i18n/{fr,en}.json`, `internal/api/views.go`, `internal/api/handlers.go`, `internal/api/handlers_test.go`

**Interfaces:**
- Produces, Go: `ProjectView` gagne `HasTestCmd bool` (`has_test_cmd`), jamais la commande.
- Produces, JS : `failurePath({attempt, gone = false}): {steps: {key, state: 'done'|'now'|'todo'|'stopped'}[], verified, open, note}` ; `isVerified(attempt)` ; `projectPlan({finding, project, level}): {title, lines: string[] (clés et paramètres), action: 'start'|null, why}` ; `plainRisk(finding, sheet, lang, advanced): string`.
- Clés de `steps` : `found`, `solution`, `accord`, `fixed`, `verified`.

Table du chemin :

| État | found | solution | accord | fixed | verified | `open` | `note` |
|---|---|---|---|---|---|---|---|
| pas de tentative, `preparing` | done | now | todo | todo | todo | oui | `preparing` si tentative |
| `proposed` | done | done | now | todo | todo | oui | |
| `approved`, `running` | done | done | done | now | todo | oui | `by_rule` si `approved_by === 'auto'` |
| `applied` | done | done | done | done | now | oui | `merge` (projet), `checking` (serveur) |
| `proven_fixed`, vérifiée (R2) | done | done | done | done | done | non | `deploy` (projet) |
| `proven_fixed`, projet sans `rescan_clean` | done | done | done | done | stopped | non | `copy_not_confirmed` |
| `inconclusive` | done | done | done | done | stopped | oui | la cause de l'API |
| `refused` | done | done | stopped | todo | todo | oui | `refused` |
| `failed` | done | stopped, ou accord, ou fixed, selon `proposal` et `approved_by` | | | | oui | la cause |
| `unknown` | done | done | done | stopped | todo | oui | `unknown` |
| `superseded` | comme aucune tentative | | | | | oui | `superseded` |

Texte vrai pour un projet (vérifié dans `docs/fix.fr.md`, `service.go`, `auto.go`, `queue.go`). Titre `plan.project.title` « Ce que l'IA va faire ». Le constructeur revérifie chaque phrase dans le code et dit moins si elle n'est pas vraie.

| Condition | Clé | Texte |
|---|---|---|
| toujours | `plan.project.copy` | « Un agent d'IA (Claude Code) travaille sur une copie à part de ton projet : seulement les fichiers de ton dernier commit, sans tes fichiers `.env` ni tes clés. » |
| dépendance, version corrigée connue, Composer ou npm | `plan.project.update` | « Michel met à jour {package} vers la version {to} sur cette copie, puis l'agent adapte ton code si besoin. » |
| sinon | `plan.project.search` | « Michel ne connaît pas de mise à jour toute prête : l'agent cherche une correction sur cette copie. » |
| `has_test_cmd`, ni yarn ni pnpm | `plan.project.tests` | « Michel lance ensuite tes tests sur cette copie et cherche à nouveau la faille. » |
| pas de commande de test | `plan.project.no_tests` | « Michel cherche à nouveau la faille sur cette copie. Tes tests ne seront pas lancés : aucune commande de test n'est indiquée pour ce projet. » |
| `yarn.lock`, `pnpm-lock.yaml` (nom de `manifest_rel_path`) | `plan.project.no_install` | « Michel n'installe rien pour ce projet (yarn ou pnpm) : ni installation ni tests. » |
| niveau 1, ou niveau 2+ non `auto_fix_minor` | `plan.project.approval` | « Rien n'arrive dans ton code sans ton accord : si tu valides, Michel crée une branche à part. Il ne fusionne jamais et ne déploie jamais : ton site ne change pas. » |
| niveau 3 et `auto_fix_minor` | `plan.project.approval_auto` | « Avec ta règle, une petite mise à jour qui remplit toutes les conditions (tests réussis, faille disparue de la copie, aucun fichier de code touché) crée sa branche sans te demander. Le reste attend ton accord. Michel ne fusionne jamais et ne déploie jamais : ton site ne change pas. » |
| niveau 2 ou plus | `plan.project.self_start` | « À ce niveau, l'agent peut commencer sans que tu cliques. » |
| toujours | `plan.project.data` | « Cette IA est externe : ce qu'elle lit de la copie part chez Anthropic. Michel te demande ton accord une fois par projet. » |
| `classification === 'health'` | `plan.project.health` | « Ce projet contient des données de santé : aucune IA n'y travaille. » `action: null` |
| niveau 0 (R14) | `plan.project.report_only` | « Ce projet est réglé sur « Signaler » : Michel ne prépare rien. Tu peux changer ce réglage sur sa fiche. » `action: null` |

Le bouton « Lancer la correction » appelle `start` de `FixPage`, donc l'écran d'accord IA et `agentProblem` restent devant lui.

- [ ] **Step 1: Test Go** : `TestProjectViewSaysIfTestsAreDeclared`, avec `testCmdMarker` absent de toute la réponse.
- [ ] **Step 2: Tests JS** : `verified table` (une ligne par état ci-dessus, `verified` vrai seulement pour les deux cas de R2) ; `project plan tells the truth for each case` (chaque condition, y compris `no_tests` sans `tests`, et `approval_auto` sans `approval`) ; `no button at level 0 nor for health` ; `plain risk has no technical id in simple mode` ; `merge note gives the branch`.
- [ ] **Step 3: Vérifier l'échec, écrire.** `stateLine` : `fix.line.inconclusive` disait à tort « Michel vérifiera au prochain scan » (`inconclusive` est un résultat, `SetState` à `service.go:1692`) ; nouveau texte « Michel n'a pas pu confirmer la correction. » suivi de la cause, et `running`, `unknown` reconnus.
- [ ] **Step 4: `FailurePath.vue`** : `<ol aria-label>` à cinq `<li>`, `aria-current="step"`, état dit en mots masqués visuellement (`path.state.*` : fait, en cours, à venir, arrêté), couleur et icône en plus. Chevrons de la maquette (`clip-path`) à partir de 640 px ; en dessous, liste verticale. Libellés exacts : `Trouvée`, `Solution proposée`, `Ton accord`, `Corrigée`, `Vérifiée`.
- [ ] **Step 5: `FailureGuide.vue`** : `FailurePath`, note, deux blocs : `path.means` « Ce que ça veut dire » et le plan. Sur `applied`, la commande `git merge {branch}` à copier et « Puis, sur la fiche du projet, clique sur Contrôler ». Monté en tête du centre de `FixPage` ; en mode simple, la colonne de liste disparaît et `FixChat` passe dans un `<details>` ouvert quand une conversation existe. `FixProposal` reste à droite, entier.
- [ ] **Step 6: Relecture FR, vérifier** les deux portes, deux largeurs, deux thèmes, clavier.
- [ ] **Step 7: Commit** `feat: the path of a flaw and what will truly happen, projects`.

### Task 9: Chemin de la faille, serveurs

**Files:**
- Modify: `web/src/lib/pathView.js`, `web/src/lib/pathView.test.js`, `web/src/components/FailureGuide.vue`, `web/src/components/ServerSheet.vue`, `web/src/components/FixPage.vue`, `web/src/lib/serversView.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: `failurePath`, `TargetView` (`kind`, `fix_level`, `executor`, `auto_config`, `site_url`, `preprod`), `TargetFindingView`.
- Produces: `serverPlan({finding, target}): {title, lines, action: 'prepare'|null, why}`.

Texte vrai pour un serveur (vérifié dans `docs/servers.fr.md` § 6 et § 9, `server.go`, `server_auto.go`, `server_exec.go`). Le constructeur revérifie chaque phrase dans le code et dit moins si elle n'est pas vraie. Titre `plan.server.title` « Ce que Michel va faire ». Bouton `plan.server.prepare` « Préparer la correction ».

| Condition | Clé | Texte |
|---|---|---|
| toujours | `plan.server.who` | « Michel prépare lui-même un script d'après ses règles, sans IA. À ce stade, rien n'est lancé. » |
| pas de préprod | `plan.server.no_copy` | « Un serveur n'a pas de copie à part : ce script agira sur le serveur lui-même. Tu peux le lire avant de valider. » |
| `preprod` | `plan.server.preprod` | « Il est d'abord essayé sur ta préprod {name}. La correction de ce serveur n'est préparée qu'une fois prouvée là-bas. » |
| `server_config`, `site_url` | `plan.server.checks` | « Le script garde d'abord une copie du fichier, teste la configuration et recharge PHP. Michel vérifie ensuite ton site et relit le serveur. Si une étape échoue après le changement, le script remet les fichiers. » |
| `server_config`, sans `site_url` | `plan.server.no_site` | « Le script garde d'abord une copie du fichier et teste la configuration. Sans adresse de site, Michel ne vérifie pas que ton site répond encore : il relit seulement le serveur. » (`checkSite` saute ce contrôle sans `site_url`, et le chemin peut quand même arriver à « Vérifiée » : la note `path.note.no_site` le redit alors) |
| `server_package` | `plan.server.package` | « Michel simule d'abord la mise à jour. Aucun script ne peut l'annuler : il te demandera un snapshot chez ton hébergeur avant ta validation. » |
| toujours | `plan.server.no_tests` | « Les tests de ton application ne sont pas lancés. » |
| `executor === 'user'` | `plan.server.approval_user` | « Rien ne change sans ton accord : après ta validation, c'est toi qui lances le script sur le serveur. » |
| `executor === 'michel'` | `plan.server.approval_michel` | « Rien ne change sans ton accord : après ta validation, Michel envoie ce script sur le serveur par sa connexion sécurisée (SSH). » |
| niveau 3, `auto_config`, `michel`, `site_url` | `plan.server.approval_auto` | « Avec ta règle, un réglage PHP de la liste de Michel est corrigé sans que tu cliques, si toutes les conditions sont remplies. Une mise à jour de logiciel attend toujours ton accord. » remplace `approval_michel` pour `server_config` seulement |
| niveau 2 ou plus | `plan.server.self_prepare` | « À ce niveau, Michel prépare le script sans que tu cliques. » |
| pas `hds` | `plan.server.agent` | « Si Michel n'a pas de correction prévue, il te proposera un agent d'IA. L'agent ne se connecte jamais au serveur, ne voit qu'un inventaire masqué et ne peut rien lancer. » |
| `hds` ou `health` | `plan.server.hds` | « Ce serveur héberge des données de santé : aucun agent d'IA n'y travaille. » |
| niveau 0 | `plan.server.report_only` | « Ce serveur est réglé sur « Signaler » : Michel ne prépare rien. » `action: null` |
| `server_exposure` | `plan.exposure` | « Michel ne sait pas fermer ce service et ne lance rien. » `action: null`, le texte de la Task 13 suit |

`plainRisk` en simple pour `server_package` : `plain.server_package` « Un logiciel installé sur ce serveur a une faille connue. Sa mise à jour la corrige. », sinon `explain` de l'API.

- [ ] **Step 1: Tests** : `server plan tells the truth for each case`, dont : `no copy is ever promised` (aucun texte serveur, sauf `no_copy`, ne contient « copie à part ») ; `the word IA is used only for the agent` ; `rule level 3 keeps packages waiting` ; `server verified needs proven_fixed` (`inconclusive` avec `detail: proven` reste non vérifiée, cas `site_unchecked` de `server_exec.go:875`) ; `verified without a site says so` : `proven_fixed` sans `site_url` donne la note `path.note.no_site` ; `level 3 warning kept` : `servers.level.3.warn` reste affiché à côté.
- [ ] **Step 2: Vérifier l'échec, écrire.** Le texte `fix.intro_server`, épinglé par `texts.test.js`, ne change pas.
- [ ] **Step 3: Brancher** : chaque carte de `ServerSheet` montre `FailurePath` et le bloc, `#/servers/<id>?finding=<fid>` fait défiler et met le focus sur sa carte. `fix(c.finding)` et son dialogue `unknownOpen`, `agentOffer` restent tels quels. `FixPage` en `serverOnly` et `ServerProposal` : `FailureGuide` en tête.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes, sur le serveur `sshtest` de démonstration.
- [ ] **Step 5: Commit** `feat: the path of a flaw on a server, with its true text`.

### Task 10: Lire les services qui écoutent

**Files:**
- Create: `internal/collect/listeners.go`, `internal/collect/listeners_test.go`, `internal/collect/testdata/ss-debian.txt`, `internal/collect/testdata/ss-rhel.txt`
- Modify: `internal/target/target.go`, `internal/collect/commands.go`, `internal/collect/collect.go`, `internal/collect/collect_test.go` (le simulateur `host` répond à `ss`), `internal/api/targets_test.go` (`demoCommands`), catalogue `internal/i18n/catalog/{fr,en}.json`, `test/docker-server/Dockerfile`

**Interfaces:**
- Produces: `target.Listener{Address string; Port int; Scope ListenScope}` ; `ListenScope` : `ScopeOpen = "open"`, `ScopeServer = "server"`, `ScopePrivate = "private"` ; `target.ClassifyListen(addr string) ListenScope` ; `Inventory.Listeners []Listener`, `Inventory.ListenersRead bool`.
- Produces: `collect.ParseListeners(out string) (ls []target.Listener, rejected int, sawHeader bool)` ; `collect.ReasonListeners = "collect.unseen.listeners"`.

Ce que la lecture a trouvé dans le code : `allowed` n'accepte que les formes de `fixedCommands` ; `withLocale` préfixe `env LC_ALL=C LANG=C`, donc un `ss` absent répond 127 ; 60 s et 1 Mio par commande. Le conteneur n'a **pas** `ss` : `iproute2` n'est pas dans le `Dockerfile`, et `--no-install-recommends` ne l'amène pas.

- [ ] **Step 1: Tests de `ClassifyListen`** (R11), table : `0.0.0.0`, `::`, `*`, `203.0.113.7`, `2001:db8::1` ouvert ; `127.0.0.1`, `127.0.0.53`, `::1`, `::ffff:127.0.0.1` serveur ; `10.0.0.5`, `172.16.0.1`, `192.168.1.10`, `fd00::1`, `fe80::1`, `100.64.0.1` privé ; `::ffff:203.0.113.7` ouvert.
- [ ] **Step 2: Tests de `ParseListeners`** : `TestParseListeners` sur les fixtures (formes `0.0.0.0:80`, `*:80`, `[::]:80`, `127.0.0.1:5432`, `[::1]:5432`, `127.0.0.53%lo:53`, `0.0.0.0%eth0:68`, `[fe80::1]%eth0:22`) : zone retirée, adresse et port seuls gardés ; `TestParseListenersRefusesForged` (tabulation, port 0, 70000, adresse non IP, `$(id)`, ligne qui ne commence pas par `LISTEN`, séquence ANSI) : compte `rejected`, aucune valeur gardée ; au plus 4096 lignes ; `TestNoHeaderIsNotRead` (`sawHeader` faux).
- [ ] **Step 3: Tests de la collecte** : `TestListenersRunAsTheClosedList` ; `TestSsInSbinOnlyAfter127` (`/usr/sbin/ss` n'est demandé qu'après un 127, jamais après un 1) ; `TestSsMissingIsUnseen` (`ListenersRead` faux, une ligne `Unseen{What: "listeners", Reason: ReasonListeners}`, pas de `netstat`, pas de `sudo`) ; `TestSsFailureIsUnseen` (code 1, délai dépassé, sortie coupée `res.Truncated`, ligne rejetée) ; `TestSsDoesNotAskProcessNames` (pas de `-p` dans l'argv) ; `TestAuditCountsListenersOnly` (preuve `listeners: n`, sans adresse) ; `TestSameOnHdsAndShared`.
- [ ] **Step 4: Vérifier l'échec, écrire** : `cmdSS = {"ss", "-tln"}`, `cmdSSSbin = {sbin + "ss", "-tln"}` dans `fixedCommands`, `c.listeners()` appelé après `c.web(found)`. Texte `collect.unseen.listeners` : « Michel n'a pas pu lister les services qui écoutent sur ce serveur : la commande ss manque ou a échoué. Il ne sait donc pas ce qui est ouvert. » Mettre à jour le commentaire de `Commands` et le préambule du paquet.
- [ ] **Step 5: `Dockerfile`** : ajouter `iproute2`, et dans `michel-test.conf` de PostgreSQL `listen_addresses = '*'`, pour avoir une base « à fermer » ; le commentaire rappelle que seuls 22 et 80 sortent, sur `127.0.0.1`.
- [ ] **Step 6: Relecture FR, vérifier** `go test ./internal/collect/ ./internal/target/ ./internal/i18n/ ./internal/api/`, puis la porte Go. Si Docker est disponible, comparer les fixtures à la sortie réelle du conteneur.
- [ ] **Step 7: Commit** `feat: read the listening services over SSH, address and port only`.

### Task 11: Règles d'exposition

**Files:**
- Create: `internal/serverrules/exposure.go`, `internal/serverrules/exposure_test.go`
- Modify: `internal/serverrules/rules.yaml`, `internal/serverrules/rules.go` (`Version = 3`, section, validation), `internal/serverrules/eval.go`, `internal/scan/normalize.go`, `internal/scan/repo.go` (`ApplyServerFindings`, `ListServerFindings`), `internal/servercheck/check.go`, `internal/servercheck/check_test.go`, `internal/fix/server_agent_test.go`, `internal/api/targets_fix_test.go`, catalogue `internal/i18n/catalog/{fr,en}.json`

**Interfaces:**
- Produces: `scan.KindServerExposure = "server_exposure"`.
- Produces: `serverrules.ListenRule{Ports []int; Service, Verdict, Rule, Severity, Key string}` ; `Set.Listen []ListenRule` ; `Verdict` : `VerdictNormal = "normal"`, `VerdictClose = "close"`, `VerdictUnknown = "unknown"` ; `Judgement{Service, Verdict string}` (`Service` : `web`, `admin`, `database`, `cache`, `other`) ; `JudgeListener(s Set, t target.Target, l target.Listener) Judgement`.

Section de `rules.yaml` (`version: 3`) :

```yaml
listen:
  - {ports: [80, 443], service: web, verdict: normal}
  - {ports: [22], service: admin, verdict: normal}
  - {ports: [3306, 5432, 27017, 9200], service: database, verdict: close, rule: exposed_database, severity: medium, key: serverrules.exposed_database}
  - {ports: [6379, 11211], service: cache, verdict: close, rule: exposed_cache, severity: medium, key: serverrules.exposed_cache}
```

Une faille : `FindingID(t.ID, "exposure:"+port, "server-exposure", port, rule)`, `ManifestRelPath: "exposure:<port>"`, `Package: "<port>"`, `OSVID: rule`, `Kind: KindServerExposure`, `Ecosystem: "server-exposure"`, une seule par port même sur `0.0.0.0` et `::`.

- [ ] **Step 1: Tests** : `TestJudgeListenerTable` (chaque port de la spec, autre port `other`/`unknown`, `t.Port = 2222` donne `admin`/`normal`, R10) ; `TestOpenDatabaseIsAFinding` ; `TestReservedDatabaseIsNot` (serveur, privé) ; `TestNoExposureFindingOnShared` (R8) ; `TestHdsGetsTheFinding` ; `TestOnePerPortAcrossIPv4AndIPv6` ; `TestExposureIsNeverUrgent` (`prod`, `servercheck.Urgent` faux, `grave` faux : aucune alerte, R9) ; `TestUnknownVersionIsRefused` (`rules.go`).
- [ ] **Step 2: Tests du jugement** : `TestUnreadListenersKeepExposureOpen` (`ListenersRead` faux, y compris `Rematch` d'un ancien inventaire : `judge` ajoute le préfixe `exposure:` aux `UnreadPrefixes`, la faille reste ouverte) ; `TestClosedServiceBecomesGone` (lecture complète, service fermé : `gone`, compté dans la réponse) ; `TestDigestServersSectionNamesExposureInPlainWords`.
- [ ] **Step 3: Tests du refus de correction** : `TestExposureCannotStartAFix` (`POST /findings/{id}/fix`, `POST /targets/{id}/fix/{f}`, `POST /targets/{id}/agent-fix/{f}` refusent et ne créent aucune tentative) ; `TestExposureNeverQueued` (`EligibleServer` faux, niveau 3 compris) ; `TestAgentInventoryHasNoListeners` (`serverInventoryView` : aucun port, aucune adresse d'écoute dans le JSON, le marqueur d'une fixture absent).
- [ ] **Step 4: Vérifier l'échec, écrire**, avec `serverrules.exposed_database.title` « Une base de données écoute sur toutes les adresses de ce serveur », `.explain` « Elle est joignable depuis l'extérieur si aucun pare-feu ne la bloque. Personne dehors n'a besoin d'y accéder : c'est une porte d'entrée possible vers tes données. », `exposed_cache` de même forme avec « Un cache (une mémoire rapide utilisée par le site) ».
- [ ] **Step 5: Relecture FR, vérifier** la porte Go.
- [ ] **Step 6: Commit** `feat: judge what listens, a database open to all is a server flaw`.

### Task 12: API d'exposition et docs

**Files:**
- Create: `internal/api/targets_exposure.go`, `internal/api/targets_exposure_test.go`
- Modify: `internal/api/targets.go` (route), `docs/servers.md`, `docs/servers.fr.md`, `docs/security/network-egress.md`, `docs/security/network-egress.fr.md`

**Interfaces:**
- Produces: `GET /api/v1/targets/{id}/exposure` : `ExposureView{Read bool `json:"read"`; CheckedAt string `json:"checked_at"`; Kind string `json:"kind"`; Services []ExposureService `json:"services"`; Unseen []TargetUnseenView `json:"unseen"`; Closed []ExposureClosed `json:"closed"`}` ; `ExposureService{Port int; Addresses []string; Scope, Service, Verdict, FindingID, DecidedWhy string}` (JSON : `port`, `addresses`, `scope`, `service`, `verdict`, `finding_id`, `decided_why`) ; `ExposureClosed{Port int; Service, At string}`.
- Produces: `POST /api/v1/targets/{id}/exposure/{finding}/decision`, corps `{"why": "…"}` (R12).

- [ ] **Step 1: Tests** : `TestExposureNeverCheckedSaysNotRead` (`read: false`, liste vide, 200) ; `TestExposureGroupsByPortAndScope` ; `TestExposureOldInventoryNotRead` ; `TestExposureDecisionNeedsWhy` ; `TestExposureDecisionOnlyForExposureOfThisServer` (404 pour une faille d'un autre serveur ou d'un autre genre) ; `TestExposureDecisionAudited` (`decide.Apply`, acteur `web`) ; `TestExposureDecisionLeavesTheServiceInItsColumn` ; `TestAuthRequired` pour les deux routes.
- [ ] **Step 2: Vérifier l'échec, écrire.**
- [ ] **Step 3: Docs.** `servers*.md` § 4 : ajouter `ss -tln` (puis `/usr/sbin/ss -tln` si la commande n'est pas trouvée) ; seuls adresse et port sont gardés, jamais le nom d'un processus (il demanderait des droits que Michel ne demande pas) ; TCP seulement ; sur tout type de serveur, `hds` compris, avec la raison ; une section « Ce qui est exposé » : ce que veulent dire les trois colonnes, **cette lecture se fait depuis l'intérieur et ne prouve pas qu'on peut joindre le service, le pare-feu de l'hébergeur n'est pas vérifié**, un serveur en conteneur ou mutualisé peut montrer d'autres services, l'agent IA ne reçoit pas cette liste. `network-egress*.md`, ligne `target.ssh` : aucun nouvel usage, et ce qui revient maintenant : la liste des adresses et ports en écoute. **Relecture FR.**
- [ ] **Step 4: Vérifier** la porte Go.
- [ ] **Step 5: Commit** `feat: exposure view of a server, and what comes back documented`.

### Task 13: Écran d'exposition

**Files:**
- Create: `web/src/lib/exposureView.js`, `web/src/lib/exposureView.test.js`, `web/src/components/ServerExposure.vue`
- Modify: `web/src/components/ServerSheet.vue` (première section sous l'en-tête ; les failles `server_exposure` n'ont pas de bouton de correction), `web/src/lib/todoView.js`, `web/src/lib/todoView.test.js`, `web/src/components/TodayPage.vue`, `web/src/components/ResolvedPage.vue`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: Task 12, `FailurePath`, `FieldHelp` (ajouter `exposure.decision` à `helpIds`, FR et EN).
- Produces: `exposureColumns(view, target, lang, advanced): {title, sub, open: Row[], reserved: Row[], unverified: Row[]}` ; `Row = {name, note, tag: 'close'|'normal'|'check'|null, findingId, detail}`.

Textes exacts (R3) :

| Clé | Texte |
|---|---|
| `expo.title.none` | « {serveur} : Michel ne voit aucun service ouvert à tous depuis le serveur » |
| `expo.title.one` | « {serveur} : {n} service joignable si aucun pare-feu ne le bloque » |
| `expo.title.other` | « {serveur} : {n} services joignables si aucun pare-feu ne les bloque » |
| `expo.title.of_close` | « , dont {n} à fermer » |
| `expo.title.not_read` | « {serveur} : Michel n'a pas encore pu lire ce qui écoute » |
| `expo.sub` | « Un service, c'est un programme de ton serveur qui attend qu'on le contacte. Michel regarde depuis l'intérieur du serveur. » |
| `expo.col.open` | `Ouvert à tous` |
| `expo.col.reserved` | `Réservé` |
| `expo.col.unverified` | `Non vérifié` |
| `expo.reserved.server` | « Réservé au serveur : il ne répond qu'au serveur lui-même. » |
| `expo.reserved.private` | « Réservé au réseau privé : seules les machines de ce réseau peuvent le joindre. » |
| `expo.firewall.name` | `Pare-feu de l'hébergeur` |
| `expo.firewall.note` | « Michel ne le voit pas depuis le serveur. Un service listé « ouvert à tous » peut être bloqué par ce pare-feu, et Michel ne le sait pas. » |
| `expo.udp.name` | `Services UDP` |
| `expo.udp.note` | « Michel lit seulement les services TCP, le type le plus courant. Les autres n'apparaissent pas ici. » |
| `expo.service.web` | `Site web` |
| `expo.service.web_note` | « Normal, c'est ton site. » |
| `expo.service.admin` | `Connexion d'administration` |
| `expo.service.admin_note` | « Normal. C'est par là que Michel se connecte. À protéger par une clé. » |
| `expo.service.database`, `.cache` | `Base de données`, `Cache` |
| `expo.tag.close` | `À fermer` |
| `expo.service.other` | `Service non reconnu` |
| `expo.tag.check` | `À vérifier` |
| `expo.how` | « Demande à la personne qui gère le serveur, ou à ton hébergeur, de la faire écouter seulement sur le serveur lui-même, ou de la bloquer dans le pare-feu. Puis lance une vérification : si Michel ne la voit plus ouverte, c'est confirmé. » |
| `expo.shared` | « Sur un hébergement mutualisé, ces services peuvent être ceux de l'hébergeur ou d'autres clients : Michel n'en fait pas des failles. » |
| `expo.decision.open` | « Je sais, c'est bloqué ou voulu » |
| `expo.decided` | « Tu as indiqué : {why} Michel ne l'a pas vérifié. » |

- [ ] **Step 1: Tests** : `the firewall row is always there` (lu, non lu, sans service, `shared`, `hds`) ; `UDP row always there` ; `not read says so and keeps the firewall row` ; `columns follow scope` ; `title says firewall whenever something is open` ; `no reassuring word anywhere` (toutes les sorties et toutes les clés `expo.` en FR et EN : ni « protégé », « sécurisé », « sûr », `safe`, `protected`, `secure`, ni « fermé » hors de `À fermer` et `expo.closed`) ; `simple mode hides numbers, advanced shows them` ; `unseen lines join the third column` ; `decided row keeps its column and says not verified`.
- [ ] **Step 2: Vérifier l'échec, écrire** `ServerExposure.vue` : bordure haute de 4 px (rouge, vert, gris) comme `.wall`, toujours avec le mot ; `flex-wrap`, une colonne sur téléphone ; bouton `Vérifier maintenant` si jamais lu ; chemin de la faille et `plan.exposure` + `expo.how` sous un service à fermer ; dialogue de décision avec justification obligatoire (`validateDecision`).
- [ ] **Step 3: À faire, Résolu** : lignes `todo.exposure` depuis `details[].findings` de genre `server_exposure` ; action `Comprendre` vers `#/servers/<id>?finding=<fid>` ; services fermés dans `resolvedLines` avec `closed`.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes.
- [ ] **Step 5: Commit** `feat: what is exposed on a server, the firewall always said unverified`.

### Task 14: Ajouter et contrôler un projet depuis la page

**Files:**
- Create: `internal/api/projects_run.go`, `internal/api/projects_run_test.go`, `web/src/components/AddProjectDialog.vue`, `web/src/lib/projectsView.js`, `web/src/lib/projectsView.test.js`
- Modify: `internal/api/server.go` (`Deps.ScanProject`, routes), `internal/api/views.go`, `internal/api/handlers.go`, `internal/cli/scan.go`, `internal/cli/serve.go`, `internal/cli/serve_test.go`, catalogue `internal/i18n/catalog/{fr,en}.json`, `web/src/components/ProjectsPage.vue`, `web/src/components/ProjectCard.vue`, `web/src/i18n/{fr,en}.json`, `README.md` et `grep -ln "project add" docs` là où la ligne de commande est dite seule possible

**Interfaces:**
- Produces, Go : `Deps.ScanProject func(ctx context.Context, p project.Project) error` (nil : 503) ; `POST /api/v1/projects` corps `{path, name}`, 201 `ProjectView` ; `POST /api/v1/projects/{name}/scan`, 202 `{started: true}`, 409 si déjà en cours ; `ProjectView` gagne `scanning bool` et `last_failure *TargetLastCheck` (mémoire du processus, tracker `checkTracker`). Codes : `api.project.not_dir`, `api.project.relative_path`, `api.project.duplicate`, `api.project.bad_name`, `api.project.no_database`, `api.project.nothing_to_scan`, `api.project.scan_failed`, avec `_hint`.
- Produces, CLI : `scanOneProject(ctx, cmd, deps, p, queue bool) (scan.Result, string, error)`, extrait du corps de `newScanCmd` : scan, `fix.Prove`, analyse, plugins, sans rien imprimer de plus ; `newScanCmd` l'appelle, sa sortie ne change pas.
- Produces, JS : `projectNameFromPath(path): string` (`\` et `/`, dernier dossier) ; `scanSentence(project, lang)`.

- [ ] **Step 1: Tests Go** : `TestAddProjectFromThePage` (`repo.Add`, audit `project.add` acteur `web`, classement par défaut de la politique) ; `TestAddProjectRefusesRelativePathAndFile` ; `TestAddProjectAnswerHasNoAbsolutePath` (chemin absent de la réponse et du message d'erreur, comme `TestAPIResponsesHaveNoAbsolutePathsNorCommands`) ; `TestAddProjectCannotSetTestCmdOrLevel` (R13 : champ inconnu refusé) ; `TestScanRunsInBackgroundOnce` (202, 409) ; `TestScanReportsMissingDatabase` et `TestScanReportsNothingToScan` ; `TestScanProvesAMergedFix` (`fix.Prove` appelé) ; `TestScanWritesNothingInTheProject` ; `TestAuthRequired` ; `internal/cli` : `TestScanOutputUnchanged`, `TestServeGivesScanProject`.
- [ ] **Step 2: Tests JS** : `name from a windows or unix path` ; `scan sentence for never, running, failed, ok`.
- [ ] **Step 3: Vérifier l'échec, écrire.** `AddProjectDialog` : `path` et `name` avec `FieldHelp` (ajouter `project.path` et `project.name` à `helpIds`), texte `project.path` : le chemin complet du dossier, Michel n'y écrit rien lors du contrôle. `ProjectCard` : bouton « Contrôler ce projet », état. `api.project.no_database` : phrase qui dit de télécharger la liste des failles, et lien `#/sources`.
- [ ] **Step 4: Relecture FR, vérifier** les deux portes, et `go test ./internal/cli/` à part : la sortie de `michel scan` ne bouge pas.
- [ ] **Step 5: Commit** `feat: add and check a project from the page`.

### Task 15: Guide du premier lancement, écrans vides

**Files:**
- Create: `web/src/lib/guideView.js`, `web/src/lib/guideView.test.js`, `web/src/components/FirstSteps.vue`
- Modify: `web/src/lib/storage.js`, `web/src/components/TodayPage.vue`, `ProjectsPage.vue`, `ServersPage.vue`, `ServerExposure.vue`, `FixPage.vue`, `ResolvedPage.vue`, `FailureGuide.vue`, `SettingsPanel.vue`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `keys.guide = 'michel.guide'` ; `readGuide(load): {dismissed: boolean, read: boolean}` (JSON invalide ou absent donne faux) ; `guideSteps({projects, servers, read, anyFinding}): {key: 'add'|'check'|'read', done: boolean, current: boolean, action: {label, href}|null}[]` ; `guideVisible(steps, state): boolean`.

- [ ] **Step 1: Tests** : `guide resumes from data when storage is empty` (un projet scanné : `add` et `check` faits, `read` courant) ; `no flaw means step three says so` ; `dismissed stays dismissed, settings can show it again` ; `storage that throws changes nothing` ; `done guide disappears`.
- [ ] **Step 2: Écrire.** `FirstSteps.vue` : un panneau en tête d'À faire, jamais de bulle ni de voile. Trois lignes numérotées, état en mots, une action par étape, `Ignorer pour l'instant`. Étape 3 : `read` passe vrai au montage de `FailureGuide` ou d'une carte de faille.
- [ ] **Step 3: Écrans vides** : chacun dit quoi faire et porte l'action. `empty.todo` (À faire sans projet ni serveur), `empty.projects` + `Ajouter un projet`, `empty.servers` + `Trouver mes serveurs`, `empty.fix` + retour à À faire, `empty.exposure` + `Vérifier maintenant`, `empty.resolved` (Task 7). `today.no_projects_hint` (qui renvoie à la ligne de commande) n'est plus utilisée en mode simple.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes, avec un dossier de données vide.
- [ ] **Step 5: Commit** `feat: first steps guide and empty screens that act`.

### Task 16: Essai par une personne novice

**Files:**
- Create: `docs/superpowers/sdd/2026-11-03-michel-ui-guided/novice-run.md`
- Modify: ce que l'essai oblige à corriger, en commits séparés, avec son test d'abord

- [ ] **Step 1: Préparer, hors du dépôt** : dossier de données jetable ; `test/docker-server` dans WSL (`wsl -d Ubuntu -- docker build …`, `docker run` avec `-p 127.0.0.1:2222:22 -p 127.0.0.1:8080:80`, session WSL gardée ouverte) selon `real-run-checklist.md` ; agent SSH de test en espace utilisateur (`ssh.agent_pipe`), **service `ssh-agent` de Windows non touché** ; projet `demo` jetable avec `guzzlehttp/guzzle` 7.4.0 dans `composer.lock`, un dépôt Git et une commande de test ; faux agent (R18) ; `michel serve`.
- [ ] **Step 2: Essai.** Un sous-agent neuf joue une personne qui ne connaît pas l'informatique. Il reçoit seulement l'adresse de la page, le dossier du projet, l'adresse et l'utilisateur du serveur, et ces trois buts, en ces mots : voir les failles de son projet, savoir comment l'IA va les résoudre, voir résolu ; idem pour son serveur ; voir ce qui est ou non exposé. Ni la spec, ni le code, ni ce plan. Dans un vrai navigateur (Chrome DevTools). Il note chaque hésitation, chaque mot non compris, chaque clic sans effet, chaque moment où il aurait demandé de l'aide, avec une capture.
- [ ] **Step 3: Parcours**, complets à 1280×800 en clair, et à 375×812 en sombre (R18) :
  1. Projet : ajouter, contrôler, lire la faille, comprendre, lancer, valider, fusionner avec la commande copiée, contrôler, voir « Vérifiée » et la ligne dans Résolu.
  2. Serveur : ajouter, confirmer l'empreinte, vérifier, lire `expose_php`, préparer, lire le script, valider, voir « Vérifiée ».
  3. Exposition : voir PostgreSQL « Ouvert à tous », « À fermer », le pare-feu « Non vérifié » ; dans le conteneur, remettre `listen_addresses = 'localhost'` et redémarrer PostgreSQL ; vérifier : le service passe en « Réservé », la faille en Résolu. Puis retirer `iproute2` : l'écran dit « pas pu lire », jamais « rien d'ouvert ».
- [ ] **Step 4: Écrans** une fois chacun à 1280 px en sombre et à 375 px en clair : À faire, Mes projets, Mes serveurs, fiche, Résolu, Réglages, un dialogue. Contrôles sur chaque : `document.documentElement.scrollWidth <= innerWidth` ; aucune requête refusée par la CSP ; console sans erreur ; clavier seul sur un parcours ; `prefers-reduced-motion`.
- [ ] **Step 5: Contrôles d'absence** : `grep` d'un marqueur de journal piégé dans le DOM, les réponses et les messages de l'agent : zéro. Le canari `canari-michel-7391` jamais affiché.
- [ ] **Step 6: Corriger** ce qui bloque, test d'abord, relecture FR, puis rejouer le parcours touché. Une étape qui bloque encore sans correction possible dans ce plan (R6, la fusion, si c'est le cas) est écrite telle quelle dans le rapport, avec ce que la personne a fait.
- [ ] **Step 7: Nettoyer** : `docker rm -f`, `docker rmi`, dossier jetable, agent de test arrêté ; `git status` sans trace. `novice-run.md` en agrégats et mots de la personne, sans hôte, empreinte ni jeton.
- [ ] **Step 8: Vérifier** `go test ./...`, `go vet ./...`, `npx vitest run`, `go test ./internal/hygiene/`, revue de toute la branche.
- [ ] **Step 9: Commit** `docs: novice run of the three journeys`.

## Self-review (2026-11-03)

Couverture de la spec : Pourquoi et Objectifs, Tasks 1, 2, 16 ; Structure, Tasks 2, 6, 7 ; Chemin, Tasks 8, 9, 13 ; Exposition, Tasks 10 à 13 ; Mode avancé, Task 3 ; Guide, Tasks 4, 14, 15 ; Apparence, Tasks 1, 2 ; Contraintes, Global Constraints, Task 5 pour les remarques reportées, Task 16 pour le navigateur. Ordre de la spec respecté, sauf `isVerified`, créé à la Task 7 pour que Résolu ne dépende pas d'un écran à venir, et la Task 14, ajoutée avant le guide qui en a besoin (R4). Noms croisés vérifiés entre les blocs Interfaces. Android Studio reste possible pour la PWA, non requis par cette liste.
