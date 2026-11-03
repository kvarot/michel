# Michel : interface guidée, plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Une personne novice fait seule, en dix minutes, les trois parcours (faille de projet, faille de serveur, exposition d'un serveur), dans une interface d'allure professionnelle où rien de ce qui existe n'est retiré.

**Architecture:** Une coquille de navigation (`App.vue`, `lib/navView.js`) et un thème (`lib/theme.js`) ; le mode avancé vit dans `$ui.advanced`, sur les mêmes pages. Trois modules de logique pure : `lib/todoView.js` (À faire, Résolu), `lib/pathView.js` (le chemin de la faille et le texte vrai de « ce qui va se passer »), `lib/exposureView.js`. Côté Go : une commande de plus dans la liste fermée de `internal/collect`, des règles déterministes dans `internal/serverrules`, un genre de faille `server_exposure` que le service de correction refuse, deux routes pour ajouter et contrôler un projet depuis la page, et, pour un projet rattaché et sur clic, un envoi de branche et une mise à jour sans fusion (`internal/gitremote`, `internal/workcopy/remote.go`, `internal/fix/remote.go`).

**Tech Stack:** Go 1.27.3, Vue 3.5 Options API, JS et JSDoc, Vuetify 4.3, Vite, Vitest (fonctions pures, environnement `node`). Aucune nouvelle dépendance.

**Spec:** `docs/superpowers/specs/2026-11-03-michel-ui-guided-design.md`. Apparence de référence : `docs/superpowers/specs/2026-11-03-michel-ui-guided-mockup.html`, avec les corrections de texte de la règle R3.

## Global Constraints

- Branche `feat/ui-guided`. Module `github.com/kvarot/michel`. Anglais pour code, commits, CLI ; français pour ce plan et le ledger (`.superpowers/sdd/2026-11-03-michel-ui-guided/`, en agrégats, recopié selon la règle du propriétaire). `novice-run.md` (Task 16) va dans `docs/superpowers/sdd/2026-11-03-michel-ui-guided/`.
- Commandes Bash : `export PATH="$LOCALAPPDATA/Programs/go/bin:$PATH"`. Pas de python, pas de gcc (donc pas de `-race` ici). Docker seulement dans WSL (`wsl -d Ubuntu -- docker`).
- **Porte de chaque tâche front** : `cd web && npx vitest run && npm run build`, puis `go test ./web ./internal/hygiene/`. **Porte de chaque tâche Go** : `go test ./...` et `go vet ./...`. Les échecs `example/mcp` de `internal/api` sont environnementaux (ruling R7 du plan 7) : les citer, ne pas les corriger.
- Vue 3 Options API, JS et JSDoc, Vuetify 4. Logique testable dans `web/src/lib/*View.js`, sans DOM. Vitest reste sur `node` : pas de test de composant, pas de `@vue/test-utils` (aucune dépendance ajoutée) ; ce qu'un composant décide passe par une fonction de `lib/`.
- **CSP inchangée** : ni police téléchargée ni ressource externe. `--m-voice` (serif déjà en place) pour les phrases de Michel et les titres-verdicts, `--m-ui` pour l'interface. Icônes : chemins SVG écrits dans le code, comme `checkPath` dans `ProjectCard.vue`.
- **Une gravité est toujours une couleur et un mot.** Contraste AA, clavier, `prefers-reduced-motion`, 16 px de marge sur téléphone, aucun défilement horizontal à 375 px.
- **Textes** : `web/src/i18n/{fr,en}.json`, à égalité, FR au tutoiement ; `internal/i18n/catalog/{fr,en}.json` pour ce qui vient de Go. **Tout texte français passe un lecteur non spécialiste avant la revue de code** : c'est une étape de chaque tâche qui en crée ou en change.
- **Jargon** : pas de CVE, CVSS, port, paquet ni SSH en mode simple sans explication (`web/src/i18n/jargon.test.js`, écrit à la Task 3). **Liste `jargonExceptions` de ce test** : vide à la Task 3. Une tâche qui ajoute dans `nav.`, `todo.`, `resolved.`, `path.`, `plan.`, `expo.`, `guide.`, `empty.`, `help.` ou `git.` une clé française contenant `port`, `paquet` ou `SSH` donne l'explication dans la même phrase et ajoute cette clé à la liste, dans le même commit. `jargon.test.js` compte alors comme faisant partie de ses fichiers, même s'il n'y est pas listé.
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
- **R6, Michel ne fusionne toujours pas.** Le dernier pas du parcours projet reste à la personne : la page dit quoi faire et donne la commande à copier. C'est la seule étape où une personne sans Git peut bloquer ; l'essai de la Task 16 le mesure et le rapporte, il ne le contourne pas. Coût : l'objectif 1 de la spec n'est pas tenu à 100 % pour qui n'a jamais utilisé Git. Vrai sans rattachement ; avec, voir R19.
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
- **R19, ce que le rattachement change à R6.** Michel ne fusionne toujours pas : la personne accepte sur le site. Pour un projet rattaché, il n'y a plus de commande à taper. Non rattaché, R6 reste entier. Les seules écritures nouvelles sont deux clics. Elles s'ajoutent à la branche locale d'`Apply`, qui existe déjà. Coût si faux : une personne sans compte sur le site reste bloquée comme avec R6 ; l'essai de la Task 16 ne peut pas le mesurer avec un dépôt local.
- **R20, lecture du distant.** Lecture brute de `.git/config` par `git config --local --get-regexp`, sans réseau et sans `insteadOf`. `origin`, sinon le seul distant ; sinon Michel ne choisit pas. `pushurl` n'est pas lu. Coût si faux : qui pousse par un `pushurl` différent verra un refus du service ou un envoi à l'adresse `url`, celle qu'il a vue et acceptée.
- **R21, reconnaissance et lien.** Égalité stricte sur six hôtes, jamais une sous-chaîne : `gitlab.example.test` est « service non reconnu ». Le lien est bâti côté Go à partir de parties validées, et revérifié dans la page (`safeMergeUrl`). Une adresse bizarre ne donne aucun lien, jamais un lien approché. Coût si faux : un GitLab auto-hébergé n'a pas de lien, seulement le nom de la branche, comme le dit la spec.
- **R22, d'où part l'envoi.** Ni du miroir, ni du projet. `Apply` retire le miroir (`d.cleanup(ctx, a, true)`). Le projet a une configuration non fiable (`safeConfig` le dit), et `core.sshCommand`, `credential.helper`, `url.*.insteadOf`, `remote.<adresse>.receivepack` feraient lancer un programme ou changeraient la destination au moment où git lit des accès réels. `safeConfig` ne peut pas servir ici : elle vide `credential.helper`. Donc un dépôt temporaire propre à Michel (`<data>/fix-net/<ulid>.git`), cloné par la commande de `Prepare`, retiré après. La mise à jour récupère de la même façon. Coût : la place et le temps d'une copie du dépôt à chaque clic, comme une tentative.
- **R23, quels accès.** Le réseau de git tourne avec la vraie configuration et le vrai dossier personnel de la personne, seul moyen de trouver ses clés, son agent et son gestionnaire d'accès, avec une liste fermée de variables et aucune invite (`GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `SSH_ASKPASS_REQUIRE=never`, `BatchMode`), borné à 2 minutes. Un mot de passe écrit dans l'adresse n'est **pas** utilisé : le passer à git le mettrait dans l'argv ou le garderait. Coût si faux : qui n'a d'accès que par un jeton dans l'adresse, ou une clé à phrase secrète sans agent, ou un service encore jamais contacté, reçoit un refus expliqué (`auth`, `host_key`) et utilise son outil Git une fois.
- **R24, mise à jour.** `merge --ff-only` sur la branche courante, si elle est la principale (référence `<remote>/HEAD`, sinon seule `main` ou `master`) et sans modification suivie, ni fusion en cours. Les fichiers non suivis ne comptent pas : git refuse de les écraser (`untracked`). Elle tourne avec la configuration de la personne, pas l'environnement de `h.git`, qui ignore `core.autocrlf` et réécrirait les fins de ligne sous Windows. Hooks coupés. Git ne sait pas couper les filtres par `-c` : une clé `filter.*` locale, `core.worktree`, ou un fichier changé avec un attribut `filter` (Git LFS) donne un refus. La récupération écrit les objets et la référence de suivi avant le contrôle d'écart, d'où « n'a pas touché à tes fichiers » et non « à rien ». Coût : un projet LFS met à jour à la main.
- **R25, ce qu'il faut à `Prove`.** `Prove` exige `gone` et `IsMerged`, soit `merge-base --is-ancestor sha HEAD`. Une fusion par commit de fusion ou en avance rapide y répond, avec la mise à jour et un scan du dossier, donc « Vérifiée » peut s'allumer (`rescan_clean` selon R2). **Mais « Squash » et « Rebase », proposés sur les trois sites, changent le commit** : sans rien faire, la tentative finirait en `inconclusive` (`gone_not_merged`) et « Vérifiée » resterait éteinte. `IsMerged` accepte donc aussi `git cherry HEAD sha sha^` marqué `-`, le même changement exact, pour tous les projets. La fusion resserrée avec d'autres commits reste `inconclusive`, avec sa phrase. La page lance le contrôle après `updated`. Coût si faux : un changement identique venu d'ailleurs compte comme fusionné, ce qui reste vrai du code.
- **R26, accord.** Une ligne par projet (`project_remote`), jamais de secret. Le oui vaut pour **une adresse** (`remote_id`) ; elle est relue à chaque clic, et si elle change, plus rien ne part avant une nouvelle réponse. `strict_local` ne bloque pas : aucun code n'y interdit une règle `network.allow`, sources et serveurs (`target.ssh`) en ajoutent sur consentement dans ce mode, et le guide pose la question sur une installation neuve, donc en `strict_local`. La phrase `yes_detail` dit l'hôte. Coût si faux : qui lit `strict_local` comme « rien ne sort » voit un oui explicite faire sortir du code, à sa demande et par clic.
- **R27, réseau.** Nouvel usage `project.git`, règle écrite au oui, sur l'hôte exact. `Gateway.Authorize` décide et note **avant** le lancement, fermé si l'audit manque. HTTPS passe par le proxy d'autorisation, donc 443 seulement et aucun `http://`. SSH ouvre sa propre connexion : la passerelle ne la porte pas, c'est écrit dans « Declared only ». Coût : un GitLab sur un autre port en https est refusé (SSH reste possible), et un `url.*.insteadOf` global de la personne échappe au contrôle d'hôte.
- **R28, dépôt local.** `file://` et chemins sont refusés en produit : avec le transport local, `receive-pack` lance les hooks du dépôt cible, même avec `-c core.hooksPath` (essayé avec Git 2.46.2). Tests : `allowLocal`. Essai de la Task 16 : R33. Coût : qui a son distant sur un disque partagé pousse à la main.
- **R29, clic par clic.** `POST` sans corps, une action par clic, audit de chaque clic, refus compris (`project.git.push`, `project.git.update`, `project.git.answer`). Aucun déclenchement par le niveau 3, le worker, un scan ou une commande : **pas de ligne de commande en première version**. Second clic sur l'envoi : `already`, 200, rien de renvoyé, audité. Second clic sur la mise à jour : `up_to_date`. Pendant qu'un clic tourne : 409 `api.git.busy`, verrou par projet, dans le processus de `serve`, seul à exposer ces routes. Après un délai dépassé, recliquer est sans danger. Coût : un script ne peut pas envoyer.
- **R30, pas de dépôt Git.** `workcopy.IsGitRepo` regarde seulement le dossier ajouté, sans remonter. Le scan et la fiche marchent ; `fix.Start` répond `ErrNotGit`, et `Prepare` `ErrNoCommit` sans commit ; `Prove` ne peut jamais prouver. Michel ne fait pas `git init` : ce serait écrire dans le dossier et créer un historique qu'il ne maîtrise pas. La page dit `git.none` ou `git.empty`, la question n'est pas posée, le bouton de correction n'est pas offert (`plan.project.no_git`). Coût : le parcours « corriger » est fermé à cette personne, et elle le sait d'emblée.
- **R31, le lien.** La spec dit que la page « ouvre » le lien. Après une requête asynchrone, `window.open` est bloqué par les navigateurs : c'est un vrai lien, un clic de plus, avec `rel="noopener noreferrer"`. Coût : ce clic.
- **R32, sortie de git.** Jamais affichée ni gardée : ni `gitErr` (qui garde une ligne de stderr), ni `auditDetail`, ni message. Une classe fermée, décidée en mémoire. Les messages `remote:` du service sont perdus, et avec eux une raison utile qu'aucune classe ne reconnaît (`failed`). Les codes HTTP restent 409 et 502. Coût : un diagnostic demande l'outil Git de la personne.
- **R33, le dépôt local de l'essai.** Pas de variable d'environnement : `MICHEL_TEST_LOCAL_REMOTE` aurait élargi un contrôle du produit sur toute installation où elle est posée, et rien ne l'en aurait empêchée. `AllowLocalRemote` est un champ de `fix.Deps` et de `workcopy.Deps`, que les tests posent directement. `michel serve` le lit dans une constante de compilation, fausse par défaut, vraie seulement avec `go build -tags michel_local_remote`. `Makefile`, `README.md` et la CI construisent sans ce tag, un test le vérifie, et aucune variable, option ni réglage ne l'ouvre à l'exécution. La Task 16 construit ce binaire-là dans son dossier jetable. Un essai en SSH vers le conteneur éviterait tout interrupteur, mais demande `git` dans l'image, une clé et un `known_hosts` de test, pour le même écran. Coût si faux : l'essai tourne sur un binaire qui diffère d'une constante, et sans le réseau réel, comme avec la variable.
- **R34, ordre des refus de mise à jour.** Le refus d'une clé `filter.*` (R24) passe **avant** `git status`, qui lance le `clean` d'un fichier changé de même taille (essayé avec Git 2.46.2 : le programme témoin tourne). `check-attr` lit les attributs **du commit qui arrive** (`--source=<sha>`), sinon un `.gitattributes` amené par la mise à jour passe le contrôle (essayé : `unspecified` sans `--source`, `lfs` avec). Coût si faux : un Git trop ancien pour `--source` refuse la mise à jour par clic (`update_failed`), et la personne utilise son outil Git.
- **R35, « Contrôler ce projet » pendant un clic.** Le verrou par projet de R29 vaut aussi pour `POST /projects/{name}/scan` : 409 `api.git.busy` tant qu'un envoi ou une mise à jour tourne, car un contrôle lirait un dossier en pleine écriture. Coût si faux : un refus de plus, si la personne clique sur les deux à la suite.

## Review Focus

1. **Sortie hostile ou inattendue de `ss`** (tabulation, adresse forgée, port 70000, `%zone`, pas d'en-tête, liste coupée, sortie vide avec code 0) : rien hors schéma n'est gardé, le doute devient « non vu », jamais « rien d'ouvert ». Test : Task 10 `TestParseListenersRefusesForged`, `TestNoHeaderIsNotRead`.
2. **Lecture absente ou ancienne** (`ss` manquant, inventaire d'avant cette version, `Rematch` sans connexion) : une faille d'exposition déjà ouverte le reste, l'écran dit « pas encore lu ». Tests : Task 11 `TestUnreadListenersKeepExposureOpen`, Task 13 `not read says so and keeps the firewall row`.
3. **Liste À faire vide alors que Michel n'a rien vu** (aucun scan, scan échoué, serveur jamais vérifié, base de failles absente) : jamais de phrase rassurante. Test : Task 6 `an empty list never reassures when something was not seen`.
4. **États qui ne prouvent rien** (`inconclusive`, `unknown`, `failed`, `proven_fixed` sans `rescan_clean`, `applied` jamais fusionné) : jamais « Vérifiée », et la faille reste à faire quand elle l'est. Test : Task 8 `verified table`.
5. **Stockage bloqué ou effacé** (fenêtre privée, `localStorage` qui lève) : la page marche, le mode revient à simple, le guide reprend d'après les données et non d'après le stockage. Test : Task 15 `guide resumes from data when storage is empty`, Task 3 `advanced defaults to off`.
6. **Dépôt hostile** (`.git/config` qui lance un programme, adresse forgée, jeton dans l'adresse, sortie de git piégée) : rien ne tourne, aucun secret ni sortie brute n'est gardé ou affiché, aucun lien hors des trois sites, aucune branche que `michel/fix-…`. Tests : Task 14c `TestPushRunsNoProjectConfig`, Task 14d `TestUpdateRunsNoHookNorFilter`, Task 14b `TestMergeURLOnlyOnThreeOrigins`, Task 14e `TestPushRecordsNoOutput`.
7. **Le dossier de la personne** (branche, modifications, fins de ligne, fusion par « squash ») : un refus laisse `HEAD`, index et fichiers identiques ; une mise à jour réussie laisse un dossier propre et permet « Vérifiée ». Tests : Task 14d `TestUpdateRefused`, `TestUpdateKeepsAutocrlf`, Task 14e `TestProveAfterSquashIsProvenFixed`.

---

### Task 1: Thème et palette

**Files:**
- Create: `web/src/lib/theme.js`, `web/src/lib/theme.test.js`
- Modify: `web/src/main.js` (remplace `shared`), `web/src/styles.css`

**Interfaces:**
- Produces: `themes = {light, dark}` (couleurs Vuetify) ; `contrast(a: string, b: string): number`.

- [ ] **Step 1: Test** `every text color reaches AA on its backgrounds` : pour `on-background`, `primary`, `success`, `warning`, `error`, `critical`, `high`, `medium`, `low`, `unknown`, `secondary` sur `background` et `surface`, puis `on-primary` sur `primary`, `on-nav` sur `nav` et `nav-active`, et les mots-gravité `error` sur `tag-urgent`, `warning` sur `tag-look`, `success` sur `tag-done`, `secondary` sur `tag-info`, dans les deux thèmes : `contrast >= 4.5`.
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
| `tag-urgent` | `#FBEAEA` | `#333542` |
| `tag-look` | `#FDF2DE` | `#30383C` |
| `tag-done` | `#E3F4EE` | `#223C46` |
| `tag-info` | `#E6EEF6` | `#293949` |

- [ ] **Step 4: `styles.css`** : `--m-line: rgb(var(--v-theme-line))` ; classes `.m-tag--urgent`, `--look`, `--done`, `--info` (mot en gras, en `error`, `warning`, `success`, `secondary`, sur un fond plein `tag-urgent`, `tag-look`, `tag-done`, `tag-info` : pas de transparence, le contraste ne dépend donc pas de ce qu'il y a dessous) ; `.m-panel` (surface, filet, rayon 8 px) ; `.m-verdict` (`--m-voice`, 600, `clamp(1.5rem, 1.2rem + 1.4vw, 1.9rem)`, `max-width: 30ch`).
- [ ] **Step 5: Vérifier** la porte front, puis ouvrir la page existante en clair et en sombre : rien d'illisible dans les pages non retouchées.
- [ ] **Step 6: Commit** `feat: guided interface palette, light and dark`.

### Task 2: Navigation et pages

**Files:**
- Create: `web/src/lib/navView.js`, `web/src/lib/navView.test.js`, `web/src/components/AppNav.vue`, `web/src/components/ProjectsPage.vue`, `web/src/components/ResolvedPage.vue` (vide jusqu'à la Task 7)
- Modify: `web/src/App.vue`, `web/src/components/TodayPage.vue` (les cartes de projet partent), `web/src/components/SettingsPanel.vue` (bouton de fermeture seulement dans une boîte), `web/src/lib/serversView.js`, `web/src/lib/serversView.test.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `navEntries: {page, hash, key, shortKey, icon}[]`, pages `todo` (`#/`), `projects` (`#/projects`), `servers` (`#/servers`), `resolved` (`#/resolved`), `settings` (`#/settings`) ; `pageOf(hash): 'todo'|'projects'|'servers'|'resolved'|'settings'|'sources'|'fix'` ; `activeEntry(page)` : `fix` donne `todo`, `sources` donne `settings` ; `navMode(width): 'side'|'bottom'`, `side` à partir de 960.
- Produces: `serversRoute(hash)` lit aussi `#/servers/<id>?finding=<fid>` et rend `{id, finding}` ; `serversHash(id, finding = '')`.
- Consumes: `fixRoute`.

- [ ] **Step 1: Tests** : `pageOf reads every hash`, y compris `#/fix/abc`, `#/fix?finding=x`, `#/servers/a?finding=b`, un hash inconnu donne `todo` ; `activeEntry highlights the parent` ; `navMode switches at 960` (375, 840, 959 : `bottom` ; 960, 1280 : `side`) ; `serversRoute keeps old addresses` et `decodes finding`.
- [ ] **Step 2: Vérifier l'échec, écrire** `navView.js`.
- [ ] **Step 3: `AppNav.vue`** : `<nav :aria-label>` de liens `<a :href>`, `aria-current="page"` sur l'entrée active. À partir de 960 px (`navMode($vuetify.display.width)`, pas `mdAndUp`, qui vaut 840 px dans Vuetify 4.3 ; les seuils de Vuetify ne changent pas, d'autres pages bougeraient), `v-navigation-drawer` permanent de 200 px sur `nav`, nom d'assistant en `--m-voice`, puis l'entrée « Besoin d'aide ? Revoir le guide » vers `#/settings`. En dessous, `v-bottom-navigation` à cinq entrées, icône et mot court. Mots : `nav.todo` « À faire », `nav.projects` « Mes projets », `nav.servers` « Mes serveurs », `nav.resolved` « Résolu », `nav.settings` « Réglages, aide » ; courts : « À faire », « Projets », « Serveurs », « Résolu », « Réglages ». EN à égalité. Aucune couleur seule : `aria-current` et graisse.
- [ ] **Step 4: `App.vue`** : retire `v-tabs` et `settingsOpen`. Garde `state`, `load`, le lien d'évitement, `unauthorized`, `offline`, `error`. La nav n'apparaît qu'en `ready`. Branche `ProjectsPage` (reçoit `digest`, reprend `groupAttention` et `ProjectCard`, `@decided`), `SettingsPanel` en page, `SourcesPage` à `#/sources`, et `ResolvedPage`. `stale` recharge le digest en revenant sur `todo` ou `projects`.
- [ ] **Step 5: Relecture FR, vérifier** la porte front et, au navigateur à 375, 900 et 1280 px : chaque entrée, retour arrière, tabulation clavier, aucun défilement horizontal.
- [ ] **Step 6: Commit** `feat: side and bottom navigation, projects and settings pages`.

### Task 3: Mode avancé

**Files:**
- Create: `web/src/lib/modeView.js`, `web/src/lib/modeView.test.js`, `web/src/i18n/jargon.test.js`
- Modify: `web/src/lib/storage.js`, `web/src/main.js`, `web/src/components/SettingsPanel.vue`, `web/src/components/FindingSheet.vue`, `web/src/components/PackageRow.vue`, `web/src/components/ProjectCard.vue`, `web/src/components/ServerSheet.vue`, `web/src/components/ServerLogs.vue`, `web/src/components/ServerProposal.vue`, `web/src/components/FixProposal.vue`, `web/src/components/TodayPage.vue`, `web/src/i18n/{fr,en}.json`, `web/src/i18n/texts.test.js`

**Interfaces:**
- Produces: `keys.advanced = 'michel.advanced'` ; `readAdvanced(load): boolean` (vrai seulement pour `'1'`) ; `$ui.advanced` réactif ; `stripTechnicalIds(text): string` retire `CVE-…`, `GHSA-…`, `PHP2Shell` reste.

- [ ] **Step 1: Tests** : `advanced defaults to off` (vide, valeur inconnue, `load` qui lève) ; `stripTechnicalIds removes ids and keeps the sentence` ; `jargon.test.js` : `no unexplained jargon in simple texts`, pour les familles `nav.`, `todo.`, `resolved.`, `path.`, `plan.`, `expo.`, `guide.`, `empty.`, `help.`, regex `/\b(CVE|CVSS|GHSA|EPSS|KEV)\b/` interdite partout en FR, et `/\b(port|paquet|SSH)\b/i` permise seulement si la même phrase donne son explication (liste `jargonExceptions` écrite dans le test, vide ici, voir Global Constraints ; le test échoue aussi si une clé de la liste n'existe pas ou ne contient plus le mot) ; `i18n catalogs have the same keys` dans `texts.test.js`.
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

Un script reste lisible en mode simple par un lien « Voir le script » qui bascule localement l'affichage, et un changement de projet par un lien « Voir le changement » sur `FixProposal`, qui montre le diff et la sortie des tests : on ne valide jamais sans pouvoir voir. L'empreinte courte reste cachée : `Valider` ne demande pas de la recopier.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, et au navigateur les deux modes sur une fiche serveur de démonstration. Vérifier qu'aucun `v-dialog` n'est sous un `v-if` lié au mode (`grep`).
- [ ] **Step 5: Commit** `feat: advanced mode, off by default, same pages`.

### Task 4: Aide au champ

**Files:**
- Create: `web/src/components/FieldHelp.vue`, `web/src/lib/helpView.js`, `web/src/lib/helpView.test.js`
- Modify: `web/src/components/DiscoverServersDialog.vue`, `HostKeyDialog.vue`, `ServerSheet.vue`, `FixSettings.vue`, `DecisionPanel.vue`, `ServerLogs.vue`, `ServerProposal.vue`, `FixProposal.vue`, `SettingsPanel.vue`, `web/src/i18n/{fr,en}.json`, `web/src/i18n/jargon.test.js`

**Interfaces:**
- Produces: `helpIds: string[]` ; `<FieldHelp id="server.host" />`, texte `help.<id>`.

- [ ] **Step 1: Tests** : `every help id has fr and en text` ; `help stays short` (au plus 280 caractères) ; `every FieldHelp in the components is listed` et l'inverse, en lisant `import.meta.glob('../components/*.vue', { query: '?raw', eager: true })`.
- [ ] **Step 2: Écrire** `FieldHelp.vue` : un vrai `<button type="button">` « ? » de 24 px (zone de 44 px sur téléphone), `aria-expanded`, `aria-controls`, nom accessible `help.label` « Aide : {champ} », texte **en ligne sous le champ** (pas au survol : il marche au doigt, et ne masque rien). `Échap` referme.
- [ ] **Step 3: Écrire les textes**, trois idées par clé : à quoi ça sert, quoi mettre, ce qui se passe si on se trompe. Identifiants : `server.host`, `server.user`, `server.port`, `server.name`, `server.site`, `server.kind`, `server.env`, `server.level`, `server.auto`, `server.executor`, `server.sudo`, `server.interval`, `server.preprod`, `server.active`, `server.fingerprint`, `server.check`, `server.snapshot`, `project.level`, `project.auto`, `project.ai`, `decision.action`, `decision.until`, `decision.why`, `logs.path`, `logs.format`, `logs.try`, `logs.interval`, `logs.store_text`, `logs.alert_text`, `logs.retention`, `logs.sms`, `fix.approve`, `fix.refuse`, `settings.token`, `settings.advanced`, `settings.theme`, `settings.lang`. Les Tasks 13, 14 et 14g ajoutent `exposure.decision`, `project.path`, `project.name`, `project.git` avec leurs champs. `help.server.port` explique le mot « port » dans sa phrase et entre dans `jargonExceptions`. Le texte se vérifie dans le code : ex. `server.executor` dit qui lance le script, `server.sudo` que Michel n'utilise `sudo` que pour lancer un script validé, jamais pour lire.
- [ ] **Step 4: Relecture FR, vérifier** la porte front ; au navigateur, clavier seul, puis 375 px.
- [ ] **Step 5: Commit** `feat: plain help on every field and action`.

### Task 5: Remarques reportées du plan 7, tâche 9

**Files:**
- Modify: `web/src/components/ServerLogs.vue`, `web/src/lib/serverLogsView.js`, `web/src/lib/serverLogsView.test.js`, `web/src/components/ServerSheet.vue`, `web/src/i18n/{fr,en}.json`, `internal/i18n/catalog/{fr,en}.json`

**Interfaces:**
- Produces: `domId(text): string` (identifiant sûr, stable, sans espace) ; `intervalNote(settings, advanced, lang)` : pour `manual`, toujours la phrase locale du mode ; sinon `settings.interval_note` de l'API, repli local si absent ; `settingsSaveOutcome(err): {kind: 'confirm'|'error'|'ok', ...}`.

Le registre du plan 7 liste ces points, à reprendre un par un.

- [ ] **Step 1: Tests** : `domId has no space and differs for different paths` ; `settingsSaveOutcome reads the 409 logs.confirm_needed` (le flux 409 sans test de composant passe ainsi par une fonction) ; `api interval note wins over the local one` ; `manual follows the mode, whatever the api says` (deux modes, note d'API présente).
- [ ] **Step 2: Corriger** : `candKey` dans les `id` (`aria-describedby` cassé sur un chemin avec espace) ; `now` figé à l'ouverture (rafraîchir chaque minute, minuteur arrêté à `beforeUnmount`) ; `load()` sans séquence (ignorer la réponse d'un appel dépassé, comme `acceptResult`) ; `refreshView` qui avale son erreur dans `ServerSheet` (la montrer) ; `strong` de `privacyChoices`, calculé et non lu (le retirer, avec le test qui l'épingle dans `serverLogsView.test.js` ; `deviationWarning.strong` reste) ; phrase de l'intervalle `manual` : elle promet « quand tu le demandes » sans bouton. `logs.interval.manual` laisse la place à `logs.interval.manual_advanced` « Michel ne lit les journaux de ce serveur qu'avec la commande `michel target logs read`. Personne n'est prévenu entre-temps. » et `logs.interval.manual_simple` « Michel ne lit les journaux de ce serveur que quand tu le demandes en ligne de commande. Personne n'est prévenu entre-temps. », EN à égalité. Côté Go, `api.logs.interval.manual` devient la phrase simple, pour que l'API ne promette plus un bouton.
- [ ] **Step 3: Relecture FR, vérifier** les deux portes, puis le bloc Journaux **en sombre** (jamais revu après le dernier commit du plan 7) et le contenu réel copié par « Copier ».
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

Ton : `Urgent` donne `urgent` ; `Important` et `À regarder` donnent `look` ; `À valider` et `À finir` donnent `info`.

À rang égal, l'ordre d'arrivée, serveurs et projets mêlés. Une seule action par ligne. Un composant de projet dont la décision est `ignore` ou `defer` n'a pas de ligne tant qu'il n'est pas dû. Sur un serveur, `TargetFindingView` ne porte pas de décision : une faille n'a de ligne qu'avec le `status` `new` ou `pending`, la règle d'`openStatus` côté Go. Une décision la met en `decided` ; un report dû revient à `pending` à la vérification suivante ou à l'envoi du résumé. Aucun changement Go ici.

Une tentative `applied` **sans** `attempt.server` donne, au rang 2, le mot `À finir`, `todo.applied` « La correction est prête : à toi de la fusionner », action `todo.action.finish` « Voir comment finir », vers la tentative. Ne pas se fier à `attempt.branch` : l'API le remplit aussi pour un serveur. Une tentative `applied` **avec** `attempt.server` n'a rien à fusionner : rang 5, mot `À regarder`, `todo.applied_server` « La correction de {serveur} est lancée : Michel vérifie le résultat. », action `Voir le serveur`, vers `serversHash(id, finding)`.

Une faille de genre `server_exposure` (la chaîne, le genre Go arrive à la Task 11) donne une ligne de rang 4, action `Comprendre`, vers `serversHash(id, finding)`. Titre selon `finding.rule` : `exposed_cache` donne `todo.exposure_cache` « Un cache (une mémoire rapide utilisée par le site) écoute sur toutes les adresses : joignable si aucun pare-feu ne le bloque », le reste `todo.exposure`, texte dans les tests ci-dessous. La Task 13 n'écrit pas cette ligne. En mode simple, `stripTechnicalIds` sur tout titre ; le titre d'un `server_package` en simple est `todo.server_package` : « Un logiciel installé sur {serveur} a une faille connue ».

Textes de tête (R3) : `todo.head.one` « Bonjour. Une chose demande ton attention. », `todo.head.other` « Bonjour. {n} choses demandent ton attention. », sous-titre comptant projets et serveurs, **sans jamais « Le reste va bien »**. Liste vide : `todo.head.none` « Rien à faire pour l'instant, d'après ce que Michel a pu voir. », suivi de ce qui n'a pas été vu.

- [ ] **Step 1: Tests** : `urgent first, projects and servers mixed` ; `one action per line` ; `an empty list never reassures when something was not seen` (aucun scan, `failed_scans > 0`, `never_checked`, `unread`, `osv_stale`, base absente : `unseen` non vide, et aucun texte du résultat ne contient « va bien », « protégé », « sécurisé », `safe`, `protected`) ; `simple mode removes ids` ; `no raw log text` (une fixture d'erreur de journal avec marqueur ne laisse aucune trace) ; `more than 20 servers makes one line` ; `exposure line says firewall` : son titre vaut `todo.exposure` « Ta base de données écoute sur toutes les adresses : joignable si aucun pare-feu ne la bloque » ; `an open cache is not called a database` (`todo.exposure_cache`) ; `only a project attempt is told to merge` (`applied` avec `attempt.server` et `attempt.branch` : aucun « fusionner », rang 5) ; `a decided server finding has no line` ; `every word has a tone`.
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
- Modify: `web/src/lib/pathView.js`, `web/src/lib/fixView.js` (`stateLine`), `web/src/lib/fixView.test.js`, `web/src/components/FixPage.vue`, `web/src/i18n/{fr,en}.json`, `internal/api/views.go`, `internal/api/handlers.go`, `internal/api/handlers_test.go`

**Interfaces:**
- Produces, Go: `ProjectView` gagne `HasTestCmd bool` (`has_test_cmd`), jamais la commande, et `GitRepo bool` (`git_repo`, `workcopy.IsGitRepo(p.Path)`, qui lit le disque sans lancer git, R30).
- Produces, JS : `failurePath({attempt, gone = false}): {steps: {key, state: 'done'|'now'|'todo'|'stopped'}[], verified, open, note}` ; `isVerified(attempt)` ; `projectPlan({finding, project, level}): {title, lines: string[] (clés et paramètres), action: 'start'|null, why}` ; `plainRisk(finding, sheet, lang, advanced): string` ; `mergeStep({attempt, project}): {mode: 'manual'|'none', branch, command}`, `none` pour une tentative avec `attempt.server`, qui n'a rien à fusionner (la Task 14g l'étend, R19).
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
| pas de tentative et `gone` (exposition, R2) | done | done | done | done | done | non | |

Une exposition encore ouverte prend la ligne « pas de tentative », sans nouvel état : ce qui suit « Solution proposée » est dit par son texte (Task 13).

Texte vrai pour un projet (vérifié dans `docs/fix.fr.md`, `service.go`, `auto.go`, `queue.go`). Titre `plan.project.title` « Ce que l'IA va faire », et `plan.project.title_michel` « Ce que Michel va faire » pour un plan terminal, où aucune IA ne travaille. Le constructeur revérifie chaque phrase dans le code et dit moins si elle n'est pas vraie.

| Condition | Clé | Texte |
|---|---|---|
| toujours | `plan.project.copy` | « Un agent d'IA (Claude Code) travaille sur une copie à part de ton projet : seulement les fichiers de ton dernier commit, sans tes fichiers `.env` ni tes clés. » |
| dépendance, version corrigée connue, Composer ou npm | `plan.project.update` | « Michel met à jour {package} vers la version {to} sur cette copie, puis l'agent adapte ton code si besoin. » |
| sinon | `plan.project.search` | « Michel ne connaît pas de mise à jour toute prête : l'agent cherche une correction sur cette copie. » |
| `has_test_cmd`, ni yarn ni pnpm | `plan.project.tests` | « Michel lance ensuite tes tests sur cette copie et cherche à nouveau la faille. » |
| pas de commande de test | `plan.project.no_tests` | « Michel cherche à nouveau la faille sur cette copie. Tes tests ne seront pas lancés : aucune commande de test n'est indiquée pour ce projet. » |
| `yarn.lock`, `pnpm-lock.yaml` (nom de `manifest_rel_path`) | `plan.project.no_install` | « Michel n'installe rien pour ce projet (yarn ou pnpm) : ni installation ni tests. » |
| niveau 1 ou plus, sauf niveau 3 avec `auto_fix_minor` | `plan.project.approval` | « Rien n'arrive dans ton code sans ton accord : si tu valides, Michel crée une branche à part. Il ne fusionne jamais et ne déploie jamais : ton site ne change pas. » |
| niveau 3 et `auto_fix_minor` | `plan.project.approval_auto` | « Avec ta règle, une petite mise à jour qui remplit toutes les conditions (tests réussis, faille disparue de la copie, aucun fichier de code touché) crée sa branche sans te demander. Le reste attend ton accord. Michel ne fusionne jamais et ne déploie jamais : ton site ne change pas. » |
| niveau 2 ou plus | `plan.project.self_start` | « À ce niveau, l'agent peut commencer sans que tu cliques. » |
| toujours | `plan.project.data` | « Cette IA est externe : ce qu'elle lit de la copie part chez Anthropic. Michel te demande ton accord une fois par projet. » |
| `classification === 'health'` | `plan.project.health` | « Ce projet contient des données de santé : aucune IA n'y travaille. » `action: null` |
| niveau 0 (R14) | `plan.project.report_only` | « Ce projet est réglé sur « Signaler » : Michel ne prépare rien. Tu peux changer ce réglage sur sa fiche. » `action: null` |
| `git_repo` faux (R30) | `plan.project.no_git` | « Ce dossier n'est pas un dépôt Git (un dossier qui garde l'historique de tes fichiers) : Michel ne peut pas préparer de correction, mais il t'explique la faille. » `action: null`, et aucune des lignes ci-dessus |

Une ligne `action: null` est **terminale** : `lines` ne contient qu'elle, car « toujours » n'est vrai que pour un plan qui s'exécute. Si plusieurs s'appliquent : `no_git`, puis `health`, puis `report_only`.

Le bouton « Lancer la correction » appelle `start` de `FixPage`, donc l'écran d'accord IA et `agentProblem` restent devant lui.

- [ ] **Step 1: Test Go** : `TestProjectViewSaysIfTestsAreDeclared`, avec `testCmdMarker` absent de toute la réponse ; `TestProjectViewSaysIfInGit`.
- [ ] **Step 2: Tests JS** : `verified table` (une ligne par état ci-dessus, `verified` vrai seulement pour les trois cas de R2 : projet vérifié, serveur `proven_fixed`, exposition `gone`) ; `project plan tells the truth for each case` (chaque condition, y compris `no_tests` sans `tests`, `approval_auto` sans `approval`, et le niveau 2 avec `auto_fix_minor` qui garde `approval`) ; `terminal plans stand alone` (`health`, `report_only`, `no_git` : une seule ligne, titre `title_michel`) ; `no button at level 0 nor for health` ; `no button without a Git repository` ; `plain risk has no technical id in simple mode` ; `merge note gives the branch` (projet ; une tentative serveur en `applied` a la note `checking` et `mergeStep` en `none`, jamais `git merge`) ; `manual merge step gives the command` ; dans `fixView.test.js`, un cas par texte de `stateLine` changé (`inconclusive`, `running`, `unknown`).
- [ ] **Step 3: Vérifier l'échec, écrire.** `stateLine` : `fix.line.inconclusive` disait à tort « Michel vérifiera au prochain scan » (`inconclusive` est un résultat, `SetState` à `service.go:1692`) ; nouveau texte « Michel n'a pas pu confirmer la correction. » suivi de la cause, et `running`, `unknown` reconnus.
- [ ] **Step 4: `FailurePath.vue`** : `<ol aria-label>` à cinq `<li>`, `aria-current="step"`, état dit en mots masqués visuellement (`path.state.*` : fait, en cours, à venir, arrêté), couleur et icône en plus. Chevrons de la maquette (`clip-path`) à partir de 640 px ; en dessous, liste verticale. Libellés exacts : `Trouvée`, `Solution proposée`, `Ton accord`, `Corrigée`, `Vérifiée`.
- [ ] **Step 5: `FailureGuide.vue`** : `FailurePath`, note, deux blocs : `path.means` « Ce que ça veut dire » et le plan. Sur `applied`, le bloc donné par `mergeStep`. Ici, le cas sans rattachement, le seul qui existe à cette tâche : `git.manual.lead` « Il te reste à faire entrer cette correction dans ton code, avec Git. Copie cette commande et lance-la dans ton dossier, sur ta branche principale. » (« You still have to bring this fix into your code, with Git. Copy this command and run it in your folder, on your main branch. »), la commande `git merge {branch}` à copier, et `git.manual.next` « Puis, dans Mes projets, clique sur « Contrôler ce projet ». » (« Then, in My projects, click "Check this project". »), avec un lien vers `#/projects`. Le bouton arrive à la Task 14. La Task 14g remplace ce bloc par `MergeStep.vue`, qui garde ce cas et ajoute celui d'un projet rattaché : bouton d'envoi, lien de demande de fusion, `Mettre à jour mon dossier`. Monté en tête du centre de `FixPage` ; en mode simple, la colonne de liste disparaît et `FixChat` passe dans un `<details>` ouvert quand une conversation existe. `FixProposal` reste à droite, entier.
- [ ] **Step 6: Relecture FR, vérifier** les deux portes, deux largeurs, deux thèmes, clavier.
- [ ] **Step 7: Commit** `feat: the path of a flaw and what will truly happen, projects`.

### Task 9: Chemin de la faille, serveurs

**Files:**
- Modify: `web/src/lib/pathView.js`, `web/src/lib/pathView.test.js`, `web/src/components/FailureGuide.vue`, `web/src/components/ServerSheet.vue`, `web/src/components/FixPage.vue`, `web/src/lib/serversView.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: `failurePath`, `TargetView` (`kind`, `fix_level`, `executor`, `auto_config`, `site_url`, `preprod`), `TargetFindingView`.
- Produces: `serverPlan({finding, target}): {title, lines, action: 'prepare'|null, why, warn}`, `warn` valant `servers.level.3.warn` au niveau 3, `null` sinon.
- Changes: `failurePath({attempt, gone = false, target = null})`. `target` est le `TargetView` : `ServerAttemptView.Target` n'a ni `site_url` ni réglages. `proven_fixed` avec un `target` sans `site_url` donne la note `path.note.no_site` ; sans `target`, pas de note. `isVerified` reste sur la tentative, la Task 7 ne change pas.

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
| ni `hds` ni `health` | `plan.server.agent` | « Si Michel n'a pas de correction prévue, il te proposera un agent d'IA. L'agent ne se connecte jamais au serveur, ne voit qu'un inventaire masqué et ne peut rien lancer. » |
| `hds` ou `health` | `plan.server.hds` | « Ce serveur héberge des données de santé : aucun agent d'IA n'y travaille. » |
| niveau 0 | `plan.server.report_only` | « Ce serveur est réglé sur « Signaler » : Michel ne prépare rien. » `action: null` |
| `server_exposure` | `plan.exposure` | « Michel ne sait pas fermer ce service et ne lance rien. » `action: null`, suivi de `expo.how` |

`expo.how`, écrit ici (la Task 13 s'en sert) : « Demande à la personne qui gère le serveur, ou à ton hébergeur, de la faire écouter seulement sur le serveur lui-même, ou de la bloquer dans le pare-feu. Puis lance une vérification : si Michel ne la voit plus ouverte, c'est confirmé. »

Une ligne `action: null` est **terminale** : `lines` ne contient qu'elle (`plan.exposure` et `expo.how` pour une exposition), car « toujours » n'est vrai que pour un script qui existera. Si les deux s'appliquent, `plan.exposure` d'abord.

`plainRisk` en simple pour `server_package` : `plain.server_package` « Un logiciel installé sur ce serveur a une faille connue. Sa mise à jour la corrige. », sinon `explain` de l'API.

- [ ] **Step 1: Tests** : `server plan tells the truth for each case`, dont : `no copy is ever promised` (aucun texte serveur, sauf `no_copy`, ne contient « copie à part ») ; `the word IA is used only for the agent` (seules `who`, qui dit son absence, `agent` et `hds` contiennent « IA », et aucun texte serveur ne contient « l'IA ») ; `terminal plans stand alone` (`report_only`, exposition : ni `who`, ni `no_copy`, ni `no_tests`) ; `a health server hears only hds` (un `vps` classé `health` : `hds` sans `agent`) ; `rule level 3 keeps packages waiting` ; `server verified needs proven_fixed` (`inconclusive` avec `detail: proven` reste non vérifiée, cas `site_unchecked` de `server_exec.go:875`) ; `verified without a site says so` : `proven_fixed` sans `site_url` donne la note `path.note.no_site` ; `level 3 warning kept` : `serverPlan` rend `warn` au niveau 3 et seulement là, et le composant l'affiche à côté du plan.
- [ ] **Step 2: Vérifier l'échec, écrire.** Le texte `fix.intro_server`, épinglé par `texts.test.js`, ne change pas.
- [ ] **Step 3: Brancher** : chaque carte de `ServerSheet` montre `FailurePath` (avec `target`) et le bloc, `#/servers/<id>?finding=<fid>` fait défiler et met le focus sur sa carte. `fix(c.finding)` et son dialogue `unknownOpen`, `agentOffer` restent tels quels. `FixPage` en `serverOnly` et `ServerProposal` : `FailureGuide` en tête.
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
- Modify: `internal/serverrules/rules.yaml`, `internal/serverrules/rules.go` (`Version = 3`, section, validation), `internal/serverrules/eval.go`, `internal/scan/normalize.go`, `internal/scan/repo.go` (`ApplyServerFindings`, `ListServerFindings`), `internal/servercheck/check.go`, `internal/servercheck/check_test.go`, `internal/fix/server_agent_test.go`, `internal/api/targets_fix_test.go`, `internal/api/targets.go` (`ruleKeys`), `internal/api/targets_title_test.go`, `internal/digest/servers_test.go`, catalogue `internal/i18n/catalog/{fr,en}.json`

**Interfaces:**
- Produces: `scan.KindServerExposure = "server_exposure"`, ajouté aux trois listes de genres de `internal/scan/repo.go` : `ApplyServerFindings`, `ListServerFindings`, et le `NOT IN` de `ListFindings`, sans quoi la faille passerait pour une faille de projet.
- Produces: `ruleKeys` lit aussi `set.Listen` (les règles qui ont une `Key`), sans quoi le titre français n'arrive jamais à la page.
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
- [ ] **Step 2: Tests du jugement** : `TestUnreadListenersKeepExposureOpen` (`ListenersRead` faux, y compris `Rematch` d'un ancien inventaire : `judge` ajoute le préfixe `exposure:` aux `UnreadPrefixes`, la faille reste ouverte) ; `TestClosedServiceBecomesGone` (lecture complète, service fermé : `gone`, compté dans la réponse) ; `TestDigestServersCountsExposure` dans `internal/digest/servers_test.go` : la faille compte dans `New`, puis dans `Fixed` une fois `gone`, et le texte rendu ne contient ni port ni adresse. Le résumé compte sans nommer (« Counts only » en tête de `servers.go`), et sa requête ne filtre pas le genre : `internal/digest/servers.go` ne change pas. `TestExposureTitleIsInFrench` dans `targets_title_test.go`.
- [ ] **Step 3: Tests du refus de correction** : `TestExposureCannotStartAFix` (`POST /targets/{id}/fix/{f}`, `POST /targets/{id}/agent-fix/{f}` refusent ; `POST /findings/{id}/fix` répond 404, car ce n'est pas une faille de serveur corrigeable ni une faille de projet ; aucune tentative dans les trois cas, et rien ne change dans `internal/fix`) ; `TestExposureNeverQueued` (`EligibleServer` faux, niveau 3 compris) ; `TestAgentInventoryHasNoListeners` (`serverInventoryView` : aucun port, aucune adresse d'écoute dans le JSON, le marqueur d'une fixture absent).
- [ ] **Step 4: Vérifier l'échec, écrire.** `TestExposureCannotStartAFix`, `TestExposureNeverQueued` et `TestAgentInventoryHasNoListeners` passent dès le début : les listes `server.go`, `server_auto.go` et `serverInventoryView` refusent déjà. Ce sont des gardes. Le dire, et montrer chacun échouer une fois en ajoutant le genre ou le champ pour l'essai, sans rien en garder. Textes : `serverrules.exposed_database.title` « Une base de données écoute sur toutes les adresses de ce serveur », `.explain` « Elle est joignable depuis l'extérieur si aucun pare-feu ne la bloque. Personne dehors n'a besoin d'y accéder : c'est une porte d'entrée possible vers tes données. », `exposed_cache` de même forme avec « Un cache (une mémoire rapide utilisée par le site) ».
- [ ] **Step 5: Relecture FR, vérifier** la porte Go.
- [ ] **Step 6: Commit** `feat: judge what listens, a database open to all is a server flaw`.

### Task 12: API d'exposition et docs

**Files:**
- Create: `internal/api/targets_exposure.go`, `internal/api/targets_exposure_test.go`
- Modify: `internal/api/targets.go` (route), `internal/api/handlers.go`, `docs/servers.md`, `docs/servers.fr.md`, `docs/security/network-egress.md`, `docs/security/network-egress.fr.md`

**Interfaces:**
- Produces: `GET /api/v1/targets/{id}/exposure` : `ExposureView{Read bool `json:"read"`; CheckedAt string `json:"checked_at"`; Kind string `json:"kind"`; Services []ExposureService `json:"services"`; Unseen []TargetUnseenView `json:"unseen"`; Closed []ExposureClosed `json:"closed"`}` ; `ExposureService{Port int; Addresses []string; Scope, Service, Verdict, FindingID, DecidedWhy string}` (JSON : `port`, `addresses`, `scope`, `service`, `verdict`, `finding_id`, `decided_why`) ; `ExposureClosed{Port int; Service, At string}`.
- Produces: `POST /api/v1/targets/{id}/exposure/{finding}/decision`, corps `{"why": "…"}` (R12).

- [ ] **Step 1: Tests** : `TestExposureNeverCheckedSaysNotRead` (`read: false`, liste vide, 200) ; `TestExposureGroupsByPortAndScope` ; `TestExposureOldInventoryNotRead` ; `TestExposureDecisionNeedsWhy` ; `TestExposureDecisionOnlyForExposureOfThisServer` (404 pour une faille d'un autre serveur ou d'un autre genre) ; `TestExposureDecisionAudited` (`decide.Apply`, acteur `web`) ; `TestExposureDecisionLeavesTheServiceInItsColumn` ; `TestExposureRoutesNeedTheToken` pour les deux routes.
- [ ] **Step 2: Vérifier l'échec, écrire.** Extraire de `decision` (`handlers.go`) une fonction commune pour le traitement des erreurs de `decide.Validate` et `decide.Apply`, sans changer ses réponses ; la nouvelle route n'ajoute que son contrôle du serveur et du genre, et l'action `ignore`. Le `lookup` de `decision` ne convient pas : il cherche un projet.
- [ ] **Step 3: Docs.** `servers*.md` § 4 : ajouter `ss -tln` (puis `/usr/sbin/ss -tln` si la commande n'est pas trouvée) ; seuls adresse et port sont gardés, jamais le nom d'un processus (il demanderait des droits que Michel ne demande pas) ; TCP seulement ; sur tout type de serveur, `hds` compris, avec la raison ; une section « Ce qui est exposé » : ce que veulent dire les trois colonnes, **cette lecture se fait depuis l'intérieur et ne prouve pas qu'on peut joindre le service, le pare-feu de l'hébergeur n'est pas vérifié**, un serveur en conteneur ou mutualisé peut montrer d'autres services, l'agent IA ne reçoit pas cette liste. `network-egress*.md`, ligne `target.ssh` : aucun nouvel usage, et ce qui revient maintenant : la liste des adresses et ports en écoute. **Relecture FR.**
- [ ] **Step 4: Vérifier** la porte Go.
- [ ] **Step 5: Commit** `feat: exposure view of a server, and what comes back documented`.

### Task 13: Écran d'exposition

**Files:**
- Create: `web/src/lib/exposureView.js`, `web/src/lib/exposureView.test.js`, `web/src/components/ServerExposure.vue`
- Modify: `web/src/components/ServerSheet.vue` (première section sous l'en-tête ; les failles `server_exposure` n'ont pas de bouton de correction), `web/src/lib/todoView.js`, `web/src/lib/todoView.test.js`, `web/src/components/TodayPage.vue`, `web/src/components/ResolvedPage.vue`, `web/src/lib/helpView.js`, `web/src/i18n/{fr,en}.json`

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
| `expo.service.database_note`, `.cache_note` | « Personne dehors n'a besoin d'y accéder. » pour les deux |
| `expo.tag.close` | `À fermer` |
| `expo.service.other` | `Service non reconnu` |
| `expo.tag.check` | `À vérifier` |
| `expo.how` (déjà écrit à la Task 9, inchangé) | « Demande à la personne qui gère le serveur, ou à ton hébergeur, de la faire écouter seulement sur le serveur lui-même, ou de la bloquer dans le pare-feu. Puis lance une vérification : si Michel ne la voit plus ouverte, c'est confirmé. » |
| `expo.shared` | « Sur un hébergement mutualisé, ces services peuvent être ceux de l'hébergeur ou d'autres clients : Michel n'en fait pas des failles. » |
| `expo.decision.open` | « Je sais, c'est bloqué ou voulu » |
| `expo.decided` | « Tu as indiqué : {why} Michel ne l'a pas vérifié. » |
| `expo.closed` | « {service} n'écoute plus sur toutes les adresses, d'après la dernière lecture. » |

Une ligne de verdict `normal` montre sa note et aucun mot de tag. Sur `shared` (R8, aucune faille), un verdict `close` donne le tag `check`, ne compte pas dans `expo.title.of_close`, et `expo.shared` s'affiche.

- [ ] **Step 1: Tests** : `the firewall row is always there` (lu, non lu, sans service, `shared`, `hds`) ; `UDP row always there` ; `not read says so and keeps the firewall row` ; `columns follow scope` (dont `shared` : `close` donne `check`, pas de `of_close`, `expo.shared` présent) ; `title says firewall whenever something is open` ; `no reassuring word anywhere` (toutes les sorties et toutes les clés `expo.` en FR et EN : ni « protégé », « sécurisé », « sûr », `safe`, `protected`, `secure`, ni « fermé » hors de `À fermer` et `expo.closed`) ; `simple mode hides numbers, advanced shows them` ; `unseen lines join the third column` ; `decided row keeps its column and says not verified`.
- [ ] **Step 2: Vérifier l'échec, écrire** `ServerExposure.vue` : bordure haute de 4 px (rouge, vert, gris) comme `.wall`, toujours avec le mot ; `flex-wrap`, une colonne sur téléphone ; bouton `Vérifier maintenant` si jamais lu ; chemin de la faille et `plan.exposure` + `expo.how` sous un service à fermer ; dialogue de décision avec justification obligatoire (`validateDecision`).
- [ ] **Step 3: Résolu, À faire** : services fermés dans `resolvedLines` avec `closed`, titre `expo.closed`. La ligne d'À faire existe depuis la Task 6 : ne pas la réécrire, ajouter à `todoView.test.js` un cas avec la vraie forme de `GET /targets/{id}` et `scan.KindServerExposure`, et corriger si elle ne tient pas.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes.
- [ ] **Step 5: Commit** `feat: what is exposed on a server, the firewall always said unverified`.

### Task 14: Ajouter et contrôler un projet depuis la page

**Files:**
- Create: `internal/api/projects_run.go`, `internal/api/projects_run_test.go`, `web/src/components/AddProjectDialog.vue`, `web/src/lib/projectsView.js`, `web/src/lib/projectsView.test.js`
- Modify: `internal/api/server.go` (`Deps.ScanProject`, routes), `internal/api/views.go`, `internal/api/handlers.go`, `internal/cli/scan.go`, `internal/cli/scan_test.go`, `internal/cli/serve.go`, `internal/cli/serve_test.go`, catalogue `internal/i18n/catalog/{fr,en}.json`, `web/src/components/ProjectsPage.vue`, `web/src/components/ProjectCard.vue`, `web/src/lib/helpView.js`, `web/src/i18n/{fr,en}.json`, `README.md` et `grep -ln "project add" docs` là où la ligne de commande est dite seule possible

**Interfaces:**
- Produces, Go : `Deps.ScanProject func(ctx context.Context, p project.Project) error` (nil : 503) ; `POST /api/v1/projects` corps `{path, name}`, 201 `ProjectView` ; `POST /api/v1/projects/{name}/scan`, 202 `{started: true}`, 409 si déjà en cours ; `ProjectView` gagne `scanning bool` et `last_failure *TargetLastCheck` (mémoire du processus, champ `s.scans`, un `checkTracker` à part de `s.checks`). Codes : `api.project.not_dir`, `api.project.relative_path`, `api.project.duplicate`, `api.project.bad_name`, `api.project.no_database`, `api.project.nothing_to_scan`, `api.project.scan_failed`, avec `_hint`.
- Produces, CLI : `scanOneProject(ctx, cmd, deps, p, queue bool) (scan.Result, string, error)`, extrait du corps de `newScanCmd` : scan, `fix.Prove`, analyse, plugins, sans rien imprimer de plus ; `newScanCmd` l'appelle, sa sortie ne change pas.
- Produces, JS : `projectNameFromPath(path): string` (`\` et `/`, dernier dossier) ; `scanSentence(project, lang)`.

- [ ] **Step 1: Tests Go** : `TestAddProjectFromThePage` (`repo.Add`, audit `project.add` acteur `web`, classement par défaut de la politique) ; `TestAddProjectRefusesRelativePathAndFile` ; `TestAddProjectAnswerHasNoAbsolutePath` (chemin absent de la réponse et du message d'erreur, comme `TestAPIResponsesHaveNoAbsolutePathsNorCommands`) ; `TestAddProjectCannotSetTestCmdOrLevel` (R13 : champ inconnu refusé) ; `TestScanRunsInBackgroundOnce` (202, 409) ; `TestScanReportsMissingDatabase` et `TestScanReportsNothingToScan` ; `TestProjectRunRoutesNeedTheToken`. Dans `internal/cli`, contre le vrai `scanOneProject` et une vraie branche fusionnée, car l'API ne tient que `Deps.ScanProject` et un faux injecté ne prouverait rien : `TestScanProvesAMergedFix` (`proven_fixed` en base) ; `TestScanWritesNothingInTheProject` (dossier identique avant et après) ; `TestScanOutputUnchanged`, comparé à une sortie capturée **avant** l'extraction et écrite dans le test, sinon le nouveau code se compare à lui-même ; `TestServeGivesScanProject`.
- [ ] **Step 2: Tests JS** : `name from a windows or unix path` ; `scan sentence for never, running, failed, ok`.
- [ ] **Step 3: Vérifier l'échec, écrire.** `AddProjectDialog` : `path` et `name` avec `FieldHelp` (ajouter `project.path` et `project.name` à `helpIds`), texte `project.path` : le chemin complet du dossier, Michel n'y écrit rien lors du contrôle. `ProjectCard` : bouton « Contrôler ce projet » (« Check this project »), état. `api.project.no_database` : phrase qui dit de télécharger la liste des failles, et lien `#/sources`.
- [ ] **Step 4: Relecture FR, vérifier** les deux portes, et `go test ./internal/cli/` à part : la sortie de `michel scan` ne bouge pas.
- [ ] **Step 5: Commit** `feat: add and check a project from the page`.

### Task 14b: Lire l'adresse d'un distant (`gitremote`)

Spec, dernière section ; R19 à R21, R28, R33. Paquet pur, sans `exec`, sans réseau.

**Files:**
- Create: `internal/gitremote/gitremote.go`, `internal/gitremote/gitremote_test.go`

**Interfaces:**
- Produces, `gitremote` : `Provider` : `GitHub = "github"`, `Bitbucket = "bitbucket"`, `GitLab = "gitlab"`, `Other = "other"`, `Local = "local"` ; `Remote{Clean, Host string; Port int; Scheme string ("https"|"ssh"|"scp"|"file"); Path string; Provider Provider; HadCredential bool}` ; `Parse(raw string, allowLocal bool) (Remote, error)`, erreur fixe `ErrUnsupported`, **jamais la valeur lue dans une erreur** ; `(Remote) ID() string` (SHA-256 hexadécimal de `Clean`) ; `(Remote) Display() string` (`host/owner/repo`, `dépôt local` pour `Local`, jamais de chemin absolu) ; `MergeURL(r Remote, branch string) string` (`""` si `Other`, `Local`, ou si une partie n'est pas valide).
- Avec `allowLocal`, une adresse locale donne `Provider` `Local`, `Scheme` `file`, `Clean` l'adresse lue, `Host` vide. Sans `allowLocal`, `ErrUnsupported`.

Valeurs de `gitremote.Parse` (R21) :

| Entrée | `Clean` | Fournisseur et lien |
|---|---|---|
| `https://github.com/demo/app.git` | identique | `github`, `https://github.com/demo/app/pull/new/<branche>` |
| `git@bitbucket.org:demo/app.git` | identique | `bitbucket`, `https://bitbucket.org/demo/app/pull-requests/new?source=<branche>&t=1` |
| `ssh://git@gitlab.com/group/sub/app.git` | identique | `gitlab`, `https://gitlab.com/group/sub/app/-/merge_requests/new?merge_request%5Bsource_branch%5D=<branche>` |
| `ssh://git@ssh.github.com:443/demo/app.git`, `ssh://git@altssh.gitlab.com:443/demo/app.git`, `ssh://git@altssh.bitbucket.org:443/demo/app.git` | identique | le fournisseur, lien sur son site |
| `https://user:canari-git-7391@github.com/demo/app.git`, `https://canari-git-7391@github.com/demo/app.git` | `https://github.com/demo/app.git`, `HadCredential` | `github` |
| `ssh://git:canari-git-7391@example.test/demo/app.git` | `ssh://git@example.test/demo/app.git`, `HadCredential` | `other`, pas de lien |
| `https://GitHub.com/demo/app` | `https://github.com/demo/app` | `github` |
| `https://git.example.test/demo/app.git`, `git@gitlab.example.test:demo/app.git` | identique | `other`, pas de lien |
| `https://github.com.example.test/demo/app`, `https://examplegithub.com/demo/app` | identique | `other`, pas de lien |
| `https://github.com:443@example.test/demo/app` | `https://example.test/demo/app`, `HadCredential` | `other`, pas de lien |
| `https://github.com/demo`, `https://github.com/a/b/c` (GitHub et Bitbucket : deux parties exactement) | identique | `github`, **pas de lien** |
| `javascript:alert(1)`, `data:text/html,x`, `http://github.com/demo/app`, `git://github.com/demo/app`, `ext::sh -c id`, `https://github.com./demo/app`, `https://example.test:8443/demo/app`, `-oProxyCommand=id:demo/app`, `git@-oProxyCommand=id:demo/app`, `https://github.com/demo/%2e%2e/app`, `https://github.com/demo/app?x=1`, `https://github.com/demo/app#y`, `https://github.com/demo/app\x`, chemin avec `..`, espace ou caractère de contrôle, IPv6 entre crochets, chemin relatif | | `ErrUnsupported` |
| `file:///srv/demo.git`, chemin absolu | | `ErrUnsupported` sauf `allowLocal` : `Local` (R28) |

Règles : schémas `https` et `ssh`, forme scp `[user@]host:path` (hôte d'une seule lettre : chemin Windows, refusé) ; hôte en minuscules, `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$` ou IPv4 ; utilisateur SSH `^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$` ; chaque partie du chemin `^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$`, pas de `..`, au plus 20 parties ; `.git` final retiré une fois pour le lien. HTTPS : tout ce qui précède `@` est retiré et compté comme secret ; port 443 seulement. Fournisseur : égalité stricte sur une table de six hôtes (`github.com`, `ssh.github.com`, `bitbucket.org`, `altssh.bitbucket.org`, `gitlab.com`, `altssh.gitlab.com`). La forme scp reste scp : `git@host:a/b` et `ssh://git@host/a/b` ne désignent pas toujours le même chemin sur un serveur auto-hébergé. `MergeURL` exige `^michel/fix-[0-9a-z]{8,26}$` pour la branche, deux parties pour GitHub et Bitbucket, 2 à 20 pour GitLab.

- [ ] **Step 1: Tests** : `TestParseTable` (toute la table ci-dessus) ; `TestNoSecretInAnyField` et `TestErrorsCarryNoInput` (`canari-git-7391` absent de tous les champs, de `Display`, `ID` et des erreurs) ; `TestProviderIsExactHost` ; `TestMergeURLTable` (les trois sites ; partie invalide ou branche hors forme : aucun lien) ; `TestMergeURLOnlyOnThreeOrigins` (pour chaque entrée, le lien est vide ou commence exactement par `https://github.com/`, `https://bitbucket.org/`, `https://gitlab.com/`) ; `TestDisplayHasNoAbsolutePath` ; `FuzzParse` (pas de panique, jamais `javascript:`, pas de `@` dans `Host`) ; `TestLocalNeedsAllowLocal` (`file:///srv/demo.git` et un chemin absolu : `ErrUnsupported` avec `allowLocal` faux, `Local` avec vrai).
- [ ] **Step 2: Vérifier l'échec, écrire `gitremote`.**
- [ ] **Step 3: Vérifier** `go test ./internal/gitremote/`, puis la porte Go.
- [ ] **Step 4: Commit** `feat: read a Git address without its secret and build the merge link`.

### Task 14c: Lire le distant et envoyer la branche (`workcopy`)

R20, R22, R23, R27, R28, R32, R33. Aucune vraie adresse contactée par les tests : dépôt nu local, `Exec` enregistreur.

**Files:**
- Create: `internal/workcopy/remote.go`, `internal/workcopy/remote_test.go`
- Modify: `internal/workcopy/git.go` (`allowedGit`, `Deps.AllowLocalRemote`, `netGit`, préambule du paquet)

**Interfaces:**
- Produces: `RepoState(ctx, d, p) (string, error)` (`"none"`, `"empty"`, `"ok"`) ; `ReadRemotes(ctx, d, p) (name, raw string, several bool, err error)` ; `Push(ctx, d, p, url, proxyURL, branch, sha string) (PushResult, error)` avec `PushResult{Outcome string ("pushed"|"already")}`.
- Produces: `Deps.AllowLocalRemote bool`, seule source du `:file` de `GIT_ALLOW_PROTOCOL`, posée par les tests et par la Task 14e (R33).
- Produces: `*GitFailure{Class, Current, Default string}`, seule erreur de ces opérations, sans la sortie de git. `Error()` ne dit que la classe. `Current` et `Default` servent à `not_default` (Task 14d), passés par `scan.SanitizeText` et coupés à 100 caractères.

Commandes exactes de `workcopy/remote.go`. `h.git` reste tel quel pour tout ce qui lit le projet.

- `netGit` (`push`, `fetch`), seulement sur un dépôt temporaire de Michel. Environnement `userEnv` (R23) + `GIT_ALLOW_PROTOCOL=https:ssh` (`:file` avec `d.AllowLocalRemote`) ; `-c core.hooksPath=<fix-hooks> -c core.fsmonitor=false -c gc.auto=0 -c maintenance.auto=false -c core.longpaths=true`. HTTPS : `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`, `all_proxy` valent `proxyURL`, `NO_PROXY=`, `no_proxy=`, et `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=http.proxy`, `GIT_CONFIG_VALUE_0=<proxyURL>` : le jeton du proxy reste dans l'environnement, jamais dans l'argv, et un `http.proxy` global ne contourne pas le proxy.
- `allowedGit` gagne, en lecture seule : `config`.

| Étape | Commande |
|---|---|
| Lire | `git -C <p> config --local --null --get-regexp ^remote\..*\.url$` (code 1 : aucun distant). Rien d'autre : ni `remote get-url` (il appliquerait `insteadOf`), ni `ls-remote`. |
| Choisir | `origin` ; sinon le seul distant ; plusieurs sans `origin`, ou `origin` à plusieurs adresses : `several`. Nom du distant `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. `pushurl` n'est pas lu. |
| Contrôle de branche | `git -C <p> rev-parse --verify --quiet --end-of-options refs/heads/<b>^{commit}` doit égaler `prop.CommitSHA`, sinon `branch_moved`. |
| Dépôt temporaire | `git clone --bare --local --no-hardlinks --quiet --no-tags --single-branch --branch <b> -- <p> <data>/fix-net/<ulid>.git` (par `h.git`, `localTransport`, comme `Prepare`) ; retiré par `defer`. Pour `Update`, sans `--single-branch --branch`. |
| Envoi | `git -C <tmp> push --porcelain --no-follow-tags --no-recurse-submodules --no-signed --no-verify -- <clean> refs/heads/<b>:refs/heads/<b>`, délai `netTimeout = 2 * time.Minute`. Sortie porcelaine, seule la ligne à tabulations de cette référence est lue (la ligne `To …` contient l'adresse, elle est ignorée) : `*` ou espace donne `pushed`, `=` donne `already` (code 0 dans les deux cas), `!` donne `rejected`. Jamais `--force`, `+`, `--all`, `--mirror`, `--tags`, `--delete`. |

`classify(stderr)`, sur la sortie en anglais (`LC_ALL=C`, `LANGUAGE=C`), en mémoire, puis oubliée (R32) : `auth` (`Authentication failed`, `Permission denied`, `could not read Username`, `terminal prompts disabled`, `publickey`, `returned error: 401`, `returned error: 403`) ; `host_key` (`Host key verification failed`) ; `not_found` (`not found`, `does not appear to be a git repository`) ; `rejected` (`protected`, `rejected`, `non-fast-forward`, `fetch first`, `declined`) ; `network` (`Could not resolve host`, `Connection timed out`, `Connection refused`, `Failed to connect`, `unable to access`, `Could not connect`) ; `timeout` (délai dépassé) ; sinon `failed`.

- [ ] **Step 1: Tests**, Git réel, projet `demo` et dépôt nu temporaires (sauf mention `Exec` enregistreur), `HOME` et `USERPROFILE` remplacés par `t.Setenv`, `AllowLocalRemote` vrai pour joindre le dépôt nu :
  - Lecture : `TestReadRemotesRunsNoNetworkCommand` (enregistreur : `config` seulement) ; `TestReadRemotesOriginThenOnlyThenSeveral` ; `TestInsteadOfIsNotApplied` ; `TestRepoStateNoneEmptyOk` ; `TestRepoSubfolderIsNone` (`IsGitRepo` ne remonte pas au parent).
  - Envoi : `TestPushSendsOnlyTheBranch` (autres branches et tags absents du dépôt nu, sa branche principale inchangée) ; `TestPushArgvIsClosed` (enregistreur : argv exact) ; `TestPushTwiceIsAlready` ; `TestPushNeverForces` (branche distante divergente : `rejected`, distant inchangé) ; `TestPushRunsNoProjectConfig` (dans `.git/config` du projet : `core.sshCommand`, `credential.helper`, `url.*.insteadOf`, `remote.<adresse>.receivepack`, `remote.<adresse>.pushurl`, chacun vers un script témoin : aucun témoin, l'envoi arrive au bon endroit) ; `TestPushRunsNoHook` (hooks plantés dans le projet, `fix-hooks`, et `core.hooksPath` global, `pre-push` compris : aucun témoin) ; `TestPushEnvIsAllowlistedAndCannotPrompt` (variable témoin absente ; `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `SSH_ASKPASS_REQUIRE=never`, pas de `GIT_ASKPASS` ; `GIT_SSH_COMMAND=ssh -o BatchMode=yes` si la personne n'a pas le sien, le sien gardé sinon) ; `TestPushTimesOut` (`Exec` qui attend : classe `timeout`, dépôt temporaire retiré) ; `TestProxyTokenNotInArgv` ; `TestClassifyTable` ; `TestFailureHoldsNoOutput` (stderr avec `canari-git-7391` : absent de `GitFailure.Error()`).
- [ ] **Step 2: Vérifier l'échec, écrire.** `userEnv` : `PATH`, `SystemRoot`, `TEMP`, `TMP`, `PATHEXT`, `HOME`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `APPDATA`, `LOCALAPPDATA`, `ProgramData`, `XDG_CONFIG_HOME`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GIT_SSH`, `GIT_SSH_COMMAND` s'ils existent ; puis `LC_ALL=C`, `LANGUAGE=C`, `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `SSH_ASKPASS_REQUIRE=never`, `GIT_NO_REPLACE_OBJECTS=1`. `GIT_SSH_COMMAND=ssh -o BatchMode=yes` s'il n'y a ni variable ni `core.sshCommand` global. Ce réglage se lit par un appel direct `d.exec()` avec `userEnv`, argv exact `git config --global --get core.sshCommand`, depuis le dossier de données (code 1 : absent) : `h.git` ne convient pas, son `GIT_CONFIG_GLOBAL` vise le fichier vide de Michel. Jamais `GIT_CONFIG_NOSYSTEM` ni `GIT_CONFIG_GLOBAL` : c'est la configuration de la personne, et `core.autocrlf` en vient (R24). Préambule du paquet : `Apply` et `Push` sont les seules écritures, et `Push` n'écrit rien dans le projet. `<data>/fix-net` est créé au besoin.
- [ ] **Step 3: Vérifier** `go test ./internal/workcopy/`, puis la porte Go, `go test ./internal/hygiene/`.
- [ ] **Step 4: Commit** `feat: read a project's Git address and send only the fix branch`.

### Task 14d: Mettre à jour le dossier, preuve après « squash » (`workcopy`)

R24, R25, R34. Mêmes conditions de test que la Task 14c.

**Files:**
- Modify: `internal/workcopy/remote.go`, `internal/workcopy/remote_test.go`, `internal/workcopy/git.go` (`allowedGit`, `workGit`, préambule du paquet), `internal/workcopy/apply.go` (`IsMerged`)

**Interfaces:**
- Consumes: `netGit`, `userEnv`, `netTimeout`, `classify`, `*GitFailure`, `Deps.AllowLocalRemote`, le dépôt temporaire (Task 14c, cloné ici sans `--single-branch --branch`).
- Produces: `Update(ctx, d, p, url, proxyURL, remoteName string) (UpdateResult, error)` avec `UpdateResult{Outcome string ("updated"|"up_to_date"); From, To string}` ; `UpdateCheck(ctx, d, p, remoteName) (UpdatePlan, error)` avec `UpdatePlan{Current, Default string}`, lecture seule, sans réseau. Le refus `not_default` remplit `GitFailure.Current` et `.Default`.

- `workGit` (`status`, `merge`), seulement sur le dossier du projet. Environnement `userEnv`, proxy `127.0.0.1:9` ; `-c core.hooksPath=<fix-hooks> -c core.fsmonitor=false -c gc.auto=0 -c maintenance.auto=false -c credential.helper= -c commit.gpgSign=false -c core.longpaths=true -c submodule.recurse=false -c merge.verifySignatures=false`.
- `allowedGit` gagne, en lecture seule : `symbolic-ref`, `check-attr`, `cherry`.
- Pas de `--stdin` : `ExecFunc` n'a pas d'entrée standard. Les chemins passent en arguments, après `--`, par lots d'au plus 100.

| Étape | Commande |
|---|---|
| Préalable de mise à jour, sans réseau, **dans cet ordre** (R34) | `config --local --includes --name-only --list` : une clé `filter.*` ou `core.worktree`, `filter`, **avant tout `status`, qui lancerait le `clean` de cette clé sur un fichier changé** ; `symbolic-ref --quiet --short HEAD` (échec : `detached`) ; branche principale : `symbolic-ref --quiet --short refs/remotes/<remote>/HEAD`, sinon `refs/heads/main` ou `refs/heads/master` s'il n'y en a qu'une, sinon `default_unknown` ; égale à la branche courante, sinon `not_default` ; `rev-parse --verify --quiet` de `MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD` : présent, `in_progress` ; `git --no-optional-locks` par `workGit`, `status --porcelain=v1 --untracked-files=no` : sortie non vide, `dirty`. |
| Récupérer | `git -C <tmp> fetch --quiet --no-tags --no-write-fetch-head --no-auto-maintenance --no-recurse-submodules -- <clean> refs/heads/<default>:refs/michel/incoming`, délai `netTimeout`. Puis, dans le projet, par `h.git` et `localTransport` : `fetch --quiet --no-tags --no-write-fetch-head --no-auto-maintenance --no-recurse-submodules <tmp> +refs/michel/incoming:refs/remotes/<remote>/<default>` (le `+` ne touche qu'une référence de suivi, comme le réglage par défaut de Git, jamais une branche). |
| Décider | Égal à `HEAD` : `up_to_date` ; `merge-base --is-ancestor HEAD <sha>` faux : `diverged`. `diff --name-only -z HEAD <sha>` puis `check-attr --source=<sha> -z filter -- <chemins>` (R34 : les attributs du commit qui arrive, pas ceux du dossier) : une valeur autre que `unspecified` ou `unset`, `filter`. `check-attr` en échec (Git trop ancien pour `--source`) : `update_failed`, rien n'est écrit. |
| Mettre à jour | `workGit merge --ff-only --no-stat --no-autostash --quiet <sha>`, sous `context.WithoutCancel` et 2 minutes : fermer la page ou arrêter le serveur ne coupe pas une écriture en cours. Échec : `untracked` si la sortie parle de fichiers non suivis, `diverged` si `Not possible to fast-forward`, sinon `update_failed`. |

- [ ] **Step 1: Tests**, Git réel, projet `demo` et dépôt nu temporaires (sauf mention `Exec` enregistreur), `HOME` et `USERPROFILE` remplacés par `t.Setenv`, `AllowLocalRemote` vrai pour joindre le dépôt nu :
  - Mise à jour : `TestUpdateFastForwards` ; `TestUpdateUpToDateWritesNothing` ; `TestUpdateRefused` (table : `detached`, `not_default`, `default_unknown`, `dirty`, `in_progress`, `filter` par clé locale, `filter` par attribut sur un fichier changé, `filter` par un attribut que seule la mise à jour amène, `core.worktree`, `diverged`, `untracked`), et pour chaque cas `HEAD`, index et fichiers identiques avant et après ; `TestUpdateRefusesBeforeAnyNetwork` (enregistreur : aucun `fetch` pour les refus préalables) ; `TestUpdateKeepsAutocrlf` (`core.autocrlf=true` dans le `gitconfig` de la personne, fichier CRLF : dossier propre après la mise à jour) ; `TestUntrackedFileIsNotDirty` ; `TestUpdateRunsNoHookNorFilter` (`post-merge`, `post-checkout`, `reference-transaction`, et une clé locale `filter.x.clean` avec un fichier suivi changé de même taille : aucun témoin, R34) ; `TestUpdateMovesOnlyTheDefaultBranch` (autres branches, stash, tags inchangés) ; `TestUpdateCheckIsReadOnly`.
  - Preuve (R25) : `TestIsMergedAfterMergeCommit`, `TestIsMergedAfterFastForward`, `TestIsMergedAfterSquash`, `TestIsMergedAfterRebase`, `TestIsMergedFalseForAnotherChange`, `TestIsMergedFalseOnEmptyCherry`. `TestPrepareAndApplyNeverPushNorMerge` (enregistreur).
- [ ] **Step 2: Vérifier l'échec, écrire.** `IsMerged`, après un `--is-ancestor` faux : `cherry HEAD <sha> <sha>^`, vrai si la sortie est exactement une ligne commençant par `- `. Préambule du paquet : `Apply`, `Push` et `Update` sont les seules écritures.
- [ ] **Step 3: Vérifier** `go test ./internal/workcopy/`, puis la porte Go, `go test ./internal/hygiene/`.
- [ ] **Step 4: Commit** `feat: update the folder fast-forward only, and prove a squashed fix`.

### Task 14e: Accord, règle réseau, envoi et mise à jour (service)

R26, R27, R29, R33. Le service ne lance **jamais** `PushFix` ni `UpdateProject` de lui-même.

**Files:**
- Create: `internal/store/migrations/0021_project_remote.sql`, `internal/fix/remote.go`, `internal/fix/remote_test.go`
- Modify: `internal/egress/gateway.go`, `internal/egress/gateway_test.go` (`Authorize`), `internal/policy/policy.go` (`PurposeProjectGit = "project.git"`), `internal/fix/repo.go`, `internal/fix/service.go` (`Deps.AllowLocalRemote`, `Sweep`, `PurgeProject`, verrou de `Sessions`), `internal/fix/errors.go`, `internal/project/repo.go` (`Purge`), catalogue `internal/i18n/catalog/{fr,en}.json`

**Interfaces:**
- Consumes: `gitremote` (Task 14b), `workcopy` (Tasks 14c, 14d), `policy.AddAllowRules`, `policy.RemoveAllowRules`, `allowproxy.Listen`.
- Produces, `egress` : `(*Gateway).Authorize(host, purpose string) error` : même contrôle et même `egress.attempt` que `DialContext`, fermé si l'audit manque, sans ouvrir de connexion.
- Produces, `fix` : `ProjectGit(ctx, d, p) (GitState, error)` ; `AnswerGit(ctx, d, p, answer, remoteID string) (GitState, error)` ; `PushFix(ctx, d, attemptID string) (PushOutcome, error)` avec `PushOutcome{Outcome, MergeURL, Provider, Branch string; At time.Time}` ; `UpdateProject(ctx, d, p) (workcopy.UpdateResult, error)` ; `Repo.GitAnswer`, `Repo.SetGitAnswer`, `Repo.RecordPush`, `Repo.Push`. Erreurs : `ErrGitNotAttached`, `ErrGitNoRepo`, `ErrGitRemoteChanged`, `ErrGitNoRemote`, `ErrGitNoRule`, `ErrGitBranchMoved`, `ErrGitBusy`, `ErrGitNotApplied`, et `*workcopy.GitFailure`, lues par `ErrorKey` et `Explain`.
- Produces: `GitBusy(d, projectID) bool` (le verrou de ce projet est pris : lu par la route de contrôle, R35). `Deps.AllowLocalRemote` passe à `gitremote.Parse` et à `workcopy.Deps`.
- `GitState` : `Repo` (`none`, `empty`, `ok`), `Answer` (vide, `yes`, `no`, `unknown`), `Attached`, `Changed`, `Suggested`, `Reason`, `Provider`, `Display`, `Host`, `RemoteID`, `HadCredential`, `CanAttach`, `Update *UpdateState{Ready, Current, Default, Code, Why}`. `Reason` et `Suggested` : `known` et `other` suggèrent `yes`, `none` suggère `no`, `several` et `unsupported` suggèrent `unknown` et `CanAttach` faux. La suggestion n'est jamais une réponse enregistrée.
- Un distant `Local` (R33) : `Reason` `other`, `Provider` `local`, `Display` et `Host` valent `Display()`, `CanAttach` vrai ; `AnswerGit` n'écrit aucune règle (`rule_written` faux), `PushFix` et `UpdateProject` ne passent ni par `Authorize` ni par le proxy.

Migration :

```sql
-- One row per project that answered the question of the guided interface.
CREATE TABLE project_remote (
  project_id TEXT PRIMARY KEY,
  answer TEXT NOT NULL CHECK (answer IN ('yes','no','unknown')),
  remote_name TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',       -- Remote.Clean: never a password or a token
  host TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  rule_written INTEGER NOT NULL DEFAULT 0,
  answered_at TEXT NOT NULL
);
-- One row per fix branch that reached the remote.
CREATE TABLE fix_push (
  attempt_id TEXT PRIMARY KEY,
  commit_sha TEXT NOT NULL,
  host TEXT NOT NULL,
  pushed_at TEXT NOT NULL
);
```

Aucune donnée à migrer : pas de ligne veut dire « jamais répondu ». `project.Repo.Purge` ajoute, **avant** `DELETE FROM fix_attempt`, `DELETE FROM fix_push WHERE attempt_id IN (SELECT id FROM fix_attempt WHERE project_id = ?)`, et `DELETE FROM project_remote WHERE project_id = ?`. Il n'a pas accès à la politique : c'est `fix.PurgeProject`, que `internal/cli/project.go` appelle juste avant, qui retire la règle si `rule_written` et qu'aucun autre projet rattaché ne l'utilise (`policy.RemoveAllowRules`, puis `Reload`).

Textes (`internal/i18n/catalog`, clé puis `<clé>_hint`). Statut : 409 pour un refus, 502 pour une réponse ou une absence de réponse du service, **jamais 401 ni 403**, que la page prend pour un mauvais jeton.

| Clé `api.git.` | Français | Conseil en français | English | English hint |
|---|---|---|---|---|
| `no_repo` | Ce dossier n'est pas un dépôt Git. | Michel peut le contrôler et expliquer ses failles, mais il ne peut ni préparer une correction ni l'envoyer. | This folder is not a Git repository. | Michel can check it and explain its flaws, but cannot prepare a fix or send one. |
| `not_attached` | Ce projet n'est pas rattaché à un service Git. | Réponds oui à la question sur la fiche du projet si tu veux y envoyer tes corrections. | This project is not attached to a Git service. | Answer yes on the project's page if you want to send your fixes there. |
| `no_remote` | Michel ne trouve pas d'adresse utilisable dans ce projet. | Il lui faut une seule adresse en https ou SSH (une connexion sécurisée), ou une adresse nommée origin. | Michel finds no usable address in this project. | It needs one https or SSH (secure connection) address, or one named origin. |
| `remote_changed` | L'adresse du projet a changé depuis ton accord : Michel n'a rien fait. | Regarde la nouvelle adresse sur la fiche du projet et réponds à nouveau. | The project's address changed since you agreed: Michel did nothing. | Look at the new address on the project's page and answer again. |
| `no_rule` | La règle réseau qui autorise ce service a été retirée : Michel n'a rien fait. | Réponds à nouveau à la question sur la fiche du projet. | The network rule that allows this service was removed: Michel did nothing. | Answer the question again on the project's page. |
| `not_applied` | Cette correction n'a pas de branche à envoyer. | Une branche existe seulement après ta validation, et tant que la correction n'est pas terminée. | This fix has no branch to send. | A branch exists only after your approval, and until the fix is finished. |
| `branch_moved` | La branche de cette correction a changé ou n'existe plus : Michel n'a rien envoyé. | Il envoie seulement ce que tu as validé. Relance une correction, ou envoie la branche toi-même. | This fix's branch changed or no longer exists: Michel sent nothing. | It only sends what you approved. Start a new fix, or send the branch yourself. |
| `busy` | Michel travaille déjà sur ce dossier. | Attends la fin, puis réessaie. | Michel is already working on this folder. | Wait for it to end, then try again. |
| `auth` | Le service a refusé l'accès, ou Michel n'a pas trouvé tes accès Git sur cet ordinateur. Rien n'a changé. | Michel utilise les accès déjà en place et ne peut pas t'en demander. Fais un envoi avec ton outil Git habituel pour les enregistrer, puis réessaie. | The service refused access, or Michel found no Git access on this computer. Nothing changed. | Michel uses the access already set up and cannot ask you for it. Send once with your usual Git tool to save it, then try again. |
| `host_key` | Cet ordinateur ne reconnaît pas ce service, ou son identité a changé. Rien n'a changé. | Connecte-toi une fois avec ton outil Git habituel. Si tu t'y connectais déjà, demande de l'aide : ce changement peut être une attaque. | This computer does not recognise this service, or its identity changed. Nothing changed. | Connect once with your usual Git tool. If you already used to connect, ask for help: this change can be an attack. |
| `not_found` | Le service ne trouve pas ce projet, ou ton compte n'y a pas accès. Rien n'a changé. | Vérifie que l'adresse affichée est la bonne et que ton compte y a accès. | The service does not find this project, or your account has no access. Nothing changed. | Check the address shown and that your account has access. |
| `rejected` | Le service a refusé cette branche. Michel ne force jamais un envoi. | Une branche du même nom existe peut-être avec un autre contenu, ou une règle du service l'interdit. Regarde sur le site. | The service refused this branch. Michel never forces a send. | A branch of the same name may exist with other content, or a rule of the service forbids it. Look on the site. |
| `network` | Michel n'a pas réussi à joindre le service. Rien n'a changé. | Vérifie ta connexion à Internet, puis réessaie. Le proxy d'une entreprise peut aussi l'empêcher. | Michel could not reach the service. Nothing changed. | Check your Internet connection, then try again. A company proxy can also prevent it. |
| `timeout` | Le service n'a pas répondu à temps. Michel ne sait pas si l'opération a abouti. | Clique à nouveau : si tout est déjà là, Michel le verra et n'enverra rien de plus. | The service did not answer in time. Michel does not know whether it went through. | Click again: if everything is already there, Michel sees it and sends nothing more. |
| `failed` | L'opération a échoué pour une raison que Michel ne reconnaît pas. Il n'affiche pas le détail, qui peut contenir des données privées. | Essaie avec ton outil Git habituel. | It failed for a reason Michel does not recognise. It does not show the detail, which may hold private data. | Try with your usual Git tool. |
| `detached` | Ton dossier n'est sur aucune branche : Michel n'y touche pas. | Remets-le sur sa branche principale, puis réessaie. | Your folder is on no branch: Michel leaves it alone. | Put it back on its main branch, then try again. |
| `not_default` | Ton dossier est sur la branche %s, pas sur la branche principale %s : Michel n'y touche pas. | Reviens sur la branche principale, puis réessaie. | Your folder is on branch %s, not on the main branch %s: Michel leaves it alone. | Go back to the main branch, then try again. |
| `default_unknown` | Michel ne sait pas quelle est la branche principale de ton dossier : il n'y touche pas. | Fais la mise à jour avec ton outil Git habituel. | Michel does not know your folder's main branch: it leaves it alone. | Update with your usual Git tool. |
| `dirty` | Ton dossier contient des modifications pas encore enregistrées : Michel n'y touche pas. | Enregistre-les ou mets-les de côté, puis réessaie. | Your folder holds changes not saved yet: Michel leaves it alone. | Save them or set them aside, then try again. |
| `in_progress` | Une fusion ou une reprise est en cours dans ton dossier : Michel n'y touche pas. | Termine-la ou annule-la, puis réessaie. | A merge or a pick is in progress in your folder: Michel leaves it alone. | Finish or cancel it, then try again. |
| `filter` | Cette mise à jour lancerait un programme de conversion de fichiers (Git LFS par exemple) : Michel ne le lance pas et n'a pas touché à tes fichiers. | Fais la mise à jour avec ton outil Git habituel, puis clique sur « Contrôler ce projet ». | This update would run a file conversion program (Git LFS for example): Michel does not run it and left your files alone. | Update with your usual Git tool, then click "Check this project". |
| `diverged` | Ton dossier contient des enregistrements qui ne sont pas sur le site : Michel ne mélange rien et n'a pas touché à tes fichiers. | Envoie-les ou règle cet écart avec ton outil Git habituel, puis réessaie. | Your folder holds saved work that is not on the site: Michel mixes nothing and left your files alone. | Send it or settle this with your usual Git tool, then try again. |
| `untracked` | Un fichier de ton dossier serait écrasé par cette mise à jour : Michel n'a pas touché à tes fichiers. | Déplace ce fichier ou fais la mise à jour avec ton outil Git habituel. | A file in your folder would be overwritten by this update: Michel left your files alone. | Move that file or update with your usual Git tool. |
| `update_failed` | La mise à jour a échoué : Git l'a arrêtée. | Vérifie l'état de ton dossier avec ton outil Git habituel. | The update failed: Git stopped it. | Check your folder's state with your usual Git tool. |

- [ ] **Step 1: Tests d'`egress`** : `TestAuthorizeAllowsAndRecords`, `TestAuthorizeRefusesWithoutRule`, `TestAuthorizeFailsClosedWithoutAudit`.
- [ ] **Step 2: Tests de `fix/remote.go`** : `TestNothingAttachedWithoutYes` (`no`, `unknown`, jamais répondu : `PushFix` et `UpdateProject` refusent, aucune règle, aucun git) ; `TestYesWritesOneRuleAndReloads` (`{host, project.git}`, `.bak`, `Gateway` à jour, `rule_written` vrai) ; `TestYesOnStrictLocalKeepsTheMode` (R26) ; `TestYesNeedsTheAddressShown` (`remote_id` périmé : `ErrGitRemoteChanged`) ; `TestAnswerCanChange` (`yes` puis `no` retire la règle écrite par Michel ; ni celle qu'un autre projet rattaché utilise, ni celle qu'il n'a pas écrite) ; `TestStoredRowHasNoSecret` (lecture brute de la table : pas de `canari-git-7391`) ; `TestPushNeedsApplied` (chaque autre état refusé, y compris `proven_fixed`) ; `TestServerAttemptCannotPush` ; `TestChangedAddressStopsPushAndUpdate` ; `TestNoRuleStopsPush` ; `TestPushChecksGatewayFirst` (`egress.attempt` de `project.git` écrit avant le lancement ; audit en panne : pas d'envoi) ; `TestHttpsUsesTheAllowProxy` ; `TestSecondClickIsAlreadyAndAudited` ; `TestConcurrentClickIsBusy` ; `TestAutoApplyNeverPushes` (niveau 3, `fixWorker`, `Prove`, `Sweep` : aucun `push`) ; `TestPushRecordsNoOutput` (`canari-git-7391` dans stderr : absent de l'audit, de `fix_message`, `cause`, `cause_detail`) ; `TestAuditEvents` (`project.git.answer`, `project.git.push`, `project.git.update`, avec `project_id`, `host`, `provider`, `attempt_id`, `branch`, `commit`, `outcome`, `author`, sans adresse complète ; aussi pour les refus) ; `TestProveAfterUpdateIsProvenFixed` (dépôt nu, `merge --no-ff` hors de Michel, `UpdateProject`, scan : `proven_fixed`) ; `TestProveAfterSquashIsProvenFixed` ; `TestPurgeForgetsRemoteAndPush` ; `TestLocalNeedsNoRuleAndAllowLocal` (`AllowLocalRemote` faux : un `origin` local n'est pas rattachable ; vrai : aucune règle, aucun `egress.attempt`) ; `TestGitBusyDuringAClick`.
- [ ] **Step 3: Vérifier l'échec, écrire.** `AnswerGit` : même ordre que `GiveConsentWith` : `AddAllowRules`, `reload`, ligne en base, audit. `PushFix` et `UpdateProject` prennent `Sessions.gitLock(projectID).TryLock()`, relisent le distant à chaque clic et comparent `Clean`. `PushFix` : `Gateway.Authorize` (sauf `Local`), `allowproxy.Listen(d.Gateway, policy.PurposeProjectGit)` seulement en HTTPS, fermé à la fin. `outcome` `pushed` ou `already` écrit la ligne `fix_push` par `INSERT … ON CONFLICT(attempt_id) DO NOTHING` : un second clic garde la première date. `Sweep` retire les entrées de `<data>/fix-net` de plus d'une heure. `ErrorKey` et `Explain` lisent les erreurs ci-dessus ; `api.git.not_default` reçoit `GitFailure.Current` et `.Default`.
- [ ] **Step 4: Relecture FR** du catalogue, **vérifier** la porte Go, `go test ./internal/hygiene/`.
- [ ] **Step 5: Commit** `feat: agree to a Git host once, send and update on a click, audited`.

### Task 14f: Routes de rattachement et docs

R29, R31, R32, R33, R35.

**Files:**
- Create: `internal/api/projects_git.go`, `internal/api/projects_git_test.go`, `internal/cli/localremote.go` (`//go:build !michel_local_remote`, `const allowLocalRemote = false`), `internal/cli/localremote_tagged.go` (`//go:build michel_local_remote`, `const allowLocalRemote = true`), `internal/cli/localremote_test.go`
- Modify: `internal/api/server.go` (routes), `internal/api/fix.go` (route, `AttemptView.Push`), `internal/api/views.go`, `internal/api/handlers.go` (`ProjectView`), `internal/api/projects_run.go` (R35), `internal/cli/serve.go`, `docs/fix.md`, `docs/fix.fr.md`, `docs/security/network-egress.md`, `docs/security/network-egress.fr.md`

**Interfaces:**
- Consumes: Task 14e, `s.scans` (Task 14).
- Produces, API (jeton, `Host` et `Origin` déjà contrôlés par `ServeHTTP` ; champ inconnu refusé par `readJSONHint`) :
  - `GET /api/v1/projects/{name}/git`, 200 `GitView{Repo string ("none"|"empty"|"ok"); Answer string (""|"yes"|"no"|"unknown"); Attached, Changed bool; Suggested string ("yes"|"no"|"unknown"); Reason string ("known"|"other"|"none"|"several"|"unsupported"); Provider, Display, Host, RemoteID string; HadCredential, CanAttach bool; Update *GitUpdateView}`, `GitUpdateView{Ready bool; Current, Default, Code, Why string}`, sans réseau et sans écriture. Clés JSON en `snake_case`.
  - `POST /api/v1/projects/{name}/git/answer`, corps `{"answer": "yes"|"no"|"unknown", "remote_id": "…"}` (`remote_id` obligatoire pour `yes`), 200 `GitView`.
  - `POST /api/v1/fix/{attempt}/push`, corps vide, 200 `{"outcome": "pushed"|"already", "provider", "branch", "merge_url", "pushed_at"}`.
  - `POST /api/v1/projects/{name}/git/update`, corps vide, 200 `{"outcome": "updated"|"up_to_date"}`.
  - `AttemptView.Push *AttemptPushView{Provider, Display, Branch, MergeURL, PushedAt string; Pushed, CanPush bool}`, `nil` pour un serveur ou un projet non rattaché ; `ProjectView` gagne `git_answer` et `git_attached`, lus en base, sans lancer git.
- `GitView` reprend `fix.GitState`. Un distant `Local` n'a pas de lien.
- Statuts : 409 pour un refus (`no_repo`, `not_attached`, `no_remote`, `remote_changed`, `no_rule`, `not_applied`, `branch_moved`, `busy`, et les refus de mise à jour, `update_failed` compris) ; 502 pour une réponse ou une absence de réponse du service (`auth`, `host_key`, `not_found`, `rejected`, `network`, `timeout`, `failed`). **Jamais 401 ni 403**, que la page prend pour un mauvais jeton. Le texte vient de `fix.ErrorKey` et `fix.Explain`, avec `<clé>_hint`.

- [ ] **Step 1: Tests API** : `TestGitViewNeedsNoNetworkAndHasNoAbsolutePath` ; `TestGitViewHasNoSecret` ; `TestGitViewSuggests` (`known`, `other`, `none`, `several`, `unsupported`) ; `TestAnswerRefusesUnknownFieldAndBadValue` ; `TestPushReturnsMergeURL` ; `TestCraftedRemoteGivesNoLink` (`https://github.com.example.test/demo/app`, adresse refusée) ; `TestFailureIsNeverUnauthorized` (classe `auth` : 502) ; `TestFailureCodesAndTexts` (un cas par clé, FR et EN) ; `TestUpdateRefusedWhileScanning` (409 `api.git.busy`) ; `TestAttemptViewCarriesPush` ; `TestProjectsListRunsNoGit` (enregistreur) ; `TestScanRefusedWhileAClickRuns` (R35, 409 `api.git.busy`) ; `TestGitRoutesNeedTheToken` pour les quatre routes ; `TestGitPostsRefuseCrossOrigin` pour les trois `POST`.
- [ ] **Step 2: Tests du binaire** (R33), `internal/cli/localremote_test.go`, avec `//go:build !michel_local_remote` : `TestDefaultBuildRefusesALocalRemote` (`allowLocalRemote` faux ; par la pile de `serve_test.go`, un projet dont `origin` est un dépôt local donne `reason: unsupported` et `can_attach: false`) ; `TestShippedBuildsDoNotUseTheTag` (`michel_local_remote` absent de `Makefile`, `README.md`, `.github/workflows/ci.yml`, lus depuis la racine du dépôt).
- [ ] **Step 3: Vérifier l'échec, écrire.** Même forme que `fixApprove` pour les deux écritures longues : `extend(w)`, `s.detached(r)`, réponse après la fin. `TestUpdateRefusedWhileScanning` lit `s.scans`. `internal/cli/serve.go` : `AllowLocalRemote: allowLocalRemote`, jamais lu dans l'environnement ni dans une option. Vérifier aussi que l'autre construction compile : `go vet -tags michel_local_remote ./internal/cli/`.
- [ ] **Step 4: Docs**, FR et EN, à égalité :
  - `docs/fix*.md`. Introduction : « c'est toi qui la fusionnes » reste. « C'est la seule écriture de Michel dans ton projet » devient « Sans rattachement, c'est la seule écriture de Michel dans ton projet ». Nouvelle section **« Rattacher ton projet à GitHub, Bitbucket ou GitLab »** après « La branche, puis tu déploies » : la question ; rien sans un oui ; adresse lue sans réseau, secret ni affiché ni gardé ni utilisé ; bouton d'envoi : seulement `michel/fix-…`, jamais forcé, un clic par envoi, depuis un dépôt temporaire qui ne lit pas la configuration de ton projet ; lien de demande de fusion sur les trois sites, nom de branche ailleurs ; pas de jeton enregistré ; `Mettre à jour mon dossier` : `--ff-only`, branche principale, dossier sans modification, sans hook ni programme de conversion, sinon refus ; ce qu'il écrit : les commits, ta branche principale, sa référence de suivi, les fichiers changés ; **ces deux boutons lèvent, pour un projet rattaché et sur clic, la règle « Michel ne pousse pas et ne lance rien dans ton dossier »** ; audit ; **Michel ne fusionne toujours jamais**. « La preuve » : `proven_fixed` accepte aussi l'équivalent exact du commit (fusion par « squash » ou « rebase ») ; phrase des tests : « Michel ne relance pas les tests après la fusion : il ne lance aucun programme de ton projet, et « Mettre à jour » ne fait qu'y amener les fichiers ». « Risques qui restent » gagne la connexion SSH et le gestionnaire d'accès, hors du proxy. « En cas de problème » gagne une ligne par clé `api.git.` qu'une personne peut rencontrer, et la ligne `not_git` devient : « Michel copie avec git : le dossier ajouté doit être le dossier principal d'un dépôt, avec un premier commit. Le contrôle et la fiche restent disponibles. ».
  - `docs/security/network-egress*.md`, ligne de table :
    - EN : `` | `project.git` | the host of the address you attached (`github.com`, `bitbucket.org`, `gitlab.com` or your own) | Only on your click, for an attached project: **Send the fix** and **Update my folder**. Sends the branch `michel/fix-…` and the commits it needs; brings back the main branch. Your Git access already on this computer is used, Michel stores none. The rule is written when you answer yes and removed when you take it back. Over https, git goes through the allow proxy (port 443 only). Over SSH, git and ssh open their own connection: the gateway decides and records before git starts, but Michel neither carries nor stops it. | ``
    - FR : `` | `project.git` | l'hôte de l'adresse que tu as rattachée (`github.com`, `bitbucket.org`, `gitlab.com` ou le tien) | Seulement sur ton clic, pour un projet rattaché : **Envoyer la correction** et **Mettre à jour mon dossier**. Envoie la branche `michel/fix-…` et les commits dont elle a besoin ; ramène la branche principale. Tes accès Git déjà en place sur cet ordinateur servent, Michel n'en enregistre aucun. La règle est écrite quand tu réponds oui et retirée quand tu reviens dessus. En https, git passe par le proxy d'autorisation (port 443 seulement). En SSH, git et ssh ouvrent leur propre connexion : la passerelle décide et note avant le lancement de git, mais Michel ne la porte pas et ne l'arrête pas. | ``
    - Ligne « Fix work copy and branch » : « No remote is contacted » devient « No remote is contacted, except on the click described under `project.git` », FR de même. Liste testée : `TestPushSendsOnlyTheBranch`, `TestPushRunsNoProjectConfig`, `TestReadRemotesRunsNoNetworkCommand`, `TestPushChecksGatewayFirst`. Liste « Declared only » : la connexion SSH, un gestionnaire d'accès (Git Credential Manager), un `url.*.insteadOf` global de la personne qui mène ailleurs que l'hôte contrôlé, un `http.<adresse>.proxy` global de la personne, qui passe devant le proxy d'autorisation (essayé avec Git 2.46.2).
  - **Relecture FR.**
- [ ] **Step 5: Vérifier** la porte Go, `go test ./internal/hygiene/`, puis `grep -rn "canari-git-7391" internal --include=*.go` : seulement dans des tests.
- [ ] **Step 6: Commit** `feat: attach a project to its Git host, send the fix branch and update the folder on a click`.

### Task 14g: Rattacher un projet, envoyer, mettre à jour (écrans)

**Files:**
- Create: `web/src/lib/gitView.js`, `web/src/lib/gitView.test.js`, `web/src/components/GitQuestion.vue`, `web/src/components/MergeStep.vue`
- Modify: `web/src/lib/pathView.js`, `web/src/lib/pathView.test.js`, `web/src/components/FailureGuide.vue`, `web/src/components/ProjectCard.vue`, `web/src/components/FixSettings.vue`, `web/src/lib/helpView.js`, `web/src/i18n/jargon.test.js`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Consumes: `GET /projects/{name}/git`, 200 `{repo: 'none'|'empty'|'ok', answer: ''|'yes'|'no'|'unknown', attached, changed, suggested: 'yes'|'no'|'unknown', reason: 'known'|'other'|'none'|'several'|'unsupported', provider, display, host, remote_id, had_credential, can_attach, update: {ready, current, default, code, why}|null}` ; `POST /projects/{name}/git/answer`, corps `{answer, remote_id}` (`remote_id` obligatoire pour `yes`), 200 la même vue ; `POST /fix/{attempt}/push`, corps vide, 200 `{outcome: 'pushed'|'already', provider, branch, merge_url, pushed_at}` ; `POST /projects/{name}/git/update`, corps vide, 200 `{outcome: 'updated'|'up_to_date'}` ; `attempt.push` `{provider, display, branch, merge_url, pushed_at, pushed, can_push}|null` ; `project.git_answer`, `project.git_attached` (Task 14f). Toute erreur : `error` et `hint`. `POST /projects/{name}/scan` (Task 14), `FieldHelp`, `mergeStep` (Task 8). Un fournisseur `local` (R33, essai seulement) se traite comme `other` : `push.other`, `state.attached_other`, pas de lien.
- Produces: `safeMergeUrl(url): string` (le lien seulement si `new URL(url)` a `protocol === 'https:'`, ni `username` ni `password`, et une origine exacte parmi les trois ; sinon `''`) ; `gitQuestion(view): {ask: boolean, sentence: {key, params}, suggested, options: string[], canYes: boolean, credential: boolean}` ; `gitState(view): {key, params}` ; `updateFollowUp(outcome): 'scan'|'none'`.
- Changes: `mergeStep({attempt, project, git}): {mode: 'manual'|'attached'|'none', branch, command, push: {label, params, pushed}|null, link: {href, params}|null, update: {ready, why}|null}`.

Textes exacts :

| Clé `git.` | Français | English |
|---|---|---|
| `question` | Ton projet est-il sur GitHub, Bitbucket, GitLab ou un service semblable ? | Is your project on GitHub, Bitbucket, GitLab or a similar service? |
| `why` | Si oui, Michel peut y envoyer une correction en un clic. Tu l'acceptes ensuite sur le site, sans commande à taper. Rien n'est rattaché sans ton oui, et tu peux changer d'avis. | If so, Michel can send a fix there in one click. You then accept it on the site, with no command to type. Nothing is attached without your yes, and you can change your mind. |
| `answer.yes`, `.no`, `.unknown` | Oui ; Non ; Je ne sais pas | Yes ; No ; I don't know |
| `suggest.known` | Michel a lu dans ton projet une adresse {provider} : {display}. La réponse semble donc être oui. | Michel read a {provider} address in your project: {display}. The answer seems to be yes. |
| `suggest.other` | Michel a lu dans ton projet l'adresse d'un service qu'il ne reconnaît pas : {display}. La réponse semble être oui, si tu connais ce service. | Michel read the address of a service it does not recognise in your project: {display}. The answer seems to be yes, if you know this service. |
| `suggest.none` | Michel ne trouve aucune adresse de service en ligne dans ton projet. La réponse semble donc être non. | Michel finds no online service address in your project. The answer seems to be no. |
| `suggest.several` | Ton projet a plusieurs adresses, et aucune ne s'appelle origin : Michel ne sait pas laquelle choisir et ne peut pas le rattacher. | Your project has several addresses and none is called origin: Michel does not know which to choose and cannot attach it. |
| `suggest.unsupported` | L'adresse lue dans ton projet n'est pas une adresse en https ou SSH (une connexion sécurisée) que Michel sait utiliser : il ne peut pas le rattacher. | The address read in your project is not an https or SSH (secure connection) address Michel can use: it cannot attach it. |
| `credential` | L'adresse enregistrée dans ton projet contient un mot de passe ou un jeton. Michel ne l'affiche pas, ne le garde pas et ne s'en sert pas. Si l'envoi échoue, enregistre tes accès autrement, avec ton outil Git habituel. | The address saved in your project holds a password or a token. Michel does not show it, keep it or use it. If sending fails, save your access another way, with your usual Git tool. |
| `yes_detail` | En disant oui, tu autorises Michel à contacter {host}, seulement quand tu cliques sur un bouton. Il utilise les accès Git déjà en place sur cet ordinateur et n'enregistre aucun mot de passe. | By saying yes, you allow Michel to contact {host}, only when you click a button. It uses the Git access already set up on this computer and stores no password. |
| `state.attached` | Rattaché à {provider} : {display} | Attached to {provider}: {display} |
| `state.attached_other` | Rattaché à ton service Git : {display} | Attached to your Git service: {display} |
| `state.not_attached` | Non rattaché. Après une correction, il te restera à la fusionner toi-même avec Git. | Not attached. After a fix, you will have to merge it yourself with Git. |
| `state.changed` | L'adresse de ton projet a changé depuis ton accord ({display}). Michel n'envoie plus rien tant que tu n'as pas répondu à nouveau. | Your project's address changed since you agreed ({display}). Michel sends nothing until you answer again. |
| `change` | Changer ma réponse | Change my answer |
| `none` | Ce dossier n'est pas un dépôt Git (un dossier qui garde l'historique de tes fichiers). Michel peut le contrôler et t'expliquer ses failles. Il ne peut pas préparer de correction : il travaille à partir de ton dernier enregistrement. Michel ne crée pas de dépôt à ta place. | This folder is not a Git repository (a folder that keeps the history of your files). Michel can check it and explain its flaws. It cannot prepare a fix: it works from your last saved version. Michel does not create a repository for you. |
| `none_how` | Si ton projet a un dépôt Git, ajoute le dossier principal, celui qui contient le dossier .git. Sinon, demande à la personne qui gère ton code. | If your project has a Git repository, add its main folder, the one that holds the .git folder. Otherwise, ask the person who manages your code. |
| `empty` | Ce dépôt Git n'a encore aucun enregistrement. Michel peut le contrôler, mais il lui faut un premier enregistrement (commit) pour préparer une correction. | This Git repository has no saved version yet. Michel can check it, but needs a first saved version (commit) to prepare a fix. |
| `manual.attach` | Si ton projet est sur GitHub, Bitbucket ou GitLab, tu peux le rattacher : tu n'auras plus de commande à taper. | If your project is on GitHub, Bitbucket or GitLab, you can attach it: you will have no more commands to type. |
| `push.known` | Envoyer la correction sur {provider} | Send the fix to {provider} |
| `push.other` | Envoyer la correction sur ton service Git | Send the fix to your Git service |
| `push.lead` | Michel envoie seulement la branche {branch}, une version à part de ton code. Ta version principale reste telle quelle. | Michel sends only the branch {branch}, a separate version of your code. Your main version stays as it is. |
| `push.running` | Envoi en cours… | Sending… |
| `push.done.known` | Correction envoyée sur {provider}. Il te reste à l'accepter sur le site. | Fix sent to {provider}. You still have to accept it on the site. |
| `push.done.other` | Correction envoyée. Sur ton service, demande la fusion de la branche {branch}. | Fix sent. On your service, ask to merge the branch {branch}. |
| `push.already` | Cette correction est déjà sur le service : Michel n'a rien renvoyé. | This fix is already on the service: Michel sent nothing again. |
| `merge.open` | Ouvrir la demande de fusion sur {provider} | Open the merge request on {provider} |
| `after` | Une fois la correction acceptée sur le site, clique sur « Mettre à jour mon dossier » : Michel pourra alors la vérifier. | Once the fix is accepted on the site, click "Update my folder": Michel can then verify it. |
| `update.button` | Mettre à jour mon dossier | Update my folder |
| `update.lead` | Michel fait arriver sur ton ordinateur ce qui a été accepté sur le site, sans rien mélanger. Si ce n'est pas possible, il ne touche pas à tes fichiers et te dit pourquoi. | Michel brings to your computer what was accepted on the site, without mixing anything. If that is not possible, it leaves your files alone and tells you why. |
| `update.done` | Ton dossier est à jour. Michel lance le contrôle. | Your folder is up to date. Michel starts the check. |
| `update.none` | Rien de nouveau sur le site. Si la correction attend encore, accepte-la, puis réessaie. | Nothing new on the site. If the fix is still waiting, accept it, then try again. |

- [ ] **Step 1: Tests** : `safeMergeUrl keeps only the three sites` (`javascript:alert(1)`, `data:…`, `http://github.com/a/b`, `https://github.com.example.test/a/b`, `https://user@github.com/a/b`, `//github.com/a`, vide : tout donne `''`) ; `question is asked once, until answered` ; `no question without a repository` (`repo: none` et `empty` : `ask` faux, texte `none` ou `empty`) ; `yes is offered only with a usable address` ; `nothing preselected` (la suggestion est une phrase, jamais une réponse enregistrée) ; `credential says so without the value` ; `merge step manual, attached, none` (non rattaché : commande à copier et `manual.attach` ; rattaché : pas de commande ; `changed` : pas d'envoi, `state.changed` ; tentative avec `attempt.server` : `none`) ; `pushed shows the link only if safe, else the branch name` ; `unknown service gives the branch name, no link` (`other` et `local`) ; `update explains why when not ready` ; `update follow up runs the check only after updated` ; `no error text comes from git` (le texte vient de `error` et `hint` de l'API) ; le `merge note gives the branch` de la Task 8 tient dans les deux modes.
- [ ] **Step 2: Vérifier l'échec, écrire `gitView.js`.** `jargon.test.js` gagne la famille `git.` ; « SSH » y est expliqué dans la même phrase, et `git.suggest.unsupported` entre dans `jargonExceptions` ; « Git », « branche », « commit » et « fusion » n'y sont pas interdits par la regex, ils restent soumis à la relecture.
- [ ] **Step 3: `GitQuestion.vue`** : question, `why`, phrase de suggestion, trois boutons de même poids (aucune réponse par défaut), `yes_detail` puis confirmation sur place au clic sur `Oui`, `credential` si besoin. `FieldHelp id="project.git"` (ajouter à `helpIds`, FR et EN : à quoi ça sert, quoi répondre, « Si tu te trompes, change ta réponse : rien n'est envoyé sans un clic de ta part. »). Monté dans `ProjectCard` tant qu'il n'y a pas de réponse, et dans `FixSettings` (les réglages de chaque projet) avec `gitState` et `Changer ma réponse`. `repo: none` ou `empty` : le texte vrai, jamais la question.
- [ ] **Step 4: `MergeStep.vue`**, monté par `FailureGuide` à la place du bloc manuel de la Task 8, dont il garde les textes. Le bouton d'envoi est désactivé et dit `push.running` tant que la requête tourne ; une erreur affiche `error` et `hint`, rien d'autre. Après `pushed` ou `already`, un vrai lien `<a :href target="_blank" rel="noopener noreferrer">`, jamais `window.open` (R31), avec `safeMergeUrl` juste avant le rendu. Le bouton reste cliquable : un second clic répond `already`. `Mettre à jour mon dossier` : après `updated`, `POST /projects/{name}/scan` et `update.done` ; tant que le `scanning` du projet (Task 14) est vrai, relire le projet et la tentative toutes les 3 s, minuteur arrêté à `beforeUnmount` : le chemin se recharge à la fin du contrôle. Le même bouton de mise à jour est sur le `ProjectCard` d'un projet rattaché. La ligne `applied` d'un projet dans `todoView` garde son texte `todo.applied` et son unique action, vers la tentative : envoyer se fait là, jamais depuis la liste.
- [ ] **Step 5: Relecture FR, vérifier** les deux portes, deux largeurs, deux thèmes, clavier. Le lien de demande de fusion s'ouvre au clavier, la page reste ouverte derrière.
- [ ] **Step 6: Commit** `feat: ask about the Git host, send the fix and update the folder from the page`.

### Task 15: Guide du premier lancement, écrans vides

**Files:**
- Create: `web/src/lib/guideView.js`, `web/src/lib/guideView.test.js`, `web/src/components/FirstSteps.vue`
- Modify: `web/src/lib/storage.js`, `web/src/components/TodayPage.vue`, `ProjectsPage.vue`, `ServersPage.vue`, `ServerSheet.vue`, `ServerExposure.vue`, `FixPage.vue`, `ResolvedPage.vue`, `FailureGuide.vue`, `SettingsPanel.vue`, `web/src/i18n/{fr,en}.json`

**Interfaces:**
- Produces: `keys.guide = 'michel.guide'` ; `readGuide(load): {dismissed: boolean, read: boolean}` (JSON invalide ou absent donne faux) ; `guideSteps({projects, servers, read, anyFinding}): {key: 'add'|'check'|'read', done: boolean, current: boolean, action: {label, href}|null}[]` ; `guideVisible(steps, state): boolean` ; `guideGitQuestion(projects): {name, mode: 'ask'|'no_repo'}|null` : le premier projet sans réponse avec `git_repo` vrai (`ask`) ; sinon le premier sans dépôt (`no_repo`) ; sinon `null`.

- [ ] **Step 1: Tests** : `guide resumes from data when storage is empty` (un projet scanné : `add` et `check` faits, `read` courant) ; `no flaw means step three says so` ; `dismissed stays dismissed, settings can show it again` ; `storage that throws changes nothing` ; `done guide disappears` ; `the Git question is asked under step one, never a fourth step` ; `the Git question never blocks a step` (sans réponse, `add` reste fait) ; `no Git question without a repository` (`mode: 'no_repo'`, et un projet avec dépôt passe devant) ; `answered once, not asked again, from the data`.
- [ ] **Step 2: Écrire.** `FirstSteps.vue` : un panneau en tête d'À faire, jamais de bulle ni de voile. Trois lignes numérotées, état en mots, une action par étape, `Ignorer pour l'instant`. Sous la ligne `add`, quand `guideGitQuestion` nomme un projet, `GitQuestion` de ce projet (Task 14g) ; la réponse se lit dans `git_answer`, pas dans le stockage. `mode: 'no_repo'` montre `git.none` à cet endroit. Étape 3 : `read` passe vrai au montage de `FailureGuide` et d'une carte de faille de `ServerSheet`, qui montre `FailurePath` sans `FailureGuide`.
- [ ] **Step 3: Écrans vides** : chacun dit quoi faire et porte l'action. `empty.todo` (À faire sans projet ni serveur), `empty.projects` + `Ajouter un projet`, `empty.servers` + `Trouver mes serveurs`, `empty.fix` + retour à À faire, `empty.exposure` + `Vérifier maintenant`, `empty.resolved` (Task 7). `today.no_projects_hint` (qui renvoie à la ligne de commande) n'est plus utilisée en mode simple.
- [ ] **Step 4: Relecture FR, vérifier** la porte front, deux largeurs, deux thèmes, avec un dossier de données vide.
- [ ] **Step 5: Commit** `feat: first steps guide and empty screens that act`.

### Task 16: Essai par une personne novice

**Files:**
- Create: `docs/superpowers/sdd/2026-11-03-michel-ui-guided/novice-run.md`
- Modify: ce que l'essai oblige à corriger, en commits séparés, avec son test d'abord

- [ ] **Step 1: Préparer, hors du dépôt** : dossier de données jetable ; `test/docker-server` dans WSL (`wsl -d Ubuntu -- docker build …`, `docker run` avec `-p 127.0.0.1:2222:22 -p 127.0.0.1:8080:80`, session WSL gardée ouverte) selon `docs/superpowers/sdd/2026-11-02-michel-server-logs/real-run-checklist.md`, puis `docs/superpowers/sdd/2026-10-31-michel-servers/real-run-checklist.md` pour ce que la première ne couvre pas ; agent SSH de test en espace utilisateur (`ssh.agent_pipe`), **service `ssh-agent` de Windows non touché** ; projet `demo` jetable avec `guzzlehttp/guzzle` 7.4.0 dans `composer.lock`, un dépôt Git et une commande de test ; **un dépôt nu local `demo-host.git`, dans le dossier jetable, qui tient lieu de service en ligne, adresse `origin` du projet `demo`, et qui a déjà reçu sa branche `main`** ; un second projet jetable `demo-manual`, sans adresse, et un dossier `demo-nogit`, sans dépôt ; faux agent (R18) ; `cd web && npm run build`, `go build -tags michel_local_remote -o <dossier jetable>/michel.exe ./cmd/michel` (R33), puis `michel serve` de ce binaire, le seul qui accepte le dépôt local. Le rapport dit que l'essai a tourné sur cette construction. Aucun vrai service, aucun réseau pour Git.
- [ ] **Step 2: Essai.** Le contrôleur du plan lance lui-même les étapes 2 et 3 : un implémenteur ne lance pas de sous-agent. Un sous-agent neuf joue une personne qui ne connaît pas l'informatique. Il reçoit seulement l'adresse de la page, le dossier du projet, l'adresse et l'utilisateur du serveur, et ces trois buts, en ces mots : voir les failles de son projet, savoir comment l'IA va les résoudre, voir résolu ; idem pour son serveur ; voir ce qui est ou non exposé. Ni la spec, ni le code, ni ce plan. Dans un vrai navigateur (Chrome DevTools). Il note chaque hésitation, chaque mot non compris, chaque clic sans effet, chaque moment où il aurait demandé de l'aide, avec une capture.
- [ ] **Step 3: Parcours**, complets à 1280×800 en clair, et à 375×812 en sombre (R18) :
  1. Projet rattaché : ajouter `demo`, répondre à la question du guide, contrôler, lire la faille, comprendre, lancer, valider, cliquer sur `Envoyer la correction sur ton service Git`, voir le nom de la branche. Le contrôleur de l'essai, pas la personne, joue le site : `git clone demo-host.git`, `git merge --no-ff origin/michel/fix-…`, `git push origin main`, puis il lui dit « Ta demande de fusion a été acceptée sur le site ». La personne clique sur `Mettre à jour mon dossier` et voit « Vérifiée » et la ligne dans Résolu. Rapporter : ce dépôt local n'a ni lien ni page de fusion (R19) ; les liens des trois sites sont couverts par les tests de la Task 14b. Vérifier ensuite : `demo-host.git` ne contient que `main` et cette branche ; aucun `egress.attempt` de `project.git` (`michel audit list`), un `project.git.answer`, un `project.git.push`, un `project.git.update`.
  1 bis. Une fois, à 1280 px en clair : un second clic d'envoi dit « déjà », un fichier suivi modifié fait refuser la mise à jour avec sa raison, et le fichier n'a pas bougé. `demo-manual` : réponse « Non », lancer, valider, fusionner avec la commande copiée, contrôler, voir « Vérifiée » (R6). `demo-nogit` : ajouter, contrôler, lire `git.none`, pas de question ni de bouton de correction.
  2. Serveur : ajouter, confirmer l'empreinte, vérifier, lire `expose_php`, préparer, lire le script, valider, voir « Vérifiée ».
  3. Exposition : voir PostgreSQL « Ouvert à tous », « À fermer », le pare-feu « Non vérifié » ; dans le conteneur, remettre `listen_addresses = 'localhost'` et redémarrer PostgreSQL ; vérifier : le service passe en « Réservé », la faille en Résolu. Puis retirer `iproute2` : l'écran dit « pas pu lire », jamais « rien d'ouvert ».
- [ ] **Step 4: Écrans** une fois chacun à 1280 px en sombre et à 375 px en clair : À faire, Mes projets, Mes serveurs, fiche, Résolu, Réglages, un dialogue. Contrôles sur chaque : `document.documentElement.scrollWidth <= innerWidth` ; aucune requête refusée par la CSP ; console sans erreur ; clavier seul sur un parcours ; `prefers-reduced-motion`.
- [ ] **Step 5: Contrôles d'absence** : `grep` d'un marqueur de journal piégé dans le DOM, les réponses et les messages de l'agent : zéro. Le canari `canari-michel-7391` jamais affiché. Un troisième projet jetable, `demo-secret`, avec `origin` à `https://user:canari-git-7391@example.test/demo/app.git`, ouvert sans aucun envoi : `canari-git-7391` absent du DOM, des réponses, de la base et de l'audit, et `git.credential` affiché.
- [ ] **Step 6: Corriger** ce qui bloque, test d'abord, relecture FR, puis rejouer le parcours touché. Une étape qui bloque encore sans correction possible dans ce plan (R6, la fusion, si c'est le cas) est écrite telle quelle dans le rapport, avec ce que la personne a fait.
- [ ] **Step 7: Nettoyer** : `docker rm -f`, `docker rmi`, dossier jetable, agent de test arrêté ; `git status` sans trace. `novice-run.md` en agrégats et mots de la personne, sans hôte, empreinte ni jeton.
- [ ] **Step 8: Vérifier** `go test ./...`, `go vet ./...`, `npx vitest run`, `go test ./internal/hygiene/`, revue de toute la branche.
- [ ] **Step 9: Commit** `docs: novice run of the three journeys`.

## Self-review (2026-11-03)

Couverture de la spec : Pourquoi et Objectifs, Tasks 1, 2, 16 ; Structure, Tasks 2, 6, 7 ; Chemin, Tasks 8, 9, 13 ; Exposition, Tasks 10 à 13 ; Mode avancé, Task 3 ; Guide, Tasks 4, 14, 15 ; Apparence, Tasks 1, 2 ; Contraintes, Global Constraints, Task 5 pour les remarques reportées, Task 16 pour le navigateur. Ordre de la spec respecté, sauf `isVerified`, créé à la Task 7 pour que Résolu ne dépende pas d'un écran à venir, et la Task 14, ajoutée avant le guide qui en a besoin (R4). Noms croisés vérifiés entre les blocs Interfaces. Android Studio reste possible pour la PWA, non requis par cette liste. Dernière section de la spec, ajoutée ensuite : Tasks 14b à 14g, Task 8 (bloc `applied`, `no_git`), Task 15 (la question), Task 16 (fusion sur projet rattaché) ; R19 à R32.
