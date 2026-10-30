# Plan 4 — points reportés et arbitrages (2026-10-30)

Plan : registre des sources (bases OSV, `yarn.lock` et `pnpm-lock.yaml`, KEV/EPSS, enrichissements à la demande, veille « À lire », plugins, skills, serveurs MCP, page « Sources »).

**Reconstruit.** Le ledger de travail de ce plan est resté sur l'autre machine de Kévin et n'est plus disponible. La partie Tasks 1 à 8 ci-dessous a été reconstruite à partir de l'historique git (`git log main..feat/sources`, messages de commit) et des arbitrages écrits dans le plan et le design ; les points reportés notés seulement dans ce ledger perdu manquent sans doute. Les Tasks 9 et 10 viennent du ledger repris sur ce poste. Les lignes ne nomment aucun projet privé : les exemples utilisent `demo` ou `refN`. Tout ce qui est marqué *minor (deferred)* ou *open* est reporté aux plans suivants sauf mention contraire.

## Général

- Ruling (plan) : branche `feat/sources` en place, pas de worktree — rien d'autre en cours dans ce dépôt — coût si faux : aucun.
- Ruling (Kévin) : trailer des commits `Co-Authored-By: Claude Opus 5.5` au lieu du `Claude Fable 5.1` du plan, à partir de la Task 2 (les deux commits de la Task 1 portent encore Fable 5.1) — coût si faux : trailers cosmétiques.
- Ruling (Kévin, 2026-10-30) : run réel (Task 10 Step 3) refait sur ce poste après le changement d'URL EPSS, dossier de données jetable, projets sous `refN` ; arbitrages et points reportés des Tasks 1 à 8 reconstruits depuis les messages de commit seulement — coût si faux : ce fichier est incomplet par rapport au ledger de l'autre poste.

## Arbitrages du design et du plan

Repris du design (`docs/superpowers/specs/2026-10-26-michel-plan4-sources-design.md` § 13) et du plan :

- Ruling (design § 13.1) : KEV est un drapeau `exploited` à 0 point plus `urgency: urgent` (ordre et formulation), pas des points de score : le score mesure le risque de la correction, pas l'urgence.
- Ruling (design § 13.2, § 13.14) : Michel lance Trivy (configurations seulement) et Semgrep (règles placées par l'utilisateur) derrière un proxy de refus ; CodeQL et ZAP en lecture de rapport seulement ; Semgrep remplace CodeQL comme analyseur lancé (CodeQL ne couvre pas PHP et télécharge ses requêtes au premier usage).
- Ruling (design § 13.3) : pour un serveur MCP, Michel affiche la ligne `claude mcp add …` et n'écrit pas dans la configuration de Claude Code.
- Ruling (design § 13.4–13.11) : tout désactivé par défaut sauf `osv.packagist` et `osv.npm` ; la règle `allow` reste à la désactivation, `--forget` la retire ; statut `empty` à exit 0 en `--all` avec rappel hebdomadaire ; EPSS affiché à partir du 50ᵉ percentile ; lecteur `page` = détection de changement sans extraction, listes « awesome » en références non lues ; flux « suggérés pour toi » jamais activés seuls ; deux onglets sans routeur ; deux vagues, un design, un plan.
- Ruling (design § 13.12) : tête du digest = KEV en attente ou à corriger ; reportées et ignorées en une ligne de compte.
- Ruling (design § 13.13) : Trivy limité à `misconfig` ; `vuln` attend `trivy image` (plan 11) ; `secret` hors plan 4 ; CVE d'un rapport fourni déjà connues par OSV ignorées.
- Ruling (design § 13.15) : catalogue skills et MCP réduit aux entrées de pertinence D et S ; le reste documenté comme connu et non proposé (`docs/sources.md`).
- Ruling (design § 13.16) : règle déjà présente = pas de nouvelle question ; `--forget` refusé si une autre entrée activée en dépend.
- Ruling (plan, Task 3) : `scan.Options.Lookup` est une fonction (`LookupFunc`) appelée une fois par scan avec les CVE du scan, pour ne pas charger toute la table EPSS — coût si faux : aucun.
- Ruling (plan, Task 5) : `osvdb` garde `fetched_at` et envoie `If-Modified-Since` (pas d'ETag par écosystème) — coût si faux : un téléchargement complet de plus si le serveur ignore l'en-tête.
- Ruling (plan, Task 7) : le dossier des skills se remplace en test par la variable d'environnement `MICHEL_SKILLS_DIR` (documentée pour les tests seulement), pas par un drapeau caché — coût si faux : aucun.

## Task 1 (dd86f9f, a769ae0)

- Catalogue embarqué de 114 entrées, synchronisé à chaque commande sauf `audit` et `version` ; `policy.AddAllowRule` / `RemoveAllowRule` éditent le fichier en arbre `yaml.Node`, avec `.bak`, écriture atomique et relecture validée ; `Gateway.SetRules` applique les règles sans redémarrage.
- Revue (a769ae0) : `source reset --all --purge-user` liste les sources de l'utilisateur qu'il supprime et demande `y/N` ; `--yes` pour les scripts ; sans terminal et sans `--yes`, refus avec le code 3 et refus audité.
- Relecture FR (a769ae0) : 62 propositions appliquées dans `fr.json` ; `en.json` reçoit les mêmes explications ajoutées pour que les deux langues disent la même chose.

## Task 2 (063b5c9, 88fe613, d3813e4)

- Ruling : le filtre d'hygiène sur les fichiers ignorés par git (`git ls-files --exclude-standard`) arrive dès la Task 2 et non en Task 10 ; seul le test `TestHygieneSkipsGitignoredPaths` restait à écrire (fait en Task 10).
- Revue (d3813e4) : ordre du catalogue pour les écosystèmes activés ; un écosystème désactivé n'est pas un problème de scan.
- Un dossier sans lockfile devient un scan `empty`, pas un échec : règle le *minor (deferred)* du plan 3 « un dossier sans lockfile est signalé chaque matin comme scan échoué ».

## Task 3 (f850b12, 8cc0edf, 3f6d579, 0a1f942)

- Revue (3f6d579, 0a1f942) : le titre « exploitée » ne prétend plus que les failles sont nouvelles ; raison `kev_changed` formulée de façon neutre et plus simple.

## Task 4 (6aeb470, f206478)

- Revue (f206478) : absences enregistrées par source, pour que les sources à la demande se relaient ; aucune redirection suivie quand la requête porte la clé NVD.

## Task 5 (e49e386, b04491f)

- `decide --package` imprime une ligne de résumé (`--verbose` rend les anciennes lignes) et le digest dédoublonne les supersessions par faille : règle deux points du plan 3 (« une ligne d'audit par faille » au run réel, « chaîne de décisions supersédées » à la revue finale).
- La ligne planifiée des docs devient `michel scan --all --update --digest`.

## Task 6 (f91dfd0, ff4d2fb, dea5d6b)

- Catalogue v2 : les flux de type page passent au format `auto`.
- Revue (dea5d6b) : la purge des vieux avis couvre toutes les sources, et les avis d'une source supprimée partent avec elle.

## Task 7 (6e68f49, 3f082f5, fa0e18b, 8d3acca, 5304cf6, af044e4)

- Catalogue v3 : commits épinglés, licences, chemins et commandes de lancement des six dépôts retenus, relevés le 2026-10-28.
- Revue round 1 (fa0e18b) : dossier de côté sûr pendant une mise à niveau, renommage de skill refusé, noms réservés, dossier d'installation revalidé.
- Revue round 2 (8d3acca, marqué *wip*) : renommage de skill montré et appliqué à la mise à niveau ; au moment du commit, suite de tests complète non lancée (binaires de test bloqués sur la machine), revue et relecture FR pas encore faites — reprises par 5304cf6 (FR) et af044e4.
- Revue (af044e4) : sur un renommage qui ne change que la casse, le nouveau dossier est gardé et montré ; l'ancien dossier n'est retiré qu'une fois la configuration enregistrée, et seulement si son repère porte le sha précédemment installé.

## Task 8 (d0a96a6, ee069bc, b5d6b89, a817777)

- Revue (b5d6b89) : identité d'une faille de plugin par fichier plus empreinte ; un rapport trop gros échoue sans rien fermer ; les erreurs d'audit remontent ; dossier de travail et dossier personnel de l'outil sous le dossier de données.

## Task 9 (6ded4e9, 5799fbc, 2962d7b, 938ffd7, 409e0a0)

- Revue round 1 (2962d7b) : validation commune des entrées de l'utilisateur (CLI et API), accord donné depuis la page, couverture « aucun chemin » des réponses, KEV/EPSS par paquet dans le digest.
- Revue round 2 (938ffd7) : `noPaths` coupait un chemin contenant « ) » (corrigé : une parenthèse ne ferme un chemin que si le chemin ne l'a pas ouverte) ; le passage d'un plugin lancé depuis la page est lié au cycle de vie du serveur (`Handler.Close`, 503 après fermeture), ce qui règle l'échec de nettoyage du `TempDir` sous Windows ; `defer` sur `policyMu` ; action « désactiver » pour une source en attente d'accord ; pourcentage EPSS selon la langue ; nom du secret GitHub déplacé dans `internal/secret` pour que `gitrepo` n'importe plus `sourceupdate` ; chaque code de `source.Refusal` passe par les deux traducteurs d'erreurs (CLI, API), ce qui a révélé `bad_input` absent côté CLI.
- Relecture FR (409e0a0) : `api.closing`, `bad_input`, action « Refuser et désactiver cette source », `fact.epss_value`.
- minor (deferred): `pathEnd` (internal/api/views.go:571-589) — une « ( » non fermée dans un chemin puis une « ) » du texte : remplacement trop long jusqu'au prochain « : » (sens sûr : on masque plus, pas moins).
- minor (deferred): `api.New` retourne `*Handler` ; `gitrepo` prend une interface `Budget` ; constante `secret.GitHubToken` (déplacement plus large que demandé).
- Vérification contrôleur : `go test -count=1 -timeout 10m ./...` et `npm run test` (19/19) verts sur 409e0a0.

## Task 10 (476450b, 7f5c840, docs)

- Ruling (Task 10 Step 0) : le flux EPSS répond par une redirection définitive vers `epss.empiricalsecurity.com` ; `enrich.EPSSURL` et l'hôte du catalogue pour `enrich.epss` passent à cet hôte, catalogue version 4. Après la synchronisation, une base dont `enrich.epss` avait l'accord pour l'ancien hôte repasse en attente d'accord (test `TestSyncHostChangeWaitsForConsentAgain`) : pas de refus réseau silencieux.
- minor (deferred): la règle `allow` de l'ancien hôte EPSS reste dans un fichier de politique qui avait donné son accord avant le déménagement ; `disable --forget` ne retire que les règles des hôtes actuels de l'entrée.
- Ruling (Task 10 Step 1) : le filtre `git ls-files --exclude-standard` existait déjà (Task 2) ; seul `TestHygieneSkipsGitignoredPaths` a été ajouté.
- Ruling (Task 10 Step 3, contrôleur) : le `treeDigest` manuel avant/après n'est pas concluant (dossiers en cours d'utilisation : changements attribués à git, à l'IDE et à une autre session d'assistant) ; publié tel quel avec l'explication, la preuve reste les tests `treeDigest` automatisés — coût si faux : une écriture de Michel cachée dans le bruit (aucun changement n'a l'heure ni le type d'un fichier de Michel).
- Ruling (Task 10 Step 6) : commit des docs seulement ; fusion dans `main` et push faits par le contrôleur après la revue finale de la branche.
- open: KEV et EPSS hors ligne. Le plan demandait « KEV/EPSS hors ligne par copie », mais ces données vivent dans `michel.db` et aucune commande ne les exporte ni ne les importe ; `docs/operations/offline-installation.md` dit qu'on ne peut pas les emporter seules. Une commande d'import d'un fichier KEV JSON / EPSS CSV local reste à faire.

## Run réel (contrôleur, 2026-10-30)

- Run réel: minor (deferred): `source enable` ne prend qu'une clé ; la ligne du plan en passe quatre. Plusieurs clés par appel (un seul écran d'accord) suivraient le plan et la page.
- Run réel: minor (deferred): la tête du digest répète une ligne identique par lockfile quand le même avis KEV est dans plusieurs lockfiles d'un projet ; grouper par (projet, avis) ou nommer le lockfile serait plus lisible.
- Run réel: minor (deferred): osv-scanner écrit encore des avertissements `interpreting as regex/glob` sur stderr (existant depuis le plan 1).
- Run réel: minor (deferred): `scan --all` se termine avec le code 1 sans rien dire quand un projet est `partial` : conforme à la règle du plan 1, mais en `--json` rien sur stdout ne dit quel projet l'a rendu « pas propre », sauf son `status`.
- Run réel: minor (deferred): l'ancienne règle de l'hôte EPSS reste dans un fichier de politique qui avait donné son accord avant le déménagement (voir Task 10).

## Risques résiduels

- Proxy de refus contournable : il ne retient qu'un outil qui respecte `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`. Un outil, ou un programme qu'il lance, qui ouvre ses propres connexions n'est ni arrêté ni journalisé. C'est une clôture journalisée, pas une garantie ; le vrai proxy filtrant arrive avec l'exécution isolée.
- Trivy, Semgrep et leurs règles sont installés et mis à jour hors de Michel : Michel passe les options hors ligne mais ne contrôle ni la version de l'outil, ni l'origine des règles placées dans `plugins/semgrep/rules/`.
- Un serveur MCP lancé par `npx` télécharge au démarrage, hors du contrôle de Michel ; l'aperçu le dit, rien ne l'empêche.
- Découverte limitée aux sujets GitHub `mcp-security` et `claude-skills` : un dépôt utile sans ces sujets n'est jamais proposé.
- Licence détectée par heuristique (mots-clés du fichier `LICENSE*` vers un identifiant SPDX) : une licence rare ou modifiée peut être mal reconnue ou dite « non trouvée » ; l'aperçu demande de vérifier.
- Catalogue à commit fixe qui vieillit : les skills et serveurs MCP sont épinglés sur le commit relevé le 2026-10-28 ; la mise à jour quotidienne signale une nouvelle version mais n'installe rien, et les hôtes du catalogue peuvent changer (cas EPSS) jusqu'à la prochaine version du binaire.
- Aucun test ne relie l'URL appelée par chaque lecteur aux hôtes de son entrée du catalogue : une divergence donne un refus journalisé (sens sûr), pas un envoi ailleurs.
- Plafond EPSS après décompression présent dans le code mais non testé (celui de KEV l'est).
- Le jeton GitHub, quand il est enregistré, part avec les lectures de flux GitHub, d'état des dépôts et de découverte : GitHub sait alors qui lit ; l'écran d'accord le dit.
- Hygiène : le test par empreintes ne voit pas le sens ; ledgers et docs relus à la main (agrégats seulement, projets dits `refN`, aucun chemin, paquet ni version).
