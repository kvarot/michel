# Michel — Design v1

**Date :** 2026-10-22
**Auteur :** Claude (brainstorming avec Kévin Varot)
**Statut :** validé par Kévin le 2026-10-22
**Politique de référence :** `docs/security/sovereignty-policy.md` (fait autorité en cas de conflit ; rédigée sous le nom de travail « VulnPilot », qui désigne Michel)

**Nom :** **Michel** (décision Kévin, 2026-10-22). Nom du projet, du binaire (`michel`), du dépôt (`kvarot/michel`) et prénom de l'assistant dans les digests et la PWA. Le prénom reste un paramètre `assistant.name` (défaut `Michel`), jamais utilisé dans un identifiant technique. Domaine suggéré, libre au RDAP le 2026-10-22 : `michel.security` (ou `michel.so`, `michel.sh`). Prénoms écartés après vérification : Aaron (Aaron.ai, Doctolib), Adam (adam.ai), Athena (Athena Security, athenahealth, AWS). Aucun `.ai` libre ; Michel ne portera jamais ce suffixe.

---

## 1. Intention

Kévin maintient une dizaine de dépôts (PHP/Composer, Node/npm, bientôt Go) dont un SaaS de santé. Aujourd'hui la veille sécurité = lancer `osv-scanner` à la main, lire 256 lignes (233 vulnérabilités sur 65 paquets le 2026-10-22 pour the reference project seul), trier de tête, bumper une par une. Pas tenable au quotidien, et impossible de savoir ce qui a changé depuis hier.

Michel remplace ça par un **outil local, open source, qui tourne chaque jour** sur les projets choisis, liste les failles connues, dit **comment** les corriger, **à quel coût** et **avec quels effets de bord**, pour que l'utilisateur décide. Quand le risque est faible, il corrige dans un environnement jetable et prouve que c'est corrigé. Quand le risque est élevé, il **ne tente pas** : il produit un dossier de correction compact qu'une IA de codage (Claude Code, etc.) reprend sans re-parcourir le dépôt.

Le tout sans que le code quitte la machine, sauf choix explicite et journalisé de l'utilisateur.

## 2. Objectifs, non-objectifs, anti-objectifs

### Objectifs v1
- Scan quotidien automatique des projets suivis (Composer, npm ; Go en v1.1).
- Pour chaque faille : paquet, version, version corrigée, sévérité, saut sémantique, chemin de dépendance, points d'appel dans le code de l'utilisateur, tests qui couvrent, breaking changes du changelog.
- Décision par faille : **Corriger / Reporter / Ignorer** (justification obligatoire), mémorisée, jamais redemandée sauf changement.
- Digest quotidien « nouveautés depuis hier » : page PWA, plus les canaux choisis par l'utilisateur (email, toast, webhook, web push, Telegram, Slack, SMS via partenaire).
- Correction par niveau (0 à 3) choisi par projet ; preuve obligatoire (re-scan + tests exécutés) avant tout statut « corrigé ».
- **Dossier de correction** (brief) exportable en `.md`, skill Claude Code et serveur MCP, en format compressé (caveman) pour économiser les tokens de l'IA qui reprend.
- IA optionnelle, adaptée à la machine, locale par défaut, fournisseur externe en opt-in explicite.
- Fonctionne entièrement hors ligne après approvisionnement (bases OSV, modèle).

### Non-objectifs v1
- SAST (analyse statique du code de l'utilisateur), secrets, IaC, conteneurs : via plugins plus tard (Trivy, Nox).
- Multi-utilisateurs, rôles, organisations : schéma prévu, pas d'interface v1.
- Déploiement serveur Docker : le binaire le permet, le profil Docker réseau-fermé est v1.1.
- Dépôts distants clonés par Michel : le modèle `Project.source` le prévoit (`local_path` | `git_remote`), seul `local_path` est implémenté en v1.
- Vue centralisée type Dependency-Track : export CycloneDX + VEX suffit pour y pousser.

### Anti-objectifs (ce qui rend v1 raté même si « ça marche »)
- Un faux « corrigé ». Jamais de statut sans preuve.
- Toucher à un dépôt de l'utilisateur hors worktree jetable, ou sans qu'il ait choisi le niveau.
- Du bruit le matin : une faille déjà décidée ne réapparaît que si sévérité, version corrigée ou échéance change.
- Un cœur qui exige un modèle IA, ou un modèle qui exige plus que la machine n'a.
- Une sortie réseau non listée. Une télémétrie.
- Une dépendance AGPL (Patchwork exclu).

## 3. Contraintes

- Politique de souveraineté intégrale (`docs/security/sovereignty-policy.md`), notamment : `strict_local` par défaut, `ModelProvider` unique, registre de modèles, journal d'audit chaîné, niveaux de correction par projet, aucune fusion ni déploiement automatique.
- Open source. **Licence Apache-2.0** (mon choix : compatible osv-scalibr et Nox, permissive, standard).
- Doit tourner sur un portable sans GPU dédié (référence : Ryzen 7 8840HS, Radeon 780M, 60 Go RAM, Windows 11) **et** sur une machine à 8 Go sans IA.
- **Systèmes v1 : Windows et Linux, bloquants tous les deux** ; macOS compilé et testé en meilleur effort (mon choix : Linux est requis pour le mode serveur, le profil Docker réseau-fermé et la CI GitHub). Trois points d'abstraction par OS : coffre à secrets (DPAPI / `libsecret` / Keychain), planificateur (Tâche planifiée / timer systemd ou cron / launchd), notification native (toast / `notify-send` / `osascript`).
- Pas de réinvention : s'appuyer sur `osv-scalibr` / `osv-scanner` pour le scan et la base OSV hors ligne.
- Versions au 2026-10-22 : Go 1.27.3, osv-scanner v2.7.0, Vue 3.6, Vuetify 4.2.6, Ollama 0.40.8. Prendre les dernières stables à chaque étape.

## 4. Décisions prises

### 4.1 Stack (mon choix, validé par Kévin dans le principe « le plus efficient »)

| Rôle | Choix | Pourquoi |
|---|---|---|
| Cœur, API, agent, workers, MCP | **Go 1.27**, binaire unique `michel` | osv-scalibr en bibliothèque (pas de sous-processus, pas de parsing texte), zéro runtime, démarrage instantané, un seul `http.Client` à contrôler pour l'egress |
| Base | **SQLite (WAL)** via `modernc.org/sqlite` (pur Go, pas de cgo) | Fichier local, zéro service, sauvegarde = copie. Couche `store` abstraite ; PostgreSQL prévu pour le mode serveur |
| PWA | **Vue 3.6 + Vuetify 4, Options API**, Vite, embarquée via `embed` | Terrain de Kévin ; un seul binaire à distribuer |
| Scan | **osv-scalibr** (extracteurs lockfiles) + base OSV locale (`--offline` d'osv-scanner, zip par écosystème) | Composer et npm couverts hors ligne, précision la meilleure du comparatif 2026 |
| Remédiation Composer et npm | **moteur maison** unique (calcul des versions cibles en Go, puis `composer` / `npm` dans le worktree) | osv-scanner ne couvre pas Composer, et sa remédiation npm vit dans `internal/remediation` (non importable, expérimentale) ; un moteur, deux adaptateurs d'écosystème |
| IA locale | **Ollama** (adaptateur v1) derrière `ModelProvider` | Installation simple sous Windows ; llama.cpp en second adaptateur |
| IA externe | adaptateur **OpenAI-compatible** (Groq, OpenAI, Mistral, OpenRouter, vLLM réseau local) + adaptateur Anthropic | Désactivés par défaut, opt-in par classification |
| Planification | Tâche planifiée Windows / cron / timer systemd créés par `michel schedule install` ; le binaire expose `michel scan --all` | Rien ne tourne en dehors de l'OS de l'utilisateur |
| Notifications | interface `Notifier` ; v1 : toast, email SMTP, webhook générique (Slack/Discord/n8n) ; v1.1 : web push, Telegram, Slack API ; plus tard SMS via partenaire | Canaux au choix de l'utilisateur, décision Kévin |
| Export | CycloneDX 1.6 + VEX, JSON documenté, Markdown | Interop Dependency-Track et autres |
| Dépôt | GitHub `kvarot/michel`, branche `main` | Décision Kévin |

### 4.2 Architecture (un binaire, plusieurs rôles)

```
michel (Go)
├── cmd/michel            CLI : serve | scan | fix | brief | mcp | schedule | model | export | audit
├── internal/policy          chargement + validation du YAML sovereignty, refus par défaut
├── internal/egress          passerelle réseau : allowlist, journal, client HTTP unique
├── internal/scan            osv-scalibr + base OSV locale ; normalisation Finding
├── internal/analyze         enrichissement déterministe (§ 4.4)
├── internal/decide          décisions utilisateur, règles de ré-apparition, échéances
├── internal/remediate       niveaux 0-3, worktree jetable, runner de tests, re-scan, preuve
├── internal/brief           dossier de correction : md / skill / MCP, format caveman
├── internal/ai              ModelProvider, registre, prompts versionnés, traçabilité
├── internal/audit           journal chaîné par hash, checkpoints, export
├── internal/digest          calcul « depuis hier », rendu page / email / toast
├── internal/store           SQLite, migrations embarquées
├── internal/api             HTTP JSON, auth locale (token), sert la PWA
├── internal/mcp             serveur MCP stdio (lecture + report_fix_result)
└── web/                     PWA Vue 3 + Vuetify 4 (Options API), build Vite embarqué
```

Le modèle IA n'a accès qu'à `internal/ai` ; il ne peut appeler ni `policy`, ni `egress`, ni `audit`, ni `remediate` : les outils exposés au modèle sont une liste fermée de fonctions pures (lecture d'extraits, lecture de changelog) dont les arguments sont validés.

### 4.3 Modèle de données (entités principales)

- **Project** : id, nom, `source` (`local_path` | `git_remote`), chemin, manifestes détectés, `classification` (publique … santé), `fix_level` (0-3, défaut 1), commande de tests déclarée, commande d'installation (`composer install` / `npm ci`), **préparation du worktree** (liste explicite de fichiers gitignorés à copier, ex. `tests/php/phpunit.phar`, `.env.test`, et commande `prepare` optionnelle ; déclarées par l'utilisateur, exécutées uniquement dans le worktree, chemins exclus des briefs, logs et prompts), exclusions, actif.
- **Scan** : id, project, horodatage UTC, version base OSV + fraîcheur, version osv-scalibr, empreinte des lockfiles, statut, durée.
- **Finding** : id stable = hash(project, **chemin du manifeste**, écosystème, paquet, id OSV) : un projet multi-lockfiles (the reference project : `app`, `api/service-a`, `symfony`) donne une faille par lockfile, chacune avec sa version installée et sa commande de correction ; le digest regroupe par paquet pour l'affichage. Scan de première et dernière détection, sévérité (CVSS + KEV si dispo), version installée, versions corrigées, chemin de dépendance (directe / transitive, via qui), `semver_jump` (patch | minor | major | none), statut dérivé (nouvelle | en attente | décidée | corrigée | disparue).
- **Analysis** (par finding, déterministe) : points d'appel `fichier:ligne` (namespace PHP / import JS), tests couvrant ces fichiers, extrait de changelog entre version installée et corrigée, breaking changes détectés (mots-clés + sections `BREAKING`), `risk_score` (§ 4.5), recommandation (`auto_fix` | `handoff` | `report_only`).
- **Decision** : finding, action (`fix` | `defer` | `ignore`), justification, échéance (defer), auteur, horodatage ; une faille garde la dernière décision.
- **FixAttempt** : finding(s), origine (`michel` | `user_manual` | `external_ai`), niveau exécuté, worktree, commande(s) exécutées, diff (empreinte + contenu), tests (statut `passed` | `failed` | `not_run`, sortie), re-scan, verdict (`proven_fixed` | `failed` | `inconclusive`), approbation.
- **Statuts d'une faille, sans ambiguïté** (arbitrage post-relecture) :
  - `new` → `pending` (en attente de décision) → `decided` (fix / defer / ignore) ;
  - `gone` : absente au re-scan quotidien, **sans preuve** (bump manuel, paquet retiré, base OSV changée). Le digest la liste sous « disparues au re-scan », jamais sous « corrigées » ;
  - `reported_fixed` : une IA externe ou l'utilisateur a déclaré la correction via `report_fix_result` / `michel report` ; tests déclarés, pas observés ;
  - `proven_fixed` : Michel a lui-même observé re-scan sans la faille **et** tests `passed` (niveau ≥ 2, ou `michel verify <id>` lancé après un bump manuel ou externe). Seul statut affiché « corrigée ».
- **Brief** : finding(s), format (`md` | `skill` | `mcp`), contenu, empreinte, version du template, date, `consumed_by` + résultat renvoyé via `report_fix_result`.
- **AIExecution**, **PromptTemplate**, **ModelRecord**, **AuditEvent** : exactement les champs de la politique § 5.2, 6.2, 6.3, 7.
- **DigestRun** : date, projets, compteurs (nouvelles, corrigées, disparues, échéances), canaux envoyés, résultat.

Toutes les tables portent `project_id` ; les données de deux projets ne se mélangent jamais dans une requête de lecture utilisateur.

### 4.4 Le cœur n'a pas besoin d'IA

Enrichissement déterministe, en Go, pour chaque faille :

1. **Chemin de dépendance** : résolution depuis le lockfile (`composer.lock` → `require` récursif ; `package-lock.json` v3 → `packages`). Direct ou transitif, et via quel paquet direct.
2. **Saut sémantique** : comparaison SemVer entre installée et plus petite corrigée compatible ; contrainte du manifeste (`^`, `~`) respectée pour dire si un simple `update` suffit ou s'il faut changer la contrainte.
3. **Points d'appel** : pour Composer, namespaces PSR-4 du paquet → grep des `use` et appels statiques dans le code de l'utilisateur (hors `vendor/`) ; pour npm, imports / `require` du nom de paquet. Résultat : liste `fichier:ligne`, plafonnée et dénombrée.
4. **Tests couvrant** : fichiers de tests référençant les mêmes classes / modules (heuristique par nom et par import), plus la commande de tests déclarée par le projet.
5. **Changelog** : si le paquet est présent dans `vendor/` ou `node_modules/`, lecture de `CHANGELOG*.md` / notes locales ; sinon, sans réseau, « indisponible hors ligne ». Avec réseau autorisé : dépôt source déclaré dans le manifeste du paquet, destination à autoriser explicitement.
6. **Score de risque** (0-100, règle publique dans `docs/remediation-risk.md`) : saut majeur +40, breaking changes détectés +25, dépendance directe +10, plus de N points d'appel +15, aucun test couvrant +20, paquet dans la liste « cœur » du projet +20. Seuils : < 30 `auto_fix` possible (si niveau ≥ 2), 30-60 `handoff`, > 60 `handoff` avec avertissement. **Seuils modifiables par projet, jamais par le modèle.**

### 4.5 Remédiation et preuve

- **Niveau 1** : commande exacte affichée (`composer update vendor/paquet:^x.y --with-all-dependencies`, `npm install paquet@x.y.z --save-exact`) et diff prévisionnel du lockfile obtenu par `--dry-run`. L'utilisateur lance.
- **Niveau 2** : `git worktree add` dans `<data_dir>/worktrees/<project>/<attempt>`, préparation déclarée (copies de fichiers gitignorés, `prepare`), installation, bump, commande de tests du projet, re-scan du worktree, diff. Si la préparation ou l'installation échoue : tests `not_run`, verdict `inconclusive`, cause affichée. Commandes exécutées via une liste fermée (`composer`, `npm`, `git`, commande de tests déclarée), jamais une chaîne libre. Résultat présenté ; l'utilisateur merge lui-même (ou `michel fix apply` crée une branche dans le dépôt réel, sans merge).
- **Niveau 3** : niveau 2 + si les tests échouent, qualification IA (quel test, quel breaking change probable) et proposition de correctif de code dans le worktree, re-test. Approbation humaine toujours avant toute branche dans le dépôt réel.
- **Preuve** : `proven_fixed` exige re-scan sans la faille **et** tests `passed`. Tests non lancés = `not_run`, jamais `passed`. Worktrees supprimés après verdict ou sur `michel fix clean`.
- Pas de scripts post-install exécutés sans consentement : `composer install --no-scripts` / `npm ci --ignore-scripts` par défaut dans le worktree, option par projet.

### 4.6 Dossier de correction (brief) — produit de première classe

Déclenché quand `risk_score` ≥ seuil, ou à la demande (`michel brief <finding>` ou bouton). Même contenu, trois sorties :

1. **Markdown** : `<project>/.michel/briefs/<finding-id>.md` (ou dossier configuré ; gitignoré par défaut, choix par projet).
2. **Skill Claude Code** : `<project>/.claude/skills/michel-fix-<finding-id>/SKILL.md` avec frontmatter `name` / `description`, corps = brief, instructions de clôture (`michel report <id> --result ...` ou outil MCP).
3. **MCP** : `michel mcp` (stdio) expose `list_findings(project, status)`, `get_finding(id)`, `get_brief(id)`, `get_call_sites(id)`, `get_changelog_excerpt(id)`, `report_fix_result(id, outcome, diff_sha, tests_status, notes)`. Lecture seule sauf `report_fix_result`, qui crée un `FixAttempt` d'origine `external_ai` et un événement d'audit.

**Format caveman obligatoire** : champs structurés (YAML frontmatter), lignes courtes, pas d'articles ni de prose, aucune répétition entre sections, citations `fichier:ligne`, extraits de code bornés (N lignes autour du point d'appel, N configurable, défaut 6), changelog réduit aux entrées entre les deux versions. Exemple de squelette :

```markdown
---
michel_brief: 1
finding: demo-composer-guzzlehttp/guzzle-GHSA-xxxx
severity: high  cvss: 7.5  kev: no
package: guzzlehttp/guzzle  installed: 7.4.0  fixed: 7.4.5  jump: patch
path: direct
risk: 34  reason: 12 call sites, 0 covering tests
---
## Fix
composer update guzzlehttp/guzzle:^7.4.5 --with-all-dependencies
## Breaking
none in CHANGELOG 7.4.0..7.4.5
## Call sites (12, top 5)
src/Http/Client.php:41  new Client([...])
...
## Tests
none cover. Run: vendor/bin/phpunit
## Done when
re-scan clean + tests pass → `michel report <id> --result fixed --tests passed`
```

Le brief ne contient **jamais** de secret ni de fichier de configuration sensible ; les exclusions du projet s'appliquent.

### 4.7 IA adaptée à la machine, opt-in externe

- Au premier lancement : sondage RAM libre, VRAM, CPU, puis **proposition** d'un palier (aucun téléchargement silencieux) :
  - < 8 Go : pas de modèle, cœur seul, affiché clairement.
  - 8-16 Go : dense 3-4B (Qwen3 4B / Qwen2.5-Coder 3B) : résumés CVE, explications.
  - 16-32 Go : MoE léger (gpt-oss 20B, Qwen3-Coder 30B-A3B en quantification serrée).
  - ≥ 32 Go : Qwen3-Coder 30B-A3B Q4 : qualification d'impact, proposition de correctif (niveau 3).
- Inférence en tâche de fond à basse priorité, threads plafonnés (config), jamais pendant une interaction utilisateur.
- Registre de modèles : fiche complète (politique § 5.2), empreinte vérifiée au chargement ; modèle inconnu refusé en `strict_local`.
- Fournisseurs externes : absents du choix en `strict_local` ; sinon opt-in par projet, interdits si classification `sensible` ou `santé` ; écran « voici exactement ce qui part » avant le premier appel, avec option « paquets et CVE seulement, pas de code » ; clés chiffrées (DPAPI Windows, keyring Linux/macOS).
- Ce que l'IA fait en v1 : résumer une CVE pour un non-spécialiste, estimer l'impact réel à partir des points d'appel, lister les effets de bord probables d'un bump, (niveau 3) proposer un correctif. Chaque sortie est marquée « hypothèse IA » et jamais utilisée pour changer un statut.

### 4.8 Digest quotidien

- Déclencheur : fin du `scan --all` planifié (heure configurable, défaut 06:30 local).
- Contenu : par projet, **nouvelles** failles, failles **corrigées prouvées** (`proven_fixed`), **disparues au re-scan** (`gone`, sans preuve), **déclarées corrigées** à vérifier (`reported_fixed`), **échéances** de report, compteurs par sévérité, fraîcheur de la base OSV.
- **Canaux au choix de l'utilisateur** (décision Kévin), derrière une interface unique `Notifier` (`send(digest) error`, `test() error`) ; l'utilisateur active ceux qu'il veut, plusieurs à la fois, par projet ou globalement :
  - **v1** : toast Windows (`michel` lancé en service utilisateur), email SMTP, **webhook générique** JSON signé (couvre Slack « incoming webhook », Discord, Mattermost, n8n, Home Assistant), page PWA « Aujourd'hui ».
  - **v1.1** : web push PWA (VAPID, clés générées localement), **Telegram** (token de bot), **Slack** par clé API bot (`chat.postMessage`, pour les canaux privés et les réponses enrichies).
  - **plus tard** : SMS via partenaire connecté (Twilio, OVH, Brevo…) quand un compte est configuré ; jamais par défaut.
  - Chaque canal = une destination à ajouter explicitement dans l'allowlist egress, un test « envoyer un message d'essai », un secret stocké chiffré (DPAPI / keyring), et un contenu **sans code ni secret** : projet, compteurs, paquets, versions, identifiants OSV, lien vers la PWA. Un envoi = un événement d'audit.
- Règle anti-bruit : une faille décidée ne figure dans le digest que si sévérité, version corrigée, KEV ou échéance change.

### 4.9 Souveraineté : ce qui est implémenté en v1 (et non seulement déclaré)

- `strict_local` par défaut ; schéma YAML validé au démarrage, refus de démarrer si invalide.
- `internal/egress` : **tout** trafic sortant passe par un client unique ; destinations hors allowlist refusées et journalisées ; test automatisé qui lance un scan complet derrière un proxy témoin et vérifie zéro connexion. Allowlist v1 : SMTP et canaux de notification configurés, miroirs OSV, registres de paquets (voir ci-dessous), fournisseurs IA activés, Ollama sur `127.0.0.1`.
- **Sous-processus (`composer`, `npm`, `git`)** : ils ne contournent pas la passerelle. Michel lance un **proxy HTTP local** (port éphémère sur `127.0.0.1`) et exécute chaque sous-processus avec `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` et les variables d'écosystème (`COMPOSER_HOME` dédié avec `config.json` pointant le proxy, `npm_config_proxy`, `GIT_CONFIG_*`). Le proxy applique la même allowlist et le même journal. Registres (`packagist.org`, `repo.packagist.org`, `registry.npmjs.org`, dépôts VCS déclarés) autorisés **seulement** si le projet est au niveau ≥ 1 ; ordre d'essai : cache local (`--prefer-offline` / `COMPOSER_CACHE_DIR`), puis registre via proxy si autorisé, sinon échec explicite « registre non autorisé ». Test automatisé : un `composer update --dry-run` avec registre hors allowlist échoue et produit un événement d'audit.
- **Bases OSV** : `db.auto_update: true | false`, défaut `true` hors `strict_local`, `false` en `strict_local` avec opt-in possible (destination listée, journalisée, lancée par la tâche planifiée avant le scan). Fraîcheur de la base affichée dans chaque digest et sur la page Souveraineté ; au-delà de N jours (défaut 7), bandeau « données périmées ».
- Journal d'audit chaîné (SHA-256 de l'événement précédent), checkpoint signé quotidien (clé Ed25519 générée à l'installation, stockée chiffrée), `michel audit verify`.
- Prompts versionnés dans `internal/ai/prompts/<id>/<version>.md`, empreinte du prompt assemblé enregistrée ; politique « standard » par défaut, « audit renforcé » chiffrée (AES-256-GCM, clé dérivée d'un secret local).
- Masquage des secrets (détecteurs : clés AWS, tokens GitHub, clés privées PEM, `.env`) avant tout archivage, log, brief.
- Page **Paramètres → Souveraineté et IA** (politique § 11).
- Aucune revendication HDS : `docs/security/hds-readiness.md` liste ce qui est fourni et ce qui reste à faire.

### 4.10 Ordre de réalisation (celui de la politique § 16, adapté)

1. Squelette Go + politique YAML + refus par défaut + egress + audit minimal (fondations, testées).
2. Scan osv-scalibr hors ligne, store, CLI `scan`, premier résultat sur the reference project.
3. Analyse déterministe (chemin, saut, points d'appel, tests, changelog, score).
4. Décisions + digest + email + toast ; PWA « Aujourd'hui » et fiche faille.
5. Brief md / skill / MCP (format caveman).
6. Remédiation niveaux 1-2, worktree, preuve.
7. Passerelle IA, registre, Ollama, paliers matériel, page Souveraineté ; niveau 3.
8. Fournisseurs externes opt-in.
9. Suite de tests de la politique § 13, docs § 14, export CycloneDX/VEX.

Chaque étape livre quelque chose d'utilisable seul. Après chaque étape : tests exécutés, résultats réels notés dans le ledger.

## 5. Laissé au builder

- Découpage exact des paquets Go, nommage des tables, format des identifiants (préférence : ULID).
- Choix de la bibliothèque SemVer, du parseur Markdown de changelog, du détecteur de secrets (gitleaks en bibliothèque acceptable, licence MIT).
- Détail des heuristiques de points d'appel et de tests couvrants, tant que le résultat est dénombré et borné.
- Structure Vite / Vuetify 4 de la PWA, thème, mode sombre (souhaité, non bloquant).
- Mécanique précise du toast Windows et du service utilisateur.
- Schéma JSON des exports et du MCP, tant qu'ils sont documentés et versionnés.
- Langue : code, identifiants, commits et documentation publique en **anglais** (projet open source) ; le design et le ledger de suivi restent en français (mon choix, à confirmer).

## 6. Arbitrages pris après relecture builder (2026-10-22)

Mes choix, à contester si besoin :

1. Sous-processus derrière un proxy local soumis à l'allowlist (§ 4.9).
2. `gone` ≠ `proven_fixed` ; déclaration externe = `reported_fixed` jusqu'à `michel verify` (§ 4.3).
3. Remédiation npm maison, pas de code vendorisé d'osv-scanner (§ 4.1).
4. Un Finding par lockfile (§ 4.3).
5. Windows + Linux bloquants en v1, macOS meilleur effort (§ 3).
6. Préparation du worktree déclarée par projet (§ 4.3, § 4.5).
7. Mise à jour OSV en opt-in, autorisée en `strict_local` (§ 4.9).

## 7. Hors design, à faire après validation

- `git init`, licence Apache-2.0, création du dépôt `kvarot/michel` (outil `gh` à installer ou dépôt créé par Kévin).
- Plan d'implémentation (`superpowers:writing-plans`).
- Installation locale de Go 1.27.3 et Ollama 0.40.8 pour le développement.
