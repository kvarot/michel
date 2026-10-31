# Michel — Design du plan 5 : corriger avec un agent (côté code)

Date : 2026-10-30. Auteur : Claude, avec Kévin (brainstorming du 2026-10-30). Remplace, pour le périmètre « briefs et remédiation du code », les § 4.5 et § 4.6 du design v1 (`2026-10-22-michel-design.md`), et modifie § 4.12 par une décision de Kévin (voir § 3).

## 1. Intention

Michel trouve les failles ; il s'arrête là. Pour Php2shell, Kévin a dû lire des articles pour comprendre qu'il y avait une faille, en chercher d'autres pour savoir comment la corriger, les donner à Claude, puis corriger lui-même sur le serveur. Trois temps faits à la main : **trouver** (est-ce que ça me touche, où), **comprendre** (en clair, pourquoi chez moi), **corriger** (quoi changer, puis vérifier).

Le plan 5 fait faire ce travail par un agent (Claude Code), piloté par Michel, avec la validation de l'utilisateur. L'outil doit ressembler à Claude Desktop : **simple mais efficace**, une conversation, une proposition, un bouton.

## 2. Périmètre

### Plan 5 (ce document) : le code
- Le brief en trois temps (trouver, comprendre, corriger), au format caveman, dans le dossier de données de Michel.
- `michel mcp` (stdio) et un skill Claude Code, pour que l'agent ait ce que Michel sait.
- Michel lance Claude Code lui-même, en arrière-plan, sur une **copie** du projet dans son dossier de données ; l'agent prépare la correction (modification, tests, re-scan).
- Page « Corriger » dans l'esprit de Claude Desktop : bouton « OK, répare » ou conversation, proposition en clair, bouton Valider.
- Après validation, Michel crée une branche dans le dépôt de l'utilisateur ; l'utilisateur déploie comme d'habitude (PhpStorm). La preuve : re-scan sans la faille et tests passés.
- Masquage réversible des secrets dans tout ce que l'agent voit et dit (idée reprise d'aaron.ai, `packages/core/src/ai/mask.ts`).
- Niveaux d'autonomie réglables par projet pour le code ; champ réservé pour le serveur.

### Plan 6 (après) : le serveur
Cibles (`Target`), lecture du serveur en SSH en lecture seule (v1 § 4.12), puis commandes de correction proposées par l'agent et **exécutées par Michel** après validation, avec un niveau réglable par cible. Le plan 6 réutilise la proposition, la validation et la page de ce plan. Ce document ne fixe du plan 6 que ce qu'il faut réserver (§ 9.4).

### Non-objectifs du plan 5
- Rien sur les serveurs (plan 6), rien sur leurs journaux (plan 7).
- Pas de déploiement par Michel : la branche est poussée dans le dépôt local, l'utilisateur déploie.
- Pas de merge automatique, jamais.
- Pas d'IA locale (Ollama, paliers, v1 § 4.7) : l'agent du plan 5 est Claude Code ; une IA locale pourra s'y brancher plus tard derrière la même interface.
- Pas d'autre agent que Claude Code dans ce plan (interface prévue pour en ajouter).

### Anti-objectifs (raté même si « ça marche »)
- **L'utilisateur doit taper une commande** pour corriger une faille (décision Kévin). La ligne de commande existe, mais tout se fait depuis la page.
- Quelque chose arrive dans le dépôt de l'utilisateur sans son clic Valider (ou sans une règle qu'il a posée d'avance, niveau 3).
- Ce qui est validé n'est pas exactement ce qui est appliqué.
- Du code ou un secret part chez un fournisseur d'IA sans accord explicite, ou un secret part tout court.
- L'agent peut se valider lui-même, élargir ses droits, ou écrire hors de sa copie.
- Une page de validation qu'on ne comprend pas sans être développeur.

## 3. Décisions de Kévin (2026-10-30)

1. **Automatiser avec des agents, avec validation** ; le niveau d'autonomie est **au choix de l'utilisateur**.
2. **Deux réglages séparés : code et serveur**, réglables par projet (et par environnement dev/prod au plan 6). Remplace la règle v1 § 4.12 « niveau plafonné à 1 sur une cible, jamais d'application par l'agent » : sur le serveur aussi, c'est le choix de l'utilisateur ; défaut « préparé, validé avant d'agir ».
3. **Aucune commande à connaître** : tout se fait depuis la page ; la validation se lit en clair, le détail technique est à un clic.
4. **« OK, répare » ou discussion** comme dans Claude Desktop.
5. Kévin déploie le code par **PhpStorm (deployment)** et agit sur les serveurs en **SSH depuis son poste** : Michel ne court-circuite pas le déploiement du code.
6. « On suit tes recommandations, quelque chose de simple pour l'utilisateur » : les choix techniques ci-dessous sont les miens (Claude), à contester au § 12.
7. Emplacement des briefs (choix laissé ouvert au plan 3) : **dossier de données de Michel**, jamais dans le projet scanné ; skill dans `~/.claude/skills/michel-fix-<id>/`.

## 4. Niveaux d'autonomie (code)

On garde le champ `project.fix_level` (0-3, défaut 1, déjà en base et dans l'API) avec ce sens :

| niveau | nom affiché | ce que fait Michel |
|---|---|---|
| 0 | Signaler | digest et page seulement |
| 1 | Expliquer | brief en trois temps ; bouton « Préparer la correction » (lance l'agent à la demande) |
| 2 | Préparer | l'agent prépare **de lui-même** une correction pour chaque faille éligible ; elle attend ta validation |
| 3 | Appliquer ce que j'ai autorisé | comme 2, et Michel applique sans clic les corrections qui respectent les règles posées d'avance (§ 4.1) ; les autres attendent ta validation |

- **Faille éligible au niveau 2 (mon choix)** : ouverte (`pending` ou décidée « corriger »), jamais reportée ni ignorée, avec une version corrigée connue, sans tentative en cours ni proposition refusée pour la même version corrigée ; KEV d'abord, puis par gravité effective. **Déclenchement** : `scan --all` met les failles éligibles en file dans le store ; `michel serve` (le processus qui reste lancé, service utilisateur) les prend dans l'ordre. Si `serve` ne tourne pas, rien ne se lance et le digest le dit (« 2 corrections attendent que Michel soit lancé »).
- Le niveau 1 suffit pour corriger depuis la page : « Préparer la correction » est un clic, pas un réglage. Les niveaux 2 et 3 ajoutent seulement l'initiative.
- Niveaux 2 et 3 exigent l'accord IA du projet (§ 7.3) ; sans lui, Michel reste au comportement du niveau 1 et le dit.
- Champ nouveau `project.server_fix_level` (0-3, défaut 1) : stocké et affiché dès ce plan (« utilisé au plan 6 »), sans effet.

### 4.1 Règles d'application automatique (niveau 3)
Une correction est appliquée sans clic seulement si **toutes** ces conditions tiennent, vérifiées par Michel (jamais par l'agent) :
- elle ne change que `composer.lock`/`composer.json` ou `package-lock.json`/`package.json` (ou yarn/pnpm) — aucun fichier de code ;
- saut patch ou mineur (pas majeur) ;
- `risk_score` < seuil du projet (défaut 30, v1 § 4.4) ;
- re-scan de la copie sans la faille **et** tests `passed` (pas `not_run`) ;
- l'utilisateur a coché la règle pour ce projet (case « appliquer seul les mises à jour mineures sûres »).
« Appliquer » = créer la branche (§ 8.3), jamais merger ni déployer. Le digest et la notification disent ce qui a été appliqué.

## 5. Le brief

### 5.1 Contenu, en trois temps
Assemblé **sans IA** depuis ce que Michel sait déjà : finding, enrichissements KEV/EPSS/CVE (plan 4), analyse (chemin de dépendance, saut, sites d'appel, tests couvrants, changelog, risque — plan 2), explication en langage courant (gabarits `internal/explain`), références de l'avis (OSV `references`), articles « À lire » liés à la technologie (plan 4, `feed`).
- **Trouver** : paquet, version installée, corrigée, lockfile(s) relatifs, chemin direct/transitif, sites d'appel `fichier:ligne`, KEV/EPSS.
- **Comprendre** : les trois phrases de `explain` (c'est quoi, ce qui pourrait arriver, ce que ça coûte), liens de l'avis et des articles.
- **Corriger** : commande(s) de mise à jour proposée(s) (niveau 1 du v1 § 4.5), changements cassants du changelog, tests à lancer, « fini quand ».

### 5.2 Formats
- **Markdown caveman** (v1 § 4.6, squelette conservé, sections `## Trouver / ## Comprendre / ## Corriger / ## Fini quand`), dans `<data>/briefs/<project-id>/<finding-id>.md`. Les sections EN (`Fix`, `Breaking`…) du v1 deviennent les trois temps ; la langue du brief suit `--lang`/la politique.
- **Skill Claude Code** : `~/.claude/skills/michel-fix-<id-court>/SKILL.md` (frontmatter `name`, `description`, corps = brief + consignes de clôture via MCP), avec le marqueur `.michel-source` du plan 4 (un dossier que Michel n'a pas créé n'est jamais touché). Écrit à la demande (« Ouvrir dans Claude Code ») et supprimé quand la faille est close.
- **MCP** : `get_brief(id)` (§ 6).
- `michel brief <finding>` (CLI, optionnelle) imprime le brief ; `--write-skill` écrit le skill.

### 5.3 Ce que le brief ne contient jamais
Secret, contenu de fichier de configuration sensible, chemin absolu (chemins relatifs au projet), nom d'un autre projet. Les extraits de code sont bornés (6 lignes autour d'un site d'appel, v1) et masqués (§ 7.2).

## 6. `michel mcp` (stdio)

Serveur MCP lancé par Claude Code, jamais à l'écoute réseau. Outils :
- lecture : `list_findings(project, status)`, `get_finding(id)`, `get_brief(id)`, `get_call_sites(id)`, `get_changelog_excerpt(id)`, `get_attempt()` (la tentative en cours : faille, copie, règles) ;
- action : `propose_fix(summary, details)` — enregistre la proposition de la tentative en cours (§ 8.1). C'est le seul outil qui écrit, et il n'écrit que dans le store de Michel.
- Pas d'outil d'approbation, de branche, de réglage ou de politique : l'agent ne peut ni valider, ni appliquer, ni élargir ses droits.
- Quand Michel lance l'agent, la session MCP est liée à **une tentative** par un jeton à usage limité passé en variable d'environnement ; `propose_fix` refuse sans jeton valide. Lancé à la main par l'utilisateur (skill), le serveur est en lecture seule.
- Tout résultat MCP est masqué (§ 7.2) et sans chemin absolu.

## 7. L'agent : Claude Code piloté par Michel

### 7.1 Lancement
- Détection : `claude` sur le PATH (ou chemin configuré), version, connexion. Absent ou non connecté : la page dit simplement « Claude Code n'est pas installé / pas connecté » avec le lien d'installation, et propose le brief à lire.
- Michel lance `claude` en mode non interactif à flux JSON (entrée et sortie `stream-json`, reprise de session par identifiant pour la conversation), argv fermé construit par Michel, `cwd` = la copie (§ 8.2), environnement en liste blanche (comme les plugins du plan 4, jamais `os.Environ()` entier), configuration MCP générée qui ne déclare que `michel mcp`.
- Droits de l'agent (permissions Claude Code passées par Michel) : lire et modifier des fichiers **dans la copie seulement** ; commandes limitées à la liste fermée du v1 § 4.5 (`composer`, `npm`/`yarn`/`pnpm` avec `--no-scripts`/`--ignore-scripts`, `git` en lecture/commit dans la copie, commande de tests déclarée du projet) ; outils web désactivés (les articles utiles sont dans le brief). Rien d'autre.
- **Réglages Claude Code isolés (mon choix)** : Michel lance l'agent avec la connexion existante de l'utilisateur (abonnement ou clé déjà configurée dans Claude Code, que Michel ne lit ni ne transmet), mais **sans** ses réglages, hooks, plugins, autres serveurs MCP ni mémoire : aucune source de réglages utilisateur ou projet chargée (la copie peut contenir un `.claude/` non fiable), réglages et MCP fournis par Michel seulement, MCP strict. Le builder vérifie les options exactes de la version de Claude Code ciblée ; si une isolation n'est pas possible sans nouvelle connexion, il s'arrête et le signale.
- Plafonds : durée par tentative (défaut 20 min), nombre de tours, taille de la sortie conservée ; une tentative à la fois par projet ; au niveau 2, au plus 3 tentatives lancées d'elles-mêmes par jour et par projet (réglable).
- Une tentative sans proposition à la fin (abandon, plafond, erreur) est `failed` avec la cause en clair.

### 7.2 Masquage réversible
- Avant qu'un contenu n'atteigne l'agent (brief, extraits MCP) et dans ce que l'agent renvoie à la page : détecteurs de secrets (v1 § 4.9 : clés AWS, jetons GitHub, clés PEM, valeurs de `.env`, affectations à forte entropie nommées `password|secret|token|key`), chemins absolus du poste → chemins relatifs.
- Une valeur devient un jeton stable `[secret-n]` ; la table jeton → valeur reste dans le store de Michel, chiffrée, jamais envoyée. Démasquage seulement au moment d'appliquer (§ 8.3), et en flux pour la conversation (un jeton coupé entre deux morceaux est recollé avant affichage — test dédié).
- **Limite assumée (mon choix : on ne masque pas les fichiers de la copie)** : la copie de travail contient le vrai code ; Claude Code peut lire les fichiers du projet copiés. Les fichiers exclus (`.env*`, clés, fichiers listés par le projet, gitignorés hors lockfiles) ne sont **pas copiés** ; le masquage protège ce que Michel donne lui-même (brief, MCP) et ce qui s'affiche. Avant le premier lancement sur un projet, Michel passe ses détecteurs sur les fichiers suivis de la copie : s'il trouve un secret écrit en dur, l'écran d'accord le dit (« 2 secrets semblent écrits dans ton code : ils seraient lus par l'agent ») avec les fichiers relatifs, et propose de les exclure. Le démasquage du § 8.3 ne sert donc qu'à un jeton que l'agent aurait recopié depuis le brief.
- Audit : nombre et type de valeurs masquées par tentative, jamais les valeurs.

### 7.3 Accord IA par projet
Claude Code envoie à Anthropic ce qu'il lit. C'est un fournisseur externe au sens de la politique (§ 5.1, `ai.external_providers_enabled`).
- Accord **par projet**, écran « voici exactement ce qui part » (le code de la copie que l'agent lit, le brief masqué, tes messages ; pas les fichiers exclus, pas les secrets masqués), comme l'accord des sources du plan 4 : écrit `ai.external_providers_enabled: true` si besoin et la règle réseau, journalisé `ai.consent`.
- `strict_local` : refusé tant que l'utilisateur n'a pas activé les fournisseurs externes (la page explique et propose de le faire).
- Classification `health` : refusé, sans exception. Classification `sensitive` (le défaut des projets) : **autorisé avec l'accord explicite du projet** (décision Kévin, 2026-10-30), masquage actif et fichiers exclus non copiés ; l'écran d'accord dit que le projet est classé sensible.
- **Paquets (mon choix)** : préparer la copie télécharge des paquets (Packagist, archives GitHub, registre npm). Nouveau purpose `fix.install`, derrière le proxy de sous-processus du v1 § 4.9, hôtes des registres. Un seul écran d'accord par projet couvre les deux sorties (Anthropic et registres de paquets), pour rester simple ; une correction sans agent (`origin manual`, Michel fait seul la mise à jour) n'a besoin que de l'accord des registres. En `strict_local`, comme les bases OSV : opt-in explicite, jamais par défaut.
- Réseau : Claude Code est lancé avec `HTTPS_PROXY`/`HTTP_PROXY` vers un **proxy local d'autorisation** de Michel (même passerelle `internal/egress`, purpose `agent.claude`, allowlist réduite aux hôtes d'Anthropic nécessaires), chaque tentative journalisée. Comme pour les plugins : un outil qui ignore les variables de proxy n'est pas arrêté ; c'est déclaré, pas garanti (docs network-egress).

## 8. Proposition, validation, application

### 8.1 Tentative et proposition
- Entité `fix_attempt` (déjà prévue au v1 § 4.3) : `id`, `finding_id`, `project_id`, `origin` (`agent.claude`, `manual`), `state`, `clone_dir` (jamais exposé), `session_id` agent, horodatages, `cause`.
- États : `preparing` → `proposed` → `approved` | `refused` → `applied` → `proven_fixed` | `inconclusive` ; `failed` depuis `preparing` ; `superseded` quand une nouvelle proposition remplace la précédente.
- Une **proposition** est immuable : résumé en clair (une à trois phrases, langue de l'utilisateur), diff (calculé **par Michel** depuis la copie, pas recopié de l'agent), fichiers touchés, tests lancés et résultat (lancés **par Michel** dans la copie, v1 § 4.5), re-scan de la copie, risque, empreinte SHA-256 de l'ensemble. `steps_server` réservé, vide (plan 6).
- Toute modification après proposition (l'agent continue dans la conversation) crée une nouvelle proposition ; l'ancienne passe `superseded`.

### 8.2 La copie de travail
- **Projet hors git** (décision Kévin) : refusé avec un message clair (« ce projet n'est pas dans git : Michel ne peut pas préparer de correction ; voici le brief à lire ») ; le brief reste disponible.
- `git clone --local --no-checkout` puis checkout dans `<data>/worktrees/<project-id>/<attempt-id>` (lecture seule sur le dépôt de l'utilisateur ; pas de `git worktree add`, qui écrirait dans son `.git`), plus les fichiers non suivis nécessaires déclarés par le projet (v1 § 4.5), moins les exclusions (§ 7.2).
- Installation sans scripts, tests du projet, re-scan : par Michel, liste fermée, sous-processus derrière la passerelle (v1 § 4.9).
- Supprimée après `applied`+preuve, `refused`, `failed`, ou par `michel fix clean`. `treeDigest` du projet de l'utilisateur inchangé pendant toute la préparation (test).

### 8.3 Validation et application
- Valider = un clic sur la page (ou `michel fix approve <id>`), via l'API locale à jeton. L'approbation porte l'empreinte de la proposition ; Michel refuse d'appliquer si l'empreinte ne correspond plus.
- Appliquer = depuis le dépôt de l'utilisateur, `git fetch` de la copie vers une branche `michel/fix-<id-court>` ; **aucun checkout, aucun merge, copie de travail de l'utilisateur intacte** (seule écriture : objets et ref dans son `.git`, autorisée par la validation ; ajoutée à la liste des écritures permises). Démasquage appliqué au commit de la copie avant le fetch (aucun jeton `[secret-n]` ne peut atterrir dans une branche : vérification bloquante).
- Message de fin : « La branche michel/fix-… est prête. Fusionne-la puis déploie avec PhpStorm comme d'habitude. »
- Preuve (mon choix) : tests `passed` et re-scan propre **dans la copie** sont exigés pour proposer au niveau 3 et affichés pour les autres. `proven_fixed` est donné quand un scan du projet de l'utilisateur ne voit plus la faille **et** que le commit de la branche est contenu dans la branche courante du dépôt (Michel le vérifie en lecture, `git merge-base --is-ancestor`) ; la faille disparue sans ce commit est `gone` comme aujourd'hui. Michel ne relance pas les tests après la fusion. Un scan local voit la fusion, pas le déploiement : le digest dit « corrigée dans ton code » et rappelle de déployer, il ne prétend pas que le serveur est à jour (le plan 6 le vérifiera).
- Refuser = un clic, raison facultative ; la faille revient au circuit de décision du plan 3 (le refus n'est pas une décision « ignorer »).

## 9. La page « Corriger » (dans l'esprit de Claude Desktop)

### 9.1 Entrées
- Sur « Aujourd'hui » et la fiche faille : bouton **« Corriger »** sur chaque faille ouverte. Nouvelle rubrique « Corrections à valider » en tête d'« Aujourd'hui » quand il y en a.
- Notification (canaux du plan 3) : « Michel a préparé 1 correction, elle attend ta validation » + lien ; rien d'autre (minimisation).

### 9.2 Disposition
Une page, trois zones, rien de plus :
- **à gauche** : la liste « À corriger », « En cours », « À valider », « Fait » (une ligne par faille, voix de Michel) ;
- **au centre** : la conversation avec l'agent, comme Claude Desktop — messages de Michel (« Je regarde si ton projet est vraiment touché… »), réponses en flux, champ de saisie ; en tête, le gros bouton **« OK, répare »** pour qui ne veut pas discuter ;
- **à droite** : la faille en clair (les trois phrases), puis la proposition en clair (« Je passe guzzlehttp/guzzle de 7.4.0 à 7.4.5 ; 12 endroits l'utilisent, les tests passent ») avec **Valider** / **Refuser**, et « Voir le détail » (diff, tests, commandes, re-scan) replié.
- Pendant le travail de l'agent : ce qu'il fait en une ligne (« lance les tests »), jamais un terminal brut.
- États vides et erreurs en clair, avec quoi faire (Claude Code absent, accord IA manquant, tests impossibles…).

### 9.3 Réglages
Sur la fiche projet : « Corriger le code » (les quatre niveaux du § 4, en phrases), la case de la règle automatique, l'accord IA, et « Corriger le serveur » grisé « arrive bientôt ».

### 9.4 Réservé pour le plan 6
`server_fix_level`, `proposal.steps_server` (étapes lisibles + commandes exactes + vérification), la même validation par empreinte, la même page. Au plan 6, Michel exécute lui-même les commandes validées en SSH ; l'agent ne reçoit jamais d'accès au serveur.

## 10. API, CLI, migration

- API (`/api/v1`, jeton, mêmes règles de minimisation que le plan 4 : aucun chemin absolu, aucun secret) : `POST /findings/{id}/fix` (démarre une tentative), `GET /fix/{attempt}` , `GET /fix/{attempt}/events` (flux SSE de la conversation et de l'avancement), `POST /fix/{attempt}/message`, `POST /fix/{attempt}/approve` (empreinte requise), `POST /fix/{attempt}/refuse`, `GET /fixes?state=`, `PATCH /projects/{id}` (niveaux, règle auto), `POST /projects/{id}/ai-consent`, `GET /agent/status`.
- CLI (optionnelle, pour scripts) : `michel brief`, `michel fix prepare|approve|refuse|status|clean`, `michel mcp`. Aucune n'est nécessaire à l'utilisateur.
- Migration `0007_fix.sql` : `fix_attempt`, `fix_proposal`, `fix_message` (contenu masqué, rétention configurable, défaut 30 jours), `mask_entry` (chiffré), colonnes `project.server_fix_level`, `project.auto_fix_minor`. SQL portable PostgreSQL (règles des plans précédents).

## 11. Sécurité et souveraineté, ce qui est enforcé (tests nommés au plan)

- Le projet de l'utilisateur n'est jamais écrit pendant la préparation (`treeDigest`) ; seule l'application validée ajoute objets et ref dans son `.git`.
- L'agent ne peut pas valider (aucun outil MCP, approbation seulement par l'API à jeton), ne peut pas écrire hors de la copie (permissions + `cwd` + vérification du diff par Michel : un fichier hors de la copie ou un chemin `..` invalide la proposition).
- Ce qui est validé est ce qui est appliqué (empreinte).
- Aucun jeton de masquage dans une branche appliquée ; aucune valeur masquée dans le store en clair, l'audit, l'API ou un canal.
- Contenu du dépôt, des avis et des articles = données non fiables (politique § 9) : passés à l'agent comme données, jamais comme consignes de Michel ; l'agent n'a aucun droit qu'un texte puisse élargir.
- Réseau de l'agent par le proxy de Michel, journalisé (`agent.claude`), déclaré non garanti.
- Accord IA par projet ; `health` refusé ; `strict_local` refusé sans activation explicite.
- Audit : `fix.start`, `fix.propose`, `fix.approve`, `fix.refuse`, `fix.apply`, `fix.proven`, `ai.consent`, avec empreintes, jamais de contenu de conversation.

## 12. Arbitrages

Décisions de Kévin après relecture builder (2026-10-30) :
1. Projets `sensitive` : Claude Code autorisé avec l'accord explicite du projet (§ 7.3) ; `health` toujours refusé.
2. Après validation : branche `michel/fix-<id>` dans le dépôt, sans merge ; Kévin fusionne puis déploie avec PhpStorm (§ 8.3).
3. Projet hors git : refusé avec message, brief disponible (§ 8.2).

Mes choix (Claude), à contester à la lecture :
4. Niveau par défaut des nouveaux projets : 1 ; rien ne se lance seul sans qu'on l'ait choisi.
5. Claude Code lancé avec la connexion de l'utilisateur mais sans ses réglages, hooks, plugins ni MCP (§ 7.1).
6. Les fichiers de la copie ne sont pas masqués ; secrets écrits en dur signalés avant l'accord (§ 7.2).
7. Purpose `fix.install` pour les registres, un seul écran d'accord par projet (§ 7.3).
8. Niveau 2 : file d'attente remplie par `scan --all`, traitée par `michel serve`, 3 tentatives par jour et par projet (§ 4, § 7.1).
9. `proven_fixed` = faille absente au scan + commit de la branche dans la branche courante ; sinon `gone` (§ 8.3).
10. Rétention des conversations : 30 jours, contenu masqué.

## 13. Laissé au builder

Format exact du flux `stream-json` et reprise de session (suivre la doc Claude Code au moment du plan) ; liste exacte des hôtes Anthropic à autoriser ; détecteurs de secrets supplémentaires ; composants Vue de la conversation (Options API, JS + JSDoc, textes `web/src/i18n`) ; découpage en tâches. Tout texte FR passe par le relecteur non spécialiste.
