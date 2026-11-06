# Michel : feu par projet, « Ignorer » qui se revoit, export CycloneDX

Date : 2026-11-06. Idées reprises de Harbor (seuil de blocage par sévérité, liste d'exceptions qui expire, SBOM) et de Dependency-Track (CycloneDX avec VEX). Kévin : « suis les reco, il faut un logiciel couteau suisse, pro, propre, et intuitif. Pas une usine à gaz où il faut connaître toutes les commandes pour travailler ». Les choix ci-dessous sont tous ceux du constructeur, sauf cette phrase.

## Intention

Trois manques, un même but : que Michel serve aussi quand on ne le regarde pas.

1. **Savoir d'un coup d'œil si un projet peut partir** (feu vert, rouge, gris), et pouvoir refuser un `git push` quand il est rouge, sans connaître de commande.
2. **Qu'un « Ignorer » ne soit pas éternel par défaut.** Aujourd'hui seul « Reporter » a une échéance. Une faille ignorée il y a deux ans pour une raison oubliée reste cachée pour toujours.
3. **Montrer à quelqu'un d'autre ce qu'on embarque et ce qu'on en a décidé**, dans le format standard que lisent Dependency-Track, les clients et les auditeurs : CycloneDX 1.6 JSON avec la partie VEX.

Règle de forme pour tout le lot : chaque chose se fait depuis la page, avec un bon réglage par défaut et des mots simples. La commande CLI existe en miroir, jamais seule.

## Objectifs

### 1. Feu par projet

**Règle de calcul (Go, un seul endroit, partagée CLI et page comme au lot `cli-api-shared`).**

Un projet est :

- **rouge** s'il a au moins une faille ouverte qui passe le seuil du projet et qui n'a pas de décision « Reporter » ou « Ignorer » en vigueur. Une décision « Corriger » ne la fait pas passer : la faille est toujours là tant que la correction n'est pas prouvée.
- **gris** (« pas sûr ») si Michel ne peut pas répondre : jamais scanné, dernier scan en échec, ou dernier scan réussi vieux de plus de 7 jours. Le gris n'est jamais montré comme vert.
- **vert** sinon.

Ordre : rouge l'emporte sur gris, gris sur vert. Une faille lue qui bloque rend le projet rouge même si le scan est partiel.

Précisions (choix du constructeur après relecture) :

- Statuts de scan : `ok` peut donner vert ; `partial` (un fichier de verrou non lu) donne au mieux gris, « un fichier de dépendances n'a pas été lu » ; `failed` donne gris ; `empty` (aucun fichier de verrou) donne gris, « aucun fichier de dépendances trouvé ».
- Base des failles : si la base OSV utilisée par le dernier scan (`scan.osv_db_fetched_at`) a plus de 7 jours, gris, « base des failles vieille de N jours ».
- Gravité : on compare la gravité effective (`scan.EffectiveSeverity`, enrichissement compris), pas l'étiquette OSV brute. Une faille « urgente » au sens de `scan.Urgent` (KEV ou paquet malveillant `MAL-`) bloque dans les trois réglages. Une gravité inconnue ne bloque pas seule (sinon trop de bruit) ; elle reste visible sur la page Failles.
- Seules les failles de projet comptent (pas les failles de serveur).

Seuils, au choix par projet, trois réglages et rien d'autre (« exploitée » ci-dessous = urgente : KEV ou malveillant) :

| Réglage | Rouge si une faille ouverte non décidée est… |
|---|---|
| Souple | exploitée (KEV) |
| **Normal (défaut)** | critique, ou exploitée (KEV) |
| Strict | haute ou critique, ou exploitée (KEV) |

Le seuil vit sur la ligne du projet en base, à côté du niveau de correction (`FixLevel`), nouvelle colonne avec migration. Projet sans réglage = Normal. Changement écrit au journal d'audit.

**Page.**

- La carte projet (`ProjectCard`) montre le feu en tête : pastille + mot (« Prêt », « Bloquant », « Pas sûr »), jamais la couleur seule. Le mot porte la raison courte : « Bloquant : 2 failles critiques à décider », « Pas sûr : dernier contrôle il y a 9 jours ».
- Clic sur le feu rouge : ouvre la page Failles filtrée sur ce projet et sur les failles qui bloquent.
- Les réglages du projet ont une ligne « Quand bloquer ? » avec les trois choix et une phrase d'explication sous chacun.
- La Vue d'ensemble compte les projets par feu dans une tuile.

**Garde-fou avant envoi (`git push`).**

- Dans les réglages du projet, un bouton « Bloquer l'envoi quand le feu est rouge ». Il installe un hook `pre-push` dans le dépôt, après une fenêtre de consentement qui dit exactement quoi : un fichier `.git/hooks/pre-push`, non suivi par git, qui lance Michel avant chaque `git push` ; contournement possible avec `git push --no-verify`.
- Seulement si aucun `pre-push` n'existe déjà. S'il en existe un qui n'est pas celui de Michel : Michel n'y touche pas et montre la ligne à ajouter, avec un bouton « Copier ».
- Le hook de Michel porte une ligne marqueur. Le bouton devient « Retirer le garde-fou », qui supprime le fichier seulement s'il porte encore le marqueur et n'a pas été modifié (comparaison au contenu écrit).
- Installation et retrait écrivent un événement dans le journal d'audit.
- Le hook appelle le binaire Michel par son chemin absolu au moment de l'installation. Si ce binaire n'existe plus, le hook laisse passer avec une phrase (« Michel introuvable, envoi non vérifié »). Ne jamais bloquer le travail parce que Michel a disparu.
- Le hook va dans le dépôt git qui contient le projet (dossier des hooks donné par `git rev-parse --git-path hooks`), même si le projet est un sous-dossier. Un dépôt n'a qu'un `pre-push` : le hook de Michel vérifie **tous** les projets Michel situés dans ce dépôt (`michel gate --repo <racine du dépôt>`), et le pire feu l'emporte. Sur la carte de chacun de ces projets, l'état dit « Garde-fou installé (partagé avec : A, B) » ; le retrait se fait depuis n'importe lequel.
- Le hook passe `--data-dir` et `--config` comme le fait déjà le lancement des tests dans `fix`.
- `core.hooksPath` réglé dans le dépôt : Michel installe dans ce dossier s'il est dans le dépôt, sinon n'installe pas et le dit.
- Dépôt sans `.git` (projet non git) : bouton absent, phrase « pas un dépôt git ».

**CLI miroir.** `michel gate <projet>` : écrit le feu et sa raison en une phrase, code de sortie 0 vert, 1 rouge, 2 gris. C'est ce que lance le hook. Avant de répondre, si les fichiers de verrou du projet ont changé depuis le dernier scan (empreinte `scan_manifest.lock_sha256`), il relance un scan hors ligne (un vrai scan, par `scan.Run`, enregistré comme les autres) ; sinon il lit le dernier scan. Limite de 60 secondes pour ce scan. Scan déjà en cours ailleurs (`ErrScanRunning`), scan en échec ou limite dépassée : code 2, avec la raison. Le hook traite 2 comme un passage avec avertissement (le gris n'arrête pas un envoi, il prévient). `--repo <dossier>` vérifie tous les projets du dépôt, code = le pire.

### 2. « Ignorer » qui se revoit

- Une décision « Ignorer » prend une date « à revoir le », comme « Reporter » a une échéance. Choix dans le panneau de décision : **dans 1 an (défaut)**, dans 6 mois, dans 3 mois, jamais.
- « Jamais » reste possible : la justification, déjà obligatoire, suffit.
- À la date, la décision est remplacée avec une nouvelle raison `review_due` (distincte de `due_reached` du report), la faille revient « à traiter », un événement `reopened` est écrit (lot 2), et le digest la liste dans une section « À revoir » : « Ignorée le 06/11/2026, raison : … ». Même mécanique que l'échéance d'un report : même endroits d'appel (`ExpireDue` dans le scan et dans `digest --send`).
- Les « Ignorer » déjà en base gardent « jamais ». Pas de date ajoutée en douce. La page Failles, filtre « Ignorées », montre la date à revoir ou « jamais ».
- CLI miroir : `michel decide … --ignore --review 1y|6m|3m|never` (défaut 1y), refus d'une date passée.

### 3. Export CycloneDX avec VEX

- Bouton « Exporter (CycloneDX) » dans le menu d'un projet. Il télécharge `<projet>-cyclonedx-AAAA-MM-JJ.json`, un seul fichier CycloneDX 1.6 JSON qui contient la liste des composants et, dans `vulnerabilities`, les failles ouvertes avec ce que l'utilisateur en a décidé.
- **Composants.** Aujourd'hui Michel ne garde que les paquets touchés. Le scan garde désormais, pour le dernier scan réussi de chaque projet, tous les paquets lus : nouvelle table `scan_component` (`project_id`, `manifest_rel_path`, `ecosystem`, `name`, `version`, `purl`, `dep_group`), remplacée à chaque scan au statut `ok`, dans la même transaction que les failles. Un scan `partial`, `failed` ou `empty` ne la touche pas. L'export n'est permis que si le dernier scan du projet est `ok` et a écrit ses composants ; sinon il est refusé avec la raison. Les composants viennent de ce qu'osv-scanner a extrait (pas de deuxième lecture des fichiers). `dep_group` dev → `scope: optional`, sinon `required`.
- **Failles et décisions** (partie VEX, `analysis` de CycloneDX) :

| Michel | `analysis` |
|---|---|
| ouverte, sans décision | `state: in_triage` |
| Corriger | `state: exploitable`, `response: [update]` |
| Reporter | `state: in_triage`, `detail: "Reportée jusqu'au AAAA-MM-JJ. <justification>"` |
| Ignorer | pas de `state`, `response: [will_not_fix]`, `detail: <justification>` |
| disparue | absente du fichier |

  Michel ne dit jamais `not_affected` : il ne le sait pas. C'est l'utilisateur qui l'écrirait dans sa justification.
- `ratings` : gravité et score CVSS quand connus. Marque KEV et EPSS en `properties` (`michel:kev`, `michel:epss`).
- `metadata` : outil Michel et sa version, date, composant racine = le projet (nom seul).
- **Hygiène** : aucun chemin absolu (seulement `manifest_rel_path`), justifications passées par le masquage existant (`internal/mask`) avant écriture. Aucune sortie réseau : le fichier est rendu par l'API locale et téléchargé par le navigateur.
- Route : `GET /api/v1/projects/{name}/export/cyclonedx`. CLI miroir : `michel export cyclonedx <projet> [-o fichier]`, sortie standard par défaut.
- Projet jamais scanné après la migration : le bouton dit « Relance un contrôle pour avoir la liste complète des composants » et l'export est refusé, plutôt qu'un fichier qui laisserait croire qu'il n'y a que les paquets touchés.

## Non-objectifs

- Pas d'export pour les serveurs dans ce lot.
- Pas d'import de VEX ni de SBOM venant d'ailleurs.
- Pas de format SPDX ni OpenVEX : CycloneDX seul.
- Pas de jetons d'API par usage, pas de rôles : idées notées pour plus tard (Harbor robots, RBAC).
- Pas de feu dans le digest au-delà de la section « À revoir » ; pas de blocage de CI distante (Michel ne tourne pas sur GitHub).
- Pas de nouvelle dépendance Go ou JS : le JSON CycloneDX est écrit avec `encoding/json` et des structures à nous.

## Anti-objectifs

- Un feu vert faux. Doute = gris. Scan en échec ou trop vieux = gris.
- Un hook qui bloque le travail sans dire pourquoi, ou qui écrase un hook existant.
- Un fichier exporté qui affirme plus que Michel ne sait (`not_affected`, liste de composants partielle présentée comme complète).
- Un chemin, un nom de machine ou un secret dans l'export.
- Un réglage de plus à apprendre : trois seuils, une case, un bouton.

## Contraintes

- Règles constantes du projet : politique de souveraineté, `strict_local`, journal d'audit chaîné, textes FR et EN dans `internal/i18n` et `web/src/i18n`, CSP stricte, pas de couleur seule, tests Go et JS pour chaque règle.
- Migrations SQLite numérotées à la suite, sans `AUTOINCREMENT`.
- La règle du feu est écrite une fois en Go et exposée par l'API (`feu` dans `GET /api/v1/projects`) ; la page ne la recalcule pas.
- Windows et Linux : le hook est un script `sh` (git for Windows le lance avec son `sh`), chemin du binaire écrit avec des `/`.
- Avec 200 projets et 50 000 composants, `GET /api/v1/projects` reste sous 300 ms sur ce PC (le feu se calcule par une requête groupée, pas un aller-retour par projet).

## Laissé au constructeur

- Placement exact des boutons et libellés, dans le style du lot CRM.
- Découpage en tâches et en branches.
- Forme de la purl par écosystème (via `packageurl` si déjà présent dans les dépendances d'osv-scanner, sinon construite à la main pour Composer, npm, Go).
- Texte exact du hook et de son marqueur.
