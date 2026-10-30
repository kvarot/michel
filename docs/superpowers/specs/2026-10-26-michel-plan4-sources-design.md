# Michel — Design du plan 4 : registre des sources

**Date :** 2026-10-26
**Auteur :** Claude (brainstorming court, cadre fixé par Kévin)
**Statut :** validé par Kévin le 2026-10-26 (questions 1 à 3 du § 13 tranchées dans le sens recommandé : KEV = drapeau + urgence, Trivy misconfig et Semgrep lancés, commande MCP affichée) ; chaque choix non dicté par le cadre est marqué « mon choix » et reste à contester
**Entrées :** `docs/superpowers/specs/2026-10-23-michel-sources-catalog.md` (catalogue et règles), design v1 `docs/superpowers/specs/2026-10-22-michel-design.md` (§ 4.3, § 4.4, § 4.8, § 4.9, § 4.11), design plan 3 `docs/superpowers/specs/2026-10-23-michel-plan3-decisions-digest-design.md`, politique `docs/security/sovereignty-policy.md`
**Reports hérités :** `docs/superpowers/sdd/2026-10-23-michel-digest/deferred-and-rulings.md` (dossiers sans lockfile, `decide --package` bavard, chaîne de décisions supersédées)

---

## 1. Intention

Michel lit aujourd'hui deux bases OSV (Packagist, npm), ne sait pas qu'une faille est exploitée dans la nature, ne lit aucun bulletin d'éditeur, et n'a aucun endroit où l'utilisateur voit **d'où viennent ses données**. Le plan 4 livre ce lieu unique : un **registre des sources**, géré par l'utilisateur depuis la page « Sources » de la PWA et `michel source …`, qui couvre les six sortes du catalogue et se met à jour chaque matin avant le scan. Chaque entrée dit en clair qui Michel va contacter, n'est active qu'avec l'accord de l'utilisateur, et montre sa dernière lecture.

Le gain visible pour l'utilisateur le matin : « exploitée activement » en tête du digest, une rubrique « À lire » filtrée sur ses technologies, une ligne « catalogue », et des findings venus d'outils tiers (Trivy, CodeQL) dans la même boucle de décision.

## 2. Périmètre (donné par Kévin) et ce qui reste dehors

Dedans :

1. **Registre unique** : page « Sources » et `michel source list|show|enable|disable|add|remove|reset|update|install|upgrade|run`. Six sortes : `osv`, `enrichment`, `feed`, `plugin`, `skill`, `mcp`, plus `reference` (sorte 4 du catalogue, documentaire, sans lecture).
2. **Bases OSV par écosystème**, dont distributions Linux et paquets malveillants (`MAL-…`).
3. **Enrichissements** : CISA KEV, FIRST EPSS, CISA Vulnrichment, NVD (optionnel, clé API optionnelle), CIRCL Vulnerability-Lookup.
4. **Veille** « À lire » : RSS/Atom, avis GitHub d'un dépôt, page surveillée ; filtrée par les technologies déclarées.
5. **Plugins** : interface générique « source de findings » ; lecteurs SARIF 2.1.0 et Trivy JSON ; Trivy (configurations) et Semgrep (code PHP et JS) lancés par Michel, CodeQL et ZAP en lecture de rapport seulement (voir § 7).
6. **Skills et serveurs MCP** pour l'IA de codage : épinglés sur un commit, montrés avant installation avec leur licence, jamais mis à jour seuls, installés hors des projets.
7. **Mise à jour quotidienne** de tout le catalogue avant le scan ; état des dépôts via l'API GitHub (jeton optionnel) ; rubrique « À découvrir » ; ligne « catalogue » dans le digest.
8. **KEV** : marque « exploitée activement », en tête du digest, dans « mérite ton attention », terme visible du risque, changement KEV ⇒ Michel redemande.
9. **Lockfiles** `yarn.lock` et `pnpm-lock.yaml`.
10. **Restes du plan 3** : dossier sans lockfile ≠ scan échoué, `decide --package` résumé en une ligne, chaîne de décisions supersédées dans une même fenêtre.

Dehors (plans suivants) : briefs, serveur MCP de Michel et format caveman (plan 5) ; remédiation et proxy local complet des sous-processus (plan 6) ; cibles et collecteur serveur (plan 11) qui donneront leur valeur aux bases OSV des distributions et aux flux nginx/PostgreSQL ; lecture des workflows GitHub Actions ; OSV API en ligne (Michel reste sur les zips) ; `michel schedule`.

Règles non négociables (Kévin) : aucune trace des projets privés dans le dépôt (test d'hygiène + relecture manuelle des ledgers, projet de référence = « demo ») ; SQL portable vers PostgreSQL ; relecteur francophone non spécialiste sur tout texte FR (tutoiement) ; jamais d'écriture dans les projets scannés ; toute sortie réseau par `internal/egress`.

## 3. Le registre (`internal/source`)

### 3.1 Modèle

Table `source` (migration `0005`, § 11) :

| colonne | type | sens |
|---|---|---|
| `id` | TEXT PK (ULID) | |
| `key` | TEXT UNIQUE | identifiant stable, lisible : `osv.packagist`, `enrich.kev`, `feed.nginx`, `plugin.trivy`, `skill.trailofbits-code-audit`, `mcp.safedep-vet`, `ref.cve-org` ; une entrée perso prend le préfixe de sa sorte et un slug du nom (`feed.mon-flux`) |
| `kind` | TEXT | `osv` \| `enrichment` \| `feed` \| `plugin` \| `skill` \| `mcp` \| `reference` |
| `origin` | TEXT | `catalog` \| `user` |
| `name`, `url` | TEXT | affichés ; `url` = page humaine |
| `hosts` | TEXT JSON | hôtes contactés (`["www.cisa.gov"]`) ; vide pour `plugin` et `reference` |
| `purpose` | TEXT | purpose egress (§ 9) ; vide quand `hosts` est vide |
| `enabled` | INTEGER 0/1 | voulu par l'utilisateur |
| `hidden` | INTEGER 0/1 | entrée du catalogue retirée par l'utilisateur (`reset` la rétablit) ; une entrée `user` retirée est supprimée |
| `config` | TEXT JSON | propre à la sorte (§ 3.3) |
| `tech` | TEXT JSON | étiquettes de technologies (`["nginx"]`) pour les flux |
| `catalog_version` | INTEGER | version du catalogue embarqué qui a écrit l'entrée (0 pour `user`) |
| `last_read_at`, `last_read_result`, `last_read_error`, `last_read_items`, `last_read_etag` | TEXT / TEXT / TEXT / INTEGER / TEXT | dernière lecture : `ok` \| `error` \| `denied` \| `waiting_consent` \| `skipped` ; erreur en anglais, bornée (`SanitizeText`, 500 caractères) ; `etag` ou `Last-Modified` pour ne pas retélécharger |
| `status` | TEXT JSON | pour `skill`, `mcp`, `plugin` : relevé GitHub (§ 8.1) |
| `created_at`, `updated_at` | TEXT | RFC 3339 UTC |

Pas de `rowid`, pas de type SQLite-spécifique ; `?` et `ON CONFLICT (key) DO UPDATE`.

**État affiché** (calculé, jamais stocké) : `off` (`enabled=0`), `waiting_consent` (`enabled=1`, un hôte sans règle `network.allow` pour le purpose), `on` (activée et autorisée), `hidden`. Un plugin ou une référence n'a pas d'état `waiting_consent`.

### 3.2 Catalogue embarqué

`internal/source/catalog/catalog.yaml`, embarqué, versionné par un entier `version`. Il reprend le document du 2026-10-23, sorte par sorte, avec pour chaque entrée : `key`, `kind`, `name`, `url`, `hosts`, `config`, `tech`, `note` (FR et EN, clés i18n `source.note.<key>`). Au premier `source` (CLI ou API) et à chaque démarrage, `Sync` insère les entrées absentes et met à jour `name`, `url`, `hosts`, `config.catalog` des entrées `catalog` dont `catalog_version` est plus ancien, **sans toucher** à `enabled`, `hidden`, `tech` ni à la partie `config.user`. Une entrée retirée du catalogue dans une version future est marquée `hidden` avec une note, jamais supprimée.

État par défaut (mon choix, respecte « rien en strict_local sans accord ») : **tout désactivé**, sauf `osv.packagist` et `osv.npm` qui sont `enabled=1` parce que le scan en dépend ; sans règle `osv.db` ils sont `waiting_consent`, exactement le comportement actuel de `michel db update` (refus, message qui dit quoi faire). Aucun skill ni serveur MCP installé par défaut.

`michel source reset [<key> | --all]` : remet l'entrée (ou toutes les entrées `catalog`) à l'état du catalogue : `enabled` par défaut, `hidden=0`, `tech` et `config.user` vidés ; les entrées `user` sont conservées (`--all --purge-user` les supprime, confirmation demandée). Un skill installé n'est pas désinstallé par `reset` (dit explicitement dans la sortie).

### 3.3 `config` par sorte

```yaml
osv:        { ecosystem: Packagist }                            # nom du dossier du bucket OSV
enrichment: { format: kev | epss | vulnrichment | nvd | circl, on_demand: false, api_key_secret: nvd-api-key }
feed:       { format: auto | rss | atom | github_advisories | page, repo: owner/name }   # page = détection de changement
plugin:     { format: sarif | trivy_json, tool: trivy | semgrep | codeql | zap | generic, run: true|false, projects: [], input: <chemin fixe optionnel> }
skill:      { repo: owner/name, path: sous/dossier, pinned: <sha>, installed_sha: "", install_dir: "", license: "" }
mcp:        { repo: owner/name, pinned: <sha>, installed_sha: "", launch: { command: "", args: [] }, license: "" }
reference:  {}
```

`config.catalog` vient du catalogue, `config.user` de l'utilisateur ; la lecture fusionne (`user` gagne). Les clés inconnues sont refusées.

### 3.4 Accord, allowlist, journal

Activer une entrée qui contacte le réseau passe toujours par **l'écran d'accord** (CLI : question `y/N`, `--yes` pour les scripts ; page : dialogue) :

> Michel va contacter **www.cisa.gov** pour lire la liste des failles exploitées. Rien de tes projets ne part : c'est un téléchargement.
> Pour les enrichissements à la demande (Vulnrichment, NVD, CIRCL) : Michel enverra **les identifiants CVE de tes failles** à <hôte>. Rien d'autre.
> Pour les dépôts (skills, MCP, plugins) : Michel lira **l'état public du dépôt** sur api.github.com ; avec un jeton, GitHub saura que c'est toi.

Après accord, Michel **écrit la règle** `{host, purpose}` dans `sovereignty.network.allow` du fichier de politique (`--config`). Écriture par `yaml.v3` sur l'arbre de nœuds (commentaires et ordre conservés), atomique (fichier temporaire puis renommage), copie `config.yaml.bak` de la version précédente ; si le fichier n'existe pas, Michel crée un fichier minimal ne contenant que `sovereignty.network.allow`. La politique est **rechargée et revalidée** après l'écriture ; une politique invalide est restaurée depuis la copie et l'activation échoue avec la cause. La passerelle apprend les nouvelles règles sans redémarrage (`Gateway.SetRules`, § 9) : `michel serve` en bénéficie immédiatement. Chaque accord = événement d'audit `source.consent` `{key, hosts, purpose, author}` ; chaque désactivation `source.disable` ; la règle n'est **pas** retirée à la désactivation (mon choix : l'utilisateur a donné son accord à une destination, la retirer à sa place serait une surprise ; `michel source disable --forget` la retire). **Règle déjà présente** (plusieurs entrées partagent un couple hôte/purpose : tous les `osv.*` → `osv.db`, les avis GitHub → `api.github.com`/`source.feed`) : l'activation d'une entrée suivante ne repose pas la question ; elle dit « déjà autorisé pour <entrée qui l'a obtenu> », passe `on` et écrit quand même `source.consent` (mon choix, après relecture builder). `--forget` est refusé quand une autre entrée activée a besoin du même couple ; l'erreur la nomme.

Chaque lecture = événement `source.read` `{key, kind, hosts, result, bytes, items, duration_ms}` ; jamais le contenu. Une entrée `waiting_consent` n'est pas lue : résultat `waiting_consent`, visible sur la page et dans la ligne « catalogue » du digest.

### 3.5 Commandes

```
michel source list [--kind <kind>] [--all]            # --all montre aussi hidden
michel source show <key>                              # détail, hôtes, purpose, règle présente ou absente, dernière lecture, items récents
michel source enable <key> [--yes]                    # accord + règle
michel source disable <key> [--forget]
michel source add --kind feed --name "…" --url https://… [--format rss|atom|github_advisories|page] [--repo owner/name] [--tech x]
michel source add --kind osv --ecosystem <Nom>        # un écosystème du bucket OSV non listé
michel source add --kind plugin --name "…" --format sarif|trivy_json [--input <chemin>] [--tool generic]
michel source add --kind skill|mcp --repo owner/name [--path sous/dossier] --pin <sha> [--name …]
michel source remove <key>                            # user : supprime ; catalog : hidden ; skill installé : désinstalle (confirmation)
michel source reset [<key> | --all [--purge-user]]
michel source update [<key>…] [--kind <kind>]         # § 8
michel source install <key> / upgrade <key>           # skill, mcp (§ 7.3)
michel source run <key> --project <name> [--input <fichier>]   # plugin (§ 7.2)
michel source items [--unread] [--since 7d] [--tech x]         # « À lire »
michel source read <item-id|--all>                    # marque lu
michel source discover [--ignore <repo> | --add <repo>]       # « À découvrir »
michel project set <name> --tech nginx --tech postgresql      # technologies déclarées du projet
michel tech list|add|remove <tag>                     # technologies déclarées globales (hors projet)
michel db update|status                               # inchangés en surface ; ne travaillent que sur les osv activés
```

Toutes les sorties passent par `internal/i18n` ; `--json` sur `list`, `show`, `items`, `update`, `discover`.

## 4. Bases OSV et lockfiles

### 4.1 Écosystèmes dynamiques

`osvdb.Ecosystems` devient `osvdb.Enabled(ctx, sourceRepo)` : la liste des entrées `osv` à l'état `on`. Catalogue : `Packagist`, `npm` (activés), puis désactivés : `PyPI`, `Go`, `Maven`, `RubyGems`, `NuGet`, `crates.io`, `Pub`, `Hex`, `SwiftURL`, `Android`, `GitHub Actions`, `Debian`, `Ubuntu`, `Alpine`, `Rocky Linux`, `AlmaLinux`, `SUSE`, `openSUSE`, `Red Hat`, `Chainguard`, `Wolfi`. Les noms sont ceux des dossiers du bucket, vérifiés par le builder au moment d'écrire le catalogue (une entrée dont le zip n'existe pas est une erreur de catalogue, pas une erreur utilisateur).

`scan.Run` n'exige plus toutes les bases : il exige celles des écosystèmes **des lockfiles trouvés** (`Require(root, needed ∩ enabled)`) ; un lockfile d'un écosystème désactivé est listé dans `Result.Manifests` avec l'erreur `ecosystem disabled: enable osv.<x>` et compte comme `partial`.

**Paquets malveillants.** Le catalogue porte `osv.malicious` (ossf/malicious-packages) en entrée `reference` avec la note « déjà repris par osv.dev dans les zips par écosystème » **si** le builder constate des `MAL-` dans les zips Packagist/npm du jour ; sinon l'entrée devient une `osv` dont `config.catalog.url` pointe la release zip du dépôt ossf, lue par le même téléchargeur. Dans les deux cas : un finding dont l'identifiant OSV commence par `MAL-` est marqué `finding.malicious=1`, affiché « paquet malveillant » (gabarit *what* dédié, gravité forcée `critical`), listé en tête du digest avec les KEV (§ 5.3).

### 4.2 `yarn.lock` et `pnpm-lock.yaml`

`scan.lockfiles` gagne `yarn.lock → npm` et `pnpm-lock.yaml → npm` ; `scanPlugins` gagne `javascript/yarnlock` et `javascript/pnpmlock` (extracteurs présents dans l'osv-scalibr du graphe). `checkContent` apprend les deux formats : yarn v1 (texte, entête `# yarn lockfile v1`), yarn berry (YAML, clé `__metadata`), pnpm (YAML, `lockfileVersion`) ; « vide » = aucune entrée de paquet, « illisible » = format non reconnu. `ErrNoManifests` et les messages i18n listent les quatre fichiers.

Analyse (`internal/analyze`) : le graphe de dépendances npm lit aujourd'hui `package-lock.json` v3. Il gagne deux lecteurs : yarn v1 et berry (entrées `name@range:` → `version`, `dependencies`), pnpm v6 et v9 (`importers`, `packages`, `snapshots`). Direct = présent dans `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies` du `package.json` racine (et des workspaces pour pnpm `importers`) ; chemin « via » = première chaîne trouvée, comme pour npm. Lecteur en échec ⇒ `Directness: unknown`, note anglaise stockée « lockfile format not understood », aucune panique ; le reste de l'analyse (points d'appel, tests, changelog) continue : il ne dépend pas du lockfile. Fixtures `demo` minimales pour les trois formats dans `internal/analyze/testdata/`.

### 4.3 Dossier sans lockfile (reste du plan 3)

Nouveau statut de scan `empty` (« rien à scanner ») : le projet n'a aucun lockfile lu. Findings existants intacts (comme aujourd'hui), événement `scan.finish` `result=empty`, **exit 0** dans `scan --all` (exit 1 reste pour `scan --project <x>` explicite : l'utilisateur visait ce dossier). Le digest ne le compte plus dans `failed_scans` ; il a un compteur `empty_projects` et une phrase (« 2 projets n'ont rien à scanner : pas de lockfile ») affichée **une fois par semaine** ou quand le nombre change (mon choix : un rappel sans bruit quotidien ; la page Sources/Projets le montre toujours).

## 5. Enrichissements

### 5.1 Données

| source | lecture | table | taille |
|---|---|---|---|
| `enrich.kev` | téléchargement complet du JSON CISA | `kev(cve PK, vendor, product, name, date_added, due_date, ransomware, notes_url)` | ~1 500 lignes |
| `enrich.epss` | téléchargement complet du CSV gz du jour | `epss(cve PK, score REAL, percentile REAL, model_date)` | ~300 000 lignes, remplacement en une transaction |
| `enrich.vulnrichment` | **à la demande** : `raw.githubusercontent.com/cisagov/vulnrichment/develop/<année>/<bloc>/<CVE>.json` pour les CVE de findings sans CVSS, plafonné à 200 par mise à jour | `cve_enrichment(cve PK, cvss_score, cvss_vector, cvss_source, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, cwe JSON, fetched_at, source_key)` | une ligne par CVE consulté |
| `enrich.nvd` | à la demande, API 2.0 `cves?cveId=`, 5 req / 30 s sans clé, 50 avec (`nvd-api-key` dans le magasin de secrets), plafond 100 par mise à jour | même table (`cvss_source=nvd`) | idem |
| `enrich.circl` | à la demande, `vulnerability.circl.lu/api/vulnerability/<id>` ; alternative européenne à NVD/Vulnrichment | même table (`cvss_source=circl`) | idem |

KEV et EPSS sont des téléchargements entiers : ils ne révèlent rien. Les trois autres envoient des identifiants CVE : l'écran d'accord le dit, et ils restent désactivés par défaut. Caps : KEV 50 Mo, EPSS 200 Mo décompressé, réponse à la demande 5 Mo ; `etag` honoré ; une lecture en échec garde les données précédentes.

### 5.2 Application aux findings

Colonnes dénormalisées sur `finding` : `kev INTEGER 0/1`, `kev_added TEXT`, `epss REAL`, `epss_percentile REAL`, `malicious INTEGER 0/1`, `cvss_enriched REAL` (utilisée seulement quand `cvss_score` vaut 0). Le lien se fait **en Go** par les alias (`finding.aliases` contient les `CVE-…`) : `enrich.Apply(ctx, store)` recalcule ces colonnes pour tous les findings non `gone` après chaque `source update`, et `applyScan` les remplit à l'insertion d'un finding. `cvss_enriched` et la gravité : si `severity_label` vaut `unknown` et qu'un CVSS enrichi existe, la gravité affichée vient du CVSS enrichi (`severity_source=enrichment` dans la fiche) ; la colonne `severity_label` stockée n'est pas réécrite (c'est l'instantané OSV), la gravité **effective** est calculée à la lecture par une fonction unique `scan.EffectiveSeverity(f)`, utilisée par le digest, l'API, la CLI et le score.

### 5.3 KEV partout où Kévin l'a demandé

- **Marque** : « exploitée activement » (chip rouge PWA, `[KEV]` CLI, `kev: yes` dans `--json` et les futurs briefs), avec la date d'ajout CISA et l'échéance fédérale (information, pas une obligation : le texte le dit).
- **Tête du digest** : section « Exploitées activement » avant « nouvelles », qui liste les failles KEV **en attente** (`new`, `pending`) et **à corriger** (`decided fix`), pas seulement celles de la fenêtre, paquets et projets, tant qu'il en reste ; les KEV reportées ou ignorées avec justification n'y reviennent pas chaque matin : une seule ligne de compte (« 2 exploitées que tu as reportées ou ignorées ») les rappelle (mon choix, après relecture builder : un report justifié n'est pas un échec, design v1 § 4.11). Le titre de Michel devient « Michel a trouvé 3 nouveautés cette nuit, **1 est exploitée dans la nature** » quand une KEV est en attente. Les `MAL-` suivent les mêmes règles (« paquet malveillant »).
- **Mérite ton attention** : `Attention` compte toute faille KEV ou malveillante ouverte non décidée, quelle que soit sa gravité.
- **Terme de risque** (à trancher, § 13 question 1 ; mon choix par défaut) : le score de risque public mesure le **risque de la correction**, pas l'urgence ; une faille exploitée n'est pas plus risquée à corriger, elle est plus urgente. Donc KEV entre dans `Risk.Terms` comme **drapeau** `exploited: 1` (0 point, visible dans la fiche et les briefs, comme `thresholds_fallback`), et la **recommandation** gagne un qualificatif `urgency: urgent` qui force « corrige en premier » dans les trois phrases et place la faille en tête de tous les tris. `docs/remediation-risk.md` explique pourquoi KEV ne change pas le score.
- **Michel redemande** : `decision.seen_kev INTEGER` entre dans l'instantané ; au re-scan ou à l'`enrich.Apply`, un changement de `kev` sur une faille `decided` supersède la décision avec la raison `kev_changed` (nouvelle raison dans `decide.Reason`, libellé « elle est maintenant exploitée dans la nature »), la faille repasse `pending` et sort dans « décisions à revoir ». `enrich.Apply` est donc la **troisième écriture** autorisée à superséder (avec `applyScan` et `digest --send`), dans sa transaction, avec l'événement `decision.superseded`.
- **Explication** : la phrase *ce qui pourrait arriver* ajoute « Cette faille est exploitée dans la nature (liste KEV de la CISA depuis le 12/03) » et passe la certitude à `high` ; EPSS donne « probabilité d'exploitation sous 30 jours : 12 %, plus que 95 % des failles connues » quand `epss_percentile ≥ 0,5` (en dessous, rien : le silence vaut mieux qu'un chiffre rassurant mal lu ; mon choix).

## 6. Veille « À lire » (`feed`)

### 6.1 Lecteurs

Un lecteur par format, tous bornés à 5 Mo et 200 items par lecture, contenu passé par `SanitizeText`, HTML retiré, résumé tronqué à 500 caractères :

- `rss` / `atom` : `encoding/xml` ; `auto` détecte sur l'élément racine ; `guid`/`id` sinon `link` sinon hash du titre.
- `github_advisories` : `GET https://api.github.com/repos/{owner}/{repo}/security-advisories?state=published&per_page=50` (public sans jeton ; `github-token` du magasin de secrets ajouté en `Authorization: Bearer` quand il existe) ; item = `ghsa_id`, `summary`, `severity`, `published_at`, `html_url`, paquets touchés.
- `page` : GET de la page humaine, hash du texte normalisé (balises retirées, espaces réduits) ; un changement de hash crée **un** item « la page a changé » avec le lien ; pas d'extraction de contenu (mon choix : fiable, sans parseur par site).

Table `feed_item(id PK, source_id, guid, title, url, published_at, summary, tech JSON, seen_at, read_at, UNIQUE(source_id, guid))`. Rétention : 180 jours puis purge à la mise à jour.

### 6.2 Technologies déclarées et filtre

Trois origines, fusionnées en un ensemble d'étiquettes par projet et un ensemble global :

1. **automatique depuis les manifestes** : écosystème (`php`, `node`) et paquets vers étiquettes par une table de règles embarquée dans le catalogue (`tech_rules`: `symfony/* → symfony`, `laravel/framework → laravel`, `drupal/core → drupal`, `vue → vue`, `react → react`, `next → nextjs`, `@angular/core → angular`, `express → express`, …) ; recalculée à chaque scan, stockée `project.tech_auto JSON` ;
2. **déclarées par projet** : `michel project set --tech`, `project.tech JSON` ;
3. **déclarées globales** : table `tech(tag PK, created_at)`, pour ce qui n'est dans aucun projet (nginx, postgresql, ubuntu…).

Un item est « à lire » si `source.tech ∩ déclarées ≠ ∅` ou si son titre contient une étiquette déclarée (mot entier, insensible à la casse). Un flux activé dont aucune étiquette ne correspond est quand même lu (l'utilisateur l'a voulu) et ses items sont visibles sur la page sans être « à lire ». La page Sources marque « suggéré pour toi » les flux désactivés dont une étiquette correspond (mon choix : la découverte sans décision automatique).

### 6.3 Où ça s'affiche

Digest : section « À lire » (max 10 items, groupés par source, titre + date + lien ; items non lus publiés dans la fenêtre), **après** les sections de failles. Page « Aujourd'hui » : même liste, bouton « lu ». CLI : `michel source items`. Jamais de création de faille à partir d'un flux : la version installée n'est pas connue.

## 7. Plugins, skills, serveurs MCP

### 7.1 Interface « source de findings » (`internal/plugin`)

```go
type Provider interface {
    Key() string                                     // source.key
    Detect(ctx) (installed bool, version string)     // outil présent ? (PATH, version, jamais de téléchargement)
    Run(ctx, p project.Project, outDir string) (reportPath string, err error)  // argv fermé, voir 7.2 ; ErrNotRunnable pour ZAP et generic
    Ingest(ctx, reportPath string, p project.Project) ([]ExternalFinding, error)
}
```

Deux lecteurs partagés : **SARIF 2.1.0** (`runs[].results[]`, `ruleId`, `level`, `properties.security-severity`, `locations[0].physicalLocation` relatif à la racine du projet, `partialFingerprints`) et **Trivy JSON** (`Results[].Misconfigurations[]` ; les `Vulnerabilities[]` d'un rapport fourni par `--input` sont **ignorées** quand un alias CVE existe déjà en finding OSV du même projet, et comptées dans la sortie comme « déjà connues par OSV » ; mon choix, après relecture builder). Un `ExternalFinding` devient une ligne `finding` avec `kind` ≠ `dependency` :

| colonne nouvelle sur `finding` | sens |
|---|---|
| `kind` | `dependency` (défaut, existant) \| `code` (Semgrep, CodeQL) \| `config` (Trivy misconfig : Dockerfile, compose, Kubernetes) \| `container` (réservé : `trivy image`, plan 11) \| `dynamic` (ZAP) |
| `source_key` | `""` pour OSV, sinon la clé du plugin |
| `rule_id`, `location`, `fingerprint` | règle de l'outil, `chemin/relatif:ligne` assaini, empreinte stable de l'outil quand elle existe |

Identité : `FindingID(project, source_key, rule_id, fingerprint ou location)`. Gravité : `security-severity` (CVSS) sinon `level` (`error → high`, `warning → medium`, `note → low`). Statuts, décisions, digest, supersession : identiques ; **pas d'analyse** (points d'appel, saut, changelog ne s'appliquent pas) : `Analysis` absente, gabarits *what/impact/cost* dédiés par `kind` (« CodeQL signale *règle* dans `src/x.php:41` ; corriger = modifier ton code, pas une dépendance »). Les findings d'un plugin ne sont jamais marqués `gone` par un scan OSV : seule une nouvelle **exécution du même plugin** sur le même projet les fait disparaître.

### 7.2 Exécution

`michel source run <key> --project demo [--input fichier]` et, pour les plugins dont `config.run=true` et dont `projects` contient le projet (ou est vide), à la fin de `michel scan` du projet :

- `--input` ⇒ `Ingest` seul (ZAP, `generic`, ou rapport produit ailleurs, par exemple en CI).
- sinon `Detect` puis `Run` avec un **argv fermé** par outil, jamais une chaîne de l'utilisateur :
  - Trivy : `trivy fs --scanners misconfig --format sarif --output <data-dir>/plugins/trivy/<project>/<ulid>.sarif --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --cache-dir <data-dir>/plugins/trivy/cache <project.path>` ; **`misconfig` seulement** (mon choix, après relecture builder) : `vuln` sur un dossier source rescanne les lockfiles et doublerait chaque finding OSV ; il reviendra avec `trivy image` au plan 11 ; `secret` reste hors plan 4 (un finding « secret à tel endroit » est lui-même une donnée sensible ; le masquage des secrets de Michel arrive au plan 5). Les règles de configuration de Trivy sont embarquées dans son binaire ; toute mise à jour de règles est téléchargée par l'utilisateur lui-même, jamais par Michel ;
  - Semgrep : `semgrep scan --sarif --output <…>.sarif --metrics=off --disable-version-check --config <data-dir>/plugins/semgrep/rules <project.path>` ; **remplace CodeQL comme analyseur lancé** (mon choix, après relecture builder : CodeQL ne couvre pas PHP, cœur de Michel, et télécharge ses packs de requêtes au premier usage) ; les règles sont des fichiers YAML placés par l'utilisateur dans ce dossier (`docs/sources.md` montre comment récupérer `p/php` et `p/javascript` une fois, hors Michel) ; dossier vide ⇒ erreur « aucune règle Semgrep » avec la marche à suivre ;
  - CodeQL : lecture de rapport SARIF seulement (`--input`, produit en CI GitHub par exemple) ; la note du catalogue dit « PHP non couvert, licence d'usage à vérifier » ;
  - ZAP : `ErrNotRunnable` en plan 4 (test dynamique = réseau vers une URL cible, réservé au moment où le proxy complet des sous-processus existe, plan 6) ; lecture de rapport SARIF seulement.
- **Clôture réseau des sous-processus** : Michel lance l'outil avec `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` pointant un **proxy local de refus** (`internal/egress/denyproxy`, port éphémère sur `127.0.0.1`) qui répond 403 à toute requête et `CONNECT`, et journalise chaque tentative en `egress.attempt` refusé avec le purpose `plugin.<key>` ; `NO_PROXY` vide ; variables propres aux outils (`TRIVY_SKIP_DB_UPDATE=true`, `CODEQL_…`) fixées. Ce n'est pas une garantie (un outil peut ignorer le proxy), c'est une clôture journalisée ; la doc le dit.
- `cwd` = dossier de données, jamais le projet ; sortie et base d'outil sous `<data-dir>/plugins/` ; **aucune écriture sous `project.path`** (test `treeDigest` avant/après, avec un faux `trivy` dans le `PATH` du test) ; timeout 30 min ; `stdout`/`stderr` de l'outil tronqués à 64 Ko, stockés dans `plugin_run.log` ; événement `plugin.run` `{key, project, tool_version, argv_hash, duration_ms, findings, result}`.

Table `plugin_run(id PK, source_id, project_id, started_at, finished_at, tool_version, report_path, status, error, findings)`.

### 7.3 Skills et serveurs MCP (`skill`, `mcp`)

Cycle : `show` (état du dépôt) → `install` (aperçu + accord) → quotidien `update` (relevé, **signalement** d'une nouvelle version) → `upgrade` (aperçu du changement + accord) → `remove`.

- **Récupération épinglée** : archive `https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}` (purpose `source.repo`, cap 50 Mo compressé / 200 Mo extrait / 5 000 fichiers, chemins vérifiés contre la traversée, liens symboliques refusés) extraite dans `<data-dir>/sources/repos/<key>/<sha>/` (données non fiables : jamais exécutées par Michel, jamais importées comme code).
- **Aperçu avant installation** : liste des fichiers avec tailles, les 40 premières lignes de `SKILL.md` (ou `README.md`), **licence** détectée (`LICENSE*` → SPDX par mots-clés : MIT, Apache-2.0, BSD-2/3, GPL-2/3, AGPL, MPL ; sinon « licence non trouvée : vérifie avant d'installer »), note de confiance (étoiles, dernier commit, archivé, auteur « dans le catalogue de Michel »), ce que l'installation va écrire et où. CLI : aperçu puis `y/N` ; page : dialogue avec les mêmes informations, `GET /sources/{key}/preview` puis `POST /sources/{key}/install {sha}`. Le `sha` installé est **toujours** celui montré (vérifié).
- **Skill** : copie de `path` vers `~/.claude/skills/<nom-du-dossier>/` (le `name` du frontmatter ; refus si le dossier existe sans marqueur Michel) avec un fichier marqueur `.michel-source` (`key`, `sha`, date) ; `remove` ne supprime que les dossiers portant un marqueur qui correspond. **Jamais** dans un projet scanné ni dans `.claude/` d'un projet.
- **MCP** : Michel récupère et épingle la source pour lecture et audit, montre la licence et le `launch` du catalogue (commande + arguments écrits à la main dans le catalogue, par exemple `npx -y <paquet>` ou un binaire) et **affiche** la ligne `claude mcp add --scope user <nom> -- <commande> <args>` à lancer par l'utilisateur. Michel **n'écrit pas** dans la configuration de Claude Code (mon choix, § 13 question 3) : ce fichier est partagé avec d'autres outils, et un serveur lancé via `npx` télécharge au démarrage hors du contrôle de Michel, ce que l'aperçu dit en clair.
- **Jamais de mise à jour automatique** : `update` relève `pushed_at`, `stargazers_count`, `archived`, dernier `releases/latest` et le `sha` de tête de la branche par défaut ; si le `sha` de tête ≠ `pinned`, l'entrée porte « nouvelle version disponible » (digest, page) ; `upgrade` télécharge la nouvelle archive, montre **fichiers ajoutés / modifiés / supprimés** et le diff de `SKILL.md`, puis réinstalle après accord et ré-épingle.
- Un dépôt **archivé** ou dont la licence change est signalé « à revoir » ; rien n'est retiré à la place de l'utilisateur.
- **Contenu du catalogue embarqué** (mon choix, après relecture builder) : seules les entrées de pertinence **D** (défense des dépendances et du code) et **S** (serveur, utile au plan journaux) du relevé du 23/10 entrent, désactivées : skills Trail of Bits Code Audit et Claude Code OWASP ; serveurs MCP Semgrep, SafeDep vet, CVE-Search, Wazuh. Exclus du catalogue : Snyk (données envoyées à un tiers, contraire à la politique), les outils offensifs et OSINT (Burp, SecOps, Shodan, VirusTotal, Maigret), la rétro-ingénierie (IDA, Ghidra, JADX), Mobb (envoi de code à vérifier), les dépôts quasi inconnus ; ils restent cités dans `docs/sources.md` comme « connus, non proposés, et pourquoi ». Le builder ouvre chaque dépôt retenu au moment d'écrire le catalogue : `pinned` = sha de tête du jour, `license` et `launch` relevés ; une licence introuvable ou un `launch` non évident donne `license: unknown` / `launch` vide, et l'aperçu d'installation le dit (« licence non trouvée : vérifie avant d'installer »). L'utilisateur ajoute n'importe quel autre dépôt par `source add`.

### 7.4 « À découvrir »

Source `discover.github` (désactivée par défaut, accord sur `api.github.com`, purpose `source.discover`) : `GET /search/repositories?q=topic:mcp-security&sort=stars&per_page=20` et `topic:claude-skills` ; les cinq listes « awesome » du catalogue sont des entrées `reference` cliquables, pas lues (mon choix : extraire des liens d'un README est fragile). Table `discovery(repo PK, topic, stars, description, html_url, first_seen_at, state new|ignored|added)`. Un dépôt qui existe déjà dans `source` n'y entre pas. Digest : « À découvrir : 2 nouveaux dépôts suivis » (noms, étoiles) tant qu'il y a du `new` ; page : ajouter (crée une entrée `user` `skill` ou `mcp` à épingler, puis `install` normal) ou ignorer.

## 8. Mise à jour quotidienne et digest

### 8.1 `michel source update`

Ordre fixe : `osv` → `enrichment` (KEV, EPSS, puis à la demande) → `enrich.Apply` → `feed` → relevé GitHub des `skill`/`mcp`/`plugin` (dépôt déclaré) → `discover`. Par entrée : état `waiting_consent` ou `off` ⇒ `skipped`/`waiting_consent` sans réseau ; sinon lecture bornée (timeout 15 min pour une base OSV, 5 min sinon), résultat stocké sur l'entrée, événement `source.read`. Une erreur n'arrête pas les suivantes ; exit 1 si au moins une erreur ; `--json` donne la liste. Les relevés GitHub partagent un **budget** de 50 requêtes par mise à jour sans jeton (la limite publique est 60/h), 500 avec jeton ; au-delà, `skipped: rate budget` et reprise le lendemain.

`michel scan --all --update --digest` enchaîne `source update` **avant** les scans (le `--update` est explicite comme `--digest` ; la ligne de la tâche planifiée dans `docs/operations/daily-digest.md` devient `michel scan --all --update --digest`). Une mise à jour en échec n'empêche pas le scan : les données précédentes servent, et le digest le dit.

### 8.2 Ligne « catalogue » du digest

`Digest.Catalog` : `{updated, failed [keys], waiting_consent [keys], new_versions [{key, name, from, to}], discover_new, unreachable [keys], osv_disabled_needed [ecosystems]}`. Rendu : une ligne de synthèse (« Catalogue : 6 sources à jour, nginx injoignable, nouvelle version de ton skill Trail of Bits Code Audit ») puis les détails en liste courte ; silencieux quand tout est à jour et sans nouveauté (« Catalogue à jour » tient en deux mots). Sections « À lire » (§ 6.3) et « À découvrir » (§ 7.4) suivent. Les canaux reçoivent la même chose que le texte : noms de sources, clés, nombres, jamais d'URL de rapport local ni de chemin.

### 8.3 Restes du plan 3

- `decide --package` : une ligne de résumé (« 59 failles de acme/lib décidées (defer, jusqu'au 25/11) dans demo ; audit : 01J…A1 → 01J…Z9 ») ; `--verbose` rétablit la ligne par faille ; `--json` inchangé.
- Chaîne de décisions supersédées dans une fenêtre : « décisions à revoir » ne garde, par faille, que la **dernière** décision supersédée de la fenêtre (tri `superseded_at` décroissant, dédoublonnage par `finding_id`) ; une faille qui a une décision en vigueur plus récente que la supersession sort (déjà le cas).

## 9. Souveraineté et sécurité, ce qui est enforcé

- **Purposes** nouveaux dans l'inventaire `docs/security/network-egress.md` : `osv.db` (inchangé, tous les écosystèmes), `source.enrich` (`www.cisa.gov`, `epss.cyentia.com`, `raw.githubusercontent.com`, `services.nvd.nist.gov`, `vulnerability.circl.lu`), `source.feed` (hôte de chaque flux ; `api.github.com` pour les avis), `source.repo` (`api.github.com`, `codeload.github.com`), `source.discover` (`api.github.com`), `plugin.<key>` (jamais autorisé : refus journalisé du proxy de clôture). Toujours par `Gateway.Client(purpose)` ; le test de frontière AST couvre les nouveaux paquets ; un test lance `source update` avec toutes les entrées activées et un `Sink` témoin et vérifie que **chaque** hôte contacté a une règle et un événement.
- **`Gateway.SetRules(rules)`** (nouvelle méthode, sous mutex) ; `policy.Reload` relit et revalide ; le fichier n'est jamais réécrit sans copie `.bak` ni sans relecture réussie.
- **Données non fiables** : tout ce qui vient d'une source (flux, JSON, archives, rapports SARIF) est **donnée** : assainie (`SanitizeText`), bornée (caps § 5.1, § 6.1, § 7.3), jamais exécutée, jamais importée ; archives extraites avec garde de traversée, sans liens symboliques, sans bits exécutables ; les rapports de plugins ne sont lus que depuis `<data-dir>/plugins/` ou un `--input` explicite.
- **Minimisation** : les requêtes vers GitHub ne portent que `owner/repo` ; les enrichissements à la demande n'envoient que des identifiants CVE et sont désactivés par défaut ; aucune donnée de projet ne sort nulle part ; la page et les canaux ne montrent ni chemin absolu ni commande.
- **Secrets** : `github-token`, `nvd-api-key` par `michel secret set` ; jamais en argument ni en audit ni en erreur ; un jeton absent n'est pas une erreur (mode public).
- **Écritures hors dossier de données** : exactement deux, toutes deux sur accord explicite et journalisées : la règle `network.allow` dans le fichier de politique (`source.consent`) et le dossier `~/.claude/skills/<nom>/` avec marqueur (`source.install`, `source.remove`). Jamais sous `project.path`, jamais dans `.claude/` d'un projet, jamais dans la configuration de Claude Code.
- **Sous-processus** : argv fermé, `cwd` hors projet, proxy de refus, timeout, sortie bornée ; `exec.LookPath` seulement ; aucun shell.
- **Hygiène** : test par empreintes inchangé ; fixtures `demo`, `acme/lib`, `vuln-pkg`, dépôts d'exemple `example/skill` ; ledger relu à la main, agrégats seuls ; le relevé réel sur le poste de Kévin ne publie que des comptes.

## 10. API et page « Sources »

### 10.1 Routes (`/api/v1`)

| méthode | chemin | rôle |
|---|---|---|
| GET | `/sources?kind=&all=1` | liste avec état calculé, dernière lecture, badges (`new_version`, `suggested`, `archived`) |
| GET | `/sources/{key}` | détail : hôtes, purpose, règle présente, config fusionnée (sans secret), items récents, relevé GitHub |
| POST | `/sources/{key}/enable` | corps `{consent: true}` obligatoire quand l'entrée a des hôtes ; écrit la règle (§ 3.4) ; 409 si `consent` manque avec le texte d'accord à afficher |
| POST | `/sources/{key}/disable` | `{forget: bool}` |
| POST | `/sources` | ajout d'une entrée `user` (mêmes validations que la CLI) |
| DELETE | `/sources/{key}` | `remove` ; 409 si un skill installé exige confirmation (`{confirm: true}`) |
| POST | `/sources/reset` | `{key}` ou `{all: true}` |
| POST | `/sources/{key}/update` | lecture immédiate de cette entrée (bornée, synchrone, 5 min) |
| GET | `/sources/{key}/preview?sha=` | aperçu d'installation ou d'`upgrade` (§ 7.3) |
| POST | `/sources/{key}/install` | `{sha}` ; `/upgrade` identique |
| POST | `/sources/{key}/run` | `{project}` ; plugin ; 202 + `plugin_run` id, suivi par `GET /plugin-runs/{id}` |
| GET | `/sources/items?unread=1&since=` | « À lire » ; `POST /sources/items/{id}/read` |
| GET | `/sources/discoveries` ; `POST /sources/discoveries/{repo}` `{action: add\|ignore}` | « À découvrir » |
| GET | `/tech` ; `POST /tech` `{tag}` ; `DELETE /tech/{tag}` | technologies globales |

Les réponses passent par les mêmes vues assainies que le reste de l'API (aucun chemin absolu, aucune commande, aucun secret). `GET /today` gagne `catalog`, `reading` (items à lire), `discover`, et chaque paquet/faille gagne `kev`, `epss`, `malicious`, `kind`.

### 10.2 Page

Navigation à deux onglets dans l'en-tête : **Aujourd'hui** | **Sources** (route `#/sources`, pas de routeur externe : un `hash` et un `v-if`, mon choix). Page Sources :

1. En-tête : « Tes sources » + phrase de Michel (« 8 sources actives, 2 attendent ton accord, dernière mise à jour ce matin 06:31 »), bouton « Mettre à jour maintenant ».
2. Une section par sorte, dans l'ordre OSV, Enrichissements, Veille, Plugins, Skills, Serveurs MCP, Références ; chaque ligne : nom, chip d'état (`active` / `attend ton accord` / `désactivée` / `suggérée pour toi` / `nouvelle version`), hôte(s) en petit, dernière lecture (« il y a 2 h · 14 nouveautés » ou l'erreur en langage courant), interrupteur, menu (détail, mettre à jour, retirer, réinitialiser).
3. **Dialogue d'accord** à l'activation : le texte de § 3.4, la règle exacte qui va être écrite, « Michel va écrire cette ligne dans ton fichier de politique », boutons « D'accord » / « Pas maintenant ».
4. **Dialogue d'installation** (skill, MCP) : fichiers, licence, note de confiance, 40 lignes d'aperçu, ce qui sera écrit et où ; pour un MCP, la ligne `claude mcp add …` avec bouton copier.
5. « Ajouter une source » : formulaire par sorte (URL + format pour un flux, écosystème pour OSV, dépôt + chemin + commit pour skill/MCP, format + fichier pour plugin) ; les champs expliquent *pourquoi* on les demande.
6. « À découvrir » en bas : cartes avec étoiles, description, « ajouter » / « ignorer ».
7. Page Aujourd'hui : bandeau « exploitée activement » en tête quand il y en a, section « À lire » avec bouton « lu », ligne « catalogue » dépliable.

Textes dans `web/src/i18n/{fr,en}.json`, relus par le relecteur francophone ; textes générés (états, erreurs) arrivent traduits de l'API.

## 11. Migration `0005_sources.sql`

- `source`, `feed_item`, `kev`, `epss`, `cve_enrichment`, `plugin_run`, `discovery`, `tech` (colonnes § 3.1, § 5.1, § 6.1, § 7.2, § 7.4) et leurs index (`feed_item(source_id, published_at)`, `finding(kind)`, `finding(kev)`).
- `finding` : `+ kind TEXT NOT NULL DEFAULT 'dependency'`, `+ source_key TEXT NOT NULL DEFAULT ''`, `+ rule_id TEXT NOT NULL DEFAULT ''`, `+ location TEXT NOT NULL DEFAULT ''`, `+ fingerprint TEXT NOT NULL DEFAULT ''`, `+ kev INTEGER NOT NULL DEFAULT 0`, `+ kev_added TEXT NOT NULL DEFAULT ''`, `+ epss REAL NOT NULL DEFAULT 0`, `+ epss_percentile REAL NOT NULL DEFAULT 0`, `+ malicious INTEGER NOT NULL DEFAULT 0`, `+ cvss_enriched REAL NOT NULL DEFAULT 0`.
- `decision` : `+ seen_kev INTEGER NOT NULL DEFAULT 0`.
- `project` : `+ tech TEXT NOT NULL DEFAULT '[]'`, `+ tech_auto TEXT NOT NULL DEFAULT '[]'`.
- `scan` : statut `empty` ajouté aux valeurs (pas de contrainte SQL).

Portable : pas de `rowid`, `AUTOINCREMENT`, `datetime()` ; `REAL` pour les scores ; dates `TEXT` RFC 3339 UTC.

## 12. Ordre de réalisation (tâches du plan)

Deux vagues exécutables l'une après l'autre, chaque tâche livrant quelque chose d'utilisable seul :

**Vague A — registre, données, KEV**
1. Migration `0005`, `internal/source` (modèle, repo, catalogue embarqué, `Sync`, états), accord + écriture de la règle + `Gateway.SetRules`, `michel source list|show|enable|disable|add|remove|reset`, `michel tech`, `project set --tech`.
2. OSV dynamiques (`osvdb.Enabled`, `Require` sur les écosystèmes trouvés, `db update|status` sur les activés), `yarn.lock` et `pnpm-lock.yaml` (scan, `checkContent`, lecteurs de graphe dans `analyze`), statut `empty`, drapeau `malicious`.
3. KEV et EPSS : lecteurs, tables, `enrich.Apply`, colonnes dénormalisées, `EffectiveSeverity`, `seen_kev` + `kev_changed`, gabarits *what/impact* (FR relu), digest (tête « exploitées activement », titre, attention), CLI (`[KEV]`), `Risk.Terms.exploited` + `urgency`, `docs/remediation-risk*.md`.
4. Enrichissements à la demande (Vulnrichment, NVD avec clé optionnelle, CIRCL), plafonds, `cvss_enriched`.
5. `michel source update` (orchestration, budget GitHub, événements), `scan --all --update --digest`, `Digest.Catalog` + rendu (FR relu), `decide --package` résumé, chaîne de supersessions, `empty_projects` dans le digest.

**Vague B — veille, dépôts, plugins, page**
6. Flux : lecteurs rss/atom/page/github_advisories, `feed_item`, `tech_rules` et `tech_auto`, filtre « à lire », `michel source items|read`, section « À lire » du digest (FR relu).
7. Skills et MCP : récupération épinglée, extraction sûre, aperçu + licence + note de confiance, `install|upgrade|remove` avec marqueur, relevé GitHub quotidien, « nouvelle version », `discover.github` et table `discovery`, `michel source discover`.
8. Plugins : `internal/plugin` (`Provider`, lecteurs SARIF et Trivy JSON), `finding.kind` et colonnes, gabarits par `kind`, `michel source run`, proxy de refus `internal/egress/denyproxy`, Trivy (`misconfig`) et Semgrep (argv fermé, faux outils dans les tests), CodeQL et ZAP en lecture, `plugin_run`, enchaînement depuis `michel scan`.
9. API (§ 10.1) et page « Sources » + ajouts « Aujourd'hui » (§ 10.2), tests `httptest`, Vitest sur les fonctions pures (état calculé, regroupement), relecture FR du `fr.json` front, vérification manuelle Chrome notée au ledger.
10. Docs bilingues (`docs/sources.md` + `.fr.md` : les six sortes, l'accord, ce qui sort, les plugins et leur clôture ; `network-egress` ; `daily-digest` ligne planifiée ; `offline-installation` pour les bases supplémentaires ; README), relevé réel sur le poste de Kévin (agrégats seuls : nombre de sources, KEV trouvées, items), hygiène, `deferred-and-rulings.md` du plan 4.

## 13. Choix à contester (résumé) et questions pour Kévin

Questions dont la réponse change ce qui est construit :

1. **KEV et le score de risque.** Le score public mesure le risque de la *correction* ; j'ai fait de KEV un drapeau `exploited` à 0 point plus un qualificatif `urgency: urgent` qui force l'ordre et la formulation (§ 5.3). Si tu veux que KEV **ajoute des points** au score (par exemple `kev: 30` dans `risk:`), dis-le : c'est une ligne de configuration et un paragraphe de doc en plus, mais la recommandation `auto_fix` deviendrait plus rare justement pour les failles les plus urgentes.
2. **Plugins : lancer ou lire.** Michel lance **Trivy (configurations seulement)** et **Semgrep (code PHP et JS, règles placées par toi)** lui-même (argv fermé, proxy de refus), et ne fait que **lire** un rapport CodeQL ou ZAP (§ 7.2). Le catalogue du 23/10 nommait CodeQL : il ne couvre pas PHP et télécharge ses requêtes au premier usage, d'où Semgrep à sa place. Alternative plus prudente : tout en lecture de rapport en plan 4, lancement au plan 6 avec le vrai proxy. Je recommande la première.
3. **Serveurs MCP.** Michel récupère, épingle, montre la licence et **affiche** la ligne `claude mcp add …` ; il n'écrit pas dans la configuration de Claude Code (§ 7.3). Si tu préfères que Michel l'écrive (fichier `~/.claude.json`, portée utilisateur, avec sauvegarde et marqueur), c'est une tâche de plus dans la vague B.

Mes choix, à contester si besoin :

4. Tout désactivé par défaut sauf `osv.packagist` et `osv.npm` (§ 3.2).
5. La règle `network.allow` reste à la désactivation ; `--forget` la retire (§ 3.4).
6. Statut `empty` : exit 0 dans `--all`, rappel hebdomadaire dans le digest (§ 4.3).
7. EPSS affiché seulement à partir du 50ᵉ percentile (§ 5.3).
8. Lecteur `page` = détection de changement sans extraction (§ 6.1) ; listes « awesome » en références, pas lues (§ 7.4).
9. Flux désactivés « suggérés pour toi » par étiquette, jamais activés seuls (§ 6.2).
10. Navigation à deux onglets sans routeur (§ 10.2).
11. Deux vagues d'exécution, un seul design et un seul plan (§ 12).

Arbitrages pris après relecture builder (2026-10-26) :

12. Tête du digest = KEV en attente ou à corriger ; reportées et ignorées en une ligne de compte (§ 5.3).
13. Trivy limité à `misconfig` ; `vuln` attend `trivy image` (plan 11) ; `secret` hors plan 4 ; CVE d'un rapport fourni déjà connues par OSV ignorées (§ 7.1, § 7.2).
14. Semgrep lancé à la place de CodeQL ; CodeQL en lecture SARIF (§ 7.2).
15. Catalogue skills et MCP réduit aux entrées D et S ; le reste documenté comme non proposé (§ 7.3).
16. Règle déjà présente = pas de nouvelle question ; `--forget` refusé si une autre entrée en dépend (§ 3.4).

## 14. Laissé au builder

- Découpage interne de `internal/source` (catalogue, repo, consent, readers) et de `internal/enrich` ; nom exact des tables secondaires.
- Bibliothèques : `encoding/xml` et `compress/gzip` de la stdlib suffisent ; aucun parseur HTML tiers (retrait de balises par expression régulière bornée) ; `yaml.v3` déjà présent pour l'écriture de la règle et les lockfiles YAML.
- Détail du proxy de refus (réponse 403, fermeture de `CONNECT`), tant qu'il est journalisé et testé.
- Heuristique SPDX de la licence et forme de la note de confiance, tant qu'elles sont affichées avant l'accord.
- Composants Vuetify de la page Sources, icônes, densité ; mode sombre existant conservé.
- Noms des clés i18n et des gabarits `kind`.
- Table `tech_rules` du catalogue : liste initiale raisonnable (PHP : symfony, laravel, drupal, wordpress, magento ; JS : vue, react, nextjs, angular, express, nuxt, svelte ; plus `php`, `node` par écosystème), extensible dans le YAML.
