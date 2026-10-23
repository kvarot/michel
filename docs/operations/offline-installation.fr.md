# Installation hors ligne

🇬🇧 English version : [offline-installation.md](offline-installation.md)

Michel analyse les lockfiles à partir de bases OSV stockées sur disque. Un scan ne touche jamais le réseau. Seul `michel db update` le fait, et seulement si tu l'autorises explicitement.

## Compilation

Nécessite Go 1.27 ou plus récent.

```
go build -o bin/michel ./cmd/michel        # Linux, macOS
go build -o bin/michel.exe ./cmd/michel    # Windows
bin/michel version
```

La page « Aujourd'hui » (`michel serve`) est intégrée au programme. Pour la reconstruire depuis `web/`, lance `make web` (nécessite Node et npm ; `make build` le fait tout seul quand npm est présent) avant `go build`. Sans cette étape, le programme se compile quand même et `michel serve` affiche une courte page de texte.

## Premier lancement et emplacement de la config

Michel lit `config.yaml` et stocke ses données (base SQLite, bases OSV) dans `<dossier de config utilisateur>/michel/`, où le dossier de config utilisateur est celui de `os.UserConfigDir()` en Go :

| Système | Dossier |
|---|---|
| Linux | `~/.config/michel/` (ou `$XDG_CONFIG_HOME/michel/`) |
| macOS | `~/Library/Application Support/michel/` |
| Windows | `%AppData%\michel\` |

Tu peux les remplacer par `--config <fichier>` et `--data-dir <dossier>` (les deux sont requis si aucun dossier de config utilisateur n'existe). Sans fichier de config, les valeurs par défaut `strict_local` s'appliquent : tout accès réseau sortant est refusé. `config.example.yaml` liste chaque valeur par défaut. Michel refuse de démarrer si le fichier de politique est illisible.

Les bases OSV sont dans `<data-dir>/osv/`, sauf si `db.osv_path` est défini.

## Mettre à jour les bases (machine connectée)

Les téléchargements sont refusés par défaut. Ajoute une règle d'autorisation dans `config.yaml` :

```yaml
sovereignty:
  network:
    allow:
      - host: osv-vulnerabilities.storage.googleapis.com
        purpose: osv.db
```

Puis :

```
michel db update
michel db status
```

`db update` télécharge `Packagist/all.zip` et `npm/all.zip` depuis le bucket OSV, vérifie le zip, l'installe de façon atomique (l'ancienne base est conservée en cas d'échec) et écrit un fichier `fetched_at` à côté de chaque zip : `<racine osv>/osv-scalibr/<écosystème>/fetched_at` (date RFC 3339). `db status` affiche `STALE` quand cette date a plus de 7 jours. Une base copiée autrement, sans fichier `fetched_at`, est utilisée normalement mais n'affiche aucune date et est signalée `STALE`.

## Copie vers une machine isolée

1. Sur la machine connectée, lance `michel db update`.
2. Copie tout le dossier `osv/` (fichiers `fetched_at` compris) vers la machine isolée, dans `<data-dir>/osv/` ou à l'endroit désigné par `db.osv_path`.
3. Sur la machine isolée, aucune règle d'autorisation n'est nécessaire. Vérifie avec `michel db status`.

## Scanner

```
michel project add /chemin/du/projet --name monprojet --classification sensitive
michel scan --project monprojet
michel findings --project monprojet [--status new] [--severity critical]
michel audit verify
michel audit list --last 20
```

`scan` cherche les fichiers `composer.lock` et `package-lock.json`, en ignorant tout dossier `vendor/` et `node_modules/`. Une base OSV absente fait échouer le scan avant tout le reste, en indiquant la commande pour y remédier. Un manifeste corrompu est consigné comme échoué (statut de scan `partial`) et les autres manifestes sont quand même analysés. `audit verify` contrôle la chaîne de hachage du journal d'audit. Après un scan hors ligne, `audit list` ne doit montrer aucun événement `egress.attempt`.

## Analyse

```
michel analyze --project monprojet [--force]
michel analyze --all
michel scan --project monprojet [--no-analyze]
```

`analyze` ne lit que les fichiers du projet (jamais le réseau, jamais une IA). Pour chaque finding nouveau ou en attente, il détermine comment le paquet est atteint (direct ou transitif, via quels paquets), quelle mise à jour le corrige et si ta contrainte de version l'autorise, où ton code utilise le paquet, quels tests couvrent ce code, ce que dit le journal des modifications local, puis un score de risque avec une recommandation (`auto_fix`, `handoff`, `report_only` ; voir [remediation-risk.fr.md](../remediation-risk.fr.md)). `scan` le lance automatiquement sauf avec `--no-analyze`. `--force` recalcule les analyses encore fraîches. La qualité de la recherche dépend de l'installation locale des dépendances (`vendor/`, `node_modules/`) : sans elles, Michel se rabat sur une recherche par nom plus faible et le dit.

## Un finding en détail

```
michel finding <id-ou-préfixe> [--lang fr] [--json]
michel findings --project monprojet --severity critical --explain
```

`finding` affiche trois phrases : Quoi (comment le paquet est utilisé dans ton code), Impact (gravité et probabilité que ça te concerne), Coût (taille de la mise à jour, journal des modifications, tests, ce que Michel peut faire). Un préfixe d'id suffit s'il est sans ambiguïté. `findings --explain` affiche la même phrase « Quoi » sous chaque ligne.

## Langue

`--lang en|fr` (toute commande qui t'affiche du texte) l'emporte sur `assistant.lang` du fichier de politique, `auto` par défaut : la langue du système, l'anglais si ce n'est pas le français. La langue ne change que la formulation : les faits, le score et les clés JSON sont identiques. Les textes gardés dans le dossier de données (erreurs de scan, erreurs de canaux, preuves du journal d'audit) restent en anglais.

## Décisions, digest, notifications et page « Aujourd'hui »

```
michel decide <id-ou-préfixe> fix|defer|ignore [--why "..."] [--for 30d | --until AAAA-MM-JJ]
michel decide --project monprojet --package vendor/lib defer
michel decisions --project monprojet [--status superseded]
michel digest [--send] [--since AAAA-MM-JJ] [--html | --json]
michel scan --all --digest
michel notify list
michel notify test <canal>
michel secret set|list|delete <nom>
michel serve [--listen 127.0.0.1:7331] [--open]
```

Aucune de ces commandes n'a besoin du réseau, sauf `digest --send`, `scan --all --digest` et `notify test` sur un canal e-mail ou webhook : il leur faut alors une règle d'autorisation pour le serveur de ce canal. Tout est expliqué dans [daily-digest.fr.md](daily-digest.fr.md), y compris comment lancer le digest automatiquement chaque matin.

## Réglages par projet

```
michel project set monprojet --core-package vendor/core --core-package autre-lib
michel project set monprojet --risk major_jump=50 --risk many_call_sites_threshold=20
```

`--core-package` remplace toute la liste des paquets dont la mise à jour est plus risquée pour ce projet (`--core-package ''` la vide). `--exclude <nom-de-dossier>` (tu peux le répéter) remplace la liste des dossiers que les scans et les analyses ignorent, où qu'ils se trouvent dans le projet, en plus de `vendor/` et `node_modules/` (`--exclude ''` la vide), par exemple `michel project set monprojet --exclude fixtures --exclude legacy`. `--risk clé=valeur` remplace une valeur de la section `risk.*` de la politique pour ce projet seulement ; les autres remplacements sont conservés. Les analyses stockées gardent une empreinte de ces réglages : elles sont donc recalculées au scan suivant ou avec `michel analyze --project monprojet`, sans `--force`. Les clés et seuils sont décrits dans [remediation-risk.fr.md](../remediation-risk.fr.md) et listés dans `config.example.yaml`.

## Scripts

`michel scan --json` affiche un objet :

```json
{
  "results": [
    {
      "scan_id": "...", "project": "monprojet", "status": "ok",
      "manifests": [{"rel_path": "composer.lock", "ecosystem": "Packagist", "lock_sha256": "...", "packages": 120, "findings": 40}],
      "new": 0, "still": 40, "reappeared": 0, "gone": 0,
      "by_severity": {"critical": 4, "high": 10, "medium": 20, "low": 6}
    }
  ],
  "failures": [{"project": "...", "error": "..."}]
}
```

`failures` liste les projets dont le scan n'a pas pu s'exécuter du tout ; elle est vide en cas de succès. Les sévérités sans finding sont omises de `by_severity`.

`michel analyze --json` affiche un objet :

```json
{
  "results": [{"project": "monprojet", "analyzed": 42, "skipped": 3, "failed": 0, "duration_ms": 1234}],
  "failures": []
}
```

`michel finding <id> --json` affiche `{"finding": {...}, "analysis": {...}, "explanation": {...}}`. `finding` est le finding stocké (id, paquet, versions, sévérité, statut...). `analysis` vaut `null` tant que le finding n'est pas analysé ; ses clés sont en snake_case et stables :

```json
{
  "finding_id": "...", "project_id": "...", "computed_at": "...", "michel_version": "...", "inputs_hash": "...",
  "path": {"directness": "direct|transitive|unknown", "via": [], "constraint": "^1.2"},
  "has_root_manifest": true,
  "upgrade": {"target": "1.2.5", "jump": "patch|minor|major|unknown|none", "constraint_allows": true},
  "calls": {"sites": [{"file": "src/Http/ApiClient.php", "line": 41, "is_test": false}], "count": 3,
            "quality": "psr4|name|low|noautoload|import", "namespaces": [], "unreadable": 0,
            "unreadable_paths": [], "test_files": [], "test_file_count": 0, "test_hit_count": 0, "source_files": []},
  "coverage": {"test_files": [], "count": 0, "method": "callsite|reference|none", "skipped": [], "unreadable": 0},
  "changelog": {"source": "...", "excerpt": "...", "available": true, "breaking": false, "breaking_lines": [], "note": ""},
  "risk": {"score": 30, "recommendation": "auto_fix|handoff|report_only", "warning": false, "terms": {"no_tests": 20, "direct": 10}}
}
```

Les lignes de code elles-mêmes n'y figurent jamais. `explanation` contient les trois phrases (`what`, `impact`, `cost`) dans la langue demandée.
