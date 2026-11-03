# Plan 7 : test réel des journaux sur le conteneur

But : vérifier sur de vrais `sh`, `awk`, PHP, PostgreSQL et Monolog ce que les tests automatiques ne prouvent pas. Compte une heure et demie, dont des attentes.

Règles du run :

- **Le conteneur seulement.** Jamais de production, jamais de serveur `hds`.
- **Tout jetable** : conteneur, image, clé, configuration et dossier de données, hors du dépôt, supprimés à la fin.
- **Dans le ledger, seulement des chiffres et des résultats** : ni nom d'hôte, ni adresse, ni empreinte, ni chemin de ton poste.

## 1. Préparer

Suis la section « Sans serveur jetable » de [la checklist du plan 6](../2026-10-31-michel-servers/real-run-checklist.md), jusqu'à la confirmation de l'empreinte et un `target check` réussi, avec ces différences :

- Avec le Docker de WSL, garde une session ouverte pendant tout le test.
- Choisis des ports libres sur ta machine, et garde `127.0.0.1` dans les `-p`.
- Ajoute le serveur avec `--env prod`, pour que les erreurs critiques partent tout de suite.
- Dans le fichier de configuration jetable, ajoute un canal webhook vers un récepteur local qui écrit l'heure et le corps de chaque message dans un fichier, et sa règle `notify.webhook`. Mets `notify.digest_at` à `off` : le résumé partira à l'étape 5.

Le conteneur contient déjà PostgreSQL (avec `%e` à la fin de `log_line_prefix`), `logrotate`, Monolog, l'utilisateur `michel` dans le groupe `adm`, et la page `errors.php`.

Lance `michel serve` avec ton dossier de données jetable, puis déclare ces sources (bloc Journaux, ou `POST /api/v1/targets/<id>/logs/sources`) :

| Chemin | Format |
|---|---|
| `/var/log/php/error.log` | `php` |
| `/var/log/postgresql/postgresql-*.log` | `postgres` |
| `/var/www/app/storage/logs/*.log` | `monolog` |
| un fichier par format sous `/var/log/trap/`, droits `640`, groupe `adm` | `php`, `postgres`, `monolog`, `json`, `text` |
| un fichier `600` de `root` | `text` |

## 2. Journal piégé et vraies erreurs

Après la première lecture (elle ne fait que repérer la fin des fichiers), écris le corpus `internal/serverlog/testdata/trap.log` dans chaque fichier piégé, puis provoque de vraies erreurs avec tes marqueurs :

```sh
curl "http://127.0.0.1:<port>/errors.php?kind=php&m=<marqueurs>"
curl "http://127.0.0.1:<port>/errors.php?kind=db&m=<marqueurs>"
curl "http://127.0.0.1:<port>/errors.php?kind=db-fatal&m=<nom>"
curl "http://127.0.0.1:<port>/errors.php?kind=app&m=<marqueurs>"
```

| Vérifie | Attendu |
|---|---|
| Lignes écrites sur le serveur | les marqueurs y sont : l'erreur est bien réelle |
| Fichier `600` | indiqué comme non lu, avec la raison du groupe `adm` |
| Erreurs sur la fiche | type PHP, code `SQLSTATE` PostgreSQL, classe et canal Monolog |
| Marqueurs (`grep -ai`) dans le dossier de données : base, journal d'audit | **0** |
| Marqueurs dans les messages reçus | **0** |
| Marqueurs dans `michel target logs list --json` et le journal de `serve` | **0** |
| `michel audit verify` | code `0` |

## 3. Délai réel

Provoque une erreur critique juste après une lecture : c'est le pire cas. Note l'heure d'écriture et l'heure d'arrivée au récepteur, sur plusieurs essais.

Attendu : **moins de 10 min** à l'intervalle par défaut de 5 min.

## 4. Texte nettoyé

Active le texte (réglage, avec confirmation), dans les alertes aussi. Provoque les mêmes erreurs.

| Vérifie | Attendu |
|---|---|
| Sans confirmation | refus |
| Email, IP, nombres, URL dans les messages | absents |
| Nom sans guillemets | il peut rester : c'est la limite que la documentation annonce |
| Base, sur Windows | texte illisible en clair |
| Retour à « Aucun » | texte effacé, `log.purge` à l'audit |

## 5. Poste coupé puis repris

Tue `serve` sans lui laisser le temps de finir. Pendant plus de 30 minutes, provoque des erreurs, dont une juste avant le retour. Mets `notify.digest_at` à une heure déjà passée, puis relance `serve`.

| Vérifie | Attendu |
|---|---|
| Erreurs écrites pendant la coupure | lues à la première passe, dans la limite du plafond, et alerte envoyée |
| Délai après le retour | une passe, quelques secondes |
| Résumé envoyé par `serve` quelques secondes après la première passe | les erreurs de cette passe, et la période non lue avec ses dates |

## 6. Rotation réelle

Lance de vraies rotations avec `logrotate -f` : `create` sur `/var/log/php/error.log`, `copytruncate` sur le fichier de Monolog. Provoque une erreur juste avant et juste après chacune. Un intervalle de 1 min fait gagner du temps.

| Vérifie | Attendu |
|---|---|
| Nouvelle erreur | lue depuis le début du nouveau fichier |
| Erreur écrite juste avant la rotation `create` | perdue, comme la documentation le dit |
| Note de rotation | sur la fiche |
| `copytruncate`, fichier déjà plus long que la position | le début est manqué, sans note : limite annoncée |
| Compte | pas de double comptage de l'ancien contenu |

## 7. Je ne lis plus (si tu as le temps)

Coupe `sshd` dans le conteneur pendant plus de 30 minutes, avec `serve` lancé et un intervalle de 1 minute.

Attendu : **une seule** alerte, après 3 échecs et 30 minutes, puis le retour à la normale quand `sshd` revient.

## 8. Nettoyage

Arrête `serve`, l'agent de test et le récepteur. Puis `docker rm -f` du conteneur, `docker rmi` de son image, et supprime le dossier jetable. Ne touche pas aux autres conteneurs de la machine. Vérifie qu'il ne reste rien, et que `git status` ne montre aucune trace du run.

## Ce que ce test ne prouve pas

Ni l'agent OpenSSH de Windows s'il passe par un agent de test, ni un vrai réseau, ni le réglage d'un hébergeur, ni un mutualisé, ni un serveur à l'heure locale.
