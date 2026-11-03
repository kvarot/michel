# Serveurs : suis-je touché, et corriger sans rien casser

🇬🇧 English version : [servers.md](servers.md)

Avec le plan 6, Michel regarde ce qui tourne vraiment sur tes serveurs (PHP, le serveur web, les paquets du système, les réglages de PHP), le compare aux failles connues et à un jeu de règles de configuration, te prévient, puis prépare la correction sous forme de **deux scripts lisibles, `appliquer` et `annuler`**, que tu valides. La question de départ : avec une faille comme PHP2Shell, « est-ce que je suis touché sur mon serveur ? » Michel y répond sans que tu tapes une commande.

Deux peurs guident tout : **un bug en production**, et pire, **un effacement**. Michel n'a aucune action qui supprime quoi que ce soit, et chaque changement est sauvegardé avant et peut être annulé.

Tout se fait depuis la page **Serveurs** (`michel serve`). La ligne de commande (`michel target …`, `michel fix resolve`) sert aux scripts et aux cas décrits plus bas.

## Sommaire

1. [Trouver tes serveurs](#1-trouver-tes-serveurs)
2. [Préparer un utilisateur SSH et une clé pour Michel](#2-préparer-un-utilisateur-ssh-et-une-clé-pour-michel)
3. [Confirmer l'empreinte](#3-confirmer-lempreinte)
4. [Ce que Michel lit, et ne lit jamais](#4-ce-que-michel-lit-et-ne-lit-jamais)
5. [Suis-je touché ? Les sources](#5-suis-je-touché--les-sources)
6. [Une correction : les scripts et leurs actions](#6-une-correction--les-scripts-et-leurs-actions)
7. [Qui lance le script, et sudo](#7-qui-lance-le-script-et-sudo)
8. [Préprod, snapshot, sauvegardes](#8-préprod-snapshot-sauvegardes)
9. [Les quatre niveaux, et l'agent](#9-les-quatre-niveaux-et-lagent)
10. [Alertes et SMS](#10-alertes-et-sms)
11. [En cas de problème](#11-en-cas-de-problème)
12. [Les limites à connaître](#12-les-limites-à-connaître)
13. [Les journaux des serveurs : être prévenu sans les copier](#13-les-journaux-des-serveurs--être-prévenu-sans-les-copier)

## 1. Trouver tes serveurs

**Trouver mes serveurs** (ou `michel target discover`) propose une liste ; tu coches, rien n'est ajouté tout seul. Michel regarde :

- `~/.ssh/config` : `Host`, `HostName`, `User`, `Port`, `IdentityFile` (le chemin, jamais le contenu d'une clé) ;
- les projets que Michel suit déjà : `.idea/deployment.xml` et `.idea/webServers.xml` de PhpStorm, y compris les serveurs qui utilisent une *configuration SSH enregistrée* (Michel lit `sshConfigs.xml` de PhpStorm et son dossier d'options, uniquement pour l'hôte, le port et l'utilisateur). Cela dit quel projet est déployé sur quel serveur, dans quel dossier distant. Tu peux corriger le lien. Les mots de passe de PhpStorm sont dans le coffre du système : Michel ne les cherche pas.

Toutes ces lectures sont en lecture seule. Michel n'écrit rien dans un projet ni dans `~/.ssh`.

Tu peux aussi ajouter un serveur à la main (`michel target add <alias|hôte> --user …`). Noms d'hôte et adresses IPv4 seulement : une adresse IPv6 est refusée (utilise le nom d'hôte).

**Ajouter un serveur, c'est ton accord pour le réseau** : Michel écrit alors les deux règles dont il a besoin dans le fichier de politique (`target.ssh` vers l'hôte, `target.http` vers l'adresse du site si tu en as donné une). Rien d'autre n'ouvre jamais de connexion vers un serveur. Supprimer le serveur retire les règles **que Michel a écrites** ; une règle que tu as écrite à la main n'est jamais retirée.

Un serveur a un *type* (`vps`, `shared` pour un mutualisé, ou `hds` pour un serveur qui héberge des données de santé : il est alors classé `health`, ce qui ne se change pas) et un *rôle* (`prod`, `preprod`, `dev`).

## 2. Préparer un utilisateur SSH et une clé pour Michel

Michel se connecte **uniquement avec les clés de ton agent SSH**. Il ne lit jamais un fichier de clé privée, ne stocke aucune clé, ne demande ni n'envoie jamais de mot de passe.

1. **Crée une clé** (ou prends-en une que tu as), de préférence une clé rien que pour Michel : `ssh-keygen -t ed25519 -f ~/.ssh/michel_ed25519`.
2. **Mets la clé publique sur le serveur**, dans le `~/.ssh/authorized_keys` de l'utilisateur SSH : `ssh-copy-id -i ~/.ssh/michel_ed25519.pub utilisateur@serveur`.
3. **Charge la clé dans ton agent** :
   - Windows : démarre le service *OpenSSH Authentication Agent* (Services, démarrage automatique), puis `ssh-add $env:USERPROFILE\.ssh\michel_ed25519`.
   - Linux et macOS : `ssh-add ~/.ssh/michel_ed25519` (Michel utilise `SSH_AUTH_SOCK`).
   - Pageant (PuTTY) : mets Pageant en mode compatible OpenSSH et donne son tube ou sa socket à Michel avec `ssh.agent_pipe` (voir plus bas). Ce chemin **n'est pas testé** par les auteurs.
4. **Choisis l'utilisateur.** Les droits de l'utilisateur SSH décident de ce que Michel peut voir et faire ; Michel fait avec, et ne cherche jamais à contourner un refus. Un utilisateur dédié, en lecture, est une bonne idée. Si cet utilisateur ne peut pas lire un fichier, le serveur le montre dans la liste « non vu ».

`ssh.agent_pipe` (dans la section `ssh:` du fichier de politique, voir `config.example.yaml`) : vide, Michel prend l'agent du système. Sinon, un tube nommé Windows (`\\.\pipe\…`) ou le chemin complet d'une socket Unix locale, même sous Windows. Une socket doit se trouver dans un dossier où toi seul peux écrire : celui qui la contrôle voit les demandes de connexion de Michel.

Un serveur qui n'accepte qu'un **mot de passe** ne peut pas être utilisé : Michel le dit et montre comment installer une clé. Il ne se connectera pas par mot de passe.

## 3. Confirmer l'empreinte

La première fois, Michel montre l'**empreinte** du serveur (`SHA256:…`). Tu la compares à celle que ton hébergeur te donne (ou que tu obtiens toi-même depuis le serveur), puis tu confirmes sur la page (`michel target trust <id> --fingerprint SHA256:…`). Elle peut aussi venir de ton `~/.ssh/known_hosts`.

Une empreinte confirmée est gardée par Michel et utilisée **seule** : `known_hosts` n'est consulté que tant qu'aucune empreinte n'est confirmée. Ensuite, un serveur qui présente une autre clé est **refusé**, toujours : voir [l'empreinte a changé](#empreinte-changee). Jamais d'acceptation automatique.

Chaque connexion est écrite dans le journal d'audit (`target.connect` : serveur, utilisateur, empreinte, durée, résultat).

## 4. Ce que Michel lit, et ne lit jamais

Michel lance une **liste fermée de commandes de lecture**, construites par lui, dans une seule session SSH, et n'installe rien sur le serveur :

- système : `/etc/os-release`, `uname -r` ;
- PHP : `php -v`, `php -m`, `php --ini`, et les réglages de PHP, pour la ligne de commande et pour chaque `php-fpm` trouvé ;
- serveur web : `nginx -v`, `apache2 -v` / `httpd -v` ;
- paquets : `dpkg-query`, `rpm -qa`, `apk info` selon le système ;
- fichiers de configuration : seulement ceux que PHP et le serveur web désignent, les `.user.ini` des dossiers de déploiement liés, et ceux que tu ajoutes (taille plafonnée).

Ce que cette vérification ne lit **jamais** : les dossiers de données, les bases de données, les dossiers personnels des autres utilisateurs, les journaux, les clés privées, et tout ce qui n'est pas un fichier de configuration. Sur un serveur de type `hds`, tu ne peux ajouter aucun chemin à cette vérification. Les fichiers de journaux sont un chemin à part : seulement ceux que tu déclares, avec leur propre filtre, sur tout type de serveur ([section 13](#13-les-journaux-des-serveurs--être-prévenu-sans-les-copier)).

- **Aucun secret n'est conservé.** Les valeurs de `password`, `secret`, `key`, `token`, les DSN et les réglages secrets connus sont masquées avant d'être stockées ; la base garde le nom du réglage, une valeur non secrète, le fichier et la ligne, plus l'empreinte du fichier, jamais le fichier brut.
- **Les liens symboliques** ne sont pas suivis pour lire un fichier que PHP ne désigne pas.
- Ce que Michel n'a pas pu lire est listé comme **non vu** (« `php.ini` illisible avec l'utilisateur deploy »), en clair. Il n'essaie jamais un autre moyen. À noter : un `.user.ini` illisible garde ouvertes toutes les alertes de réglages de ce serveur, ce qui est large exprès.
- Les commandes supposent un shell de connexion POSIX pour l'utilisateur SSH. La recherche des programmes (`command -v`) demande d'abord `sh`, présent partout : si le shell de connexion ne connaît pas `command` (csh, tcsh), Michel le voit. La recherche de PHP est alors notée **non vue**, et les alertes PHP du serveur restent ouvertes : jamais « PHP absent ».
- Plafonds : 60 s par commande, 5 min par collecte, 1 Mio de sortie par commande, 256 Kio par fichier de configuration.

### Le PHP de la ligne de commande n'est pas toujours celui du site

Le `php` d'un terminal peut être une autre version que celle qui sert le site (PHP-FPM, autre `php.ini`, réglages par site). Michel lit **les deux** quand il les trouve, et dit quand il n'a vu que la ligne de commande. Si tu donnes l'adresse du site (`--site-url`), Michel lit aussi les en-têtes `Server` et `X-Powered-By` par une simple requête GET, comme un navigateur. Il ne détecte pas tous les cas : voir [les limites](#12-les-limites-à-connaître).

### Quand Michel vérifie

Une fois par jour par défaut ; par serveur : toutes les N heures, ou **seulement à la main** ; **Vérifier maintenant** ou `michel target check <id>` à tout moment. `michel serve` fait tourner le calendrier ; s'il ne tourne pas, le digest le dit. Quand une base de failles est mise à jour, Michel compare de nouveau ce qu'il a déjà gardé, **sans se connecter au serveur**. Si une nouvelle faille grave touche une version que tu utilises, il t'alerte tout de suite. La prochaine connexion la confirme.

## 5. Suis-je touché ? Les sources

- **Paquets du système** : les bases OSV des distributions (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat…), **désactivées par défaut**. Michel propose d'activer celle du système vu sur le serveur (`michel source enable osv.debian`, même accord que dans [sources.fr.md](sources.fr.md)) ; `michel target check` affiche la commande exacte quand il en manque une. La version est jugée d'après la base de la distribution, pas d'après `php -v` : les distributions corrigent sans changer le numéro amont.
- **Règles PHP** : un jeu de règles embarqué, versionné, déterministe (sans IA). Chacune a un réglage, une valeur à risque, une valeur conseillée, une gravité et une explication en clair : `display_errors` activé en production, `expose_php`, `allow_url_include`, `open_basedir` vide en mutualisé, `session.cookie_secure`, une branche de PHP qui n'est plus suivie, et PHP2Shell. Un réglage que PHP ne lit que dans la configuration principale (`PHP_INI_SYSTEM`) n'est pas « corrigé » par un `.user.ini`.
- **PHP2Shell** (CVE-2026-109618 et CVE-2026-109619, déjà utilisées par des attaquants) : jugé sur la **version**. Corrigé dans PHP 8.5.12, 8.4.27, 8.3.36 et 8.2.35 ; une branche plus ancienne que 8.2 est traitée comme non suivie et touchée. Michel peut proposer `session.upload_progress.enabled=0`, étiqueté **« réduit le risque, ne corrige pas »** : seule la mise à jour corrige. Il ne propose jamais `memory_limit=-1`.
- La liste des failles de PHP embarquée dans Michel n'est à jour que si ta version de Michel l'est (mets Michel à jour pour la mettre à jour).
- Si Michel n'a pas pu lire la version de PHP, il alerte « version de PHP illisible ». Il ne dit jamais « rien à signaler » quand la version de la distribution est inconnue ou que des paquets n'ont pas pu être jugés.

La fiche du serveur dit **touché / pas touché / pas pu tout voir**, liste les failles, et la liste « non vu ». Une faille dans le code d'un projet indique où il est déployé (« déployé sur : serveur X (prod) »).

## 6. Une correction : les scripts et leurs actions

Une correction n'est jamais du texte libre. C'est une **suite d'actions prises dans une liste fermée**, que Michel traduit en un script shell POSIX lisible (`sh`, compatible dash et busybox) :

| Action | Ce qu'elle fait | Annulation |
|---|---|---|
| `backup_file` | copie un fichier de configuration dans le dossier de sauvegardes du serveur et rapatrie la copie sur ton poste | rien à annuler |
| `set_directive` | met un réglage PHP dans un fichier autorisé : le `php.ini` que PHP charge (et ses autres fichiers ini), un pool PHP-FPM, ou un `.user.ini` | remet le fichier sauvegardé |
| `test_config` | `php-fpm -t`, ou fait lire l'ini par PHP ; un échec arrête tout avant le moindre rechargement | aucune |
| `reload_service` | `systemctl reload` d'un service PHP-FPM, jamais `restart` | rechargement une fois les fichiers remis |
| `package_upgrade` | met à jour **un** paquet vers **une** version exacte | **pas de script** : ton snapshot est le retour |
| `check_site` | une requête GET sur l'adresse de ton site, depuis ton poste | aucune |

- **Aucune action ne supprime quoi que ce soit.** Pas de `rm`, pas de vidage, pas de base de données. Le seul fichier écrit est un fichier de configuration déjà présent, sauvegardé juste avant. Si un réglage n'est nulle part, Michel **ajoute une ligne** à la fin du `php.ini` chargé (ou du `.user.ini` en mutualisé), jamais un nouveau fichier dans `conf.d`.
- Chaque correction produit deux scripts, `appliquer` et `annuler`, plus un texte « ce que ça fait ». Une empreinte SHA-256 couvre les scripts et la liste des vérifications, avec le serveur et la correction ; **ce que tu valides est exactement ce qui est lancé**, et Michel revérifie avant l'envoi.
- `appliquer` se protège lui-même : `set -eu`, et un `trap` qui remet les fichiers sauvegardés et recharge si une étape échoue après un changement, puis sort avec le code `9`. Les nouvelles copies sont préparées, et chaque ligne vérifiée, avant que le `trap` ne soit posé : le code `5` (la ligne a changé) veut toujours dire que rien n'a été modifié. Ça vaut aussi quand tu le lances toi-même.
- Ordre fixe : sauvegarde, changement, test de configuration, rechargement, vérification du site, nouvelle collecte du serveur. Une étape qui échoue arrête tout.
- Michel n'écrit que de la **configuration PHP**. Pour nginx et Apache, il signale et explique quoi changer ; il n'écrit rien.
- **Pas testable, pas de script.** Une correction recharge PHP, et Michel ne le fait pas sans avoir testé la configuration. Le test ne se lance qu'avec des binaires PHP nommés `php` ou `php-fpm` (avec une version éventuelle) dans `/usr/bin`, `/usr/sbin`, `/usr/local/bin` ou `/usr/local/sbin`. Un PHP ailleurs (`/opt/…`, compilé à la main) n'a **aucun script**, même pas pour toi, et Michel explique pourquoi.
- Une mise à jour de paquet est d'abord essayée à blanc par le gestionnaire de paquets (`apt-get -s`, `dnf --assumeno`, `apk --simulate`). Si elle supprimerait ou remplacerait un paquet, si c'est un retour en arrière de version, ou si elle passe à une autre branche de PHP ou à une version majeure, la correction est **refusée** : « la mise à jour retirerait X ». Les mises à jour majeures sont seulement expliquées.
- Un fichier qui est un lien symbolique (par exemple les liens de `conf.d` vers `mods-available` sur Debian) n'est jamais modifié à travers le lien : le script s'arrête, « corrige ce fichier à la main ».

### Quand ça se passe mal

| Situation | Ce que fait Michel |
|---|---|
| Une étape échoue après un changement | le script remet les fichiers, recharge et sort avec le code `9` ; état *annulé*, alerte. Michel lit ce code, ou la dernière ligne du script, avant tout autre code : une commande qui échoue avec son propre code (un rechargement qui sort avec `5`) n'est jamais prise pour « la ligne a changé » |
| Le site ne répond plus après une correction de configuration | `annuler` tout de suite si c'est Michel qui lance ; sinon alerte urgente « lance `annuler` maintenant », script affiché |
| `annuler` échoue lui aussi | alerte urgente, avec les copies sauvegardées à remettre à la main |
| Une mise à jour de **paquet** échoue, ou le site tombe après | **jamais annulée automatiquement** : état *échoué*, alerte urgente « restaure ton snapshot » |
| Le script a dépassé sa limite de temps, ou la connexion a coupé | état **`unknown`** (inconnu) : Michel ne peut pas dire ce qui a changé, alerte urgente, nouvelle collecte, et aucune annulation devinée |

Limites de temps d'un script lancé par Michel : **5 minutes** pour la configuration, **30 minutes** pour les paquets. Michel n'envoie jamais de signal pour arrêter le script (tuer `dpkg` en plein travail est pire qu'attendre). Mais une fois la limite passée, il ferme la connexion : une commande qui écrit encore sur sa sortie peut alors s'arrêter. Une mise à jour de paquet de plus de 30 minutes peut donc être coupée : garde ton snapshot. Une correction échouée n'est jamais relancée : prépare-en une nouvelle (nouvel identifiant).

Si tu lances le script toi-même, voici les codes de sortie :

- `0` : tout va bien.
- `3` : pas lancé par le bon utilisateur (root pour `php.ini` ou un pool, l'utilisateur SSH pour un `.user.ini`).
- `4` : cette correction a déjà été appliquée (pour `annuler` : une sauvegarde manque).
- `5` : la ligne a changé depuis la dernière vérification (rien n'a été modifié).
- `6` : un fichier est un lien symbolique.
- `7` : dossier ou sauvegarde pas sûr.
- `8` : le **retour en arrière a échoué** (urgent : va voir le serveur).
- `9` : une étape a échoué après le changement ; les fichiers ont été remis et PHP rechargé.

Les codes `3` à `7` sont toujours donnés avant tout changement, avec leur ligne d'explication. Voir [en cas de problème](#11-en-cas-de-problème).

## 7. Qui lance le script, et sudo

- **`executor: user`** (par défaut) : la page montre les deux scripts avec un bouton **Copier**. Tu les lances toi-même, puis tu cliques **Je l'ai appliqué**, ce qui lance une vérification.
- **`executor: michel`** : après **Valider**, Michel envoie le script validé par SSH (`sh -s`, rien d'exécutable ne reste sur le serveur hors sauvegardes) et suit chaque étape.

Qui le lance :

- Un script qui touche un fichier appartenant à root (`php.ini`, un pool) tourne **entièrement en root**. Il vérifie d'abord qu'il est root, sinon il s'arrête avant tout changement avec « lance ce script en root ». Avec `executor: michel` et `sudo: nopasswd`, Michel l'envoie par `sudo -n sh -s` (jamais ligne par ligne, et `-n` veut dire qu'il n'attend jamais de mot de passe : s'il en faut un, l'étape échoue et le dit). Sans `sudo`, Michel te propose seulement la correction : tu la lances toi-même.
- Un script `.user.ini` tourne avec l'**utilisateur SSH**, jamais en root.
- Le texte du script ne dépend pas de qui le lance (même empreinte).

## 8. Préprod, snapshot, sauvegardes

- **Préprod d'abord** : si le serveur a une préprod liée, la correction s'y exécute d'abord. La correction de la production est **reconstruite** à partir de l'inventaire de la production (chemins, versions, services), avec sa propre empreinte et son propre Valider (ou les règles du niveau 3). Si la préprod est liée mais ne montre pas la faille, la correction est refusée tant que tu ne la détaches pas ou ne la revérifies pas.
- **Snapshot** : avant tout script avec `package_upgrade`, Michel bloque sur **« fais un snapshot de ce serveur chez ton hébergeur »** ; tu coches **Snapshot fait** (horodaté, journalisé). Sans la case, pas d'exécution, même au niveau 3. Michel n'a jamais accès à ton compte chez l'hébergeur.
- **Sauvegardes** : sur le serveur, un script lancé en root sauvegarde dans `/var/lib/michel/backups/<correction>/` (un dossier réservé à root), un script `.user.ini` dans `~/.michel/backups/<correction>/`. Michel ne les **supprime jamais**, pas même les siennes : vide-les toi-même quand tu veux (`sudo rm -r /var/lib/michel/backups/<correction>` ; la fiche du serveur montre la taille et le dit). `annuler` refuse une sauvegarde qui n'appartient pas à root. Sur ton poste, chaque copie est conservée **chiffrée** (AES-256-GCM, clé dans le coffre de secrets de Michel), 90 jours. Une copie dont la clé est perdue indique « clé perdue » ; celle du serveur reste.
- Seuls les **fichiers de configuration de PHP** sont modifiables : le `php.ini` que PHP charge, les autres fichiers ini qu'il lit, un pool PHP-FPM, un `.user.ini`. Une installation PHP de type cPanel qui n'en fait pas partie n'est pas modifiable. Root n'écrit que dans des dossiers qui lui appartiennent et que personne d'autre ne peut modifier, jamais sous `/home`.

## 9. Les quatre niveaux, et l'agent

Chaque serveur a son propre niveau (`--level`, 1 par défaut) :

| Niveau | Nom | Ce que fait Michel |
|---|---|---|
| 0 | Signaler | l'alerte et la fiche |
| 1 | Expliquer, préparer à la demande | le bouton **Préparer la correction** (par défaut) |
| 2 | Préparer | prépare les scripts de lui-même pour chaque faille ; ils attendent ta validation |
| 3 | Appliquer ce que j'ai autorisé | comme 2, et lance sans clic les corrections qui respectent toutes tes règles |

**Règles du niveau 3.** Michel (jamais un agent) vérifie que toutes ces conditions sont réunies :

1. `executor: michel`.
2. La case « corriger seul les réglages à risque connus » est cochée pour ce serveur.
3. La correction contient seulement des `set_directive` issus des règles de Michel, à leur valeur conseillée (aucun paquet, aucune proposition d'un agent, jamais un `.user.ini`, qui n'a pas de test de configuration).
4. Il y a un test de configuration et une vérification du site (donc un `site_url`).
5. `sudo: nopasswd` si le fichier appartient à root.
6. Si une préprod est liée, la **propre** correction de Michel pour cette faille y a d'abord réussi.
7. Aucune autre tentative n'est en cours sur le serveur (lancée, ou en vérification après le script) ni à l'état `unknown`.
8. Le PHP est testable (voir [section 6](#6-une-correction--les-scripts-et-leurs-actions)).

Les corrections que tu as préparées à la main peuvent se lancer seules si ces règles sont respectées. Le digest et les alertes disent ce qui a été appliqué seul et ce qui a été annulé.

**Une correction à la fois par serveur.** Tant qu'une correction est préparée, attend ta validation, tourne, ou est vérifiée après son script (site, annulation, nouvelle collecte), ou tant que son résultat est `unknown`, Michel ne prépare, ne valide par une règle et ne lance aucune autre correction sur ce serveur, et le serveur ne peut pas être supprimé. Il en va de même à la main : **Préparer la correction** répond qu'une correction est déjà en cours.

Si la ligne a changé (code `5`), Michel revérifie le serveur et prépare **une** nouvelle correction. Si celle-ci trouve à son tour une ligne changée, il n'en prépare pas d'autre, même au niveau 3, et t'alerte : c'est toi qui relances.

**L'agent** (Claude Code, comme dans [fix.fr.md](fix.fr.md)) ne sert qu'à comprendre ou à discuter un cas : une faille combinée, plusieurs réglages possibles, un choix entre mise à jour et contournement. Michel prépare seul les corrections connues (une règle vers sa valeur conseillée, un paquet vers sa version corrigée). L'agent n'a jamais d'accès SSH, ne voit que l'inventaire **masqué**, ne peut pas valider, et n'a aucun outil de fichiers : il propose des actions typées par un seul outil MCP, et Michel vérifie chaque action avant d'assembler les scripts. **L'accord est par serveur**, et c'est celui de la **préprod** quand une préprod est liée (c'est son inventaire qui part). **Tu peux le retirer** à tout moment. Un serveur de type `hds` (`health`) n'a jamais d'agent.

## 10. Alertes et SMS

Les alertes passent par les canaux de [daily-digest.md](operations/daily-digest.md) (mail, notification du bureau, webhook), avec un contenu minimal (« serveur X : 1 faille grave », un lien), jamais une version détaillée ni un réglage. **Un canal limité à certains projets ne reçoit jamais d'alerte de serveur.**

Sur un webhook `generic`, une alerte de serveur est `{"michel_server_alert": 1, "kind": "…", "title": "…", "text": "…"}`, à ne pas confondre avec le message « une correction t'attend » (`michel_fix_waiting`).

Le **SMS** est un type de canal `sms` (`provider: freemobile` pour l'API de Free Mobile, gratuite pour ses abonnés, ou `generic` pour un fournisseur payant, qui reçoit un message signé comme un webhook). Sa clé est dans le coffre de secrets (`michel secret set sms-urgent`), jamais dans le fichier de politique ; le numéro d'identifiant Free Mobile est un champ ordinaire. Il lui faut sa propre règle réseau (`notify.sms`). Le SMS n'est envoyé **que pour l'urgent** : un serveur `prod` avec une faille déjà attaquée (liste KEV) ou critique, un retour arrière qui a échoué, un état `unknown`, une mise à jour de paquet à restaurer par snapshot. Une faille de distribution sans correctif et hors KEV n'est jamais urgente.

Au plus **3 SMS par jour** (`sms_per_day`), tous canaux confondus, comptés sur **ta journée locale**. Le digest et le mail portent le reste. Une alerte urgente qui a échoué n'est pas renvoyée (le digest la liste).

## 11. En cas de problème

Michel affiche ces messages dans ta langue ; voici quoi faire.

| Ce que tu vois | Ce que ça veut dire, quoi faire |
|---|---|
| **Aucun agent SSH avec une clé** | L'agent ne tourne pas ou n'a aucune clé. Windows : démarre le service OpenSSH Authentication Agent, puis `ssh-add` ta clé. Ou règle `ssh.agent_pipe`. |
| **Le serveur n'a accepté aucune clé de l'agent** | Mauvais utilisateur, ou la clé publique n'est pas dans le `authorized_keys` du serveur. Teste avec `ssh utilisateur@hôte`. Michel n'utilise pas de mot de passe. |
| **Serveur à mot de passe seulement** | Installe une clé (étape 2) puis réessaie ; Michel n'utilisera pas de mot de passe. |
| **Michel ne connaît pas encore l'empreinte** | Confirme-la d'abord (page, ou `michel target trust <id> --fingerprint …`). |
| <a id="empreinte-changee"></a>**Le serveur présente une autre empreinte : Michel ne s'est pas connecté** | Ça peut être une **attaque** (quelqu'un se fait passer pour ton serveur) ou une réinstallation. Vérifie auprès de ton hébergeur. Ne confirme la nouvelle empreinte que si tu sais pourquoi elle a changé (`--replace`). Michel ne se connecte pas d'ici là. |
| **La politique réseau n'autorise pas ce serveur** | La règle `target.ssh` a été retirée. Remets l'hôte dans `network.allow` avec ce but, ou supprime puis ajoute de nouveau le serveur. |
| **Michel n'a pas pu joindre le serveur** / **n'a pas répondu à temps** | Adresse, port, pare-feu, serveur éteint. |
| **sudo a demandé un mot de passe** | Le script n'a pas été lancé, rien n'a changé. Mets `sudo: nopasswd` pour cet utilisateur (seulement si tu l'acceptes), ou lance le script toi-même en root. |
| **Michel ne peut pas tester la configuration : le PHP n'est pas celui du système** | Le PHP est hors des dossiers du système : pas de script, pour ne pas recharger PHP sans test. Change le réglage de PHP à la main. |
| **Pour vérifier ses paquets, Michel a besoin de la source …** | Lance la commande `michel source enable …` affichée. |
| **La version de PHP n'a pas pu être lue** | Vérifie que `php -v` marche pour l'utilisateur SSH, puis revérifie. |
| **Le fichier a changé sur le serveur depuis la dernière vérification** (code 5) | Rien n'a été modifié. Michel revérifie et prépare une nouvelle correction, une seule fois. |
| **Une correction n'a pas pu s'appliquer deux fois de suite, le fichier change sans cesse** | Quelque chose d'autre modifie ce fichier (un outil de déploiement, un panneau d'hébergement). Michel arrête d'essayer seul. Trouve ce qui le modifie, puis prépare la correction à la main. |
| **La correction a échoué et a été annulée** (code 9) | Une étape après le changement a échoué (test de configuration, rechargement) ; les fichiers ont été remis. Regarde l'étape en échec sur la page, corrige la cause, puis prépare une nouvelle correction. |
| **Un fichier à modifier est un lien symbolique** (code 6) | Corrige ce fichier à la main. |
| **Un dossier ou un fichier peut être modifié par quelqu'un d'autre que root** (code 7) | Arrêt de sécurité, rien n'a changé. Répare les droits du dossier. Si une sauvegarde n'appartient pas à root, vérifie-la, puis remets-en la propriété à root avant de relancer. |
| **La correction a échoué et n'a pas pu être annulée** (code 8) | Urgent. Va voir le serveur maintenant ; les copies sauvegardées sont sur la page et dans le dossier de sauvegardes. |
| **Déjà appliquée** (code 4) | Michel ne lance jamais deux fois la même correction. Prépare-en une nouvelle. Pour `annuler`, le code 4 veut dire qu'une sauvegarde manque : rien n'a été remis. |
| **Pas lancé par le bon utilisateur** (code 3) | Lance-le en root (ou avec l'utilisateur SSH pour un `.user.ini`). |
| **Le script n'a pas répondu : état inconnu** | Va voir le serveur toi-même (la configuration est-elle valide, le site répond-il ?). Puis dis que tu as vérifié : **J'ai vérifié le serveur** sur la page, ou `michel fix resolve <tentative>`. La correction se termine en échec ; Michel ne change rien sur le serveur. D'ici là, le serveur n'accepte aucune nouvelle correction et ne peut pas être supprimé. |
| **Une mise à jour de paquet a échoué / le site ne répond plus après** | Aucun script ne peut l'annuler : restaure ton snapshot, puis vérifie le serveur. |
| **Le site ne répond plus après une correction, alors qu'il marche** | Si l'adresse du site redirige vers un autre hôte (par exemple `www.`), la vérification du site est refusée par la politique réseau : seule l'adresse donnée a une règle. Donne l'adresse finale comme `site_url`. |

## 12. Les limites à connaître

- Le PHP de la ligne de commande n'est pas toujours celui du site ; Michel ne sait pas toujours le dire.
- La liste des failles de PHP embarquée dans Michel n'est à jour que si Michel l'est.
- Un script que tu lances toi-même échappe au contrôle de Michel : il se protège, mais c'est toi qui décides quand et avec quel utilisateur le lancer.
- nginx et Apache sont signalés et expliqués, jamais modifiés.
- Les systèmes BSD ne sont pas pris en charge.
- Un agent Pageant n'est pas testé.
- Les fiches Debian marquées `unimportant` (sans effet sur la sécurité dans Debian, d'après son équipe de sécurité) ne sont pas signalées. Celles que Debian n'a pas encore jugées le sont.
- Les auteurs ont fait un essai complet sur un conteneur Debian 13 jetable, avec systemd, sshd, PHP-FPM et nginx. Pas encore essayés : les réglages d'un vrai hébergeur, le mutualisé, un vrai réseau et l'agent OpenSSH de Windows (cet essai passait par un agent de test, avec `ssh.agent_pipe`). Essaie d'abord sur un serveur de test.
- Les journaux (section 13) ont été essayés pour de vrai sur le même type de conteneur, avec PHP-FPM, PostgreSQL et Monolog : à l'intervalle par défaut de 5 minutes, l'alerte est arrivée en 5 minutes au plus après l'erreur. Pas encore essayés : un vrai serveur, un vrai réseau, un serveur de type `hds`, un serveur réglé sur une autre heure que l'heure UTC et l'agent OpenSSH de Windows (cet essai passait aussi par un agent de test, avec `ssh.agent_pipe`).

## 13. Les journaux des serveurs : être prévenu sans les copier

Cette fonction t'évite de fouiller les journaux pour voir les erreurs PHP, PostgreSQL et applicatives. Michel lit les fichiers que tu déclares, à intervalle régulier, et te prévient de lui-même. Par défaut, **aucune ligne de journal et aucun texte de message ne quitte le serveur** : Michel ne récupère que quelques informations courtes et de forme prévue (niveau, type d'erreur, emplacement dans le code, nombre de fois, chemin du fichier lu ; le détail est plus bas). Tout se passe dans le bloc **Journaux** de la fiche du serveur.

**Ce n'est pas un avis juridique, fais valider par ton délégué à la protection des données (DPO) ou par un juriste.** Les journaux peuvent contenir des données personnelles, et des données de santé sur un serveur de type `hds`. Michel réduit ce qui sort du serveur et dit ce qu'il fait ; il ne décide pas si cela répond à tes obligations.

### Ce qui est lu

- **Seulement ce que tu déclares et coches.** Un serveur sans source n'est pas lu du tout. **Chercher des journaux sur ce serveur** propose, à partir de ce que Michel sait déjà, et ne crée rien :
  - le `error_log` de PHP, en ligne de commande et dans PHP-FPM, pools compris. Une valeur FPM qui contient `$pool` n'est **pas proposée** : Michel ne sait pas quel nom de pool va avec, déclare ces fichiers à la main ;
  - `/var/log/postgresql/postgresql-*.log`, le dossier par défaut de Debian et Ubuntu. Michel ne lit pas `postgresql.conf` pour cela : sur un serveur dont les journaux sont ailleurs, cette proposition est fausse, déclare le vrai chemin à la main ;
  - `storage/logs/*.log` et `var/log/*.log` sous les dossiers distants des projets liés.
- **Un chemin ajouté à la main** doit être absolu, sans `..`. Un `*` ou un `?` n'est permis que dans le nom du fichier (`laravel-*.log`, pour les fichiers datés) : Michel lit alors tous les fichiers qui correspondent, chacun avec l'endroit où Michel s'est arrêté de lire.
- **Essayer** lance le filtre une fois et montre exactement ce qui reviendrait, sans rien garder. C'est le moyen de vérifier que le format choisi convient au fichier.
- **Aucun fichier écrit, rien d'installé.** Michel envoie un filtre par SSH (`sh -s`, avec `awk`, `tail`, `head`), lancé avec les droits de l'utilisateur SSH. Si un outil manque, le fichier est indiqué comme non lu : Michel ne copie jamais le fichier pour le filtrer sur ton ordinateur. Le filtrage se fait sur le serveur.
- **Jamais de `sudo`.** Un fichier illisible est indiqué comme non lu, avec la raison. La solution habituelle est d'ajouter l'utilisateur SSH au groupe qui lit les journaux : `adm` sur Debian et Ubuntu (`sudo usermod -aG adm <utilisateur>`, valable à sa prochaine connexion). Les fichiers de PostgreSQL y sont lisibles par `adm`. Un journal PHP ou applicatif a le groupe et les droits que ta configuration lui donne : si l'utilisateur SSH ne peut pas le lire, c'est à toi de changer ces droits dans ta configuration, Michel n'y touche pas. Les mêmes règles valent sur un serveur de type `hds`.
- **Les raccourcis (liens symboliques) sont refusés**, fichier par fichier, avec une limite : Michel ne contrôle que le fichier lui-même, juste avant de le lire. Si un dossier du chemin est un raccourci (par exemple `current` dans `current/storage/logs/app.log`), Michel le suit ; et si quelqu'un remplaçait le fichier au dernier moment, le nouveau fichier serait lu. Dans les deux cas, il faut déjà pouvoir écrire dans ce dossier. Si le fichier lui-même est un raccourci, déclare son vrai chemin.

### Ce qui sort du serveur

| Format | Champs lus | À savoir |
|---|---|---|
| `php` | niveau, type d'erreur (« exception ») s'il y en a un, `fichier:ligne` | Le message est ignoré. Deux erreurs différentes à la même ligne comptent pour une. |
| `postgres` | sévérité, code d'erreur (`SQLSTATE`) si `%e` est dans `log_line_prefix` | Utilisateur, base, adresse, `DETAIL`, `STATEMENT`, `HINT` et `CONTEXT` : jamais. Voir plus bas pour `%e`. |
| `monolog` (Laravel, Symfony…) | niveau, canal, classe de l'exception, `fichier:ligne` | Du contexte, seuls la classe et l'endroit sont repris, par des règles fixes. |
| `json` | les champs de niveau et de canal que tu nommes | Un champ n'est gardé que s'il est d'un type connu à l'avance : un niveau connu, un identifiant court. |
| `text` | le niveau seulement, par mots-clés ou par un mot que tu donnes | L'alerte dit juste combien d'erreurs. |

Michel garde aussi le nombre par heure, selon la date de la ligne quand il sait la lire, et les dates où il a lu l'erreur pour la première et la dernière fois. La fiche montre ces dates de lecture : une erreur lue en retard porte donc la date de sa lecture, pas celle de son écriture. Seule la première ligne d'un message d'erreur sur plusieurs lignes compte. Un `fichier:ligne` est donné à partir du dossier du projet lié, sinon c'est le nom du fichier seul : un chemin comme `/home/<nom>/…` ne revient pas tel quel à cet endroit.

**Pour chaque fichier de journal lu ou non lu**, Michel reçoit aussi son chemin complet, y compris les noms trouvés par un motif avec `*` que personne n'a déclarés (`client-jean_dupont.log`) ; pour un fichier lu, son numéro de fichier (inode) et sa position. Il les garde pour reprendre au bon endroit, et l'heure des lignes revient aussi. **Un chemin ou un nom de fichier peut donc nommer une personne.** Ces chemins ne partent ni dans les alertes ni dans le résumé.

**PostgreSQL et `%e`.** Sans lui, Michel ne voit que la sévérité. Mets `%e` **à la fin de `log_line_prefix`, juste avant le message**, par exemple `log_line_prefix = '%m [%p] %q%u@%d %e '`. Ailleurs dans le préfixe, il n'est pas lu. Michel explique comment faire mais ne modifie rien sur le serveur.

**Jamais, quel que soit le réglage :** une ligne brute de journal gardée ou envoyée, une adresse IP, une adresse e-mail, une adresse web avec paramètres. Michel contrôle chaque information qui revient et jette celle qui n'a pas la forme attendue ; la ligne est alors comptée comme une ligne qui « n'a pas pu être comprise ». Un long numéro est écarté aussi : dans un type, un emplacement ou un canal, 7 chiffres à la suite, ou 3 groupes de chiffres ou plus séparés par `-`, `_` ou `.`. Ce champ est alors retiré, et l'erreur reste comptée par niveau. Dans un emplacement, un dossier fait d'un numéro à points ou qui contient un `.x` comme un nom de machine est écarté de la même façon. Un nombre plus court dans un nom, comme `Foo123456`, reste. Dans le texte nettoyé, tout mot qui contient un chiffre devient `[n]`. Cela ne retire pas forcément les noms : voir la limite ci-dessous. Aucune donnée de journal ne part vers un agent d'IA, quel que soit le serveur. Le journal d'audit ne contient aucun contenu : il dit quel serveur et quelle source, la période, le volume, le nombre d'enregistrements et une empreinte du résultat (`log.read`), et il trace `log.source_add`, `log.settings` et `log.purge`.

**Une limite.** Un nom qui s'écrit comme un identifiant (`jean_dupont`) peut rester dans le type d'erreur, dans l'emplacement ou dans le canal, parce que Michel ne peut pas le distinguer d'un nom de classe de programme. Cela suppose qu'une ligne ait été écrite exprès ainsi, ou qu'un vrai chemin ou un vrai nom de fichier contienne ce nom.

**Pour voir le détail**, la fiche donne la commande SSH à copier (`grep` sur le fichier, à la date de l'erreur). Michel ne la lance pas, et les lignes restent sur le serveur. Elle cherche à la date de la dernière ligne connue de cette erreur, en heure UTC (l'heure de référence mondiale). Si cette date n'est pas connue (plus aucun compte, ou ligne sans date lisible, comme toujours en `json`), elle cherche à la date de la dernière lecture. Un serveur réglé sur une autre heure que l'heure UTC peut faire manquer des lignes autour de minuit : élargis alors la recherche.

### Tes choix, et ce que Michel recommande

| Réglage | Recommandé (par défaut) | Autres choix |
|---|---|---|
| Texte du message gardé par Michel | Aucun | Texte nettoyé |
| Texte du message dans les alertes | Aucun | Texte nettoyé, seulement si le réglage précédent l'autorise |
| Conservation | 90 jours | 7 à 365 jours, jamais moins que le délai avant « plus revue depuis un moment » |

- Le choix recommandé vient en premier. Tout autre choix demande une **confirmation** qui dit ce qui peut sortir et où cela finit : ton ordinateur, le destinataire du webhook, le fournisseur de mail. Sur un serveur de type `hds`, l'avertissement est plus fort et cite les données de santé : elles se retrouveraient hors de l'hébergement `hds`, et la responsabilité t'en revient. Michel ne bloque pas.
- Tant qu'un réglage s'écarte, un **badge** reste sur la fiche et sur la liste des serveurs, et le résumé du matin te le rappelle une fois par semaine. Les choix, les retours au recommandé et les confirmations sont inscrits dans le journal d'audit.
- Le **texte nettoyé** est fait sur le serveur par le filtre : le texte entre guillemets, les nombres, les adresses IP, les adresses e-mail et les adresses web sont remplacés, et la longueur est plafonnée à 200 caractères. Il passe ensuite par le masquage de Michel, qui cache ce qui ressemble à un secret, sur ton ordinateur. **Un nom écrit sans guillemets peut rester.** Le nettoyage réduit le risque et ne garantit rien.
- **Le texte nettoyé n'est chiffré dans la base de Michel que sur Windows**, comme les autres données masquées. Sur Linux et macOS, il n'est pas chiffré : il est seulement protégé par les droits du dossier de données.
- Le résumé suit le réglage des alertes : il ne contient du texte que si les alertes en contiennent. **Remettre à « Aucun » le texte gardé par Michel** efface tout de suite le texte gardé pour ce serveur, et l'effacement est inscrit dans le journal d'audit. Remettre à « Aucun » seulement le texte des alertes arrête son envoi et n'efface rien.
- **Effacer les données de journaux de ce serveur** oublie tout ce que Michel a gardé sur ton ordinateur pour ce serveur, y compris les erreurs que tu as choisi d'ignorer : si l'une d'elles revient, elle compte comme nouvelle et elle est de nouveau annoncée selon tes réglages. Les sources et les réglages restent. Les positions de lecture s'effacent : la lecture suivante repart de la fin des fichiers. Rien n'est effacé sur le serveur. Retirer le serveur de Michel fait la même chose, et oublie aussi ses sources et ses réglages.
- À la fin de la conservation, les comptes, le texte et les erreurs sont purgés. Seule une erreur que tu as choisi d'ignorer garde son enregistrement (sans texte), pour que « ne plus me prévenir » tienne.

### Quand tu es prévenu

- **Intervalle de lecture** par serveur : 5 minutes par défaut, de 1 minute à 24 heures, ou seulement quand tu le demandes. Michel vise à te prévenir moins de 10 minutes après une erreur qui part tout de suite : par défaut une erreur critique sur `prod`, et aussi tout niveau que tu règles ainsi. Une erreur envoyée dans le résumé n'a pas ce délai. Avec un intervalle de plus de 10 minutes, ce délai peut être dépassé ; la page le signale.
- **« Seulement quand je le demande »** n'a pas de bouton sur la page : la lecture se lance avec `michel target logs read <serveur>`. Personne n'est prévenu entre-temps.
- **Ce délai de 10 minutes ne tient que si ton ordinateur est allumé**, `michel serve` lancé et la clé dans l'agent SSH. Michel ne peut pas te prévenir quand ton ordinateur est éteint. Quand il se rallume, Michel lit ce qui a été écrit entre-temps, dans la limite de volume décrite plus bas. Le résumé du matin indique alors, avec ses dates, la période qui n'a pas été lue, si elle a duré au moins 30 minutes et au moins deux intervalles de lecture.
- **« Je ne lis plus »** : si Michel échoue 3 fois de suite à lire un serveur et n'a eu aucune lecture réussie depuis au moins 30 minutes, il te le signale, une seule fois par panne. Tout de suite sur un serveur `prod`, dans le résumé sur `preprod` et `dev`. Une cause commune à tous les serveurs (agent SSH verrouillé ou absent) donne une seule alerte. La fiche montre toujours la dernière lecture réussie de chaque source.
  - **Cela vaut aussi quand le serveur répond mais que Michel ne peut pas ouvrir ses journaux :** aucun fichier d'une source n'a pu être lu, parce que les droits ont été perdus (souvent après une rotation, quand le nouveau fichier a d'autres droits), qu'un outil manque, ou que la lecture du fichier a échoué. C'est pareil pour un fichier illisible dès le début. Sur un serveur `prod`, l'alerte donne la cause ; ailleurs, le résumé donne seulement les dates. Les autres sources du serveur continuent d'être lues. Quand les droits reviennent, la panne prend fin et Michel reprend là où il s'était arrêté.
  - **Ce qui ne compte pas comme un échec :** un fichier absent (Michel l'attend), et un raccourci ou un dossier à la place du fichier. Ils restent dans la liste « non lu » de la fiche, et personne n'est prévenu. Avec un motif avec `*`, un seul fichier lu suffit pour une bonne lecture : les fichiers que Michel n'a pas pu ouvrir sont indiqués sur la fiche.
- **Qui est prévenu, par défaut :** sur `prod`, une erreur critique tout de suite, une erreur ordinaire dans le résumé ; sur `preprod` et `dev`, les deux dans le résumé ; les avertissements et les informations nulle part. Tout se change par serveur. Sur la ligne d'une erreur, dans le bloc Journaux, le bouton **Ne plus me prévenir pour celle-ci** arrête les alertes pour celle-là et efface tout de suite le texte que Michel en gardait, s'il y en avait.
- **Ce qui est « critique » :** pour PHP, les erreurs fatales (fatal, parse, compile, core, catchable et recoverable fatal) ; pour PostgreSQL, `PANIC` et `FATAL` ; pour Monolog et `json`, emergency, emerg, alert, critical, crit, fatal et panic ; pour `text`, les mêmes mots en capitales, ou `[emerg]`, `[alert]`, `[crit]`, `[critical]`, `[fatal]`. **Une erreur « ordinaire »** (niveau `error`) : `ERROR` et `ERREUR` pour PostgreSQL ; error, err et severe ailleurs. PHP n'a pas ce niveau : ses lignes sont critiques, des avertissements ou des informations. Un motif à toi sur un journal `text` donne toujours `error`.
- **Pas trop d'alertes :** une par nouvelle erreur, regroupées par lecture ; à nouveau seulement si elle revient après 7 jours sans être revue (réglable ; ne pas revoir une erreur pendant 7 jours ne prouve pas qu'elle est corrigée), ou si elle atteint 10 fois l'heure précédente et au moins 100 occurrences. Au plus 10 messages d'erreurs par heure et par serveur (ce réglage n'est pas sur la page : voir la fin de cette section). Un message regroupe toutes les erreurs d'une lecture, quel que soit leur nombre : il en montre 5, les plus graves d'abord, et compte les autres, qui sont sur la fiche. Une fois ces 10 messages partis, les nouvelles erreurs attendent le résumé, et un seul message par heure le dit. « Je ne lis plus », l'alerte sur un journal trop gros et ce message-là ne comptent pas dans les 10. Le compte est gardé en mémoire : redémarrer `michel serve` le remet à zéro.
- **Contenu d'une alerte :** `PDOException, Invoice.php:42, 37 fois`, le nom du serveur et un lien vers sa page dans Michel (jamais le jeton d'accès). Un webhook envoie le même message à un service extérieur, avec un marqueur et le genre d'alerte : le texte nettoyé n'y figure que si tu l'as gardé et autorisé pour les alertes. Le SMS reste désactivé pour les erreurs de journaux, sauf si tu le coches pour un serveur et que le canal SMS a `urgent: true`, car les 3 SMS par jour doivent rester aux failles. Sans canal configuré, tu peux quand même lire un journal, avec un avertissement et un badge : personne ne sera prévenu.
- **Résumé du matin :** voir [daily-digest.fr.md](operations/daily-digest.fr.md) pour `notify.digest_at` (8 h par défaut).
- **Pas sur la page :** le délai avant « plus revue depuis un moment », les plafonds de lecture, le seuil de hausse et le nombre de messages par heure ne se changent que par l'API de Michel, une requête technique (`PATCH /api/v1/targets/<id>/logs/settings`, champs `resolve_after_days`, `read_cap_bytes` jusqu'à 64 Mio, `read_timeout_seconds` jusqu'à 300, `max_alerts_per_hour`, `spike_factor` de 2 à 1000, `spike_min`). Sans raison précise, garde les valeurs par défaut.

### Rotation, volume et caractère `*`

- **Première lecture :** à partir de la fin des fichiers présents quand tu actives la source. Michel ne remonte pas le passé. Un fichier apparu ensuite est lu depuis son début.
- **Rotation** (quand un journal est archivé et remplacé par un nouveau fichier) : si le fichier a été remplacé (autre numéro de fichier, ou inode) ou s'il est devenu plus court, Michel repart du début du nouveau fichier. Ce qui restait à lire dans l'ancien est perdu, sauf si ton motif avec `*` couvre aussi l'ancien ; dans ce cas, l'ancien est relu depuis son début : ce qui avait déjà été lu est compté une seconde fois, prend du volume et peut faire croire à une hausse. La fiche indique la rotation. Avec l'option `copytruncate` de logrotate (l'outil qui archive les journaux), le fichier reste le même : Michel ne voit la rotation que si le fichier est plus court que sa position à la lecture suivante. S'il a déjà dépassé cette position, le début du nouveau contenu est manqué et rien ne le dit. Si tu peux choisir, préfère l'option `create`.
- **Volume :** au plus 5 Mio (environ 5 Mo) et 30 secondes par source et par lecture, réglables. Au-delà de 5 Mio, Michel saute à la fin et dit combien il n'a pas lu. Une lecture qui dépasse 30 secondes échoue : la position ne bouge pas, Michel réessaie à l'intervalle suivant, et des échecs répétés finissent en « Je ne lis plus ». La fiche dit combien a été laissé de côté, et le résumé suivant donne une ligne par serveur avec le total de sa période. Si les erreurs de niveau `error` partent tout de suite sur ce serveur, une alerte part aussi, au plus une fois par heure et par source. Si ce niveau ne part nulle part sur ce serveur, le résumé n'en dit rien et seule la fiche le montre.
- **Motifs avec `*` :** au plus 50 fichiers par lecture, et les 5 Mio se partagent entre eux. Michel considère comme « le plus récent » le **dernier nom dans l'ordre alphabétique**, pas le fichier modifié en dernier. Cela convient aux noms datés (`laravel-2026-11-02.log`). Cela ne convient pas à un motif comme `app.log*` : les vieux fichiers numérotés viennent après `app.log` dans l'ordre, ils sont donc lus d'abord et prennent le volume disponible ; la fiche indique le volume laissé de côté. **Au-delà de 50 fichiers, Michel écarte les premiers noms, et `app.log` est le premier : le fichier en cours d'écriture n'est alors plus lu.** Déclare `app.log` seul, ou choisis un motif qui ne couvre pas les copies numérotées.

### Pour ton registre des traitements

Le registre des traitements est le document RGPD où tu notes ce que tu fais des données personnelles. Pour t'aider à le remplir, avec le même rappel : ce n'est pas un avis juridique, fais valider par ton DPO.

| Question | Réponse |
|---|---|
| Finalité | Détecter des erreurs de fonctionnement. Le but n'est pas de suivre des personnes, mais un nom peut rester dans ce qui est gardé : un chemin, un nom de fichier trouvé par un motif avec `*`, un type ou un emplacement (voir plus haut). |
| Données lues | Les fichiers de journaux que tu déclares, sur le serveur, avec les droits de l'utilisateur SSH |
| Données sorties | Niveau, type, `fichier:ligne`, canal, nombres par heure et dates, heure des lignes. Le chemin de chaque fichier de journal lu, y compris les noms trouvés par un motif avec `*`, son numéro de fichier (inode) et sa position. Texte nettoyé seulement si tu le choisis |
| Où elles sont gardées | La base de Michel, sur ton ordinateur. Texte chiffré sur Windows seulement |
| Combien de temps | 90 jours par défaut, de 7 à 365 |
| Qui les reçoit | Toi, par les canaux que tu as configurés : mail, notification du bureau, webhook, SMS si tu le coches pour ce serveur et que le canal a `urgent: true`. Leurs fournisseurs reçoivent le même contenu |
| Trace | Le journal d'audit de Michel, sans contenu |
| Effacement | Automatique à la fin de la conservation, ou par le bouton de la fiche. Rien n'est jamais effacé sur le serveur |

Règles fixes : pas d'agent (Claude Code, voir la section 9) sur un serveur de type `hds` ; aucune donnée de journal n'est transmise à une IA, sur aucun type de serveur ; la lecture passe par la même sortie réseau que les vérifications (`target.ssh`). Commandes utiles : `michel target logs list <serveur>` et `michel target logs read <serveur>`.

Destinations réseau : [security/network-egress.fr.md](security/network-egress.fr.md) (`target.ssh`, `target.http`, `notify.sms`). Niveaux de correction du code : [fix.fr.md](fix.fr.md).
