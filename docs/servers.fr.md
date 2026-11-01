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

Ce que Michel ne lit **jamais** : les dossiers de données, les bases de données, les dossiers personnels des autres utilisateurs, les journaux, les clés privées, et tout ce qui n'est pas un fichier de configuration. Sur un serveur de type `hds`, tu ne peux ajouter aucun chemin.

- **Aucun secret n'est conservé.** Les valeurs de `password`, `secret`, `key`, `token`, les DSN et les réglages secrets connus sont masquées avant d'être stockées ; la base garde le nom du réglage, une valeur non secrète, le fichier et la ligne, plus l'empreinte du fichier, jamais le fichier brut.
- **Les liens symboliques** ne sont pas suivis pour lire un fichier que PHP ne désigne pas.
- Ce que Michel n'a pas pu lire est listé comme **non vu** (« `php.ini` illisible avec l'utilisateur deploy »), en clair. Il n'essaie jamais un autre moyen. À noter : un `.user.ini` illisible garde ouvertes toutes les alertes de réglages de ce serveur, ce qui est large exprès.
- Les commandes supposent un shell de connexion POSIX pour l'utilisateur SSH (un shell csh ou fish peut donner des résultats étranges).
- Plafonds : 60 s par commande, 5 min par collecte, 1 Mio de sortie par commande, 256 Kio par fichier de configuration.

### Le PHP de la ligne de commande n'est pas toujours celui du site

Le `php` d'un terminal peut être une autre version que celle qui sert le site (PHP-FPM, autre `php.ini`, réglages par site). Michel lit **les deux** quand il les trouve, et dit quand il n'a vu que la ligne de commande. Si tu donnes l'adresse du site (`--site-url`), Michel lit aussi les en-têtes `Server` et `X-Powered-By` par une simple requête GET, comme un navigateur. Il ne détecte pas tous les cas : voir [les limites](#12-les-limites-à-connaître).

### Quand

Une fois par jour par défaut ; par serveur : toutes les N heures, ou **seulement à la main** ; **Vérifier maintenant** ou `michel target check <id>` à tout moment. `michel serve` fait tourner le calendrier ; s'il ne tourne pas, le digest le dit. **Sans connexion**, quand une base de failles est mise à jour, Michel compare de nouveau ce qu'il a déjà stocké : une nouvelle faille grave sur une version que tu utilises alerte tout de suite, et la prochaine connexion la confirme.

## 5. Suis-je touché ? Les sources

- **Paquets du système** : les bases OSV des distributions (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat…), **désactivées par défaut**. Michel propose d'activer celle du système vu sur le serveur (`michel source enable osv.debian`, même accord que dans [sources.fr.md](sources.fr.md)) ; `michel target check` affiche la commande exacte quand il en manque une. La version est jugée d'après la base de la distribution, pas d'après `php -v` : les distributions corrigent sans changer le numéro amont.
- **Règles PHP** : un jeu de règles embarqué, versionné, déterministe (sans IA). Chacune a un réglage, une valeur à risque, une valeur conseillée, une gravité et une explication en clair : `display_errors` activé en production, `expose_php`, `allow_url_include`, `open_basedir` vide en mutualisé, `session.cookie_secure`, une branche de PHP qui n'est plus suivie, et PHP2Shell. Un réglage que PHP ne lit que dans la configuration principale (`PHP_INI_SYSTEM`) n'est pas « corrigé » par un `.user.ini`.
- **PHP2Shell** (CVE-2026-109618 et CVE-2026-109619, exploitées dans la nature) : jugé sur la **version**. Corrigé dans PHP 8.5.12, 8.4.27, 8.3.36 et 8.2.35 ; une branche plus ancienne que 8.2 est traitée comme non suivie et touchée. Michel peut proposer `session.upload_progress.enabled=0`, étiqueté **« réduit le risque, ne corrige pas »** : seule la mise à jour corrige. Il ne propose jamais `memory_limit=-1`.
- La liste des failles de PHP embarquée dans Michel n'est à jour que si ta version de Michel l'est (mets Michel à jour pour la mettre à jour).
- Un serveur dont la version de PHP n'a pas pu être lue reçoit une alerte « version de PHP illisible » : zéro faille avec une version de distribution inconnue ou des paquets non jugés n'est jamais présenté comme « rien à signaler ».

La fiche du serveur dit **touché / pas touché / pas pu tout voir**, liste les failles, et la liste « non vu ». Une faille dans le code d'un projet indique où il est déployé (« déployé sur : serveur X (prod) »).

## 6. Une correction : les scripts et leurs actions

Une correction n'est jamais du texte libre. C'est une **suite d'actions typées, d'une liste fermée**, que Michel traduit en un script shell POSIX lisible (`sh`, compatible dash et busybox) :

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
- `appliquer` se protège lui-même : `set -eu`, et un `trap` qui remet les fichiers sauvegardés et recharge si une étape échoue après un changement. Ça vaut aussi quand tu le lances toi-même.
- Ordre fixe : sauvegarde, changement, test de configuration, rechargement, vérification du site, nouvelle collecte du serveur. Une étape qui échoue arrête tout.
- Michel n'écrit que de la **configuration PHP**. Pour nginx et Apache, il signale et explique quoi changer ; il n'écrit rien.
- **Pas testable, pas de script.** Une correction recharge PHP, et Michel ne le fait pas sans avoir testé la configuration. Le test ne se lance qu'avec des binaires PHP nommés `php` ou `php-fpm` (avec une version éventuelle) dans `/usr/bin`, `/usr/sbin`, `/usr/local/bin` ou `/usr/local/sbin`. Un PHP ailleurs (`/opt/…`, compilé à la main) n'a **aucun script**, même pas pour toi, et Michel explique pourquoi.
- Une mise à jour de paquet est d'abord essayée à blanc par le gestionnaire de paquets (`apt-get -s`, `dnf --assumeno`, `apk --simulate`). Si elle supprimerait ou remplacerait un paquet, si c'est un retour en arrière de version, ou si elle passe à une autre branche de PHP ou à une version majeure, la correction est **refusée** : « la mise à jour retirerait X ». Les mises à jour majeures sont seulement expliquées.
- Un fichier qui est un lien symbolique (par exemple les liens de `conf.d` vers `mods-available` sur Debian) n'est jamais modifié à travers le lien : le script s'arrête, « corrige ce fichier à la main ».

### Quand ça se passe mal

| Situation | Ce que fait Michel |
|---|---|
| Une étape échoue après un changement | le script remet les fichiers, recharge ; état *annulé*, alerte urgente |
| Le site ne répond plus après une correction de configuration | `annuler` tout de suite si c'est Michel qui lance ; sinon alerte urgente « lance `annuler` maintenant », script affiché |
| `annuler` échoue lui aussi | alerte urgente, avec les copies sauvegardées à remettre à la main |
| Une mise à jour de **paquet** échoue, ou le site tombe après | **jamais annulée automatiquement** : état *échoué*, alerte urgente « restaure ton snapshot » |
| Le script a dépassé sa limite de temps, ou la connexion a coupé | état **`unknown`** (inconnu) : Michel ne peut pas dire ce qui a changé, alerte urgente, nouvelle collecte, et aucune annulation devinée |

Limites de temps d'un script lancé par Michel : **5 minutes** pour la configuration, **30 minutes** pour les paquets ; Michel ne tue jamais le processus (tuer `dpkg` en plein travail est pire qu'attendre). Une correction échouée n'est jamais relancée : prépare-en une nouvelle (nouvel identifiant).

Les codes de sortie d'un script, si tu le lances toi-même : `0` tout va bien ; `3` pas lancé par le bon utilisateur (root pour `php.ini` ou un pool, l'utilisateur SSH pour un `.user.ini`) ; `4` cette correction a déjà été appliquée ; `5` la ligne a bougé depuis la dernière vérification (rien n'a changé) ; `6` un fichier est un lien ; `7` dossier ou sauvegarde non sûr ; `8` le **retour arrière a échoué** (urgent : va voir le serveur). Voir [en cas de problème](#11-en-cas-de-problème).

## 7. Qui lance le script, et sudo

- **`executor: user`** (par défaut) : la page montre les deux scripts avec un bouton **Copier**. Tu les lances toi-même, puis tu cliques **Je l'ai appliqué**, ce qui lance une vérification.
- **`executor: michel`** : après **Valider**, Michel envoie le script validé par SSH (`sh -s`, rien d'exécutable ne reste sur le serveur hors sauvegardes) et suit chaque étape.

Qui le lance :

- Un script qui touche un fichier appartenant à root (`php.ini`, un pool) tourne **entièrement en root**. Il vérifie d'abord qu'il est root, sinon il s'arrête avant tout changement avec « lance ce script en root ». Avec `executor: michel` et `sudo: nopasswd`, Michel l'envoie par `sudo -n sh -s` (jamais ligne par ligne, et `-n` veut dire qu'il n'attend jamais de mot de passe : s'il en faut un, l'étape échoue et le dit). Sans `sudo`, la correction n’est proposée qu’à toi, pour que tu la lances toi-même.
- Un script `.user.ini` tourne avec l'**utilisateur SSH**, jamais en root.
- Le texte du script ne dépend pas de qui le lance (même empreinte).

## 8. Préprod, snapshot, sauvegardes

- **Préprod d'abord** : si le serveur a une préprod liée, la correction s'y exécute d'abord. La correction de la production est **reconstruite** à partir de l'inventaire de la production (chemins, versions, services), avec sa propre empreinte et son propre Valider (ou les règles du niveau 3). Si la préprod est liée mais ne montre pas la faille, la correction est refusée tant que tu ne la détaches pas ou ne la revérifies pas.
- **Snapshot** : avant tout script avec `package_upgrade`, Michel bloque sur **« fais un snapshot de ce serveur chez ton hébergeur »** ; tu coches **Snapshot fait** (horodaté, journalisé). Sans la case, pas d'exécution, même au niveau 3. Michel n'a jamais accès à ton compte chez l'hébergeur.
- **Sauvegardes** : sur le serveur, un script lancé en root sauvegarde dans `/var/lib/michel/backups/<correction>/` (un dossier réservé à root), un script `.user.ini` dans `~/.michel/backups/<correction>/`. Michel ne les **supprime jamais**, pas même les siennes : vide-les toi-même quand tu veux (`sudo rm -r /var/lib/michel/backups/<correction>` ; la fiche du serveur montre la taille et le dit). `annuler` refuse une sauvegarde qui n'appartient pas à root. Sur ton poste, chaque copie est conservée **chiffrée** (AES-256-GCM, clé dans le coffre de secrets de Michel), 90 jours. Une copie dont la clé est perdue indique « clé perdue » ; celle du serveur reste.
- Seuls les **arbres de configuration PHP** sont modifiables : le `php.ini` que PHP charge, les autres fichiers ini qu'il lit, un pool PHP-FPM, un `.user.ini`. Un arbre PHP de type cPanel qui n'en fait pas partie n'est pas modifiable. Root n'écrit que dans des dossiers qui lui appartiennent et que personne d'autre ne peut modifier, jamais sous `/home`.

## 9. Les quatre niveaux, et l'agent

Chaque serveur a son propre niveau (`--level`, 1 par défaut) :

| Niveau | Nom | Ce que fait Michel |
|---|---|---|
| 0 | Signaler | l'alerte et la fiche |
| 1 | Expliquer, préparer à la demande | le bouton **Préparer la correction** (par défaut) |
| 2 | Préparer | prépare les scripts de lui-même pour chaque faille ; ils attendent ta validation |
| 3 | Appliquer ce que j'ai autorisé | comme 2, et lance sans clic les corrections qui respectent toutes tes règles |

**Règles du niveau 3**, toutes requises, vérifiées par Michel (jamais par un agent) : `executor: michel` ; la case « corriger seul les réglages à risque connus » cochée pour ce serveur ; **seulement des `set_directive` issus des règles embarquées de Michel, à leur valeur conseillée** (aucun paquet, aucune proposition d'un agent, jamais un `.user.ini`, qui n'a pas de test de configuration) ; un test de configuration et une vérification du site (donc un `site_url`) ; `sudo: nopasswd` pour un fichier de root ; une préprod liée d'abord prouvée par la **propre** correction de Michel pour cette même faille ; aucune tentative en cours ou `unknown` sur le serveur ; un binaire testable. Les corrections que tu as préparées à la main peuvent se lancer seules si ces règles sont respectées. Le digest et les alertes disent ce qui a été appliqué seul et ce qui a été annulé.

**L'agent** (Claude Code, comme dans [fix.fr.md](fix.fr.md)) ne sert qu'à comprendre ou à discuter un cas : une faille combinée, plusieurs réglages possibles, un choix entre mise à jour et contournement. Michel prépare seul les corrections connues (une règle vers sa valeur conseillée, un paquet vers sa version corrigée). L'agent n'a jamais d'accès SSH, ne voit que l'inventaire **masqué**, ne peut pas valider, et n'a aucun outil de fichiers : il propose des actions typées par un seul outil MCP, et Michel vérifie chaque action avant d'assembler les scripts. **L'accord est par serveur**, et c'est celui de la **préprod** quand une préprod est liée (c'est son inventaire qui part). **Tu peux le retirer** à tout moment. Un serveur de type `hds` (`health`) n'a jamais d'agent.

## 10. Alertes et SMS

Les alertes passent par les canaux de [daily-digest.md](operations/daily-digest.md) (mail, notification du bureau, webhook), avec un contenu minimal (« serveur X : 1 faille grave », un lien), jamais une version détaillée ni un réglage. **Un canal limité à certains projets ne reçoit jamais d'alerte de serveur.**

Le **SMS** est un type de canal `sms` (`provider: freemobile` pour l'API de Free Mobile, gratuite pour ses abonnés, ou `generic` pour un fournisseur payant par un POST signé). Sa clé est dans le coffre de secrets (`michel secret set sms-urgent`), jamais dans le fichier de politique ; le numéro d'identifiant Free Mobile est un champ ordinaire. Il lui faut sa propre règle réseau (`notify.sms`). Le SMS n'est envoyé **que pour l'urgent** : un serveur `prod` avec une faille exploitée dans la nature (KEV) ou critique, un retour arrière qui a échoué, un état `unknown`, une mise à jour de paquet à restaurer par snapshot. Une faille de distribution sans correctif et hors KEV n'est jamais urgente. Au plus **3 SMS par jour** (`sms_per_day`), tous canaux confondus, comptés sur **ta journée locale**. Le digest et le mail portent le reste. Une alerte urgente qui a échoué n'est pas renvoyée (le digest la liste).

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
| **Le fichier a changé sur le serveur depuis la dernière vérification** (code 5) | Rien n'a été modifié. Michel revérifie et prépare une nouvelle correction. |
| **Un fichier à modifier est un lien symbolique** (code 6) | Corrige ce fichier à la main. |
| **Un dossier ou un fichier peut être modifié par quelqu'un d'autre que root** (code 7) | Arrêt de sécurité, rien n'a changé. Répare les droits, ou le dossier ou la sauvegarde qui n'appartient pas à root. |
| **La correction a échoué et n'a pas pu être annulée** (code 8) | Urgent. Va voir le serveur maintenant ; les copies sauvegardées sont sur la page et dans le dossier de sauvegardes. |
| **Déjà appliquée** (code 4) | Michel ne lance jamais deux fois la même correction. Prépare-en une nouvelle. |
| **Pas lancé par le bon utilisateur** (code 3) | Lance-le en root (ou avec l'utilisateur SSH pour un `.user.ini`). |
| **Le script n'a pas répondu : état inconnu** | Va voir le serveur toi-même (la configuration est-elle valide, le site répond-il ?). Puis dis que tu as vérifié : **J'ai vérifié le serveur** sur la page, ou `michel fix resolve <tentative>`. La correction se termine en échec ; Michel ne change rien sur le serveur. D'ici là, le serveur n'accepte aucune nouvelle correction et ne peut pas être supprimé. |
| **Une mise à jour de paquet a échoué / le site ne répond plus après** | Aucun script ne peut l'annuler : restaure ton snapshot, puis vérifie le serveur. |

## 12. Les limites à connaître

- Le PHP de la ligne de commande n'est pas toujours celui du site ; Michel ne sait pas toujours le dire.
- La liste des failles de PHP embarquée dans Michel n'est à jour que si Michel l'est.
- Un script que tu lances toi-même échappe au contrôle de Michel : il se protège, mais c'est toi qui décides quand et avec quel utilisateur le lancer.
- nginx et Apache sont signalés et expliqués, jamais modifiés.
- Les systèmes BSD ne sont pas pris en charge.
- Un agent Pageant n'est pas testé.
- Les auteurs n'ont pas encore essayé ceci sur un vrai serveur à eux : les tests utilisent un serveur SSH en mémoire. Essaie d'abord sur un serveur de test.

Destinations réseau : [security/network-egress.fr.md](security/network-egress.fr.md) (`target.ssh`, `target.http`, `notify.sms`). Niveaux de correction du code : [fix.fr.md](fix.fr.md).
