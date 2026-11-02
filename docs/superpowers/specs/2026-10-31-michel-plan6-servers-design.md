# Michel — Design du plan 6 : le serveur (voir si je suis touché, corriger sans casser)

Date : 2026-10-31. Auteur : Claude, avec Kévin (brainstorming du 2026-10-31). Remplace, pour le périmètre « cibles en SSH », le § 4.12 du design v1 (`2026-10-22-michel-design.md`) ; le mode « agent poussé mTLS » du § 4.12 et les journaux du § 4.12 bis restent pour plus tard. S'appuie sur le plan 5 (`2026-10-30-michel-plan5-fix-agent-design.md`) : même proposition immuable, même validation par empreinte, même page « Corriger ».

## 1. Intention

Pour PHP2Shell, la première question de Kévin n'était pas « comment corriger » mais **« est-ce que je suis concerné sur le serveur ? »**. Il a regardé à la main **la version de PHP et ses confs**, sur chacun de ses serveurs. Puis il a corrigé : **correction des confs serveur**, et parfois une **proposition de mise à jour**.

Le code sur le poste ne répond pas à cette question : ce qui tourne en production peut être différent. Le plan 6 fait lire à Michel ce qui tourne vraiment sur chaque serveur, le compare aux failles connues, prévient, puis prépare une correction sous forme de **script avec retour arrière**, que l'utilisateur valide.

Deux peurs guident tout le design (Kévin) : **un bug en prod**, et pire, **un effacement**.

## 2. Périmètre

### Plan 6 (ce document)
- Entité `Target` (un serveur), découverte depuis `~/.ssh/config` et les configurations de déploiement PhpStorm, liée aux projets qui y sont déployés.
- Lecture en SSH, en lecture seule, avec l'utilisateur SSH choisi par serveur : versions (OS, PHP, extensions, serveurs web, paquets) et configurations.
- Comparaison avec les failles connues (bases OSV des distributions, PHP amont) et avec des règles de configuration (`display_errors`, `expose_php`, `allow_url_include`…).
- Correction par **deux scripts lisibles, `appliquer` et `annuler`**, assemblés par Michel à partir d'actions sûres uniquement ; sauvegarde des confs avant, test, rechargement, vérification du site, retour arrière automatique si ça casse.
- Choix de l'utilisateur **par serveur** : préprod d'abord ou non, qui exécute (lui ou Michel), niveau d'autonomie, fréquence des vérifications.
- Alertes : mail et notification (canaux du plan 3), **SMS** pour l'urgent.
- Pages « Serveurs » et extension de la page « Corriger ».

### Non-objectifs du plan 6
- Mode agent poussé (`michel agent` sur le serveur, mTLS, instance centrale) : plus tard.
- Journaux des serveurs (v1 § 4.12 bis) : plan 7.
- Images et conteneurs (Trivy), certificats, services réseau exposés (scan de ports) : plus tard.
- Dérive entre le lockfile déployé et celui du dépôt : plus tard (noté, utile).
- Gestion des snapshots chez l'hébergeur : Michel le **propose**, l'utilisateur le fait ; Michel ne reçoit jamais d'accès au compte hébergeur.
- Authentification par mot de passe SSH (§ 5.2).
- Mises à jour majeures de PHP (8.1 → 8.3) exécutées par Michel : proposées et expliquées seulement (§ 8.4).

### Anti-objectifs (raté même si « ça marche »)
- **Un effacement**, de quoi que ce soit, par Michel ou par un script de Michel.
- **Un bug en prod** laissé en place : un changement qui casse le site et n'est pas annulé tout de suite.
- L'agent qui tape une commande sur un serveur, ou qui obtient un accès SSH.
- Ce qui est validé n'est pas exactement ce qui est exécuté.
- Une donnée applicative (base, fichiers utilisateurs, données de santé) lue ou remontée.
- Un secret de config (mot de passe de base, clé) qui part à l'agent ou s'affiche en clair.
- Contourner un droit refusé (`sudo` non prévu, élévation, autre utilisateur).
- L'utilisateur doit taper une commande pour savoir s'il est touché ou pour corriger.

## 3. Décisions de Kévin (2026-10-31)

1. Le besoin premier : **savoir si le serveur est concerné** ; regarder **les confs et la version de PHP**.
2. Trois types de serveurs : **HDS, VPS, mutualisé**.
3. Accès SSH partout, **les droits dépendent de l'utilisateur SSH qu'on impose** : Michel fait avec l'utilisateur choisi par serveur.
4. Corrections : **correction des confs serveur, et proposition de mise à jour**.
5. Peurs : **bug en prod**, et pire **effacement**.
6. **Le choix est à l'utilisateur**, et la correction passe **par script avec retour arrière possible**.
7. Snapshots et backups disponibles : Michel **propose le snapshot** et **fait le backup des confs**.
8. Alertes **par mail, notification, voire SMS**.
9. Vérification **une fois par jour**, mais **l'utilisateur décide**.
10. Rappel du plan 5 (2026-10-30) : autonomie serveur au choix de l'utilisateur, séparée du code ; défaut « préparé, validé avant d'agir » ; connexion SSH depuis le poste ; déploiement du code par PhpStorm, que Michel ne court-circuite pas.

11. Après relecture builder, « Go » sur mes recommandations : au plan 6, Michel **ne modifie que les réglages PHP** (`php.ini` chargé, pool PHP-FPM, `.user.ini`) ; pour nginx et apache, il signale et explique quoi changer, sans écrire.
12. PHP2Shell (recherche faite par Claude, Kévin n'avait plus le lien) = **CVE-2026-109618 et CVE-2026-109619**, cas de réception du plan (§ 7.2).

Les choix techniques ci-dessous sont les miens (Claude), marqués « mon choix », à contester au § 13.

## 4. Le serveur dans Michel : `Target`

- Entité `target` : `id`, nom affiché, `host`, `port`, `ssh_user`, alias SSH d'origine, empreinte de la clé d'hôte acceptée, `kind` (`hds` | `vps` | `shared`, choisi par l'utilisateur, proposé selon ce que Michel voit), `environment` (`prod` | `preprod` | `dev`), `classification` (mêmes valeurs que les projets ; **`hds` implique `health`**, non modifiable), `fix_level` (0-3, défaut 1, § 9), `check_interval` (défaut 24 h), `preprod_target_id` (facultatif), `executor` (`user` | `michel`, défaut `user`), `sudo_mode` (`none` | `nopasswd`, défaut `none`), `site_url` (pour la vérification du site, facultatif), actif.
- Lien `target_project` (plusieurs à plusieurs) : quels projets sont déployés sur ce serveur, et dans quel dossier distant. Un `Finding` se rattache à un projet **ou** à un serveur (champ réservé au v1 § 4.3) ; le cloisonnement « deux projets ne se mélangent jamais dans une lecture » s'étend aux serveurs.
- Le champ `project.server_fix_level` du plan 5 est retiré au profit de `target.fix_level` (mon choix : l'autonomie dépend du serveur, pas du projet ; un même projet peut être en préprod et en prod).

### 4.1 Découverte des serveurs (mon choix)
Michel propose une liste, l'utilisateur coche ; rien n'est ajouté seul.
- `~/.ssh/config` : `Host`, `HostName`, `User`, `Port`, `IdentityFile` (le chemin, jamais le contenu).
- Projets déjà suivis par Michel : `.idea/deployment.xml` et `.idea/webServers.xml` (serveurs SFTP de PhpStorm, utilisateur, dossier distant, correspondances de chemins). Lecture seule, dans le projet : c'est une lecture de plus du projet scanné, aucune écriture (règle des plans précédents). Les mots de passe de PhpStorm sont dans le coffre de Windows : Michel ne les cherche pas.
- Le lien serveur ↔ projet vient de PhpStorm (ce projet se déploie là) ; l'utilisateur corrige au besoin.
- Ajout manuel possible (hôte, utilisateur, port) depuis la page.

## 5. Connexion SSH

### 5.1 Principes
- Depuis ce poste, client SSH intégré à Michel (le builder choisit la bibliothèque Go, `golang.org/x/crypto/ssh` attendu), pas de `ssh.exe` en sous-processus (argv et sortie maîtrisés).
- **Clé d'hôte** : à la première connexion, Michel montre l'empreinte et l'utilisateur confirme sur la page (ou elle est déjà dans `~/.ssh/known_hosts`) ; une empreinte qui change ensuite **bloque** la connexion avec un message clair, jamais d'acceptation silencieuse.
- Une connexion = un événement d'audit `target.connect` (serveur, utilisateur, empreinte de clé d'hôte, durée, résultat).
- Réseau : nouveau purpose `target.ssh` dans la passerelle `internal/egress`, hôtes = les serveurs cochés ; en `strict_local`, comme les sources du plan 4 : opt-in explicite par serveur, jamais par défaut.

### 5.2 Authentification (mon choix)
- **Clé SSH seulement**, via l'agent SSH de Windows (OpenSSH, tube nommé) ou Pageant ; sur Linux/macOS `SSH_AUTH_SOCK`. Michel ne lit, ne stocke ni ne transmet jamais de clé privée ni de mot de passe.
- Serveur qui n'accepte qu'un mot de passe : Michel le dit et explique comment installer une clé (texte d'aide, pas d'action).
- Recommandation affichée (pas imposée) : un utilisateur SSH dédié à Michel, en lecture, et une clé distincte. Le durcissement `command=` de v1 § 4.12 est documenté comme option avancée, pas exigé : il empêcherait la correction exécutée par Michel.

### 5.3 Droits : on fait avec, on ne contourne pas
- Chaque lecture qui échoue faute de droits devient une ligne « non vu » en clair (« `php.ini` illisible avec l'utilisateur deploy »), affichée sur la fiche du serveur. Jamais de nouvel essai par un autre moyen.
- `sudo` : seulement si l'utilisateur a choisi `sudo_mode: nopasswd` pour ce serveur, et toujours `sudo -n` (n'attend jamais de mot de passe ; s'il en faut un, l'étape échoue et le dit). Jamais pour lire.

## 6. Lecture du serveur (collecte)

### 6.1 Ce qui est lu
Une **liste fermée de commandes en lecture**, construites par Michel, lancées dans une session SSH, sans rien installer sur le serveur (mon choix : ça marche aussi en mutualisé, et rien ne reste là-bas). Exemples attendus, liste exacte au plan :
- système : `/etc/os-release`, `uname -r` ;
- PHP : `php -v`, `php -m`, `php --ini`, `php -i` (ou `php -r` qui sort les directives en JSON), et les mêmes pour chaque binaire `php-fpm*` / `phpX.Y` trouvé ;
- serveur web : `nginx -v`, `apache2 -v` / `httpd -v`, liste des vhosts actifs ;
- paquets : `dpkg-query -W`, `rpm -qa`, `apk info -v` selon le système ;
- fichiers de configuration : uniquement les chemins donnés par PHP (`php --ini`) et par le serveur web, plus les `.user.ini` / `.htaccess` des dossiers de déploiement liés (§ 4), plus ceux que l'utilisateur ajoute ; taille plafonnée par fichier.

Tout le reste est refusé : pas de lecture de dossiers de données, de bases, d'`/home` des autres, de journaux (plan 7).

### 6.2 Limite à dire en clair
Le PHP de la ligne de commande n'est pas toujours celui du site (FPM, autre version, autre `php.ini`, réglages par vhost ou `.user.ini`). Michel lit les deux quand il les trouve et le dit quand il n'a vu que la ligne de commande. Si `site_url` est renseigné, il peut aussi lire les en-têtes HTTP du site (`Server`, `X-Powered-By`) en simple requête GET, comme le ferait un navigateur.

### 6.3 Secrets et HDS
- Le contenu des fichiers de configuration passe par les détecteurs de secrets **avant d'être stocké** (`internal/mask`, plan 5) : valeurs de `password`, `secret`, `key`, `token`, DSN, et directives connues (`mysql.default_password`…). En base : directives utiles (nom, valeur non secrète, fichier, ligne) et empreinte du fichier, pas le fichier brut (minimisation du v1 § 4.12).
- **Serveurs `hds` (classification `health`)** : uniquement versions et configurations de la liste fermée ; aucun ajout de chemin par l'utilisateur hors fichiers de configuration (Michel refuse les chemins sous les dossiers de données déclarés et tout fichier non reconnu comme config) ; l'agent IA externe y est **refusé**, sans exception (règle du plan 5 pour `health`), § 8.2.

### 6.4 Quand
- Par défaut une fois par jour (`check_interval`, réglable par serveur, y compris « seulement à la main ») ; bouton « Vérifier maintenant ».
- **Sans connexion** (mon choix) : quand une base de failles est mise à jour, Michel recompare l'inventaire déjà stocké ; une nouvelle faille grave sur une version vue chez toi déclenche l'alerte tout de suite, et la prochaine connexion confirme.
- Lancé par `michel serve` ; si `serve` ne tourne pas, le digest le dit (comme le plan 5).

## 7. Est-ce que je suis touché ?

### 7.1 Sources
- Paquets du système : bases OSV des distributions déjà au catalogue du plan 4 (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat…), désactivées par défaut ; **Michel propose d'activer celle du système vu** sur le serveur (même écran d'accord que le plan 4). Correspondance par paquet source et version de la distribution.
- PHP amont (mutualisé et PHP compilé, hors paquets de distribution) : nouvelle source au catalogue (mon choix : versions et fin de support depuis php.net ; failles par CPE `php:php` depuis une base publique, NVD ou équivalent ; le builder choisit, dans les règles de consentement du plan 4).
- Règles de configuration : **jeu de règles embarqué et versionné** dans Michel (comme le catalogue), déterministe, chacune avec : directive, valeur à risque, valeur conseillée, gravité, explication en clair FR/EN, contexte (prod seulement, SAPI…). Exemples : `display_errors=On` en prod, `expose_php=On`, `allow_url_include=On`, `open_basedir` vide en mutualisé, `session.cookie_secure=Off` avec HTTPS. Une règle peut combiner « version + réglage » (faille qui n'existe qu'avec un réglage donné) ; PHP2Shell, lui, dépend de la version seule (§ 7.2).

### 7.2 Cas de réception : PHP2Shell
Sources publiques (octobre 2026) : PHP2Shell = CVE-2026-109618 (épuisement mémoire pendant l'analyse d'un POST multipart) et CVE-2026-109619 (état périmé dans un worker après une erreur fatale), CVSS v4 9.2, exécution de code à distance sans authentification, **dans le KEV de la CISA depuis le 26 octobre 2026**. Corrigé le 21 octobre 2026 dans PHP **8.5.12, 8.4.27, 8.3.36 et 8.2.35**. Les éditeurs citent des réglages provisoires (`session.upload_progress.enabled=0`, et sur 8.5 `fatal_error_backtraces=0`) ; les mainteneurs de PHP disent qu'aucun réglage ne protège complètement et que **seule la mise à jour est sûre**.

Ce que le plan doit montrer, de bout en bout, sur un serveur de test :
- **Version amont** (mutualisé, PHP compilé) : PHP 8.3.35 → finding `server_package` grave, KEV, alerte urgente (SMS si `prod`). La correction proposée est la mise à jour (paquet si distribution, sinon explication « change la version dans le panneau de ton hébergeur ») ; jamais présentée comme réglée par un réglage.
- **Paquet de distribution** : version jugée d'après la base OSV de la distribution (les distributions corrigent sans changer le numéro amont), pas d'après `php -v` seul.
- **Réglage provisoire** : en attendant la mise à jour, Michel peut proposer `session.upload_progress.enabled=0` (script `set_directive` + test + rechargement + vérification du site + `annuler`), étiqueté « réduit le risque, ne corrige pas » ; la faille reste ouverte jusqu'à la version corrigée. `memory_limit=-1`, cité par certains, **n'est pas proposé** (mon choix : il ouvre un autre risque, l'épuisement de la mémoire du serveur).
- Les numéros de CVE, versions et réglages viennent des sources (OSV, KEV, règles embarquées versionnées), jamais codés en dur hors du jeu de règles ; le builder revérifie ces valeurs au moment du plan.

### 7.3 Résultat
- Nouveaux types de `Finding` (mon choix de noms) : `server_package` (paquet ou PHP vulnérable), `server_config` (réglage à risque), même cycle de statuts que les findings de code (plan 3) ; `proven_fixed` seulement quand une nouvelle collecte ne voit plus le problème (§ 8.5).
- Fiche serveur : « touché / pas touché / pas pu tout voir », la liste des failles en voix de Michel, et la liste « non vu » (§ 5.3).
- Croisement code ↔ serveur : une faille de code d'un projet lié affiche « déployé sur : serveur X (prod) ».

## 8. Corriger : scripts avec retour arrière

### 8.1 Les actions sûres (le cœur)
Un script n'est jamais du texte libre. C'est une **suite d'actions typées**, d'une liste fermée codée dans Michel, que Michel traduit en script shell POSIX lisible. Liste attendue (exacte au plan) :

| action | ce qu'elle fait | annulation |
|---|---|---|
| `backup_file` | copie un fichier de config dans `/var/lib/michel/backups/<correction>/` (fichier root) ou `~/.michel/backups/<correction>/` (`.user.ini`) sur le serveur — voir amendement § 8.1 bis, et rapatrie la copie sur le poste | — |
| `set_directive` | met une directive PHP à une valeur dans un fichier autorisé : `php.ini` chargé, pool PHP-FPM, `.user.ini` (décision Kévin : pas de nginx/apache ni `.htaccess` au plan 6, signalés et expliqués seulement) | remet le fichier sauvegardé |
| `test_config` | `php-fpm -t` (et `php -n -c <fichier> -r ''` pour un ini) ; échec = arrêt avant tout rechargement | — |
| `reload_service` | `systemctl reload <service>` (ou équivalent), jamais `restart` sauf service qui ne sait pas recharger, signalé | rechargement après remise des fichiers |
| `package_upgrade` | met à jour **un** paquet vers **une** version exacte (`apt-get install --only-upgrade paquet=version`, équivalents dnf/apk) | réinstalle l'ancienne version si la distribution la garde, sinon « retour par snapshot » dit d'avance |
| `check_site` | requête GET sur `site_url` depuis le poste : code HTTP et page attendue | — |

- **Aucune action de suppression n'existe** : pas de `rm`, pas de vidage, pas d'écrasement de dossier, pas de base de données. Le seul fichier écrit est un fichier de configuration déjà présent (jamais créé, sauf `.user.ini` absent en mutualisé, alors signalé) et toujours sauvegardé juste avant.
- Les chemins autorisés : ceux de la collecte (§ 6.1), jamais un chemin proposé par l'agent qui n'y figure pas ; aucune valeur n'entre dans le script sans échappement par Michel ; vérification bloquante du script produit (test : aucun script généré ne contient de commande hors de la grammaire des actions).
- Chaque correction produit **deux scripts** : `appliquer` et `annuler`, plus un fichier lisible « ce que ça fait » en clair. Empreinte SHA-256 de l'ensemble.

### 8.1 bis Précisions après relecture builder (mes choix)
- **Où tourne quoi.** `appliquer` ne contient que les étapes serveur (sauvegarde → modification → test de config → rechargement) et se protège lui-même : `set -eu` et un `trap` qui remet les fichiers sauvegardés et recharge si une étape échoue après modification. Ça vaut aussi quand l'utilisateur le lance lui-même. `check_site` et la nouvelle collecte sont faits **par Michel depuis le poste**, après le script. Si le site ne répond plus : avec `executor: michel`, Michel lance `annuler` tout de suite ; avec `executor: user`, alerte urgente « lance `annuler` maintenant », script affiché et copiable. L'empreinte couvre les deux scripts et la liste des vérifications.
- **Droits root.** Le préfixe `sudo -n` n'apparaît dans le script que si `sudo_mode: nopasswd`. Sinon, le script commence par vérifier qu'il peut écrire chaque fichier visé et s'arrête avant toute modification avec « lance ce script en root » ; le texte du script ne dépend pas de qui le lance (même empreinte). Avec `executor: michel` sans `sudo` et un fichier non inscriptible, la correction n'est proposée qu'en `executor: user`.
- **Préprod puis prod.** Deux corrections distinctes : celle de la prod est reconstruite depuis l'inventaire de la prod (chemins, versions, services), nouvelle empreinte, nouveau Valider (ou règles du niveau 3 de la prod).
- **Mises à jour de paquets.** Simulation d'abord (`apt-get -s`, `dnf --assumeno`, `apk --simulate`) : si le gestionnaire veut **supprimer ou remplacer** un paquet, la correction est refusée (« la mise à jour retirerait X »), jamais exécutée. Pas de retour automatique d'une mise à jour de paquet : `annuler` dit « retour par ton snapshot », annoncé avant la validation.
- **Directive absente ou ailleurs.** Michel modifie la directive dans le fichier où PHP la prend réellement (d'après `php -i` / `php --ini`, fichier chargé et dossier de fichiers additionnels) ; si elle n'est nulle part, il **ajoute une ligne** à la fin du `php.ini` chargé (ou du `.user.ini` en mutualisé), jamais un nouveau fichier dans `conf.d` (l'annuler voudrait dire supprimer un fichier).
- **Amendement sécurité (relecture tâche 9, mon choix).** Un script qui touche un fichier appartenant à root (`php.ini`, pool) tourne **entièrement en root** : il vérifie au début qu'il est root, sinon « lance ce script en root » et arrêt avant toute modification ; avec `executor: michel` et `sudo_mode: nopasswd`, Michel l'envoie par `sudo -n sh -s` (plus de `sudo -n` ligne à ligne). Ses sauvegardes et fichiers de travail vont dans `/var/lib/michel/backups/<correction>/` (dossier root, `mkdir -m 700`, vérifié non lien), jamais dans le `$HOME` de l'utilisateur SSH, qui pourrait remplacer une sauvegarde que root remettrait ensuite dans `php.ini`. `annuler` refuse une sauvegarde qui n'appartient pas à root. Root n'écrit que dans des dossiers appartenant à root et non inscriptibles par d'autres, jamais sous `/home`. Les scripts `.user.ini` tournent en utilisateur SSH (jamais en root) et gardent `~/.michel/backups/`. Le texte du script ne dépend toujours pas de qui le lance.
- **Sauvegardes sur le serveur.** Jamais supprimées par Michel (aucune action de suppression, même pour ses propres fichiers). La rétention de 90 jours ne s'applique qu'aux copies chiffrées du poste. La fiche serveur affiche la taille de `~/.michel/backups/` (et de `/var/lib/michel/backups/` quand Michel peut la lire) et explique comment la vider soi-même.

### 8.2 Qui prépare
- **Michel seul** pour les règles de configuration et les mises à jour de paquets : la correction est connue (directive → valeur conseillée, paquet → version corrigée), pas besoin d'IA. C'est le cas courant, et **le seul cas sur les serveurs HDS**.
- **L'agent (Claude Code, plan 5)** quand il faut comprendre ou discuter : faille combinée, plusieurs réglages possibles, choix entre mise à jour et contournement, conversation de l'utilisateur. L'agent reçoit l'inventaire **masqué** et la faille, et propose des actions **typées** via un outil MCP (`propose_server_fix`, lié au jeton de tentative comme `propose_fix`) ; Michel vérifie chaque action et assemble les scripts. L'agent n'a **jamais** d'accès SSH, ne voit jamais une valeur secrète, ne peut pas valider. Accord IA par serveur (même écran que le plan 5, « voici ce qui part : versions et réglages masqués de ce serveur ») ; `health` refusé.

### 8.3 Exécution (choix par serveur)
- **Préprod d'abord** (si `preprod_target_id` est renseigné et l'utilisateur l'a choisi) : la correction s'exécute d'abord sur la préprod ; la prod n'est proposée qu'après succès complet là-bas.
- **`executor: user`** (défaut) : la page montre les deux scripts avec un bouton « Copier » ; l'utilisateur les lance lui-même. Ensuite « J'ai appliqué » lance une collecte de vérification.
- **`executor: michel`** : après Valider, Michel envoie **exactement** le script validé (même empreinte, contrôle avant envoi) par SSH (`sh -s` sur l'entrée standard, aucun fichier exécutable laissé sur le serveur hors sauvegardes) et suit chaque étape.
- **Ordre fixe** : sauvegarde → modification → test de config → rechargement → vérification du site → nouvelle collecte. Une étape qui échoue arrête tout ; **si la modification a eu lieu, `annuler` est lancé automatiquement**, puis Michel recharge et revérifie le site, et prévient (alerte urgente si le retour arrière lui-même échoue, avec les fichiers de sauvegarde à remettre à la main).
- Les sauvegardes restent sur le serveur et sur le poste (dossier de données de Michel, jamais dans un dépôt git, fichiers chiffrés au repos comme `mask_entry`, rétention réglable, défaut 90 jours). L'agent ne les voit jamais.

### 8.4 Mises à jour
- Avant tout script qui contient `package_upgrade` : **étape bloquante** « Fais un snapshot de ce serveur chez ton hébergeur » avec la raison en une phrase ; l'utilisateur coche « Snapshot fait » (horodaté, journalisé). Sans cette case, pas d'exécution, même au niveau 3.
- Mise à jour majeure de PHP ou d'un service : **proposition seulement** (étapes, risques, ce qui peut casser dans les projets liés, d'après leurs `composer.json` : `require.php`, extensions) ; jamais de script exécuté par Michel dans ce plan.
- Mutualisé : pas de paquets ; « mise à jour » = changer la version de PHP dans le panneau de l'hébergeur : Michel explique quoi choisir, l'utilisateur le fait.

### 8.5 Preuve
- `proven_fixed` serveur : collecte après exécution qui ne voit plus le problème **et** site vérifié (si `site_url`). Sinon `inconclusive` avec la cause. Disparu sans correction de Michel : `gone`, comme pour le code.

## 9. Niveaux d'autonomie (serveur, par serveur)

| niveau | nom affiché | ce que fait Michel |
|---|---|---|
| 0 | Signaler | alerte et fiche seulement |
| 1 | Expliquer et préparer à la demande | bouton « Préparer la correction » (défaut) |
| 2 | Préparer | prépare de lui-même les scripts pour chaque faille, ils attendent ta validation |
| 3 | Appliquer ce que j'ai autorisé | comme 2, et exécute sans clic les corrections qui respectent tes règles cochées |

- Règles d'exécution sans clic (niveau 3), vérifiées par Michel, toutes requises : `executor: michel` ; seulement `set_directive` issues des règles de configuration embarquées (aucune mise à jour de paquet, aucune proposition d'agent) ; test de config et vérification du site configurés ; préprod réussie d'abord si une préprod est liée ; case cochée par l'utilisateur pour ce serveur (« corriger seul les réglages à risque connus »). Les mises à jour exigent toujours la case « Snapshot fait » (§ 8.4), donc un humain.
- Le digest et les alertes disent ce qui a été appliqué seul, et ce qui a été annulé.

## 10. Alertes

- Canaux existants du plan 3 : mail, notification Windows, webhook ; contenu minimal (« serveur X touché par 1 faille grave », lien), jamais de version détaillée ni de config dans le message.
- **SMS (mon choix)** : un nouveau type de canal branché sur le webhook, avec un modèle prêt pour l'API SMS de Free Mobile (gratuite pour ses abonnés) et un modèle générique pour un fournisseur payant ; l'utilisateur choisit et configure (identifiants dans le coffre de secrets de Michel, `internal/secret`). Purpose réseau dédié, opt-in.
- **SMS seulement pour l'urgent (mon choix, réglable)** : serveur `prod` touché par une faille KEV ou critique, ou retour arrière échoué. Le reste : mail et notification. Au plus N SMS par jour (défaut 3).

## 11. Pages

### 11.1 « Serveurs » (nouvelle)
- Liste des serveurs : nom, type (HDS / VPS / mutualisé), environnement, état en une phrase (« touché par 2 failles », « rien de connu », « pas pu tout voir », « dernière vérification il y a 3 h »).
- Ajout : « Trouver mes serveurs » (découverte § 4.1, liste à cocher), confirmation de l'empreinte de clé d'hôte, choix de l'utilisateur SSH.
- Fiche serveur : ce qui a été vu (versions, réglages, projets déployés), ce qui n'a pas pu être vu, les failles avec bouton « Corriger », l'historique des corrections et des retours arrière, et les réglages en phrases : niveau, qui exécute, préprod liée, fréquence, `sudo`, adresse du site.

### 11.2 « Corriger » (plan 5, étendue)
- Même disposition. À droite pour un serveur : la faille en clair, puis la proposition en clair (« Je passe `expose_php` à Off dans `/etc/php/8.2/fpm/php.ini`, je teste, je recharge PHP-FPM et je vérifie ton site »), l'étape snapshot si besoin, **Valider** / **Refuser**, « Voir les scripts » (appliquer, annuler) replié avec « Copier ».
- Pendant l'exécution : chaque étape en une ligne avec son résultat, jamais un terminal brut ; retour arrière dit en clair.

## 12. API, CLI, migration, audit

- API (`/api/v1`, jeton, minimisation des plans 4 et 5 : aucun chemin absolu du poste, aucun secret) : `GET/POST /targets`, `GET/PATCH /targets/{id}`, `POST /targets/discover`, `POST /targets/{id}/hostkey` (confirmation), `POST /targets/{id}/check`, `GET /targets/{id}/inventory`, et les routes `/fix…` du plan 5 étendues aux findings serveur (`POST /fix/{attempt}/snapshot-done`, `POST /fix/{attempt}/applied-by-me`).
- CLI optionnelle : `michel target list|add|check`, `michel fix …` existant. Aucune n'est nécessaire à l'utilisateur.
- Migration `0011_targets.sql` (portable PostgreSQL) : `target`, `target_project`, `target_inventory` (versions et directives, sans secret), `target_unseen`, extension de `finding` et `fix_proposal` (`steps_server` du plan 5 : actions typées + scripts + empreinte), `server_backup` (chiffré), retrait de `project.server_fix_level`.
- Audit : `target.add`, `target.hostkey`, `target.connect`, `target.collect`, `server_fix.propose`, `server_fix.approve`, `server_fix.snapshot_done`, `server_fix.apply`, `server_fix.rollback`, `server_fix.proven`, avec empreintes, jamais de contenu de config.
- Docs publiques bilingues : `docs/servers.md` + `.fr.md` (dont « préparer un utilisateur SSH pour Michel »), mises à jour de `network-egress`, README ; tout texte FR passe par le relecteur non spécialiste.

## 13. Arbitrages (mes choix, à contester à la lecture)

1. Collecte par commandes en lecture via SSH, sans rien installer sur le serveur (§ 6.1).
2. Clé SSH par l'agent Windows/Pageant seulement, pas de mot de passe (§ 5.2).
3. Autonomie par serveur (`target.fix_level`), `project.server_fix_level` retiré (§ 4).
4. Découverte depuis `~/.ssh/config` et `.idea/deployment.xml` de PhpStorm, liste à cocher (§ 4.1).
5. Michel prépare seul les corrections connues ; l'agent seulement pour comprendre ou discuter ; jamais sur HDS (§ 8.2).
6. Scripts = actions typées d'une liste fermée, sans action de suppression, traduites par Michel (§ 8.1).
7. Défaut : l'utilisateur exécute les scripts lui-même ; exécution par Michel à activer par serveur (§ 8.3).
8. Retour arrière automatique dès qu'une étape échoue après modification (§ 8.3).
9. Mises à jour : snapshot confirmé à la main, jamais d'exécution sans clic ; majeures en proposition seulement (§ 8.4, § 9).
10. Sauvegardes de confs sur le serveur et le poste, chiffrées, 90 jours (§ 8.3).
11. Recomparaison sans connexion quand les bases changent (§ 6.4).
12. SMS par webhook (Free Mobile ou générique), réservé à l'urgent, plafonné (§ 10).
13. Après relecture builder (§ 8.1 bis) : script serveur auto-protégé par `trap`, vérification du site par Michel ; `sudo -n` seulement si autorisé ; prod reconstruite et revalidée après la préprod ; mise à jour refusée si elle retire un paquet, retour par snapshot seulement ; directive modifiée là où PHP la lit, sinon ligne ajoutée ; sauvegardes serveur jamais supprimées par Michel.
14. PHP2Shell : réglage provisoire `session.upload_progress.enabled=0` proposé comme « réduit le risque », `memory_limit=-1` jamais proposé (§ 7.2).

## 14. Laissé au builder

Bibliothèque SSH et accès à l'agent Windows (tube nommé OpenSSH, Pageant) ; liste exacte des commandes de collecte et leurs parseurs par distribution ; source exacte pour les failles de PHP amont (dans les règles du catalogue du plan 4) ; contenu initial du jeu de règles de configuration (au moins les directives citées au § 7.1) ; grammaire exacte des actions et génération du shell (échappement, `set -eu`, compatibilité `sh`/`dash`/`busybox`) ; tests d'intégration contre un serveur SSH de test local (conteneur ou serveur Go en mémoire), jamais contre un vrai serveur de l'utilisateur dans les tests automatiques ; composants Vue (Options API, JS + JSDoc, `web/src/i18n`) ; découpage en tâches. Le run réel du plan se fait sur un serveur de test choisi par Kévin, pas sur le HDS.
