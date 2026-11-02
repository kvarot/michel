# Michel — Design du plan 7 : les erreurs des serveurs (être prévenu sans copier les journaux)

Date : 2026-11-02. Auteur : Claude, avec Kévin (brainstorming du 2026-11-02). Remplace le § 4.12 bis du design v1 (`2026-10-22-michel-design.md`) pour les erreurs ; les accès hostiles et les URL anormales passent au plan 8. S'appuie sur le plan 6 (`2026-10-31-michel-plan6-servers-design.md`) : `Target`, client `internal/sshx`, liste « non vu », canaux d'alerte, digest.

## 1. Intention

Quand Kévin fouille les journaux d'un serveur, c'est pour **voir les erreurs PHP, PostgreSQL ou applicatives**. Le plan 7 lui évite d'y aller : **Michel lit ces journaux à intervalle régulier et prévient de lui-même**.

Ces journaux peuvent contenir des données personnelles, et des données de santé sur un serveur `hds`. Le design part donc du **RGPD et des données de santé** : par défaut, **aucun contenu de journal ne quitte le serveur**, seulement des champs de forme connue. L'utilisateur peut assouplir ces réglages, mais Michel lui montre ce qu'il recommande et pourquoi.

## 2. Décisions de Kévin (2026-11-02)

1. Le besoin : voir les erreurs **PHP, PostgreSQL et applicatives**.
2. **Michel prévient de lui-même.** L'utilisateur n'a pas à ouvrir Michel pour le savoir.
3. **L'utilisateur choisit** ce qui part en alerte immédiate et ce qui attend le digest.
4. **Délai réglable par l'utilisateur.** Le pire cas acceptable donné par Kévin est **10 minutes** entre l'erreur et l'alerte.
5. Le design part **du point de vue RGPD et données de santé**.
6. **Le choix reste à l'utilisateur**, y compris sur un serveur `hds` : texte du message, conservation, contenu des alertes. J'ai recommandé de bloquer le texte sur `hds` ; Kévin a tranché pour le choix.
7. **Les recommandations sont mises en avant**, pour montrer à l'utilisateur quand un réglage n'est pas conseillé.
8. Les applications écrivent leurs erreurs dans **des formats variés** (« un peu de tout ») : frameworks, JSON, texte libre.
9. Les accès hostiles et les URL anormales seront **une option au choix de l'utilisateur**. Kévin a validé mon ordre : **erreurs au plan 7, accès au plan 8**, sur le même socle.
10. **`michel serve` envoie le digest**, après relecture builder : aujourd'hui, seule une tâche planifiée à part l'envoie, et une erreur renvoyée au digest pouvait n'atteindre personne.

Tout le reste est mon choix, marqué « mon choix » et repris au § 13.

## 3. Périmètre

### Plan 7 (ce document)
- Déclaration, serveur par serveur, des fichiers de journaux à lire.
- Lecture périodique en SSH, sans rien installer, avec tri sur le serveur.
- Erreurs groupées par signature : PHP, PostgreSQL, applicatif.
- Alertes et digest selon les règles de l'utilisateur.
- Réglages de confidentialité avec recommandations, avertissements et badge.
- Bloc « Journaux » sur la fiche serveur.

### Non-objectifs
- Accès hostiles, URL anormales, échecs d'authentification, requêtes lentes : plan 8. Le socle ne doit pas l'empêcher, mais le plan 7 n'en construit rien.
- Corriger une erreur, ou la lier à une faille : plus tard.
- Agent d'IA ou IA locale sur les erreurs : plus tard (mon choix). Aucune donnée de journal ne part vers un agent au plan 7, quel que soit le serveur.
- Agent installé sur le serveur (`michel agent`, mTLS) : plus tard.
- Fichiers compressés (`.gz`) et journaux par `journalctl` ou syslog distant : plus tard (mon choix).
- Modifier la configuration de journalisation d'un serveur : Michel explique quoi changer, sans écrire.

### Anti-objectifs (raté même si « ça marche »)
- **Une ligne brute de journal stockée ou envoyée par Michel.** Aucun réglage ne l'autorise (mon choix, § 7.3).
- **Une donnée personnelle ou de santé qui sort du serveur alors que l'utilisateur n'a rien assoupli.**
- **Un silence trompeur** : Michel ne lit plus (poste éteint, agent SSH verrouillé, droits perdus), et l'utilisateur croit qu'il n'y a pas d'erreur.
- Une écriture sur le serveur, ou un serveur ralenti par la lecture.
- Un fichier lu sans avoir été déclaré, ou un droit refusé qu'on contourne.
- Un assouplissement qui passe inaperçu : sans avertissement, sans badge, sans trace d'audit.
- Des alertes si nombreuses que l'utilisateur les coupe.

## 4. Déclarer les journaux

- Entité `log_source` : `target_id`, chemin absolu, `format` (§ 6), actif. Rien n'est lu tant qu'aucune source n'est déclarée et cochée : **un serveur sans source reste sans lecture** (mon choix). Dès qu'une source est active, l'analyse des erreurs l'est aussi.
- **Michel propose, l'utilisateur coche**, comme la découverte du plan 6 (mon choix). Propositions à partir de ce que la collecte voit déjà, et de quelques emplacements usuels :
  - PHP : directive `error_log`, CLI et FPM, pools compris ;
  - PostgreSQL : `log_directory` et `log_filename` dans `postgresql.conf` si lisible, `/var/log/postgresql/` sinon ;
  - Application : `storage/logs/` et `var/log/` sous les dossiers distants des projets liés (`target_project`).
- Ajout manuel possible. **Refusé** : chemin relatif, `..`, joker hors du dernier segment, tout ce qui n'est pas un fichier régulier au moment de la lecture (lien symbolique compris, mon choix). Un joker sur le dernier segment (`laravel-*.log`) sert aux fichiers datés : Michel lit **tous les fichiers qui correspondent**, chacun avec sa position (mon choix, pour ne pas perdre les écritures tardives autour de minuit).
- **Droits** : règle du plan 6 inchangée, **jamais de `sudo` pour lire**. Fichier illisible = ligne « non vu » en clair, avec l'explication (ajouter l'utilisateur SSH au groupe `adm`, par exemple). Ces deux règles s'appliquent aussi à `hds`.
- Amendement du plan 6 : son § 6.1 refuse les journaux et son § 6.3 refuse tout chemin non reconnu comme configuration sur `hds`. Ces refus restent pour la collecte. Les sources de journaux sont un chemin distinct, déclaré ici, avec son propre filtre.

## 5. Lire sur le serveur

### 5.1 Principe (mon choix)
Michel envoie par SSH un **script de filtre embarqué et versionné** (`sh -s`, POSIX, avec `awk`), comme pour les corrections du plan 6. Le script lit depuis la dernière position, extrait seulement les champs autorisés, **regroupe sur place**, et n'émet que le résultat. Le journal n'est jamais transféré vers le poste pour y être trié.

- **Quand le texte est désactivé, le script envoyé ne contient aucune instruction qui émet du texte.** C'est un script différent, pas une option côté poste : la garantie se lit dans le script.
- **Double barrière** : Michel revalide chaque enregistrement reçu contre un schéma strict (niveau dans une liste fermée, type au format d'un identifiant de classe, `fichier:ligne`, nombres). Un enregistrement non conforme est jeté sans être stocké ni journalisé, et compté comme « illisible ».
- Pas d'écriture sur le serveur : ni fichier temporaire, ni redirection, ni position stockée là-bas. Test bloquant sur la grammaire des scripts générés (pas de `system`, `getline` de commande, `>`, `rm`).
- `awk` absent ou trop ancien : ligne « non vu », pas de repli vers une copie du fichier.

### 5.2 Position et volume
- **Position par fichier sur le poste** : identifiant du fichier (inode et périphérique), position, date de lecture. Les plafonds et « dernière lecture » restent par source (mon choix).
- **Première lecture** : à partir de la fin des fichiers présents à l'activation. Michel ne remonte pas l'historique (mon choix : minimisation, et pas de rafale d'alertes à l'activation). Un fichier apparu ensuite est lu depuis son début.
- **Rotation** : inode changé ou fichier plus court, lecture depuis le début du nouveau fichier. Ce qui restait dans l'ancien n'est pas récupéré, et la fiche le dit.
- **Plafond** : 5 Mo lus et 30 s par source et par passage, réglables (mon choix). Au-delà, Michel saute à la fin et le dit (« 40 Mo non lus »). Un journal qui gonfle compte comme un signal : il remonte dans le bloc Journaux, avec la même règle que le niveau `error` du serveur (mon choix).

### 5.3 Quand
- **Nouveau réglage `log_interval` par serveur**, distinct de `check_interval`. Défaut **5 min** (mon choix : avec le temps d'envoi, reste sous les 10 min de Kévin). Bornes : 1 min à 24 h, ou « à la main ».
- Le réglage dit la conséquence en clair : au-dessus de 10 min, le pire cas dépasse la cible.
- **Planificateur séparé** de celui de `servercheck` (mon choix) : celui-ci traite un serveur à la fois et réessaie après 1 h, trop lent ici. Ici : quelques serveurs en parallèle, nouvel essai au prochain passage. Une même lecture ne se lance jamais deux fois pour un serveur.
- Lancé par `michel serve`, avec les limites du plan 6 : poste allumé, `serve` lancé, clé dans l'agent SSH.

### 5.4 Ne pas confondre silence et absence d'erreur
- La fiche affiche « dernière lecture réussie il y a X min » par source.
- **Alerte « je ne lis plus »** après 3 échecs de suite et au moins 30 min sans lecture réussie, une fois par incident (mon choix). Immédiate en `prod`, digest en `preprod` et `dev`, **hors plafond horaire** du § 8.2. Une cause commune à tous les serveurs (agent SSH verrouillé ou absent) donne **une seule alerte**.
- Michel ne peut pas prévenir si le poste est éteint. À son retour, il lit le retard dans la limite du plafond, le **digest indique le trou** (de quand à quand), et la documentation dit clairement que les 10 min ne valent que poste allumé.

## 6. Formats et champs extraits

| format | champs par défaut | limite à dire en clair |
|---|---|---|
| `php` | niveau, type d'exception si présent, `fichier:ligne` | Le message est ignoré. Deux erreurs différentes à la même ligne sont regroupées. |
| `postgres` | sévérité, code `SQLSTATE` si `%e` est dans `log_line_prefix` | Sans `%e`, Michel ne voit que la sévérité, et explique comment l'ajouter. Utilisateur, base, IP, `DETAIL`, `STATEMENT`, `HINT`, `CONTEXT` : jamais. |
| `monolog` (Laravel, Symfony…) | niveau, canal, classe d'exception, `fichier:ligne` si présents | Du contexte, le filtre n'extrait que la classe et `fichier:ligne`, par motifs ancrés (ex. `[object] (Classe(code: N): … at chemin:ligne)`). Le message, le code et tout le reste du contexte sont ignorés (mon choix : sans cela, Laravel regrouperait toutes ses erreurs). Le corpus piégé couvre ce cas. |
| `json` | champs déclarés par l'utilisateur pour le niveau et le canal | Seuls des champs de forme fermée sont acceptés (niveau reconnu, identifiant court). |
| `text` | niveau seulement, par mots-clés (`ERROR`, `CRITICAL`…) ou motif fourni | L'alerte dit juste « 12 erreurs dans ce journal ». |

- **Signature** : empreinte de (source, niveau, type, `fichier:ligne`). Sans donnée issue du message, sauf si le texte est activé : la signature ne doit jamais en dépendre (mon choix, pour que changer de réglage ne recrée pas toutes les erreurs).
- **`fichier:ligne`** : stocké relatif au dossier du projet lié quand c'est possible, sinon nom de fichier seul. Un chemin `/home/<nom>/…` ne remonte jamais tel quel (mon choix).
- **Traces multilignes** : seule la ligne d'en-tête compte, le reste est ignoré.
- **Date** : celle de la ligne si son format est reconnu, sinon celle de la lecture.
- **Niveau d'erreur commun** à tous les formats, pour les règles d'alerte : `critical` (fatal, `PANIC`, `FATAL`, `emergency`, `alert`, `critical`), `error`, `warning`, `info`. Correspondance exacte laissée au builder.

## 7. RGPD et données de santé

Je ne donne pas d'avis juridique : la documentation le dit et invite à faire valider par le DPO.

### 7.1 Principes
- **Liste blanche plutôt que masquage** (mon choix) : masquer rate toujours un cas, donc seuls des champs de forme connue sortent.
- **Finalité** : détecter des erreurs. Rien sur les personnes : ni IP, ni identifiant, ni email, ni URL avec paramètres, dans aucun réglage du plan 7.
- **Minimisation par défaut**, serveur par serveur. Tout réglage assoupli est explicite, tracé et réversible.
- **Pour voir le détail**, Michel donne la commande à lancer soi-même en SSH (fichier, date, recherche). La ligne reste sur le serveur.

### 7.2 Réglages et recommandations

| réglage | recommandé (défaut) | autres choix |
|---|---|---|
| Texte du message stocké par Michel | **Aucun** | Texte nettoyé (§ 7.3) |
| Texte du message dans les alertes | **Aucun** | Texte nettoyé (seulement si le réglage précédent l'autorise) |
| Conservation | **90 jours** (mon choix) | 7 à 365 jours |

**Mise en avant, décision 7 de Kévin :**
- Le choix recommandé vient en premier, marqué « recommandé ».
- Choisir autre chose demande une **confirmation** qui explique le risque en clair : ce qui peut sortir, où cela finit (poste, destinataire du webhook, fournisseur de mail).
- Sur un serveur `hds`, l'avertissement est plus fort et cite les données de santé. Il rappelle que ces données se retrouveraient hors de l'hébergement `hds` et que la responsabilité en revient à l'utilisateur (Michel ne bloque pas, décision 6).
- Tant qu'un écart dure, un **badge** reste visible sur la fiche et la liste des serveurs. Le digest le rappelle une fois par semaine (mon choix).
- Choix, retour au recommandé et confirmation sont audités.

### 7.3 Texte nettoyé (mon choix)
- Fait **sur le serveur** par le filtre : chaînes entre guillemets, nombres, adresses, emails et URL remplacés. Longueur plafonnée à 200 caractères.
- Passe ensuite dans `internal/mask` sur le poste, puis est **chiffré au repos** comme `mask_entry`.
- L'avertissement dit la limite : **un nom écrit sans guillemets peut rester**. Le nettoyage réduit le risque, il ne garantit rien.
- **Le digest suit le réglage des alertes** (mon choix) : sans texte tant que le texte n'est pas autorisé dans les alertes.
- **Retour à « Aucun »** : le texte déjà stocké pour ce serveur est effacé tout de suite, et l'effacement est audité. L'avertissement le promet (mon choix).
- **Pas de ligne brute**, même si l'utilisateur le demande : c'est ma lecture de la décision 6, qui portait sur le texte du message, la conservation et les alertes. À contester au § 13.

### 7.4 Règles qui ne changent pas
- **Jamais d'agent d'IA sur un serveur `hds`** : règle du plan 6, hors de ce choix (Kévin en a été informé).
- **Journal d'audit sans contenu** : `log.read` (serveur, source, fenêtre, volume, nombre d'enregistrements, empreinte du résultat), `log.source_add`, `log.settings`, `log.purge`.
- **Réseau** : même purpose `target.ssh`, dans `internal/egress`. Aucun nouveau purpose pour la lecture.
- **Conservation** (mon choix) : à échéance, comptes horaires, texte et signatures sont purgés. Seule exception : une signature `ignored` garde sa ligne, sans texte, pour que « ne plus me prévenir » tienne. Une erreur revenue après la purge repart en `new`. La conservation ne peut pas être plus courte que le délai de `resolved`.
- **Effacement local** : bouton « Effacer les données de journaux de ce serveur » sur le poste. Il efface tout, choix `ignored` compris, et le dit avant confirmation. Rien n'est effacé sur le serveur.
- **Documentation** : `docs/servers.md` et `.fr.md` détaillent ce qui est lu, ce qui sort et combien de temps, pour aider à remplir le registre des traitements.

## 8. Être prévenu

### 8.1 Règles (décision 3, défauts à moi)

| environnement du serveur | `critical` | `error` | `warning` | `info` |
|---|---|---|---|---|
| `prod` | **immédiat** | digest | ignoré | ignoré |
| `preprod`, `dev` | digest | digest | ignoré | ignoré |

- Réglable par serveur, et par source si besoin. Valeurs : immédiat, digest, ignoré.
- Un clic sur une signature : « ne plus me prévenir pour celle-ci ».

### 8.2 Éviter le trop-plein (mon choix)
- **Une alerte par nouvelle signature**, regroupée par passage : « 3 nouvelles erreurs sur serveur X ».
- **Réalerte** seulement si la signature revient après résolution (§ 9), ou si elle dépasse un seuil réglable (défaut : 10 fois plus que l'heure précédente, et au moins 100 occurrences).
- **Plafond par serveur** : 10 alertes par heure, réglable, puis un seul message « d'autres erreurs arrivent, voir le digest ».

### 8.3 Canaux
- Canaux existants : mail, notification Windows, webhook, avec une nouvelle fonction d'envoi à côté de `SendServerAlert`.
- **SMS** désactivé par défaut pour les erreurs de journaux (mon choix : le plafond de 3 SMS par jour doit rester aux failles). À cocher par serveur.
- **Contenu par défaut** : `PDOException, Invoice.php:42, 37 fois`, le nom du serveur et un lien. Texte seulement si le réglage du § 7.2 l'autorise. Un webhook part chez un tiers : la même règle s'applique.
- **Envoi du digest (décision 10)** : `serve` envoie le digest complet, pas seulement les erreurs de journaux, à une heure réglable, 8 h par défaut (mon choix). Poste éteint à cette heure : envoi au prochain démarrage de `serve`. La tâche planifiée `michel scan --all --update --digest` reste possible : les deux passent par le même enregistrement du dernier envoi, et un digest déjà parti dans la journée n'est pas renvoyé (mon choix). Les éléments couverts ne sont jamais perdus ni envoyés deux fois.
- **Aucun canal configuré** : activer une source reste possible, avec un avertissement clair (« Michel ne pourra prévenir personne ») et un badge sur la fiche tant que ça dure (mon choix).
- **Contenu du digest** : une section par serveur, nouvelles erreurs et plus fréquentes, avec la même voix de Michel, et une ligne pour les trous de lecture.

## 9. Cycle d'une erreur

- `new` à la première occurrence.
- `seen` quand l'utilisateur l'a vue.
- `resolved` sans occurrence depuis 7 jours (réglable), jamais présenté comme une preuve de correction.
- `reopened` si elle revient.
- `ignored` sur clic.

**Tables séparées, pas de type de `finding`** (mon choix, contraire au v1 § 4.12 bis) : un `finding` porte une faille, une correction et une preuve, ce qui ne colle pas à une erreur récurrente sans correction au plan 7. Les pages et le digest les présentent à part.

## 10. Pages

Bloc **« Journaux »** sur la fiche serveur (`ServerSheet.vue`, mon choix : pas de nouvelle page) :
- sources cochées, dernière lecture, « non vu » ;
- erreurs groupées : niveau, type, `fichier:ligne`, nombre, première et dernière fois, statut ;
- « Voir le détail » : la commande SSH à copier, avec fichier et date ;
- réglages en phrases : fréquence, règles d'alerte, confidentialité, avec recommandations et badge.

**Bouton « Essayer »** avant d'activer une source (mon choix) : lance le filtre une fois et montre **exactement ce qui reviendrait**, sans rien stocker. C'est aussi le moyen de voir si le format choisi convient. Résultat vide ou illisible : Michel le dit, et propose un autre format.

Liste des serveurs : nombre de nouvelles erreurs et badge d'écart de confidentialité.

## 11. API, CLI, migration

- API `/api/v1`, mêmes règles de minimisation : `GET/POST /targets/{id}/logs/sources`, `PATCH/DELETE` d'une source (suppression dans Michel seulement), `POST …/sources/discover`, `POST …/sources/try`, `GET /targets/{id}/logs/errors`, `PATCH` d'une erreur (vue, ignorée), `GET/PATCH /targets/{id}/logs/settings`, `POST /targets/{id}/logs/purge`.
- CLI facultative : `michel target logs list|read`. Rien ne l'exige de l'utilisateur.
- Migration `0018_server_logs.sql`, portable PostgreSQL : `log_source`, `log_cursor`, `log_signature`, `log_bucket` (compte par heure), `log_settings`, texte nettoyé chiffré dans une colonne dédiée.
- Purge selon la conservation, dans la boucle de rétention existante de `serve`.

## 12. Tests et réception

- Serveur SSH en mémoire (`sshtest`) et jeux de journaux fictifs. **Corpus piégé** : noms, emails, IP, numéros de sécurité sociale, requêtes SQL avec valeurs, placés dans les lignes. **Test bloquant : aucun de ces marqueurs n'apparaît ni dans la sortie du filtre, ni en base, ni dans une alerte, ni dans l'audit**, avec les réglages par défaut.
- Rotation, troncature, gros volume, ligne coupée en fin de lecture, droits refusés, lien symbolique, binaire dans un journal, `awk` absent.
- Variantes `sh`/`dash`/`busybox` et `awk`/`mawk`/`gawk`/`busybox awk`.
- Run réel dans le conteneur `test/docker-server`, avec erreurs PHP et PostgreSQL provoquées, puis mesure du délai réel jusqu'à l'alerte. Jamais sur un serveur `hds` réel pour le premier essai.
- **Ordre** : l'exécution du plan attend le premier run réel du plan 6, prévu le soir du 2026-11-02, car le plan 7 repose sur le même client SSH (mon choix).

## 13. Arbitrages (mes choix, à contester à la lecture)

1. Tri sur le serveur par un script `awk` envoyé en SSH, rien d'installé (§ 5.1).
2. Lecture à partir de la fin du fichier à l'activation, pas d'historique (§ 5.2).
3. `log_interval` à 5 min par défaut, de 1 min à 24 h, planificateur séparé (§ 5.3).
4. Alerte « je ne lis plus » après 3 échecs et 30 min (§ 5.4).
5. Liste blanche de champs, pas de masquage (§ 7.1).
6. **Aucune ligne brute, même sur demande de l'utilisateur** (§ 7.3).
7. Texte nettoyé plafonné, chiffré, signature qui n'en dépend pas (§ 6, § 7.3).
8. Conservation de 90 jours, de 7 à 365 (§ 7.2).
9. Défauts d'alerte : seul `critical` en `prod` est immédiat (§ 8.1).
10. Une alerte par nouvelle signature, seuil et plafond horaire (§ 8.2).
11. SMS désactivé pour ces erreurs (§ 8.3).
12. Tables séparées, pas de nouveau type de `finding` (§ 9).
13. Pas d'IA sur les erreurs au plan 7 (§ 3).
14. Bloc sur la fiche serveur et bouton « Essayer » (§ 10).
15. Joker : tous les fichiers lus, une position par fichier (§ 4, § 5.2).
16. Monolog : classe et `fichier:ligne` extraits du contexte par motifs ancrés (§ 6).
17. Le digest suit le réglage de texte des alertes ; retour à « Aucun » = effacement immédiat du texte (§ 7.3).
18. Purge de tout à échéance, sauf les signatures `ignored` (§ 7.4).
19. Digest envoyé à 8 h par défaut, un seul par jour avec la tâche planifiée ; sans canal, avertissement et badge, pas de blocage (§ 8.3).
20. Lien symbolique refusé (§ 4). Conséquence possible : certains `current/storage/logs` de déploiement seront à déclarer par leur vrai chemin.

## 14. Laissé au builder

Syntaxe exacte du filtre et compatibilité `awk` ; motifs de reconnaissance PHP, PostgreSQL, Monolog ; correspondance exacte des niveaux ; format du résultat échangé ; parallélisme du planificateur ; emplacements proposés à la découverte, au-delà de ceux du § 4 ; forme de l'audit à fréquence élevée, tant que chaque lecture reste traçable ; composants Vue (Options API, JS + JSDoc, `web/src/i18n`) ; découpage en tâches. Règles permanentes du projet : aucune trace de projet privé dans le dépôt, SQL portable PostgreSQL, textes FR relus par un non-spécialiste et au tutoiement, aucune écriture dans les projets scannés, réseau par `internal/egress`.
