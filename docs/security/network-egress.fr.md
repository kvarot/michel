# Inventaire des sorties réseau (plans 1 à 6)

🇬🇧 English version : [network-egress.md](network-egress.md)

Tout le trafic web sortant (HTTP) passe par la passerelle de sortie réseau (egress) (`internal/egress`), qui applique la politique `sovereignty.network` : refus par défaut, chaque requête vérifiée contre les règles `network.allow` (hôte et finalité), chaque tentative écrite dans le journal d'audit (`egress.attempt`).

## Destinations et finalités (purposes)

| Purpose | Destination | Quand |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (uniquement) | `michel db update` explicite, et seulement si une règle d'autorisation existe. |
| `osv.scan` | aucune | Jamais utilisé en pratique. Il existe pour que toute requête inattendue de la bibliothèque de scan (osv-scalibr) pendant un scan soit refusée et journalisée. |
| `notify.email` | le serveur SMTP d'un canal e-mail (`notify.channels[].host`) | `michel digest --send`, `michel scan --all --digest`, `michel notify test`. TCP via `Gateway.DialContext`, uniquement en STARTTLS (587) ou TLS implicite (465). La politique est refusée au chargement quand un canal activé n'a pas de règle. |
| `notify.webhook` | l'hôte de l'`url` d'un canal webhook | Mêmes commandes. POST HTTPS (http non chiffré seulement vers cet ordinateur), signé avec une clé secrète (HMAC-SHA256) ; les redirections ne sont pas suivies. |
| `osv.db` (sources) | `osv-vulnerabilities.storage.googleapis.com` | `michel source update` et `scan --update`, pour chaque source `osv.*` activée (23 dans le catalogue, un seul hôte pour toutes). Bases entières, rien n'est envoyé. |
| `source.enrich` | `www.cisa.gov` (KEV), `epss.empiricalsecurity.com` (EPSS) | `source update`, une fois la source activée et ton accord donné. Fichiers entiers, rien n'est envoyé. |
| `source.enrich` | `raw.githubusercontent.com` (Vulnrichment), `services.nvd.nist.gov` (NVD), `vulnerability.circl.lu` (CIRCL) | `source update`, sources à la demande (désactivées au départ). Un numéro CVE par requête, pour les failles sans gravité connue. La requête NVD porte le secret `nvd-api-key` dans un en-tête quand tu l'as enregistré. |
| `source.feed` | les sites des éditeurs : `about.gitlab.com`, `community.openvpn.net`, `developer.joomla.org`, `grafana.com`, `httpd.apache.org`, `mariadb.com`, `msrc.microsoft.com`, `nginx.org`, `nodejs.org`, `opensearch.org`, `openssl-library.org`, `rubyonrails.org`, `source.android.com`, `support.apple.com`, `symfony.com`, `wordpress.org`, `www.atlassian.com`, `www.debian.org`, `www.djangoproject.com`, `www.drupal.org`, `www.elastic.co`, `www.jenkins.io`, `www.keycloak.org`, `www.openssh.com`, `www.oracle.com`, `www.php.net`, `www.postgresql.org` ; et `api.github.com` pour les 28 flux lus dans les avis de sécurité des dépôts GitHub | `source update`, pour chaque flux activé (55 dans le catalogue, tous désactivés au départ). Une simple demande du flux ; ton jeton GitHub (gardé secret) est ajouté dans l'en-tête `Authorization` quand tu l'as enregistré. |
| `source.repo` | `api.github.com`, `codeload.github.com` | Skills et serveurs MCP : `source install` et `source upgrade` (archive du commit choisi), `source update` (état du dépôt, 3 requêtes par dépôt). L'état du dépôt d'un plugin n'est lu que si `api.github.com` est déjà autorisé pour cette finalité. Michel envoie le nom du dépôt et le commit, plus ton jeton GitHub si tu en as enregistré un. |
| `source.discover` | `api.github.com` | `source update` avec `discover.github` activée. Michel envoie les sujets recherchés, plus ton jeton GitHub si tu en as enregistré un. |
| `plugin.<clé>` | aucune | Jamais autorisée. Cette finalité sert à noter les tentatives de connexion d'un outil lancé par Michel (Trivy, Semgrep) : un intermédiaire local, le « proxy de refus », les reçoit, les refuse et les inscrit au journal. |
| `fix.install` | `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com` (archives de Composer), `registry.npmjs.org` | Une tentative de correction (plan 5), après l'accord IA du projet : la mise à jour faite par Michel sur la copie, l'installation et les tests du projet dans le dossier séparé. Passe par le proxy d'autorisation (décrit plus bas). Envoie ce que n'importe quel lancement de `composer` ou `npm` envoie : les noms et versions des paquets demandés. |
| `agent.claude` | `api.anthropic.com` (le service de l'IA), `platform.claude.com` (renouvellement d'une connexion par abonnement) | Une tentative de correction, après l'accord IA du projet : Claude Code, par le proxy d'autorisation. Envoie ce que l'agent lit et dit : le code de la copie (les fichiers exclus ne sont pas copiés), la fiche et les réponses MCP masquées, tes messages. Claude Code connaît d'autres adresses (documentation, téléchargements, télémétrie, rapports d'erreur, connecteurs claude.ai) : Michel les désactive au lancement ; si Claude Code les essaie quand même, le proxy refuse et le note. |
| `target.ssh` | l'hôte de chaque serveur que tu as ajouté (sur n'importe quel port) | Plan 6 : une vérification du serveur (`michel target check`, le calendrier de `michel serve`, **Vérifier maintenant**) et le lancement d'une correction que tu as validée avec `executor: michel`. Une connexion TCP brute par `Gateway.DialContext`, puis la poignée de main SSH : l'empreinte du serveur est contrôlée, les clés de ton agent SSH sont le seul moyen de connexion. Michel écrit la règle quand tu ajoutes le serveur et retire celles qu'il a écrites quand tu le supprimes. N'envoie que les commandes de lecture listées dans [servers.fr.md](../servers.fr.md) et, pour une correction, le script validé. |
| `target.http` | l'hôte du `site_url` de chaque serveur | La vérification du site après une correction, et les en-têtes `Server` / `X-Powered-By` : un simple GET, redirections contrôlées par la passerelle. Écrite quand tu ajoutes un serveur qui a une adresse de site. |
| `notify.sms` | `smsapi.free-mobile.fr` pour Free Mobile, ou l'hôte de l'`url` d'un canal SMS générique | Une alerte urgente de serveur seulement (une faille exploitée dans la nature ou critique sur un serveur de production, un retour arrière échoué, un état inconnu, une mise à jour de paquet à restaurer), au plus `sms_per_day` (3 par défaut). Un court texte, sans version ni réglage. Free Mobile : une requête HTTPS qui porte ton identifiant et sa clé (coffre de secrets). Générique : un POST signé comme un webhook. Demande sa propre règle. |

Les hôtes des sources ci-dessus sont ceux du catalogue intégré (`internal/source/catalog/catalog.yaml`, version 4). Une source que tu ajoutes toi-même (`michel source add`) apporte son propre hôte, que tu acceptes comme les autres. Il n'y a aucune autre destination : pas de télémétrie, pas de remontée d'erreurs, pas de vérification de mise à jour, et aucun fournisseur d'IA en dehors de Claude Code pour l'agent de correction, après ton accord.

Michel écrit les règles d'une source après ton accord (`michel source enable`, ou la page Sources) : une règle `{host, purpose}` par hôte, avec une copie `.bak` du fichier de politique. Voir [sources.fr.md](../sources.fr.md).

Les règles `agent.claude` et `fix.install` sont écrites au moment où tu donnes l'accord IA du projet (écran d'accord de la page « Corriger », ou `michel fix consent <projet> --yes`). Cet accord active aussi `ai.external_providers_enabled`. Si ta politique est en `strict_local`, seul le bouton clair de la page la fait passer en mode standard. Voir [fix.fr.md](../fix.fr.md).

## Local seulement, sans réseau

| Quoi | Pourquoi ce n'est pas une sortie réseau |
|---|---|
| Notification sur le bureau (canal `toast`) | Un petit programme lancé sur la machine avec une ligne de commande fixe (Windows PowerShell 5.1 pris dans `%SystemRoot%`, `notify-send`, `/usr/bin/osascript`) ; le texte est transmis comme une donnée, sur l'entrée standard ou après `--`. Aucune connexion, aucune règle nécessaire. |
| `michel serve` (page « Aujourd'hui » et `/api/v1`) | N'écoute que sur une adresse locale (127.0.0.1, [::1] ou localhost ; toute autre adresse `--listen` est refusée). Il accepte les connexions venant de cet ordinateur et n'ouvre aucune connexion vers l'extérieur. L'API exige le jeton d'accès local. |
| Décisions, digest sans `--send`, secrets | Lisent et écrivent seulement le dossier de données. |
| Plugins (Trivy, Semgrep) | Michel lance l'outil avec des arguments fixes, depuis `<dossier de données>/plugins/<outil>/`, et ne lui transmet qu'une courte liste de variables d'environnement (aucun secret, aucun jeton). Les réglages de proxy de l'outil sont dirigés vers le proxy de refus : un intermédiaire local (`internal/egress/denyproxy`, sur `127.0.0.1`) qui refuse toute connexion. Chaque tentative est notée comme un `egress.attempt` refusé, avec la finalité `plugin.<clé>` (200 au plus par passage ; les suivantes sont refusées quand même, sans être notées). Détails dans [sources.fr.md](../sources.fr.md). |
| Serveurs MCP | Michel récupère et fige le code source (finalité `source.repo`) mais ne lance jamais le serveur. C'est toi qui lances la ligne `claude mcp add` ; un serveur lancé par `npx` télécharge des fichiers au démarrage, hors de Michel. |
| Copie de travail et branche d'une correction | `git` travaille seulement sur le disque : le miroir privé est cloné depuis ton dépôt, la copie de l'agent est remplie depuis ce miroir, et la branche validée est ramenée du miroir dans ton dépôt. Aucun serveur distant n'est contacté. Même si ces opérations n'utilisent pas le réseau, les programmes qui les font reçoivent aussi le réglage du proxy `fix.install`. |
| `michel mcp` | Lancé par Claude Code, il communique seulement avec lui par des échanges locaux entre programmes (entrée et sortie standard, « stdio ») ; il n'écoute jamais sur le réseau. |

## Limites

- La passerelle revérifie chaque redirection contre la politique. Une redirection vers un hôte non autorisé est refusée.
- L'adresse de cet ordinateur lui-même (« loopback » : `127.0.0.1`, `::1`, `localhost`) est autorisée sans règle pour les finalités (« purposes ») dont le nom commence par `local.`. Aucune finalité de ce type n'est encore utilisée ; un webhook sur cette machine a quand même besoin de sa règle `notify.webhook`.
- `Gateway.DialContext` (connexions directes, utilisées par le canal e-mail) n'ouvre que du TCP (`tcp`, `tcp4`, `tcp6`) ; tout autre type de réseau (udp, unix, ip) est refusé. Il applique les mêmes règles d'autorisation et écrit le même événement `egress.attempt` que le HTTP, et refuse la connexion quand le journal d'audit ne peut pas être écrit.
- Une source qui attend ton accord (activée, avec un hôte sans règle) n'est pas lue : `source update` ne fait aucune requête pour elle.
- Si une nouvelle version de Michel change l'adresse du serveur d'une source, ton ancien accord ne vaut plus : la source attend ton accord pour la nouvelle adresse. L'ancienne règle reste dans ton fichier de politique tant que tu ne la retires pas.
- Un téléchargement de base est plafonné à 2 Gio.
- Plafonds de taille :
  - liste KEV : 50 Mo ;
  - fichier EPSS : 200 Mo une fois décompressé ;
  - réponse d'une source interrogée faille par faille : 5 Mo ;
  - flux : 5 Mo et 200 avis ;
  - archive de skill ou de serveur MCP : 50 Mo compressée, puis 200 Mo et 5 000 fichiers au plus une fois extraite ;
  - rapport de plugin : 50 Mo et 10 000 résultats.
- Sources interrogées faille par faille : 200 CVE par mise à jour pour Vulnrichment et CIRCL, 100 pour NVD (une requête toutes les 6 s, 0,6 s avec une clé). Si le serveur répond par un refus ou une limite de requêtes (codes 403 ou 429), Michel cesse de l'interroger pendant cette mise à jour.
- GitHub : une mise à jour fait au plus 50 requêtes sans jeton, 500 avec ; le reste attend la mise à jour suivante (noté `rate budget` dans le journal d'audit et dans `michel source show`).
- La lecture de l'état des dépôts GitHub, les lectures faille par faille et les requêtes NVD avec clé ne suivent pas les renvois vers une autre adresse (redirections).
- Un zip de base est rejeté au-delà de 2 000 000 d'entrées ou de 8 Gio décompressés.
- En cas d'échec de téléchargement ou de validation, l'ancienne base est conservée.
- Le proxy d'autorisation (`internal/egress/allowproxy`, plan 5) est le seul proxy qui laisse passer du trafic. Michel en lance un par tentative et par usage (`fix.install`, `agent.claude`), sur `127.0.0.1` et un port libre, et le ferme à la fin.
  - Accès : il exige un jeton tiré au hasard (en-tête `Proxy-Authorization` ; adresse `http://michel:<jeton>@127.0.0.1:<port>`). Le jeton passe seulement par l'environnement (`HTTPS_PROXY`, `HTTP_PROXY`, réglages de proxy de npm), jamais par une ligne de commande, l'audit ou un message d'erreur.
  - Ce qu'il laisse passer : un tunnel `CONNECT` vers le port 443 uniquement, et seulement si la passerelle a autorisé cet hôte pour cet usage. Le HTTP non chiffré, un autre port ou une cible mal formée sont refusés.
  - Ce qu'il note : chaque décision de la passerelle est un `egress.attempt` dans le journal d'audit, et les refus du proxy lui-même aussi, 200 au plus par proxy ; au-delà, les suivants sont refusés sans être notés. Le proxy note l'ouverture d'un tunnel, pas les requêtes qui passent ensuite dedans : un programme qui garde le même tunnel n'apparaît qu'une fois.
  - Limites : 64 tunnels à la fois ; un tunnel sans trafic pendant 5 minutes est fermé.
- Les programmes lancés pendant une correction (git, composer, npm, les tests, Claude Code) reçoivent une liste fermée de variables d'environnement, jamais tout l'environnement de Michel. composer, npm et les tests utilisent le dossier personnel propre à Michel (`<data>/fix-home`). Claude Code reçoit ton dossier personnel, seulement pour y trouver sa connexion, et aucune variable qui le redirigerait vers un autre fournisseur (comme `ANTHROPIC_BASE_URL`).

## Testé ou seulement déclaré

Testé (tests automatisés) :

- Un scan n'émet aucune requête réseau (test de scan sans sortie).
- Une redirection refusée est bloquée et auditée.
- `DialContext` refuse un hôte sans règle, un réseau autre que TCP, et bloque tout quand l'audit ne peut pas être écrit.
- `michel serve` refuse une adresse `--listen` qui n'est pas locale ; l'API refuse la requête (code 401) quand le jeton d'accès est absent.
- Les plafonds de téléchargement, de nombre d'entrées et de taille décompressée.
- Une source qui attend ton accord ne fait aucune tentative de connexion pendant une mise à jour (`TestRunSkipsWaitingConsentWithoutNetwork`).
- Ton accord écrit la règle, crée le fichier de politique s'il n'existe pas et note `source.consent` dans le journal (`TestEnableWritesRuleRecordsConsentAndReloads`, `TestEnableCreatesPolicyFileWhenAbsent`).
- La passerelle applique les nouvelles règles sans redémarrage (`TestGatewaySetRulesTakesEffect`).
- Un changement d'adresse d'une source la remet en attente de ton accord (`TestSyncHostChangeWaitsForConsentAgain`).
- Hôtes des sources : un test lance `source update` sur chaque entrée du catalogue qui a un lecteur, une par une, avec les vraies adresses des lecteurs (seule la partie qui envoie réellement les requêtes est remplacée par une doublure qui répond « introuvable » (404) sans toucher au réseau) et un journal témoin. Chaque tentative doit viser un hôte de cette entrée, pour son usage, et laisser un événement `egress.attempt` dans le journal (`TestUpdateContactsOnlyTheCatalogHosts`). Si un lecteur vise un hôte absent de la liste prévue pour sa source, ce test échoue. Les adresses fixes de GitHub (API et archives), utilisées pour les skills, les serveurs MCP et la découverte, sont comparées aux hôtes autorisés du catalogue (`TestBaseURLHostsAreInTheCatalog`).
- Plafonds des lecteurs de sources : liste KEV (`TestReadKEVCapsBody`), taille du fichier EPSS après décompression (`TestReadEPSSCapsDecompressedText`), réponses faille par faille (`TestRunOnDemandCapsBody`), flux limité à 5 Mo et 200 avis (`TestRSSReaderCapsAndSanitizes`), nombre de fichiers et taille totale d'une archive (`TestExtractCapsFilesAndBytes`), taille et nombre de résultats d'un rapport de plugin (`TestReportOverTheSizeCapFailsAndClosesNothing`, `TestOversizedReportFailsAndClosesNothing`).
- Une archive dont un chemin sort du dossier ou qui contient un lien symbolique est refusée (`TestExtractRefusesTraversalAndSymlinks`).
- Michel s'arrête quand un serveur limite les requêtes, et respecte le budget GitHub (`TestRunOnDemandStopsAtRateLimit`, `TestRunRespectsGitHubBudget`).
- Aucune redirection n'est suivie pour l'état des dépôts et les lectures faille par faille (`TestStatusDoesNotFollowRedirects`, `TestGetJSONDoesNotFollowRedirects`).
- La clé NVD n'apparaît jamais dans une erreur (`TestNVDErrorsNeverCarryTheKey`).
- Le proxy de refus refuse toute requête, y compris les connexions chiffrées (`CONNECT`), et note les tentatives (`TestDenyProxyRefusesAndRecords`).
- Un faux outil qui tente une requête par le proxy est refusé, et le dossier du projet est identique après son passage (`TestPluginRunDeniesEgressAndNeverWritesInProject`).
- L'environnement de l'outil est une liste fermée, sans ton dossier personnel (`TestEnvIsAnAllowlist`, `TestEnvNeverPassesTheUserHome`).
- Agent de correction, proxy d'autorisation : une requête sans le jeton est refusée ; un hôte autorisé passe par un tunnel ; un hôte inconnu, une règle d'un autre usage, le HTTP non chiffré et les cibles mal formées sont refusés et notés, sans que le proxy renvoie le contenu de la requête ; les plafonds et la fermeture des tunnels sont vérifiés. Les proxys ne se connectent que par la passerelle, et le contrôle automatique du code (qui cherche les accès réseau directs) couvre aussi `internal/workcopy` et `internal/agent`. Tests : `TestListenReturnsProxyURLWithToken`, `TestAllowProxyRequiresToken`, `TestAllowProxyTunnelsAllowedHost`, `TestAllowProxyAcceptsHostHeaderWithoutPort`, `TestAllowProxyRefusesUnknownHost`, `TestAllowProxyRefusesWrongPurpose`, `TestAllowProxyRefusesPlainHTTP`, `TestAllowProxyRefusesMalformedTargets`, `TestAllowProxyAnswersNoEcho`, `TestAllowProxyCapsConcurrentTunnels`, `TestAllowProxyCapsRecordedRefusals`, `TestAllowProxyCloseEndsTunnels`, `TestAllowProxyIdleTunnelTimesOut`, `TestProxyPackagesDialOnlyThroughGateway`.
- Agent de correction, environnement et isolement : git, composer, npm, les tests et Claude Code reçoivent une liste fermée de variables, qui contient le proxy ; Claude Code est lancé avec des options fixées par Michel, sans Bash, sans outil web et sans aucun réglage de l'utilisateur ni du projet ; des hooks git placés dans la copie, le miroir ou les dossiers de Michel ne tournent pas ; le serveur MCP n'a aucun outil de validation. Tests : `TestExecEnvIsAllowlisted`, `TestEnvAcceptsProxyURL`, `TestLaunchEnvAllowlisted`, `TestLaunchArgvIsClosedAndIsolated`, `TestLaunchDeniesBash`, `TestLaunchLoadsNoProjectOrUserSettings`, `TestPlantedHooksDoNotRun`, `TestMCPHasNoApprovalTool`.
- Agent de correction, accord : l'accord écrit les règles des adresses d'Anthropic et des dépôts de paquets, active les IA externes et note `ai.consent` ; on ne sort de `strict_local` que sur le clic de l'utilisateur ; une tentative ne démarre pas sans accord, pour un projet santé, ou en `strict_local`. Tests : `TestGiveConsentWritesRulesAndAudit`, `TestConsentScreenPerProject`, `TestConsentSwitchesStrictLocalOnTheClick`, `TestConsentSwitchesStrictLocalOnlyOnTheClick`, `TestStartNeedsConsent`, `TestStartRefusesHealthEvenWithConsent`, `TestStartRefusesStrictLocalWithoutExternalProviders`.
- Agent de correction, ton projet : rien n'y est écrit pendant la préparation de la copie, et l'application n'ajoute que la branche, sans toucher à tes fichiers ni à ce que tu as préparé pour ton prochain commit. Tests : `TestPrepareNeverWritesInProject`, `TestApplyLeavesWorkingTreeUntouched`.

Seulement déclaré (aucun test ne le garantit aujourd'hui) :

- Le proxy de refus n'arrête qu'un outil qui obéit aux réglages de proxy. Un outil (ou un programme qu'il lance) qui ouvre ses propres connexions n'est pas arrêté et n'apparaît pas dans le journal. C'est un garde-fou, pas une garantie.
- Trivy, Semgrep et leurs règles, c'est toi qui les installes et les mets à jour, en dehors de Michel. Michel passe les options qui les gardent hors ligne mais ne vérifie pas ce que l'outil en fait.
- L'installation d'une skill ou d'un serveur MCP n'est pas testée de bout en bout face aux hôtes autorisés du catalogue ; on vérifie seulement que ses adresses fixes en font partie (`TestBaseURLHostsAreInTheCatalog`).
- Une dépendance qui utiliserait directement `http.DefaultClient` ou `http.DefaultTransport` ne serait pas vue par la passerelle. `internal/egress/boundary_test.go` (lancé par `go test ./...` en CI, et par `make lint`) analyse le code de Michel hors de `internal/egress` et échoue sur `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, les littéraux `http.Client{}` et `http.Transport{}`, `net.Dial`, `net.DialTimeout`, `net.DialTCP/DialUDP/DialIP/DialUnix`, `net.Dialer{}`, `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer{}` et `smtp.Dial`, mais il ne lit pas les dépendances. Un test installant un transport par défaut qui refuse tout est prévu.
- Le proxy d'autorisation n'arrête qu'un programme qui obéit aux réglages de proxy. Claude Code, git, composer, npm, les tests du projet, ou un programme qu'ils lancent, pourraient ouvrir leurs propres connexions : elles ne seraient ni arrêtées ni notées. C'est un garde-fou, pas une garantie.
- La liste des adresses d'Anthropic (`fix.AgentHosts`) a été relevée sur Claude Code 2.1.314. Une autre version peut avoir besoin d'une autre adresse : la tentative échoue alors, et les refus sont notés dans le journal d'audit (`michel audit list`). Tu peux ajouter toi-même l'adresse manquante dans `sovereignty.network.allow`, avec l'usage `agent.claude`, ou attendre une version de Michel qui la connaît. Une autre version peut aussi respecter autrement les variables qui coupent son autre trafic.
- L'installation et les tests tournent avec tes droits, sans bac à sable du système : le code qu'ils exécutent (celui du projet, ou celui de l'agent) n'est pas enfermé derrière le proxy. Voir « Risques qui restent » dans [fix.fr.md](../fix.fr.md).

## Pas encore

- Un environnement isolé (bac à sable) pour l'installation et les tests d'une correction. Le proxy d'autorisation existe depuis le plan 5, mais il n'enferme pas un programme qui l'ignore.
- Michel ne retire pas encore tout seul l'ancienne règle quand l'adresse d'une source change.
- Points de contrôle d'audit signés (le journal d'audit est chaîné par hachage et révèle toute altération, mais n'est pas signé).
- Trousseau du système pour les secrets sous Linux et macOS (libsecret, Keychain) : les secrets sont des fichiers chiffrés par DPAPI sous Windows, des fichiers en clair lisibles par ton seul compte (0600) ailleurs.

## Historique

- Catalogue version 4 (plan 4) : le fichier EPSS a changé d'adresse ; il est maintenant sur `epss.empiricalsecurity.com`. L'ancienne adresse (`epss.cyentia.com`) renvoie vers la nouvelle, et la passerelle refuse de suivre ce renvoi. Si tu avais donné ton accord pour l'ancienne adresse, cette règle reste dans ton fichier de politique, et `enrich.epss` attend ton accord pour la nouvelle : lance `michel source enable enrich.epss` pour le donner.
