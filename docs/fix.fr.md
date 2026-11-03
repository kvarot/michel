# Corriger : un agent prépare la correction, tu la valides

🇬🇧 English version : [fix.md](fix.md)

Michel trouve les failles et te les explique. Avec le plan 5, il peut aussi les faire corriger : Claude Code travaille sur une **copie** de ton projet, Michel vérifie ce qu'il a fait, lance lui-même les tests et te montre une proposition en clair. Rien n'arrive dans ton dépôt avant que tu cliques sur **Valider**, et même alors Michel crée seulement une branche : c'est toi qui la fusionnes et qui déploies comme d'habitude (avec PhpStorm, par exemple).

Pourquoi : pour une faille comme Php2shell (un exemple réel), il fallait lire des articles pour comprendre que tu étais touché, en chercher d'autres pour savoir comment corriger, les donner à une IA, puis corriger toi-même. Cela faisait trois étapes à faire à la main : **trouver** (est-ce que ça me touche, et où), **comprendre** (en clair, pourquoi chez moi), **corriger** (quoi changer, puis vérifier). L'agent fait ces étapes pour toi, et c'est toi qui as le dernier mot.

Tout se fait depuis la page (`michel serve`, bouton **Corriger** sur une faille de la page « Aujourd'hui », puis **OK, répare** ou un message à l'agent). La ligne de commande n'existe que pour les scripts :

```
michel brief <faille>             # la fiche de correction (trouver, comprendre, corriger), rien n'est envoyé
michel fix consent <projet> --yes # l'accord IA du projet (aussi demandé sur la page)
michel fix prepare <faille>       # lance une tentative et la suit
michel fix status [<tentative>]   # les tentatives, ou une tentative avec sa proposition et la conversation
michel fix approve <tentative>    # valide la proposition affichée par status et crée la branche
michel fix refuse <tentative>     # refuse ; la faille revient dans tes décisions
michel fix clean                  # supprime les copies des tentatives terminées
```

## Les quatre niveaux

Chaque projet a son propre niveau (`fix_level`, de 0 à 3, 1 par défaut). Tu le règles sur la page (**Réglages de correction** du projet) ou avec `michel project set <nom> --fix-level N`.

| Niveau | Nom | Ce que fait Michel |
|---|---|---|
| 0 | Signaler | Le résumé et la page, rien de plus. |
| 1 | Expliquer | La fiche de correction (le « brief ») en trois temps ; le bouton **Corriger** lance un agent quand tu le demandes (avec l'accord IA). |
| 2 | Préparer | Un agent prépare de lui-même une correction pour chaque faille qui le permet ; elle attend ta validation. |
| 3 | Appliquer ce que j'ai autorisé | Comme 2, et Michel crée seul la branche des corrections qui respectent tes règles ; les autres t'attendent. |

Le niveau 1 suffit pour corriger depuis la page : tu cliques sur **Corriger** quand tu le souhaites. Les niveaux 2 et 3 ajoutent seulement l'initiative, et demandent l'accord IA du projet ; sans lui, Michel reste au niveau 1 et te le dit.

**Quelles failles sont traitées seules au niveau 2** : celles qui sont ouvertes (ni reportées ni ignorées), situées dans une dépendance, avec une version corrigée connue, sans tentative en cours et sans proposition déjà refusée. D'abord les failles déjà attaquées (KEV), puis par gravité. `michel scan --all` les met en file d'attente ; `michel serve` les traite dans l'ordre, **une tentative à la fois par projet**, et **au plus 3 tentatives lancées seules par jour et par projet**. Si `serve` ne tourne pas, rien ne démarre.

**Règle automatique (niveau 3)** : elle ne compte que si tu as coché la case « Appliquer seul les mises à jour mineures sûres » du projet (`--auto-fix-minor`). Michel (jamais l'agent) crée alors la branche sans te demander, seulement si les six points suivants sont tous vrais :

- la correction ne change que des fichiers de dépendances (`composer.json` et `composer.lock`, ou `package.json` et `package-lock.json`, ou `yarn.lock`, `pnpm-lock.yaml`), aucun fichier de code ;
- le saut de version est petit : un correctif ou une version mineure, pas une version majeure (par exemple pas de 7 à 8) ;
- le score de risque est sous le seuil du projet `auto_fix_below` (30 par défaut, voir [remediation-risk.fr.md](remediation-risk.fr.md)) ;
- le nouveau scan de la copie ne voit plus la faille ;
- les tests ont réussi (« pas lancés » ne suffit pas) ;
- l'agent n'a rien modifié après la mise à jour faite par Michel : ce qui est appliqué est exactement cette mise à jour, relue dans le commit de la proposition.

Sinon, la proposition t'attend. « Appliquer » veut dire « créer la branche », jamais fusionner ni déployer.

## L'écran d'accord : ce qui sort de ton ordinateur

Claude Code envoie à Anthropic ce qu'il lit : c'est une IA externe au sens de la [politique de souveraineté](security/sovereignty-policy.md). Le premier clic sur **Corriger** dans un projet affiche donc un écran d'accord, un par projet. Il dit :

- ce qui sort : les fichiers de la copie que l'agent lit, la fiche de la faille (secrets masqués) et tes messages ; une clé enregistrée dans ces fichiers part avec eux ; les fichiers exclus ne sortent pas ;
- ce qui tourne : « Michel lance composer/npm et tes tests sur une copie, avec tes droits Windows ; le code écrit par l'agent s'exécute. » (voir « Risques qui restent ») ;
- que le projet est classé sensible, quand c'est le cas (c'est le réglage par défaut) : les secrets sont masqués dans la fiche de la faille et dans ce que Michel affiche, pas dans les fichiers que l'agent lit, et les fichiers exclus ne sont pas copiés ;
- chaque site (« hôte ») pour lequel il n'existe pas encore de règle réseau :
  - Anthropic, usage `agent.claude` : `api.anthropic.com` (le service de l'IA) et `platform.claude.com` (où une connexion par abonnement renouvelle son accès) ;
  - les dépôts de paquets, usage `fix.install` : `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com` (les archives que Composer télécharge), `registry.npmjs.org` ;
- qu'en acceptant, tu autorises les IA externes dans ta politique (`ai.external_providers_enabled`), quand ce n'est pas déjà le cas.

Quand tu acceptes, Michel :

1. écrit une règle par site dans `sovereignty.network.allow` de ton fichier de politique (en gardant une copie `config.yaml.bak`) ;
2. active `ai.external_providers_enabled` si besoin ;
3. relit la politique, sans redémarrer ;
4. enregistre l'accord du projet ;
5. note `ai.consent` dans le journal d'audit (sites, usages, classement, qui).

Un projet classé `health` (santé) est toujours refusé, avec ou sans accord.

### Quand ta politique est en `strict_local`

`strict_local` (le réglage par défaut) veut dire : rien ne sort de ton ordinateur et aucune IA externe n'est utilisée. Michel ne quitte jamais ce mode de lui-même. Sur la page, l'écran d'accord explique ce que `strict_local` protège et propose un bouton clair, « Passer en mode standard et autoriser les IA externes ». Ce clic écrit `sovereignty.mode: standard` et `ai.external_providers_enabled: true` en une seule modification du fichier de politique (avec son `.bak`, pour revenir en arrière), note `policy.mode` dans le journal d'audit, puis donne l'accord du projet. Tu gardes un cadre précis : seulement les sites listés, seulement les projets où tu donnes ton accord. En ligne de commande, `michel fix consent` refuse en `strict_local` : change d'abord le mode toi-même dans le fichier, ou passe par la page.

## La copie de travail

L'agent ne travaille jamais dans ton dossier. Pour chaque tentative, Michel prépare dans son dossier de données :

1. une copie technique de ton dépôt, que l'agent ne voit jamais : un **miroir privé** (`<data>/fix-mirrors/<projet>/<tentative>.git`, fait par `git clone --bare --local`, qui ne fait que lire ton dépôt) ;
2. la **copie de l'agent** (`<data>/worktrees/<projet>/<tentative>/`) : un dépôt git neuf, rempli avec les fichiers de ton dernier commit, **sans l'historique**, sans l'adresse du dépôt en ligne (le « remote ») et sans le chemin de ton dossier sur ton ordinateur, en un seul commit « michel: base ».

La copie ne contient que les fichiers de ton dernier commit. Restent donc dehors : tout ce que git ignore ou ne suit pas, les fichiers `.env*`, `*.pem`, `*.key`, `id_*` (dans tous les dossiers, majuscules comprises), les dossiers que tu as exclus (`michel project set <nom> --exclude <dossier>`), les liens symboliques et les fichiers spéciaux. Une copie est limitée à 30 000 fichiers, 256 Mio par fichier et 4 Gio en tout ; un projet plus gros est refusé (voir « En cas de problème »). Pendant la préparation, Michel n'écrit rien dans ton projet (c'est vérifié par un test).

Avant que l'agent démarre, Michel passe ses détecteurs de secrets sur les fichiers de la copie. Michel ne retient pas l'agent pour ce qu'ils trouvent : l'agent démarre et peut lire ces fichiers. Un secret écrit dans ton code est signalé dans la conversation au démarrage (« 2 secrets semblent écrits dans ton code (…) : l'agent peut les lire »), avec les fichiers concernés, pour que tu puisses les tenir à l'écart : sors le secret du code (mets-le dans une variable d'environnement ou un fichier `.env`, qui n'est jamais copié), ou exclus le ou les dossiers qui le contiennent (le message les nomme ; `--exclude` prend des noms de dossiers, pas de fichiers).

## Ce que l'agent peut faire, et ce qu'il ne peut pas faire

Michel lance Claude Code en arrière-plan, avec des options qu'il choisit lui-même et un environnement réduit à quelques variables prévues à l'avance, dans le dossier de la copie. Claude Code utilise ta connexion existante (abonnement ou clé : Michel ne la lit pas et ne la transmet pas), mais **aucun** de tes réglages, de tes hooks (scripts lancés automatiquement), de tes plugins, de tes autres serveurs MCP, de tes `CLAUDE.md` ni de ta mémoire. Il ne prend rien de tout ça dans la copie non plus, car un dossier `.claude/` venu d'un projet n'est pas fiable : aucune source de réglages n'est chargée, les hooks sont coupés, seul le serveur MCP de Michel est déclaré.

L'agent **peut** :

- lire, chercher, modifier et écrire des fichiers **dans la copie** (outils Read, Glob, Grep, Edit, Write) ;
- interroger Michel par son serveur MCP (`michel mcp`) : `list_findings`, `get_finding`, `get_brief`, `get_call_sites`, `get_changelog_excerpt`, `get_attempt`, et `propose_fix`, le seul outil qui écrit, et seulement dans les données de Michel, pour cette tentative (il faut un jeton lié à la tentative).

L'agent **ne peut pas** :

- lancer une commande : il n'a **aucun** outil Bash ; c'est Michel qui lance lui-même la mise à jour, l'installation et les tests ;
- aller sur le web (WebFetch et WebSearch coupés) : les articles utiles sont dans la fiche ;
- écrire dans `vendor/`, `node_modules/`, `.git/`, `.claude/` ou `.mcp.json`, ni lire tes fichiers Claude Code (`~/.claude`, `~/.claude.json`) et tes clés (`~/.ssh`) ;
- valider, appliquer, changer un réglage ou la politique : aucun outil ne le permet, la validation passe seulement par l'API locale avec son jeton.

Une tentative dure au plus 20 minutes et au plus 50 échanges avec l'agent (un échange = une réponse ou une action de sa part) ; ensuite Michel arrête ses processus. Michel demande à l'agent de t'écrire dans ta langue (ses messages et le résumé de sa proposition) ; le code reste tel quel. Le contenu du dépôt, les avis et les articles sont donnés à l'agent comme des données à lire, jamais comme des consignes de Michel. Les conversations sont gardées 30 jours, secrets masqués.

## Ce que Michel lance lui-même

Au départ, sur la copie encore telle que tu l'as mise dans ton commit (avant que l'agent la voie), Michel lance la mise à jour prévue, avec une commande dont il fixe lui-même chaque mot :

- Composer : `composer update <paquet>:^<version> --with-all-dependencies --no-scripts --no-plugins --no-interaction` (`composer require … --update-with-all-dependencies` pour un saut de version majeur, `composer update <paquet> --with-dependencies` pour une dépendance indirecte) ;
- npm : `npm install <paquet>@<version> --save-exact --ignore-scripts --no-audit --no-fund` (`npm update <paquet>` pour une dépendance indirecte).

Il n'y a pas de mise à jour pour un fichier `yarn.lock` ou `pnpm-lock.yaml` : l'agent part des fichiers du projet tels qu'ils sont.

Le résultat est le premier message de Michel dans la conversation. Ce que cette mise à jour installe (`vendor/`, `node_modules/`) est retiré de la copie juste après. Cela n'entre jamais dans la proposition ni dans la branche, sauf si ton dépôt versionne déjà des fichiers dans ce dossier. La proposition contient le manifeste et le fichier de verrouillage (plus ce que l'agent a changé).

Quand l'agent propose sa correction (`propose_fix`), Michel prend une fois pour toutes un instantané de la copie : ce que l'agent écrit après est ignoré. Michel reconstruit cet instantané dans un dossier séparé (`<data>/fix-tmp/<tentative>/`, jamais dans la copie de l'agent), puis il :

1. installe les dépendances (`composer install --no-scripts --no-plugins` ou `npm ci --ignore-scripts`), en repartant de zéro ;
2. lance les tests du projet, si tu as indiqué une commande (`michel project set <nom> --test-cmd "vendor/bin/phpunit"`, découpée en mots sans passer par un shell) ;
3. scanne à nouveau le résultat.

Michel n'installe qu'avec **Composer et npm**. Un projet yarn ou pnpm est lu et peut être corrigé, mais Michel ne lance ni yarn ni pnpm : la proposition arrive **sans installation ni tests**, et la page le dit.

Avant d'installer quoi que ce soit, Michel vérifie les réglages de ton projet. Il refuse tout ce qui ferait exécuter du code du projet pendant l'installation, ou télécharger depuis une source non sûre : réglages npm hors d'une courte liste autorisée, dépôts Composer locaux ou git, téléchargements sans https, anciens fichiers `package-lock.json`, paquets sans somme de contrôle. Dans ce cas, rien n'est installé, les tests ne tournent pas, et la page te dit pourquoi. Ces commandes tournent avec un dossier personnel propre à Michel (`<data>/fix-home`), jamais le tien, et passent par le proxy d'autorisation (usage `fix.install`).

## La proposition et la validation par empreinte

Une proposition ne change plus une fois faite. Elle contient : un résumé en clair, les modifications (le « diff ») **calculées par Michel** à partir de l'instantané (pas recopiées de l'agent), les fichiers touchés, les commandes lancées par Michel, le résultat des tests (`passed` réussis, `failed` échoués, `not_run` pas lancés), le nouveau scan de la copie (une faille trouvée par un outil externe (Semgrep, Trivy…) ne peut pas être scannée à nouveau sur la copie : la page dit que Michel n'a pas pu la contrôler), le risque, et une empreinte de l'ensemble (SHA-256 : un code qui change dès que le moindre détail du contenu change). Si l'agent continue et propose à nouveau, la nouvelle proposition remplace l'ancienne (`superseded`) et la page l'affiche.

Michel refuse une modification qui touche un fichier hors de la copie (`..`, chemin complet, lien), un fichier protégé ou un fichier exclu : la tentative passe `failed`, la cause est dite en clair, rien n'est appliqué.

**Valider** envoie l'empreinte de la proposition que tu as lue. Si l'agent l'a remplacée entre-temps, l'empreinte ne correspond plus : Michel n'applique rien (code d'erreur 409) et te montre la nouvelle. En ligne de commande, `michel fix approve` sans `--hash` valide la proposition que `michel fix status` a affichée en dernier, et refuse si elle a changé depuis.

## La branche, puis tu déploies

Appliquer, c'est : Michel construit **un seul commit** à lui dans le miroir (auteur Michel, parent = ton vrai commit ; les commits que l'agent aurait faits sont ignorés), puis le fait venir dans ton dépôt sur la branche `michel/fix-<id-court>`. Pas de changement de branche, pas de fusion : ta branche actuelle, tes fichiers et ce que tu as préparé pour ton prochain commit ne bougent pas (vérifié par un test, même si tu as des fichiers modifiés ou une autre branche en cours). C'est la seule écriture de Michel dans ton projet, et seulement après ta validation : des objets et une référence dans son `.git`.

La page dit alors : « La branche michel/fix-… est prête. Fusionne-la puis déploie avec PhpStorm comme d'habitude. » Michel ne fusionne jamais et ne déploie jamais.

## La preuve

- Tests réussis et nouveau scan propre **dans la copie** : obligatoires pour une application automatique (niveau 3), affichés pour les autres.
- **`proven_fixed`** (corrigée, prouvé) : après ta fusion, pendant un `michel scan` de ton projet, l'outil qui a trouvé la faille regarde à nouveau et ne la voit plus **et** le commit de la branche est dans la branche actuelle de ton dépôt (Michel le vérifie sans rien écrire, `git merge-base --is-ancestor`). Cet outil, c'est le scan de tes dépendances pour une dépendance ; pour une faille trouvée par un outil externe (Semgrep, Trivy…), c'est cet outil, qui tourne à la fin du scan.
- Faille disparue sans ce commit, ou commit fusionné alors que l'outil voit encore la faille : la tentative passe `inconclusive` (pas concluant), avec la raison.
- Si cet outil n'a pas regardé pendant ce scan (éteint, pas réglé pour tourner pendant le scan, en échec ; pour une dépendance, un dossier sans fichier de dépendances), Michel ne conclut rien : la tentative reste `applied` jusqu'à un scan où il regarde. Lancer l'outil seul (`michel source run`, ou un rapport importé) ne conclut rien non plus.
- Michel ne relance pas les tests après la fusion, parce qu'il ne lance jamais rien dans ton dossier : les tests ont tourné sur la copie, avant la fusion. Un scan sur ton ordinateur voit la fusion, pas le déploiement : Michel dit « corrigée dans ton code » et te rappelle de déployer ; il ne prétend pas que le serveur est à jour.

Voici les états que tu verras sur la page : `preparing` (en préparation) → `proposed` (proposée) → `approved` (validée) ou `refused` (refusée) → `applied` (branche créée) → `proven_fixed` ou `inconclusive` ; `failed` (échouée, avec sa cause : l'agent s'est arrêté, Michel a refusé la modification ou n'a pas pu créer la branche) depuis `preparing`, `proposed` ou `approved` ; `superseded` (remplacée) quand une proposition plus récente prend sa place.

## Le masquage, et sa limite

Avant que ce que Michel donne lui-même arrive à l'agent (la fiche, les réponses MCP), Michel masque les secrets : clés AWS, jetons GitHub, clés PEM, valeurs de type `.env`, affectations de mot de passe, secret, jeton ou clé, mots de passe dans une adresse de connexion ; les chemins complets de ton ordinateur deviennent des chemins relatifs. Chaque secret est remplacé par un repère `[secret-<aléatoire>-N]`. La table qui relie les repères aux vraies valeurs reste dans le coffre à secrets de Michel (chiffré par Windows, ou un fichier lisible par toi seul ailleurs) et n'est jamais envoyée. Le journal d'audit note combien de valeurs ont été masquées et de quel type, jamais les valeurs.

- La page et l'API ne remettent jamais la vraie valeur : un secret y reste affiché comme un repère.
- Michel ne met **jamais** de repère dans un commit : une modification qui en contient un est refusée (l'agent a pu le recopier depuis la fiche). Au moment de la proposition, l'agent est prévenu et peut proposer à nouveau ; si un repère arrivait quand même à l'étape de la branche, Michel ne crée pas la branche et la tentative passe `failed` avec cette cause (c'est un refus de Michel, pas le tien). Si une correction a vraiment besoin d'une valeur secrète dans le code, tu l'ajoutes à la main.
- Les modifications affichées sur la page sont masquées, mais la branche contient la modification telle qu'elle a été écrite : une ligne de ton code qui ressemble à un mot de passe n'est pas une raison de refuser la modification.
- **La limite** : les fichiers de la copie ne sont **pas** masqués. La copie contient ton vrai code, Claude Code le lit, donc il part chez Anthropic. Ce qui protège tes secrets, c'est que les fichiers exclus ne sont pas copiés ; un secret écrit dans un fichier de ton commit est lu par l'agent. C'est pour ça que Michel te les signale dans la conversation ; le signalement arrive une fois l'agent démarré, donc sors un secret du code avant de lancer une correction. La détection des secrets n'est jamais parfaite : certaines formes (`<password>` en XML, valeurs YAML sur plusieurs lignes, mot de passe contenant un `@` non encodé dans une adresse…) peuvent passer.

## Corrections de serveur (plan 6)

Une faille de **serveur** (un réglage de PHP, un paquet) a sa propre correction, décrite dans [servers.fr.md](servers.fr.md) : pas de copie de travail ni de branche, mais deux scripts, `appliquer` et `annuler`, que tu valides par empreinte. Tu les lances toi-même sur le serveur, ou Michel les lance pour toi.

- Le niveau se règle **par serveur** (`--level` de `michel target add|set`), pas par projet. Michel prépare seul les corrections connues ; l'agent ne sert qu'à discuter un cas, avec un accord **par serveur** (celui de la préprod quand il y en a une) et jamais pour un serveur de type `hds`.
- Le niveau 3 ne lance sans clic que les réglages des règles de Michel à leur valeur conseillée, jamais un paquet ; une mise à jour de paquet attend toujours ton **Snapshot fait**.
- Une correction dont Michel ne peut pas dire le résultat finit à l'état `unknown` (inconnu) : va voir le serveur, puis `michel fix resolve <tentative>` (ou **J'ai vérifié le serveur** sur la page).
- Une seule correction à la fois par serveur : tant qu'une correction est en cours, vérifiée après son script ou `unknown`, aucune autre n'est préparée ni lancée sur ce serveur.

## Risques qui restent

- **L'installation et les tests tournent avec tes droits, sans bac à sable.** `composer`/`npm` et tes tests tournent sur la copie en ton nom, sur ton ordinateur ; quand l'agent a modifié du code, les tests exécutent ce code. Michel verrouille ce qu'il peut (pas de scripts d'installation, pas de plugins, listes de réglages autorisés, dossiers remis à zéro avant chaque installation, dossier séparé, dossier personnel propre à Michel, le proxy), mais ce n'est pas un environnement isolé : un projet ou une modification malveillante pourrait atteindre ce que toi tu peux atteindre. Un environnement isolé (Docker) est prévu dans un plan suivant.
- **Un programme qui ignore le proxy.** Claude Code, git, composer, npm et les tests reçoivent `HTTPS_PROXY`/`HTTP_PROXY` vers le proxy d'autorisation de Michel. Mais un programme peut ignorer ce proxy et ouvrir ses propres connexions : Michel ne l'arrêterait pas et ne le noterait pas. Le proxy est un garde-fou, pas une garantie.
- **Claude Code évolue.** Michel s'appuie sur des options de Claude Code pour garder l'agent à l'écart de tes réglages. Il refuse les versions qui n'ont pas ces options, mais ne peut pas garantir qu'une future version les respectera de la même façon. Claude Code lit toujours sa connexion dans ton dossier utilisateur (ton profil).
  - Options utilisées (testées avec la version 2.1.314) : `--setting-sources ""`, `--strict-mcp-config`, `--restricted`, `--tools`, les règles de permission, et les variables qui coupent `CLAUDE.md`, la mémoire et le trafic non essentiel.
- **Anthropic lit le code de la copie**, comme le dit l'écran d'accord.
- **Le texte de l'agent ne doit pas être cru sur parole.** Il est affiché, jamais exécuté ; sa proposition est vérifiée par Michel, et c'est toi qui décides.

## En cas de problème

| Ce que tu vois | Quoi faire |
|---|---|
| « Claude Code n'est pas installé sur cet ordinateur » | Installe-le (https://claude.com/claude-code), puis **Vérifier à nouveau**. En attendant, lis la fiche (`michel brief <faille>`). Michel cherche `claude` dans le PATH (ou le programme indiqué par `MICHEL_CLAUDE_BIN`). |
| « Ta version de Claude Code est trop ancienne » | `claude update`. Michel a besoin des options qui tiennent tes réglages à l'écart de l'agent. |
| « Claude Code n'est pas connecté » | Lance `claude` dans un terminal et connecte-toi, puis réessaie. |
| « …Michel a besoin de ton accord… » | Lis l'écran d'accord et accepte, ou `michel fix consent <projet> --yes`. |
| « Ta politique est en mode strict_local » | Utilise le bouton de l'écran d'accord sur la page, ou mets toi-même `sovereignty.mode: standard` (voir plus haut). |
| « Ce projet est classé santé » | Jamais envoyé à une IA externe. Lis la fiche et corrige à la main. |
| « Ce projet n'est pas suivi par git » / « pas encore de commit » | Michel copie avec git : mets le projet dans git (et fais un premier commit). La fiche reste disponible. |
| « Ton projet est trop gros » | Exclus les gros dossiers (`--exclude`), ou corrige à la main depuis la fiche. |
| « …feraient lancer des programmes du projet lui-même » | Un réglage de ton projet (npm, Composer) demanderait d'exécuter du code pendant l'installation ; Michel ne l'accepte pas, donc rien n'a tourné. Corrige à la main ou retire ce réglage. |
| « Tests : pas lancés », aucune commande de test | Indique-la : `michel project set <nom> --test-cmd "…"`. |
| « Tests : pas lancés », projet yarn ou pnpm | Michel n'installe pas avec yarn ni pnpm : vérifie toi-même que ton site marche avant de fusionner. |
| « Tests : pas lancés », installation refusée | La page dit quel réglage bloque : retire-le, ou vérifie toi-même que ton site marche avant de fusionner. |
| « Michel a refusé la modification de l'agent » | L'agent a touché un fichier hors de la copie ou un fichier protégé. Rien n'a été appliqué ; tu peux réessayer. |
| « Michel n'a pas créé la branche : la modification contenait un repère… » | La modification contenait un repère `[secret-…]` à la place d'un secret. Rien n'a été appliqué ; relance une correction. |
| « La proposition a changé depuis que tu l'as lue » | Lis la nouvelle, puis valide-la. |
| « Une correction est déjà en cours sur ce projet » | Termine-la ou refuse-la d'abord. |
| Niveau 2 : rien ne démarre | `michel serve` doit tourner ; le projet a besoin de son accord IA ; au plus 3 tentatives lancées seules par jour et par projet. |

Ce qui sort de l'ordinateur, site par site : [security/network-egress.fr.md](security/network-egress.fr.md).
