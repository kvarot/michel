# Corriger : un agent prépare la correction, tu la valides

🇬🇧 English version : [fix.md](fix.md)

Michel trouve les failles et te les explique. Avec le plan 5, il peut aussi les faire corriger : Claude Code travaille sur une **copie** de ton projet, Michel vérifie ce qu'il a fait, lance lui-même les tests et te montre une proposition en clair. Rien n'arrive dans ton dépôt avant que tu cliques sur **Valider**, et même alors Michel crée seulement une branche : c'est toi qui la fusionnes et qui déploies comme d'habitude (avec PhpStorm, par exemple).

Pourquoi : pour une faille comme Php2shell, il fallait lire des articles pour comprendre que tu étais touché, en chercher d'autres pour savoir comment corriger, les donner à une IA, puis corriger toi-même. Trois étapes à la main : **trouver** (est-ce que ça me touche, et où), **comprendre** (en clair, pourquoi chez moi), **corriger** (quoi changer, puis vérifier). L'agent fait ces étapes pour toi, et c'est toi qui as le dernier mot.

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

Le niveau 1 suffit pour corriger depuis la page : **Corriger** est un clic, pas un réglage. Les niveaux 2 et 3 ajoutent seulement l'initiative, et demandent l'accord IA du projet ; sans lui, Michel reste au niveau 1 et te le dit.

- **Faille qui le permet, au niveau 2** : une faille ouverte dans une dépendance (ni reportée ni ignorée), avec une version corrigée connue, sans tentative en cours ni proposition déjà refusée. D'abord les failles déjà attaquées (KEV), puis par gravité. `scan --all` les met en file d'attente ; `michel serve` les prend dans l'ordre, **une tentative à la fois par projet**, et **au plus 3 tentatives lancées seules par jour et par projet**. Si `serve` ne tourne pas, rien ne démarre.
- **Règle automatique (niveau 3)** : la case « Appliquer seul les mises à jour mineures sûres » du projet (`--auto-fix-minor`). Michel (jamais l'agent) applique sans clic seulement si **tout** ceci est vrai : la correction ne touche que `composer.json`/`composer.lock` ou `package.json`/`package-lock.json` (ou `yarn.lock`, `pnpm-lock.yaml`), aucun fichier de code ; le saut de version est petit (correctif ou mineur, pas majeur, par exemple pas de 7 à 8) ; le score de risque est sous le seuil du projet `auto_fix_below` (30 par défaut, voir [remediation-risk.fr.md](remediation-risk.fr.md)) ; le nouveau scan de la copie ne voit plus la faille **et** les tests ont réussi (pas seulement « pas lancés ») ; et l'agent n'a rien changé après la mise à jour faite par Michel : ce qui est appliqué est exactement cette mise à jour, lue dans le commit de la proposition. Sinon, la proposition t'attend. « Appliquer » veut dire « créer la branche », jamais fusionner ni déployer.

## L'écran d'accord : ce qui sort de ton ordinateur

Claude Code envoie à Anthropic ce qu'il lit : c'est une IA externe au sens de la [politique de souveraineté](security/sovereignty-policy.md). Le premier clic sur **Corriger** dans un projet affiche donc un écran d'accord, un par projet. Il dit :

- ce qui sort : le code de la copie que l'agent lit, la fiche (secrets masqués) et tes messages ; pas les fichiers exclus, pas les secrets masqués ;
- ce qui tourne : « Michel lance composer/npm et tes tests sur une copie, avec tes droits Windows ; le code écrit par l'agent s'exécute. » (voir « Risques qui restent ») ;
- que le projet est classé sensible, quand c'est le cas (c'est le réglage par défaut) : le masquage est actif et les fichiers exclus ne sont pas copiés ;
- chaque adresse (« hôte ») qui n'a pas encore de règle réseau :
  - Anthropic, usage `agent.claude` : `api.anthropic.com` (le service de l'IA) et `platform.claude.com` (où une connexion par abonnement renouvelle son accès) ;
  - les dépôts de paquets, usage `fix.install` : `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com` (les archives que Composer télécharge), `registry.npmjs.org` ;
- qu'en acceptant, tu autorises les IA externes dans ta politique (`ai.external_providers_enabled`), quand ce n'est pas déjà le cas.

Quand tu acceptes, Michel écrit une règle par adresse dans `sovereignty.network.allow` de ton fichier de politique (en gardant une copie `config.yaml.bak`), active `ai.external_providers_enabled` si besoin, relit la politique sans redémarrer, enregistre l'accord du projet et note `ai.consent` dans le journal d'audit (adresses, usages, classement, qui). Un projet classé `health` (santé) est toujours refusé, avec ou sans accord.

### Quand ta politique est en `strict_local`

`strict_local` (le réglage par défaut) veut dire : rien ne sort de ton ordinateur et aucune IA externe n'est utilisée. Michel ne quitte jamais ce mode de lui-même. Sur la page, l'écran d'accord explique ce que `strict_local` protège et propose un bouton clair, « Passer en mode standard et autoriser les IA externes ». Ce clic écrit `sovereignty.mode: standard` et `ai.external_providers_enabled: true` en une seule modification du fichier de politique (avec son `.bak`, pour revenir en arrière), note `policy.mode` dans le journal d'audit, puis donne l'accord du projet. Tu gardes un cadre précis : seulement les adresses listées, seulement les projets où tu donnes ton accord. En ligne de commande, `michel fix consent` refuse en `strict_local` : change d'abord le mode toi-même dans le fichier, ou passe par la page.

## La copie de travail

L'agent ne travaille jamais dans ton dossier. Pour chaque tentative, Michel prépare dans son dossier de données :

1. un **miroir privé** de ton dépôt (`<data>/fix-mirrors/<projet>/<tentative>.git`, par `git clone --bare --local`, qui ne fait que lire ton dépôt). L'agent ne le voit jamais ;
2. la **copie de l'agent** (`<data>/worktrees/<projet>/<tentative>/`) : un dépôt git neuf, rempli avec les fichiers de ton dernier commit, **sans l'historique**, sans adresse distante ni chemin complet de ton ordinateur, en un seul commit « michel: base ».

Restent hors de la copie : les fichiers qui ne sont pas dans un commit (donc ceux que git ignore), les `.env*`, `*.pem`, `*.key`, `id_*` à tous les niveaux, majuscules comprises, les dossiers que le projet exclut (`michel project set <nom> --exclude <dossier>`), les liens symboliques et les fichiers spéciaux. Une copie est limitée à 30 000 fichiers, 256 Mio par fichier et 4 Gio en tout ; un projet plus gros est refusé (voir « En cas de problème »). Pendant toute la préparation, Michel n'écrit rien dans ton projet (c'est testé).

Avant que l'agent démarre, Michel passe ses détecteurs de secrets sur les fichiers de la copie. Un secret écrit dans ton code est signalé dans la conversation (« 2 secrets semblent écrits dans ton code (…) : l'agent peut les lire »), avec les fichiers concernés, pour que tu puisses les tenir à l'écart : déplace-les dans un dossier exclu (`--exclude` prend des noms de dossiers, pas de fichiers), ou sors le secret du code (dans un fichier `.env`, qui n'est jamais copié).

## Ce que l'agent peut faire, et ce qu'il ne peut pas faire

Michel lance lui-même Claude Code, en arrière-plan, avec une ligne de commande fixée par Michel, un environnement limité à une liste précise de variables et un dossier de travail dans la copie. Il utilise ta connexion Claude Code existante (abonnement ou clé : Michel ne la lit pas et ne la transmet pas), mais **aucun** de tes réglages, de tes hooks (scripts lancés automatiquement), de tes plugins, de tes autres serveurs MCP, de tes `CLAUDE.md` ni de ta mémoire, ni rien de tout ça venant de la copie (un dossier `.claude/` dans un projet n'est pas digne de confiance) : aucune source de réglages n'est chargée, les hooks sont coupés, seul le serveur MCP de Michel est déclaré.

L'agent **peut** :

- lire, chercher, modifier et écrire des fichiers **dans la copie** (outils Read, Glob, Grep, Edit, Write) ;
- interroger Michel par son serveur MCP (`michel mcp`) : `list_findings`, `get_finding`, `get_brief`, `get_call_sites`, `get_changelog_excerpt`, `get_attempt`, et `propose_fix`, le seul outil qui écrit, et seulement dans les données de Michel, pour cette tentative (il faut un jeton lié à la tentative).

L'agent **ne peut pas** :

- lancer une commande : il n'a **aucun** outil Bash ; c'est Michel qui lance lui-même la mise à jour, l'installation et les tests ;
- aller sur le web (WebFetch et WebSearch coupés) : les articles utiles sont dans la fiche ;
- écrire dans `vendor/`, `node_modules/`, `.git/`, `.claude/` ou `.mcp.json`, ni lire tes fichiers Claude Code (`~/.claude`, `~/.claude.json`) et tes clés (`~/.ssh`) ;
- valider, appliquer, changer un réglage ou la politique : aucun outil ne le permet, la validation passe seulement par l'API locale avec son jeton.

Une tentative dure au plus 20 minutes ; ensuite Michel arrête ses processus. Le contenu du dépôt, les avis et les articles sont donnés à l'agent comme des données à lire, jamais comme des consignes de Michel. Les conversations sont gardées 30 jours, secrets masqués.

## Ce que Michel lance lui-même

Au départ, sur la copie encore telle que tu l'as mise dans ton commit (avant que l'agent la voie), Michel lance la mise à jour prévue, avec une ligne de commande fixée par lui :

- Composer : `composer update <paquet>:^<version> --with-all-dependencies --no-scripts --no-plugins --no-interaction` (`composer require … --update-with-all-dependencies` pour un saut de version majeur, `composer update <paquet> --with-dependencies` pour une dépendance indirecte) ;
- npm : `npm install <paquet>@<version> --save-exact --ignore-scripts --no-audit --no-fund` (`npm update <paquet>` pour une dépendance indirecte).

Il n'y a pas de mise à jour pour un fichier `yarn.lock` ou `pnpm-lock.yaml` : l'agent part des fichiers du projet tels qu'ils sont.

Le résultat est le premier message de Michel dans la conversation. Quand l'agent propose sa correction (`propose_fix`), Michel fige la copie une fois (une seule photo : ce que l'agent écrit ensuite est ignoré), reconstruit cette photo dans un dossier à part (`<data>/fix-tmp/<tentative>/`, jamais la copie de l'agent), et là :

1. installe les dépendances (`composer install --no-scripts --no-plugins` ou `npm ci --ignore-scripts`), en repartant de zéro ;
2. lance les tests du projet, si tu as indiqué une commande (`michel project set <nom> --test-cmd "vendor/bin/phpunit"`, découpée en mots sans passer par un shell) ;
3. scanne à nouveau le résultat.

Michel n'installe qu'avec **Composer et npm**. Un projet yarn ou pnpm est lu et peut être corrigé, mais Michel ne lance ni yarn ni pnpm : la proposition arrive **sans installation ni tests**, et la page le dit. Avant toute installation, Michel refuse les réglages du projet qui feraient lancer du code du projet pendant l'installation, ou télécharger ailleurs (réglages npm hors d'une courte liste autorisée, dépôts Composer locaux ou git, téléchargements sans https, anciens fichiers `package-lock.json`, entrées sans empreinte de contrôle…) : rien n'est installé, les tests ne tournent pas, et la page dit pourquoi. Ces commandes tournent avec un dossier personnel propre à Michel (`<data>/fix-home`), jamais le tien, et passent par le proxy d'autorisation (usage `fix.install`).

## La proposition et la validation par empreinte

Une proposition ne change plus une fois faite : un résumé en clair, les modifications (le « diff ») **calculées par Michel** à partir de la photo figée (pas recopiées de l'agent), les fichiers touchés, les commandes lancées par Michel, le résultat des tests (`passed` réussis, `failed` échoués, `not_run` pas lancés), le nouveau scan de la copie, le risque, et une empreinte SHA-256 de l'ensemble. Si l'agent continue et propose à nouveau, la nouvelle proposition remplace l'ancienne (`superseded`) et la page l'affiche.

Michel refuse une modification qui touche un fichier hors de la copie (`..`, chemin complet, lien), un fichier protégé ou un fichier exclu : la tentative passe `failed`, la cause est dite en clair, rien n'est appliqué.

**Valider** envoie l'empreinte de la proposition que tu as lue. Si l'agent l'a remplacée entre-temps, Michel n'applique rien (réponse 409) et te montre la nouvelle. En ligne de commande, `michel fix approve` sans `--hash` valide la proposition que `michel fix status` a affichée en dernier, et refuse si elle a changé depuis.

## La branche, puis tu déploies

Appliquer, c'est : Michel construit **un seul commit** à lui dans le miroir (auteur Michel, parent = ton vrai commit ; les commits que l'agent aurait faits sont ignorés), puis le fait venir dans ton dépôt sur la branche `michel/fix-<id-court>`. Pas de changement de branche, pas de fusion : ta branche actuelle, tes fichiers et ce que tu as préparé pour ton prochain commit ne bougent pas (testé, même avec des fichiers modifiés ou une autre branche en cours). C'est la seule écriture de Michel dans ton projet, et seulement après ta validation : des objets et une référence dans son `.git`.

La page dit alors : « La branche michel/fix-… est prête. Fusionne-la puis déploie avec PhpStorm comme d'habitude. » Michel ne fusionne jamais et ne déploie jamais.

## La preuve

- Tests réussis et nouveau scan propre **dans la copie** : obligatoires pour une application automatique (niveau 3), affichés pour les autres.
- **`proven_fixed`** (corrigée, prouvé) : après ta fusion, un scan de ton projet (`michel scan`) ne voit plus la faille **et** le commit de la branche est dans la branche actuelle de ton dépôt (Michel le vérifie sans rien écrire, `git merge-base --is-ancestor`).
- Faille disparue sans ce commit, ou commit fusionné alors que la faille est encore vue : la tentative passe `inconclusive` (pas concluant), avec la raison.
- Michel ne relance pas les tests après la fusion. Un scan sur ton ordinateur voit la fusion, pas le déploiement : Michel dit « corrigée dans ton code » et te rappelle de déployer ; il ne prétend pas que le serveur est à jour.

Les étapes d'une tentative : `preparing` (en préparation) → `proposed` (proposée) → `approved` (validée) ou `refused` (refusée) → `applied` (branche créée) → `proven_fixed` ou `inconclusive` ; `failed` (échouée, avec sa cause) depuis `preparing` ; `superseded` (remplacée) quand une proposition plus récente prend sa place.

## Le masquage, et sa limite

Avant que ce que Michel donne lui-même arrive à l'agent (la fiche, les réponses MCP), Michel masque les secrets : clés AWS, jetons GitHub, clés PEM, valeurs de type `.env`, affectations de mot de passe, secret, jeton ou clé, mots de passe dans une adresse de connexion ; les chemins complets de ton ordinateur deviennent des chemins relatifs. Un secret devient un repère `[secret-<aléatoire>-N]` ; la table repère → valeur reste dans le coffre à secrets de Michel (chiffrée par Windows, ou un fichier lisible par toi seul ailleurs) et n'est jamais envoyée. Le journal d'audit note combien de valeurs ont été masquées et de quel type, jamais les valeurs.

- La page et l'API ne remettent jamais la vraie valeur : un secret y reste affiché comme un repère.
- Michel ne remet **jamais** un secret dans un commit : une proposition qui contient un repère est refusée (l'agent a pu le recopier depuis la fiche) ; si une correction a vraiment besoin d'une valeur secrète dans le code, tu l'ajoutes à la main.
- **La limite** : les fichiers de la copie ne sont **pas** masqués. La copie contient ton vrai code, Claude Code le lit, donc il part chez Anthropic. Ce qui protège tes secrets, c'est que les fichiers exclus ne sont pas copiés ; un secret écrit dans un fichier de ton commit est lu par l'agent. C'est pour ça que Michel te les signale avant que l'agent démarre. La détection des secrets n'est jamais parfaite : certaines formes (`<password>` en XML, valeurs YAML sur plusieurs lignes, mot de passe contenant un `@` non encodé dans une adresse…) peuvent passer.

## Risques qui restent

- **L'installation et les tests tournent avec tes droits, sans bac à sable.** `composer`/`npm` et tes tests tournent sur la copie en ton nom, sur ton ordinateur ; quand l'agent a modifié du code, les tests exécutent ce code. Michel verrouille ce qu'il peut (pas de scripts d'installation, pas de plugins, listes de réglages autorisés, dossiers remis à zéro avant chaque installation, dossier à part, dossier personnel propre à Michel, le proxy), mais ce n'est pas un environnement isolé : un projet ou une modification malveillante pourrait atteindre ce que toi tu peux atteindre. Un environnement isolé (Docker) est prévu dans un plan suivant.
- **Un programme qui ignore le proxy.** Claude Code, git, composer, npm et les tests reçoivent `HTTPS_PROXY`/`HTTP_PROXY` vers le proxy d'autorisation de Michel. Un programme qui ouvre ses propres connexions n'est ni arrêté ni noté. C'est une barrière, pas une garantie.
- **Claude Code évolue.** L'isolement repose sur des options de Claude Code (testées avec la version 2.1.314) : `--setting-sources ""`, `--strict-mcp-config`, `--restricted`, `--tools`, les règles de permission, les variables qui coupent `CLAUDE.md`, la mémoire et le trafic non essentiel. Michel refuse une version dont l'aide n'a pas ces options, mais ne peut pas vérifier qu'une version future les respecte toujours de la même façon. Claude Code lit toujours sa connexion dans ton dossier personnel.
- **Anthropic lit le code de la copie**, comme le dit l'écran d'accord.
- **Le texte de l'agent n'est pas digne de confiance.** Il est affiché, jamais exécuté ; sa proposition est vérifiée par Michel, et c'est toi qui décides.

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
| « …feraient lancer des programmes du projet lui-même » | Un réglage du projet (npm, Composer) sort de ce que Michel accepte ; rien n'a tourné. Corrige à la main, ou retire ce réglage. |
| « Tests : pas lancés » | Pas de commande de test : `michel project set <nom> --test-cmd "…"`. Projet yarn ou pnpm, ou installation refusée : la page dit lequel ; vérifie toi-même que ton site marche avant de fusionner. |
| « Michel a refusé la modification de l'agent » | L'agent a touché un fichier hors de la copie ou un fichier protégé. Rien n'a été appliqué ; tu peux réessayer. |
| « La proposition a changé depuis que tu l'as lue » | Lis la nouvelle, puis valide-la. |
| « Une correction est déjà en cours sur ce projet » | Termine-la ou refuse-la d'abord. |
| Niveau 2 : rien ne démarre | `michel serve` doit tourner ; le projet a besoin de son accord IA ; au plus 3 tentatives lancées seules par jour et par projet. |

Ce qui sort de l'ordinateur, adresse par adresse : [security/network-egress.fr.md](security/network-egress.fr.md).
