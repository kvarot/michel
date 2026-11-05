# Corriger : un agent prépare la correction, tu la valides

🇬🇧 English version : [fix.md](fix.md)

Michel trouve les failles et te les explique. Avec le plan 5, il peut aussi les faire corriger : Claude Code travaille sur une **copie** de ton projet, Michel vérifie ce qu'il a fait, lance lui-même les tests et te montre une proposition en clair. Rien n'arrive dans ton dépôt avant que tu cliques sur **Valider**, et même alors, sans rattachement à un service Git, Michel crée seulement une branche (voir « Rattacher ton projet à GitHub, Bitbucket ou GitLab » plus bas) : c'est toi qui la fusionnes et qui déploies comme d'habitude (avec PhpStorm, par exemple).

Pourquoi : pour une faille comme Php2shell (un exemple réel), il fallait lire des articles pour comprendre que tu étais touché, en chercher d'autres pour savoir comment corriger, les donner à une IA, puis corriger toi-même. Cela faisait trois étapes à faire à la main : **trouver** (est-ce que ça me touche, et où), **comprendre** (en clair, pourquoi chez moi), **corriger** (quoi changer, puis vérifier). L'agent fait ces étapes pour toi, et c'est toi qui as le dernier mot.

Tout se fait depuis la page (`michel serve`, bouton **Corriger** sur une faille de la page « Aujourd'hui », puis **OK, répare** ou un message à l'agent). La ligne de commande n'existe que pour les scripts :

```
michel brief <faille>             # la fiche de correction (trouver, comprendre, corriger), rien n'est envoyé
michel fix consent <projet> --yes # l'accord IA du projet (aussi demandé sur la page)
michel fix prepare <faille>       # lance une tentative et la suit
michel fix status [<tentative>]   # les tentatives, ou une tentative avec sa proposition et la conversation
michel fix test <tentative> --yes # lance les tests d'une proposition qui attend ton accord
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

- ce qui sort : les fichiers de la copie que l'agent lit, la fiche de la faille (secrets masqués) et tes messages ; quand Michel reconnaît une clé possible dans ces fichiers, l'agent ne démarre pas tant que tu n'as pas répondu (voir « La copie de travail ») ; une clé que Michel ne reconnaît pas, ou que tu choisis de laisser, part avec eux ; les fichiers exclus ne sortent pas ;
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

Avant que quoi que ce soit sorte de ton ordinateur, Michel passe ses détecteurs de secrets sur les fichiers de la copie. Quand ils trouvent ce qui a la forme d'une clé (un format connu, comme une clé AWS, ou une valeur écrite en clair qui ressemble à un secret sur un nom sensible, comme `password` ou `token`), la tentative s'arrête dans l'état `held` (en attente de ta réponse), à tous les niveaux et pour tous les démarrages, automatiques compris : pas d'agent, pas de mise à jour, rien ne sort. La page, `michel fix prepare` et `michel fix status` disent combien de clés possibles, dans quels fichiers et à quelles lignes, jamais la valeur.

Michel juge à la forme de ce qui est écrit, sans savoir si la clé est vraie. Ce jugement décide seulement de l'arrêt : Michel masque toujours autant de choses sur la page et dans la fiche.

Ce qui arrête l'agent :

- un format connu : clé AWS, jeton GitHub, clé privée, clé secrète Stripe de production (`sk_live_`, `rk_live_`), jeton JWT, jeton Slack (`xoxb-` et ses variantes). Toujours, même si c'est un exemple écrit dans ce format (`xoxb-your-bot-token`) ;
- une valeur d'au moins 8 caractères, sans espace, sur un nom sensible (`password`, `token`, `api_key`, `DB_PASSWORD=`…), quand elle n'est pas faite de mots simples : des lettres mêlées à des chiffres ou à des signes, ou des lettres qui ne font pas un mot (majuscules éparpillées, 6 consonnes de suite) ;
- la même chose en PHP : `define('DB_PASSWORD', '…')`, `'key' => 'base64:…'`, une clé de tableau comme `$config['password'] = '…'`, le troisième argument de `new PDO(…)` ou de `new mysqli(…)`, et de même pour `mysqli_connect(…)`, écrit entre guillemets (ces appels peuvent s'étendre sur plusieurs lignes, et un mot de passe écrit en plusieurs morceaux `'a' . 'b'` est lu en entier, même si une variable ou un appel s'intercale ; les commentaires entre les arguments sont ignorés) ; et un mot de passe dans une adresse de connexion ;
- un mot par défaut suivi de chiffres, entre guillemets ou dans une adresse (`password = 'admin123'`).

Ce qui n'arrête pas l'agent, même si c'est une vraie clé. Michel le dit dans un message pour une ligne qu'il a vue, et l'agent peut la lire :

- une ligne qui parle d'un mot de passe sans en montrer un : un type, une variable, un appel, une phrase, une valeur qui est un modèle d'un bout à l'autre (`${X}`, `{{ x }}`, `<x>`, `%x%`, `$x`, `[x]`, `{x}`), un exemple comme `your-key-here` ;
- une valeur sans guillemets lue comme du code : avec `(`, `)`, `;`, `<`, `>` ou un guillemet après `NOM=`, avec un crochet, une accolade, `(`, `)`, `;`, `<`, `>` ou `->` après `nom:`. Donc `DB_PASSWORD=aB3;xY9!qZ` passe ;
- un mot simple, une phrase, des mots simples reliés par des tirets (`cheval-correct-batterie`), une valeur de moins de 8 caractères, un mot par défaut (`password = 'password'`), un mot par défaut suivi de chiffres sans guillemets (`password: admin123`) ;
- une valeur dont une partie est exactement `test`, `fake`, `mock`, `stub` ou `dummy` (`sk_test_…`, `mock-kP9mW2xQ7vT`), ou un exemple (`your`, `example`, `xxx`…) avec seulement des mots et des nombres à côté ;
- une valeur qui commence par `npm:`, `workspace:`, `file:`, `link:`, `^`, `~` ou un mot de validation (`required|`, `nullable|`, `string|`, `sometimes|`), une valeur qui contient `://`, un chemin fait de mots courts en minuscules (`/etc/ssl/private/server.key`), et le hash public de l'ancienne `UserFactory` de Laravel ;
- une valeur sans nom sensible que Michel sait lire à côté : les arguments d'un appel autre que ceux cités plus haut (par exemple `ldap_bind($c, 'uid', '…')`, `mysqli_real_connect(…)`, `->real_connect(…)`), un appel `new mysqli(…)`, `new PDO(…)` ou `mysqli_connect(…)` dont un argument avant le mot de passe est trop imbriqué (plus de trois parenthèses l'une dans l'autre) ou contient une apostrophe ou un guillemet non fermé, un mot de passe construit par une variable ou un appel, placé après `?:` ou `??` ou dans un appel de fonction, écrit en heredoc ou dans un texte sur plusieurs lignes (aussi quand c'est un morceau d'une chaîne de textes), une chaîne de textes qui continue après un retour à la ligne sans point, ou sur la ligne qui suit le `=`, un simple `key:`. Dans une chaîne de textes, Michel lit les morceaux après le premier seulement pour une clé de tableau (`$c['password'] = 'a' . 'b'`), `'password' => …`, `define(…)` et les appels cités plus haut : après un simple nom (`$password = 'a' . 'b'`, `password: 'a' . 'b'`), seul le premier morceau est masqué. Hors de PHP, un point suivi d'un nombre, ou directement d'un nom, arrête la chaîne (`d['password'] = 'a'.b.'c'`). Une chaîne de plus de 64 Kio est masquée jusqu'à la fin de la ligne où tombe cette limite, pas au-delà. Une virgule dans le premier argument de `new PDO(…)` peut faire lire le nom d'utilisateur comme le mot de passe, et bloquer à tort.

Quand la tentative s'arrête, tu choisis :

- **Je les retire d'abord** (`michel fix withdraw <tentative>`) : la tentative se termine dans l'état `withdrawn`, sa copie est supprimée et aucun agent ne démarre. Sors la clé du code (mets-la dans une variable d'environnement ou un fichier `.env`, qui n'est jamais copié), fais un commit, et relance la correction : la copie contient ton dernier commit, donc une clé retirée sans commit y est encore. Exclure le dossier qui la contient marche aussi (le message de Michel le nomme ; `--exclude` prend des noms de dossiers, pas de fichiers). Un nouveau démarrage où Michel ne trouve aucune clé démarre directement. Après ce non, les démarrages automatiques ne reposent pas la question tant que ton dernier commit et tes dossiers exclus restent les mêmes, pour aucune faille de ce projet. Ton propre démarrage, lui, cherche et demande à nouveau.
- **Continuer quand même** (`michel fix continue <tentative>`, dans un terminal : Michel remontre la liste et attend que tu écrives `oui`) : l'agent démarre, il peut lire ces fichiers, et ce qu'il lit part chez Anthropic.

Ton oui vaut pour cette tentative seulement et n'est jamais gardé : la tentative suivante cherche et demande à nouveau. Le journal d'audit garde seulement des nombres (`fix.hold`, `fix.hold.continue`, `fix.hold.withdraw`). Le oui est refusé, et la tentative se termine en `failed`, si la copie a changé, si la recherche trouve autre chose, si ton projet a un nouveau commit ou un autre dossier exclu, ou si la faille est partie : relance la correction, Michel cherche à nouveau. Michel ne répond jamais à ta place : ni une règle de niveau 3, ni le travail en arrière-plan, ni une session `michel mcp` ne le peuvent, et `michel fix continue` demande un terminal. Michel ne peut pas empêcher une personne ou un programme lancé avec tes droits de contourner ça : simuler un terminal, ou appeler la page à ta place (voir « Risques qui restent »).

Pendant qu'une tentative attend, le projet ne prend aucune autre correction, sa copie et la copie Git de ton projet restent dans le dossier de données de Michel, et sa ligne reste dans À faire, au rang « À toi ». Le résumé et, pour un démarrage automatique, une notification disent qu'elle attend ta réponse. Sans réponse après 14 jours, la tentative se termine comme un non (`withdrawn`, copie supprimée, `fix.hold.withdraw` avec `author: expired`) : jamais comme un oui.

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
2. lance les tests du projet, si tu as indiqué une commande (`michel project set <nom> --test-cmd "vendor/bin/phpunit"`, découpée en mots sans passer par un shell), **seulement si l'instantané est exactement celui que la mise à jour de Michel a laissé** (l'agent n'a rien changé d'autre) ;
3. scanne à nouveau le résultat.

### Les tests sur la modification de l'agent attendent ton clic

Si l'agent a modifié d'autres fichiers en plus de la mise à jour prévue par Michel, lancer les tests ferait tourner du code écrit par l'agent, sur ton ordinateur, avec accès à ce que tu peux ouvrir toi-même (tes fichiers, tes comptes). Dans ce cas, Michel ne lance pas les tests tout seul. Il installe quand même les dépendances (aucun script ne tourne) et scanne à nouveau la copie (il ne fait que lire des fichiers). La page dit alors « Tests : en attente de ton accord ».

Cela vaut pour tout fichier, y compris la liste des logiciels du projet (composer.json, package.json) : elle peut contenir des commandes que les tests lanceraient, ou un logiciel ajouté dont le code tournerait pendant les tests.

Le message de Michel et la page listent les fichiers modifiés : d'abord la liste des logiciels du projet et le fichier qui fixe leurs versions, puis les tests, scripts et réglages, puis les autres fichiers (10 au plus, puis « et N autres »).

Lis la modification, puis choisis :

- **Lancer les tests**, dans la proposition. Sur la ligne de commande : `michel fix test <tentative>` liste les fichiers sans rien lancer ; ajoute `--yes` pour lancer les tests. Michel lance les tests de la proposition que tu as vue : si l'agent a proposé autre chose entre-temps, rien ne tourne. Michel prépare les fichiers dans un dossier à part sur ton ordinateur, installe, lance les tests (30 minutes au plus), puis affiche le résultat dans une nouvelle version de la proposition. Tu valides en connaissant ce résultat. Si l'agent propose à nouveau pendant les tests, le résultat est laissé de côté.
- **Valider** sans lancer les tests. Vérifie alors toi-même que ton site marche avant de faire entrer la branche dans ton code.

Le bouton ne sert qu'une fois par proposition. Pour relancer les tests, demande à l'agent de proposer à nouveau. L'agent ne peut pas lancer les tests lui-même.

Note technique : l'état des tests est alors `awaiting` ; il ne s'applique que lorsque l'instantané diffère de l'arbre laissé par la mise à jour de Michel (le niveau 3, qui exige cet arbre, ne change pas). Le clic porte l'empreinte de la proposition (une autre empreinte : erreur 409, rien ne tourne ; `michel fix test --hash` la donne à la main). Michel reconstruit l'arbre de la proposition dans `<data>/fix-tmp/<tentative>/tests-<aléatoire>` et enregistre une nouvelle proposition (même diff, même commit, même nouveau scan, nouvelle empreinte) : un **Valider** envoyé sur l'ancienne est refusé. Chaque clic est noté dans le journal d'audit (`fix.tests_run` : `started`, puis `ok`, `dropped`, `interrupted`, `error` ou `refused`, avec la tentative, la proposition, l'empreinte, l'auteur, le résultat et le nombre de fichiers). Une proposition faite par une version plus ancienne de Michel n'offre pas le bouton.

Michel n'installe qu'avec **Composer et npm**. Un projet yarn ou pnpm est lu et peut être corrigé, mais Michel ne lance ni yarn ni pnpm : la proposition arrive **sans installation ni tests**, et la page le dit.

Avant d'installer quoi que ce soit, Michel vérifie les réglages de ton projet. Il refuse tout ce qui ferait exécuter du code du projet pendant l'installation, ou télécharger depuis une source non sûre : réglages npm hors d'une courte liste autorisée, dépôts Composer locaux ou git, téléchargements sans https, anciens fichiers `package-lock.json`, paquets sans somme de contrôle. Dans ce cas, rien n'est installé, les tests ne tournent pas, et la page te dit pourquoi. Ces commandes tournent avec un dossier personnel propre à Michel (`<data>/fix-home`), jamais le tien, et passent par le proxy d'autorisation (usage `fix.install`).

## La proposition et la validation par empreinte

Une proposition ne change plus une fois faite. Elle contient : un résumé en clair, les modifications (le « diff ») **calculées par Michel** à partir de l'instantané (pas recopiées de l'agent), les fichiers touchés, les commandes lancées par Michel, le résultat des tests (`passed` réussis, `failed` échoués, `not_run` pas lancés, `awaiting` en attente de ton accord), le nouveau scan de la copie (une faille trouvée par un outil externe (Semgrep, Trivy…) ne peut pas être scannée à nouveau sur la copie : la page dit que Michel n'a pas pu la contrôler), le risque, et une empreinte de l'ensemble (SHA-256 : un code qui change dès que le moindre détail du contenu change). Si l'agent continue et propose à nouveau, la nouvelle proposition remplace l'ancienne (`superseded`) et la page l'affiche.

Michel refuse une modification qui touche un fichier hors de la copie (`..`, chemin complet, lien), un fichier protégé ou un fichier exclu : la tentative passe `failed`, la cause est dite en clair, rien n'est appliqué.

**Valider** envoie l'empreinte de la proposition que tu as lue. Si l'agent l'a remplacée entre-temps, l'empreinte ne correspond plus : Michel n'applique rien (code d'erreur 409) et te montre la nouvelle. En ligne de commande, `michel fix approve` sans `--hash` valide la proposition que `michel fix status` a affichée en dernier, et refuse si elle a changé depuis.

## La branche, puis tu déploies

Appliquer, c'est : Michel construit **un seul commit** à lui dans le miroir (auteur Michel, parent = ton vrai commit ; les commits que l'agent aurait faits sont ignorés), puis le fait venir dans ton dépôt sur la branche `michel/fix-<id-court>`. Pas de changement de branche, pas de fusion : ta branche actuelle, tes fichiers et ce que tu as préparé pour ton prochain commit ne bougent pas (vérifié par un test, même si tu as des fichiers modifiés ou une autre branche en cours). Sans rattachement, c'est la seule écriture de Michel dans ton projet, et seulement après ta validation : des objets et une référence dans son `.git`.

La page dit alors : « La branche michel/fix-… est prête. Fusionne-la puis déploie avec PhpStorm comme d'habitude. » Michel ne fusionne jamais et ne déploie jamais.

## Rattacher ton projet à GitHub, Bitbucket ou GitLab

Michel pose une question sur la fiche du projet : ce projet est-il sur un site qui garde ton code en ligne (GitHub, Bitbucket, GitLab ou le tien) ? **Rien ne se passe sans un oui.** Ce que Michel propose d'abord n'est qu'une suggestion, jamais une réponse. Tant que tu n'as pas dit oui, tout ce qui précède reste vrai : tu fusionnes et tu envoies avec ton propre outil.

Pour poser la question, Michel lit l'adresse en ligne de ton projet (le « remote ») dans les réglages Git de ton dossier, sans réseau. Si cette adresse contient un mot de passe ou un jeton (une clé d'accès), Michel te le dit, et il ne l'affiche pas, ne le garde pas et ne s'en sert pas. Ton oui vaut pour cette adresse seulement. Il écrit une règle réseau, pour ce seul hôte (le site de cette adresse). Répondre non ou « je ne sais pas » plus tard retire la règle, si c'est Michel qui l'a écrite et si aucun autre projet rattaché ne s'en sert. Si l'adresse change, plus rien ne part avant ta nouvelle réponse.

Un oui te donne deux boutons. Rien d'autre ne les déclenche : ni un niveau, ni un scan, ni le travail en arrière-plan, ni la ligne de commande.

**Envoyer la correction**, sur une correction qui a sa branche :

- il envoie seulement la branche `michel/fix-…` et les enregistrements (« commits ») dont elle a besoin, vers ton service. Ta branche principale ne bouge pas ;
- Michel n'écrase jamais ce qui est déjà sur le service : s'il refuse, Michel le dit et s'arrête ;
- un clic, un envoi. Un second clic n'envoie rien de plus quand la branche est déjà là ;
- l'envoi part d'une copie temporaire, dans le dossier de données de Michel (`<data>/fix-net/`), retiré ensuite. Cette copie ne lit pas les réglages de ton projet : ils ne peuvent lancer aucun programme. Dans ton projet, ce bouton n'écrit rien ;
- sur GitHub, Bitbucket et GitLab (`github.com`, `bitbucket.org`, `gitlab.com`), la page donne ensuite un lien pour demander la fusion. Sur un autre service, elle donne le nom de la branche. C'est toi qui acceptes, sur le site.

Michel n'enregistre aucun jeton. Il se sert des accès Git déjà en place sur cet ordinateur, et il ne peut pas t'en demander : s'il n'en trouve pas, il le dit, et tu fais un envoi avec ton outil Git habituel.

**Mettre à jour mon dossier**, une fois la fusion acceptée :

- il récupère la branche principale du service, puis fait avancer ton dossier jusqu'à cette version (c'est la commande `git merge --ff-only`) : rien n'est mélangé, ton dossier se met seulement à jour ;
- seulement si ton dossier est sur sa branche principale, sans modification dans les fichiers que Git suit, et sans fusion en cours ;
- aucun hook (un programme que Git lance tout seul) et aucun programme de conversion de fichiers (Git LFS par exemple) ne tourne. Si la mise à jour en avait besoin, Michel refuse et ne touche pas à tes fichiers. Il refuse aussi plutôt que d'écraser un fichier que Git ne suit pas ou qu'il ignore ;
- ce qu'il écrit dans ton projet : les enregistrements qui arrivent, ta branche principale, le repère que Git garde de l'état du service (`<service>/<branche>`) et les fichiers changés. Quand il refuse après avoir récupéré, les enregistrements et ce repère peuvent déjà être écrits : tes fichiers et ta branche n'ont pas bougé.

**Ces deux boutons lèvent, pour un projet rattaché et sur ton clic, la règle « Michel ne pousse pas et ne lance rien dans ton dossier ».** Sans rattachement, cette règle reste entière. Chaque clic est noté dans le journal d'audit, refus compris (`project.git.answer`, `project.git.push`, `project.git.update`). Ce que git affiche n'est ni montré ni gardé, car cela peut contenir des données privées : tu vois une phrase, et pour plus de détail tu utilises ton outil Git habituel.

**Michel n'accepte toujours jamais ta correction** : c'est toi qui la fusionnes, sur le site ou avec ton outil. Il ne déploie jamais non plus. Mettre à jour ton dossier n'est pas fusionner ta correction : c'est récupérer ce que tu as déjà accepté.

Une copie partielle d'un dépôt (un « partial clone ») ne peut pas être rattachée : Git irait y chercher tout seul ce qui lui manque. Michel n'y fait donc ni envoi ni mise à jour, et il le dit.

## La preuve

- Tests réussis et nouveau scan propre **dans la copie** : obligatoires pour une application automatique (niveau 3), affichés pour les autres.
- **`proven_fixed`** (corrigée, prouvé) : après ta fusion, pendant un `michel scan` de ton projet, l'outil qui a trouvé la faille regarde à nouveau et ne la voit plus **et** le changement de la branche est dans la branche actuelle de ton dépôt. Michel le vérifie sans rien écrire : le commit lui-même (`git merge-base --is-ancestor`), ou, après un « Squash » ou un « Rebase » sur le site, qui changent le commit, le même patch (`git cherry`). Cette comparaison ne regarde ni les espaces ni la place des lignes : les mêmes lignes autrement indentées, ou dans un autre bloc identique, comptent aussi. C'est un « fusionné » à tort, rare, et l'outil doit quand même ne plus voir la faille. Cet outil, c'est le scan de tes dépendances pour une dépendance ; pour une faille trouvée par un outil externe (Semgrep, Trivy…), c'est cet outil, qui tourne à la fin du scan.
- Faille disparue sans ce commit, ou commit fusionné alors que l'outil voit encore la faille : la tentative passe `inconclusive` (pas concluant), avec la raison.
- Si cet outil n'a pas regardé pendant ce scan (éteint, pas réglé pour tourner pendant le scan, en échec ; pour une dépendance, un dossier sans fichier de dépendances), Michel ne conclut rien : la tentative reste `applied` jusqu'à un scan où il regarde. Lancer l'outil seul (`michel source run`, ou un rapport importé) ne conclut rien non plus.
- Michel ne relance pas les tests après la fusion : il ne lance aucun programme de ton projet, et « Mettre à jour » ne fait qu'y amener les fichiers. Les tests ont tourné sur la copie, avant la fusion. Un scan sur ton ordinateur voit la fusion, pas le déploiement : Michel dit « corrigée dans ton code » et te rappelle de déployer ; il ne prétend pas que le serveur est à jour.

Voici les états que tu verras sur la page : `held` (clés possibles dans le code : Michel attend ta réponse) → `withdrawn` (tu les retires d'abord) ou `preparing` ; `preparing` (en préparation) → `proposed` (proposée) → `approved` (validée) ou `refused` (refusée) → `applied` (branche créée) → `proven_fixed` ou `inconclusive` ; `failed` (échouée, avec sa cause : l'agent s'est arrêté, Michel a refusé la modification ou n'a pas pu créer la branche, ton projet a changé depuis la recherche) depuis `preparing`, `held`, `proposed` ou `approved` ; `superseded` (remplacée) quand une proposition plus récente prend sa place.

## Le masquage, et sa limite

Avant que ce que Michel donne lui-même arrive à l'agent (la fiche, les réponses MCP), Michel masque les secrets : clés AWS, jetons GitHub, clés Stripe de production, jetons JWT, jetons Slack, clés PEM, valeurs de type `.env`, affectations de mot de passe, secret, jeton ou clé, mots de passe dans une adresse de connexion ; les chemins complets de ton ordinateur deviennent des chemins relatifs. Chaque secret est remplacé par un repère `[secret-<aléatoire>-N]`. La table qui relie les repères aux vraies valeurs reste dans le coffre à secrets de Michel (chiffré par Windows, ou un fichier lisible par toi seul ailleurs) et n'est jamais envoyée. Le journal d'audit note combien de valeurs ont été masquées et de quel type, jamais les valeurs.

- La page et l'API ne remettent jamais la vraie valeur : un secret y reste affiché comme un repère.
- Michel ne met **jamais** de repère dans un commit : une modification qui en contient un est refusée (l'agent a pu le recopier depuis la fiche). Au moment de la proposition, l'agent est prévenu et peut proposer à nouveau ; si un repère arrivait quand même à l'étape de la branche, Michel ne crée pas la branche et la tentative passe `failed` avec cette cause (c'est un refus de Michel, pas le tien). Si une correction a vraiment besoin d'une valeur secrète dans le code, tu l'ajoutes à la main.
- Les modifications affichées sur la page sont masquées, mais la branche contient la modification telle qu'elle a été écrite : une ligne de ton code qui ressemble à un mot de passe n'est pas une raison de refuser la modification.
- **La limite** : les fichiers de la copie ne sont **pas** masqués. La copie contient ton vrai code, Claude Code le lit, donc il part chez Anthropic. Ce qui protège tes secrets, c'est que les fichiers exclus ne sont pas copiés, et que l'agent attend ta réponse quand Michel reconnaît une clé dans les autres ; un secret écrit dans un fichier de ton commit est lu par l'agent si Michel ne le reconnaît pas ou si tu choisis de continuer. La détection des secrets n'est jamais parfaite : certaines formes (`<password>` en XML, valeurs YAML sur plusieurs lignes, mot de passe contenant un `@` non encodé dans une adresse…) peuvent passer. Michel ne cherche pas non plus dans les fichiers de plus de 1 Mo ni dans les fichiers binaires. Et ce qu'il reconnaît n'arrête l'agent que si la valeur a la forme d'une clé (voir « La copie de travail »).

## Corrections de serveur (plan 6)

Une faille de **serveur** (un réglage de PHP, un paquet) a sa propre correction, décrite dans [servers.fr.md](servers.fr.md) : pas de copie de travail ni de branche, mais deux scripts, `appliquer` et `annuler`, que tu valides par empreinte. Tu les lances toi-même sur le serveur, ou Michel les lance pour toi.

- Le niveau se règle **par serveur** (`--level` de `michel target add|set`), pas par projet. Michel prépare seul les corrections connues ; l'agent ne sert qu'à discuter un cas, avec un accord **par serveur** (celui de la préprod quand il y en a une) et jamais pour un serveur de type `hds`.
- Le niveau 3 ne lance sans clic que les réglages des règles de Michel à leur valeur conseillée, jamais un paquet ; une mise à jour de paquet attend toujours ton **Snapshot fait**.
- Une correction dont Michel ne peut pas dire le résultat finit à l'état `unknown` (inconnu) : va voir le serveur, puis `michel fix resolve <tentative>` (ou **J'ai vérifié le serveur** sur la page).
- Une seule correction à la fois par serveur : tant qu'une correction est en cours, vérifiée après son script ou `unknown`, aucune autre n'est préparée ni lancée sur ce serveur.

## Risques qui restent

- **L'installation et les tests tournent avec tes droits, sans bac à sable.** `composer`/`npm` et tes tests tournent sur la copie en ton nom, sur ton ordinateur ; quand l'agent a modifié du code, les tests exécutent ce code, mais seulement après ton clic (**Lancer les tests**, `michel fix test`). Michel verrouille ce qu'il peut (pas de scripts d'installation, pas de plugins, listes de réglages autorisés, dossiers remis à zéro avant chaque installation, dossier séparé, dossier personnel propre à Michel, le proxy), mais ce n'est pas un environnement isolé : un projet ou une modification malveillante pourrait atteindre ce que toi tu peux atteindre. Un environnement isolé (Docker) est prévu dans un plan suivant.
- **Un programme qui ignore le proxy.** Claude Code, git, composer, npm et les tests reçoivent `HTTPS_PROXY`/`HTTP_PROXY` vers le proxy d'autorisation de Michel. Mais un programme peut ignorer ce proxy et ouvrir ses propres connexions : Michel ne l'arrêterait pas et ne le noterait pas. Le proxy est un garde-fou, pas une garantie.
- **Claude Code évolue.** Michel s'appuie sur des options de Claude Code pour garder l'agent à l'écart de tes réglages. Il refuse les versions qui n'ont pas ces options, mais ne peut pas garantir qu'une future version les respectera de la même façon. Claude Code lit toujours sa connexion dans ton dossier utilisateur (ton profil).
  - Options utilisées (testées avec la version 2.1.314) : `--setting-sources ""`, `--strict-mcp-config`, `--restricted`, `--tools`, les règles de permission, et les variables qui coupent `CLAUDE.md`, la mémoire et le trafic non essentiel.
- **Anthropic lit le code de la copie**, comme le dit l'écran d'accord.
- **La réponse à une clé trouvée n'est pas une preuve qu'une personne a lu.** Michel n'accepte ce oui que par la page ou par un terminal, et sa propre automatisation ne le donne jamais. Mais une personne ou un programme lancé avec tes droits (un script, un test du projet, du code écrit par l'agent sur un autre projet) peut simuler un terminal ou appeler la page avec son jeton. Ce programme pourrait de toute façon lire la clé directement.
- **Le texte de l'agent ne doit pas être cru sur parole.** Il est affiché, jamais exécuté ; sa proposition est vérifiée par Michel, et c'est toi qui décides.
- **Sur un projet rattaché, la connexion SSH et ton gestionnaire d'accès Git passent hors du proxy.** En SSH, git et ssh ouvrent leur propre connexion : Michel décide et note avant le lancement de git, mais il ne la fait pas passer par lui et ne l'arrête pas. Un gestionnaire d'accès Git (Git Credential Manager, par exemple : le programme qui retient tes mots de passe Git) est un programme à toi que git lance : il peut lui aussi ouvrir ses propres connexions. Voir [security/network-egress.fr.md](security/network-egress.fr.md).

## En cas de problème

| Ce que tu vois | Quoi faire |
|---|---|
| « Claude Code n'est pas installé sur cet ordinateur » | Installe-le (https://claude.com/claude-code), puis **Vérifier à nouveau**. En attendant, lis la fiche (`michel brief <faille>`). Michel cherche `claude` dans le PATH (ou le programme indiqué par `MICHEL_CLAUDE_BIN`). |
| « Ta version de Claude Code est trop ancienne » | `claude update`. Michel a besoin des options qui tiennent tes réglages à l'écart de l'agent. |
| « Claude Code n'est pas connecté » | Lance `claude` dans un terminal et connecte-toi, puis réessaie. |
| « …Michel a besoin de ton accord… » | Lis l'écran d'accord et accepte, ou `michel fix consent <projet> --yes`. |
| « Ta politique est en mode strict_local » | Utilise le bouton de l'écran d'accord sur la page, ou mets toi-même `sovereignty.mode: standard` (voir plus haut). |
| « Ce projet est classé santé » | Jamais envoyé à une IA externe. Lis la fiche et corrige à la main. |
| « Ce projet n'est pas suivi par git » / « pas encore de commit » | Michel copie avec git : le dossier ajouté doit être le dossier principal d'un dépôt, avec un premier commit. Le contrôle et la fiche restent disponibles. |
| « Ton projet est trop gros » | Exclus les gros dossiers (`--exclude`), ou corrige à la main depuis la fiche. |
| « …feraient lancer des programmes du projet lui-même » | Un réglage de ton projet (npm, Composer) demanderait d'exécuter du code pendant l'installation ; Michel ne l'accepte pas, donc rien n'a tourné. Corrige à la main ou retire ce réglage. |
| « Tests : en attente de ton accord » | L'IA a modifié d'autres fichiers en plus de la mise à jour prévue : les tests feraient tourner son code sur ton ordinateur, avec accès à ce que tu peux ouvrir toi-même. Lis la modification, puis clique sur **Lancer les tests**, ou tape `michel fix test <tentative>` (puis `--yes` pour les lancer). Tu peux aussi valider sans les lancer. |
| « Tests : pas lancés », aucune commande de test | Indique-la : `michel project set <nom> --test-cmd "…"`. |
| « Tests : pas lancés », projet yarn ou pnpm | Michel n'installe pas avec yarn ni pnpm : vérifie toi-même que ton site marche avant de fusionner. |
| « Tests : pas lancés », installation refusée | La page dit quel réglage bloque : retire-le, ou vérifie toi-même que ton site marche avant de fusionner. |
| « Michel a refusé la modification de l'agent » | L'agent a touché un fichier hors de la copie ou un fichier protégé. Rien n'a été appliqué ; tu peux réessayer. |
| « Michel n'a pas créé la branche : la modification contenait un repère… » | La modification contenait un repère `[secret-…]` à la place d'un secret. Rien n'a été appliqué ; relance une correction. |
| « La proposition a changé depuis que tu l'as lue » | Lis la nouvelle, puis valide-la. |
| « Une correction est déjà en cours sur ce projet, ou attend ta réponse » | Réponds-y d'abord, ou termine-la. Elle est dans la liste des corrections. |
| Niveau 2 : rien ne démarre | `michel serve` doit tourner ; le projet a besoin de son accord IA ; au plus 3 tentatives lancées seules par jour et par projet. |
| « Ce dossier n'est pas un dépôt Git » | Michel peut le contrôler et expliquer ses failles, mais il ne peut ni préparer une correction ni l'envoyer. |
| « Ce dépôt Git n'a encore aucun enregistrement » | Fais un premier commit : il en a besoin pour préparer une correction ou l'envoyer. |
| « Michel ne trouve pas d'adresse utilisable dans ce projet » | Il lui faut une seule adresse en https ou SSH (une connexion sécurisée), ou une adresse nommée `origin`. |
| « Ce dossier est une copie partielle d'un dépôt » | Utilise ton outil Git habituel. Pour que Michel le fasse, il lui faut une copie complète du dépôt. |
| « Ce projet n'est pas rattaché à un service Git » | Réponds oui à la question sur la fiche du projet si tu veux y envoyer tes corrections. |
| « L'adresse du projet a changé depuis ton accord » | Regarde la fiche du projet et réponds à nouveau. |
| « La règle réseau qui autorise ce service a été retirée » | Réponds à nouveau à la question sur la fiche du projet. |
| « Cette correction n'a pas de branche à envoyer » | Une branche existe seulement après ta validation, et tant que la correction n'est pas terminée. |
| « La branche de cette correction a changé ou n'existe plus » | Michel envoie seulement ce que tu as validé. Relance une correction, ou envoie la branche toi-même. |
| « Michel travaille déjà sur ce dossier » | Attends la fin, puis réessaie. |
| « Le service a refusé l'accès, ou Michel n'a pas trouvé tes accès Git sur cet ordinateur » | Fais un envoi avec ton outil Git habituel pour enregistrer tes accès, puis réessaie. |
| « Cet ordinateur ne reconnaît pas ce service, ou son identité a changé » | Connecte-toi une fois avec ton outil Git habituel. Si tu t'y connectais déjà, demande de l'aide : ce changement peut être une attaque. |
| « Le service ne trouve pas ce projet, ou ton compte n'y a pas accès » | Vérifie que l'adresse affichée est la bonne et que ton compte y a accès. |
| « Le service a refusé cette branche » | Une branche du même nom existe peut-être avec un autre contenu, ou une règle du service l'interdit. Regarde sur le site. Michel ne force jamais un envoi. |
| « Michel n'a pas réussi à joindre le service » | Vérifie ta connexion à Internet, puis réessaie. Le proxy d'une entreprise peut aussi l'empêcher. En https, Michel passe seulement par le port 443 (la porte habituelle des sites sécurisés). |
| « Le service n'a pas répondu à temps » | Clique à nouveau : si tout est déjà là, Michel le verra et n'enverra rien de plus. |
| « L'opération a échoué pour une raison que Michel ne reconnaît pas » | Essaie avec ton outil Git habituel. Michel n'affiche pas le détail, qui peut contenir des données privées. |
| « Ton dossier est sur la branche …, pas sur la branche principale … » | Reviens sur la branche principale, puis réessaie. |
| « Ton dossier n'est sur aucune branche » | Remets-le sur sa branche principale, puis réessaie. |
| « Michel ne sait pas quelle est la branche principale de ton dossier » | Fais la mise à jour avec ton outil Git habituel. |
| « Ton dossier contient des modifications pas encore enregistrées » | Enregistre-les ou mets-les de côté, puis réessaie. |
| « Une opération de Git (fusion, reprise) est restée à moitié dans ton dossier » | Termine-la ou annule-la, puis réessaie. |
| « Ton dossier contient des enregistrements qui ne sont pas sur le site » | Envoie-les ou règle cet écart avec ton outil Git habituel, puis réessaie. Michel ne mélange rien. |
| « Un fichier de ton dossier serait écrasé par cette mise à jour » | Mets ce fichier ailleurs, puis réessaie. |
| « Un fichier ou un dossier que Git ignore … est à l'endroit où cette mise à jour écrit » | Mets-le ailleurs, puis réessaie. Attention : une mise à jour faite à la main avec Git peut l'écraser sans prévenir. |
| « Cette mise à jour retirerait ou remplacerait un sous-dossier que Git gère à part » | Mets son contenu ailleurs, vide ce sous-dossier sans le supprimer, puis réessaie. Attention : une mise à jour faite à la main avec Git peut effacer ce qu'il contient. |
| « Cette mise à jour lancerait un programme de conversion de fichiers » | Fais la mise à jour avec ton outil Git habituel, puis clique sur **Contrôler ce projet**. |
| « La mise à jour a échoué : Git l'a arrêtée » | Vérifie l'état de ton dossier avec ton outil Git habituel. |
| « La mise à jour s'est arrêtée en route » | Ferme le programme qui garde peut-être un fichier ouvert (un éditeur, un antivirus). Ton dossier n'avait aucune modification avant la mise à jour : avec ton outil Git habituel, annule ces modifications, puis réessaie. |

Ce qui sort de l'ordinateur, site par site : [security/network-egress.fr.md](security/network-egress.fr.md).
