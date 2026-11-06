# Michel : aucun test sur le code de l'agent sans ton accord

Date : 2026-11-05. Origine : priorité 1 de l'audit du 2026-11-05 (lecture seule, commit `bbf31e9`).

## Pourquoi

Quand l'agent propose un correctif, Michel installe les dépendances puis lance la commande de tests du projet (`test_cmd`) sur l'arbre que l'agent a laissé, dans une copie de travail à part (`internal/fix/service.go:1144-1211`). Cela se passe **avant** toute validation humaine.

Or l'agent peut écrire presque partout dans sa copie : seuls `vendor`, `node_modules`, `.git`, `.claude` et `.mcp.json` lui sont interdits (`internal/agent/claude.go:72,85`). Il peut donc modifier un fichier de test, `phpunit.xml`, `package.json` (`scripts.test`) ou ajouter une dépendance au manifeste.

L'agent lit des textes qui viennent de l'extérieur : avis de sécurité, extraits de changelog, code du projet. Une injection de prompt dans l'un d'eux peut le pousser à écrire un test qui fait autre chose que tester. Michel lance alors ce code sous le compte de la personne, avec ses droits. Le proxy réseau n'est qu'une variable d'environnement (`internal/egress/allowproxy/allowproxy.go:8`) : un programme qui l'ignore sort quand même. Ce code peut lire le jeton de l'API locale, utiliser l'agent SSH, appeler Michel.

Cela contredit deux principes de Michel : l'agent n'est jamais une frontière de sécurité, et aucune action sensible sans validation humaine.

## Ce qui change

Michel continue de lancer seul les tests **seulement** quand l'arbre de la proposition est exactement celui que sa propre mise à jour a laissé. Le drapeau existe déjà : `unchanged := a.Work.Tree0 != "" && snap.Tree == a.Work.Tree0` (`service.go:1141`). Dans ce cas, le code exécuté est celui du projet plus les versions de dépendances que Michel a choisies lui-même : c'est le comportement actuel, il reste.

Dès que l'arbre diffère (l'agent a touché un fichier, quel qu'il soit, dépendances comprises), Michel :

1. installe quand même les dépendances, comme aujourd'hui. L'installation n'exécute aucun script (`composer --no-scripts --no-plugins`, `npm ci --ignore-scripts`, `internal/workcopy/install.go`) et dit si le verrou se résout ;
2. refait quand même la vérification hors ligne (« la faille a disparu ou non »), qui lit les fichiers sans rien exécuter ;
3. **ne lance pas les tests**. La proposition porte un nouvel état de tests : `awaiting` (« en attente de ton accord ») ;
4. dit pourquoi, et liste les fichiers modifiés qui ne sont ni le manifeste ni le verrou de l'écosystème (les fichiers « de code »), parce que ce sont eux qui feraient tourner du code nouveau.

La personne peut alors cliquer sur **« Lancer les tests »** (page) ou taper `michel fix test <tentative>` (CLI). Avant le clic, la page montre en clair :

- que lancer les tests exécute sur son ordinateur du code que l'agent a écrit ou modifié ;
- la liste des fichiers « de code » touchés (au plus 10, puis « et N autres ») ;
- un lien vers le diff, déjà visible dans la proposition.

Le clic est lié à l'empreinte de la proposition affichée, comme « Valider » : si l'agent a proposé autre chose entre-temps, le clic est refusé et la page recharge la nouvelle proposition.

Après le clic, Michel matérialise l'arbre de la proposition dans une copie jetable, installe, lance les tests, puis enregistre une **nouvelle proposition** avec le même diff et le même commit, et le résultat des tests. Elle remplace l'ancienne (le mécanisme « la proposition a changé » existe déjà côté page). L'empreinte change, donc un « Valider » envoyé sur l'ancienne est refusé : la personne valide en connaissant le résultat.

Valider sans lancer les tests reste possible, comme aujourd'hui avec `not_run`. La page le dit.

## Objectifs

- Aucune exécution de code issu de l'agent sans un geste humain explicite, lié à ce qui est affiché.
- Rien ne change pour le cas courant où l'agent ne touche à rien d'autre que ce que Michel a mis à jour.
- Le niveau 3 (application automatique) ne change pas : il exige déjà l'arbre de Michel (`service.go:1274-1296`).
- Chaque lancement de tests sur clic est audité : qui, quelle tentative, quelle empreinte, quel résultat.

## Non-objectifs

- Pas de bac à sable système (conteneur, AppContainer, espace de noms réseau). C'est l'étape suivante, à part : elle protégera aussi les tests lancés sur clic.
- Pas de changement des droits de l'agent dans sa copie (il doit pouvoir adapter du code à une nouvelle version).
- Pas de changement des correctifs serveur : ils ne lancent pas de tests de projet.
- La limite de `Glob` et `Grep` de l'agent (priorité 2 de l'audit) est un autre chantier.

## Anti-objectifs

- Remplacer ce contrôle par une consigne à l'agent (« n'écris pas de test dangereux »). L'agent n'est pas une frontière.
- Lancer les tests sur clic sans montrer d'abord ce qui va tourner.
- Que « Valider » finisse par lancer les tests en douce.
- Un faux sentiment : la page ne doit jamais dire « tests passés » pour une proposition dont les tests attendent.

## Contraintes

- Règles constantes de Kévin : aucun nom de projet privé dans le dépôt (test `internal/hygiene`) ; SQL portable PostgreSQL (`?`, `ON CONFLICT`, dates RFC 3339 en TEXT, pas de `rowid`/`AUTOINCREMENT`/`datetime()`) ; tout texte français relu par un relecteur francophone non spécialiste, tutoiement ; jamais d'écriture dans les projets scannés ; tout réseau par `internal/egress`.
- Les états de tests sont des chaînes connues en plusieurs endroits : `internal/workcopy/run.go:16-18`, `internal/api/fix.go:93`, `internal/cli/fix.go:243-245`, `internal/fix/auto.go:48`, `internal/mcp/tools.go:438`, `web/src/components/FixProposal.vue:34,178`, `web/src/lib/fixView.js:153,178`, `web/src/lib/serversView.js:337`. `awaiting` doit être connu partout ; une valeur inconnue continue de s'afficher comme « non lancés », jamais comme « passés ».
- L'empreinte de la proposition inclut déjà l'état des tests (`proposalHash`, `service.go:1250`).
- La tentative doit être en état `proposed`. Les verrous de `fix` sont en mémoire d'un seul processus (`service.go:313-354`) et la proposition de l'agent arrive par le processus `michel mcp` (`service.go:1097-1105`, `proposeLock`) : ils ne protègent pas un lancement fait depuis `serve` ou le CLI. La garde est donc en base (voir Décidé).

## Décidé

- Seuil : « arbre identique à celui de Michel » et rien d'autre. Un changement limité au manifeste ou au verrou ne suffit pas à lancer seul : l'agent pourrait y ajouter un paquet dont le code se charge pendant les tests.
- L'installation et la vérification hors ligne restent automatiques : elles n'exécutent pas de code du projet.
- Le résultat d'un lancement sur clic devient une nouvelle proposition, pas un champ modifié en place : l'empreinte et l'historique restent vrais.
- Interfaces : page (bouton dans la proposition), API `POST /api/v1/fix/{attempt}/run-tests` avec l'empreinte, CLI `michel fix test <tentative>` qui affiche les fichiers et demande `--yes`.
- Audit : `fix.tests_run` avec `attempt_id`, `proposal_id`, `hash`, `author`, `tests`, `files_code` (nombre).
- L'outil MCP qui montre la proposition à l'agent montre `awaiting` tel quel ; l'agent ne peut pas lancer les tests (aucun outil MCP pour ça).

- Arbre de la proposition : une migration ajoute `tree TEXT NOT NULL DEFAULT ''` à `fix_proposal`, rempli avec `snap.Tree` à chaque proposition. Le commit du miroir ne convient pas : il contient les fichiers exclus de la copie (`internal/workcopy/copy.go:45-62`). Une proposition sans arbre (antérieure) n'offre pas le bouton.
- Course avec l'agent : l'insertion de la nouvelle proposition est conditionnelle, dans une transaction, « seulement si la proposition courante a toujours l'empreinte H » (même forme que `Repo.Approve`, `repo.go:139-145`). Si l'agent a proposé entre-temps, le résultat des tests est jeté et la personne lit : « l'agent a proposé autre chose pendant les tests ; rien n'a été remplacé ». La session de l'agent n'est ni suspendue ni fermée.
- Dossier de travail : chaque lancement sur clic a son propre dossier jetable (`fix-tmp/<tentative>/tests-<n>`), jamais `run`, que `Materialize` vide en commençant (`snapshot.go:96-101`).
- `awaiting` seulement quand les tests auraient vraiment tourné : installation réussie et `test_cmd` valide et non vide. Installation en échec : `failed`, comme aujourd'hui ; pas de commande ou commande refusée, installation non prise en charge : `not_run`, comme aujourd'hui. Le clic refait l'installation dans son dossier puis lance les tests.
- Nouvelle proposition : même diff, même commit, même arbre, même résultat de vérification hors ligne (recopié : même arbre), commandes complétées de la ligne des tests, empreinte recalculée. Pas de nouvelle notification « en attente ». Michel écrit le résultat dans la conversation (l'agent le voit par MCP, c'est voulu). Audit : `fix.tests_run` seul, avec l'identifiant de la nouvelle proposition.
- Bouton seulement en `awaiting`. Pas de relance d'un `failed` obtenu par clic : l'agent peut proposer de nouveau.

## Laissé au constructeur

- Où ranger le calcul « fichiers de code » (probablement à côté de la règle « fichiers de dépendances seulement » du niveau 3, `internal/fix/auto.go`).
- Le découpage de la fonction de lancement (réutiliser `workcopy.Materialize`, `Install`, `RunTests` et le bloc de messages actuel de `service.go:1186-1211`).
- Les mots exacts, en français puis en anglais, sous relecture.
- Comment la page affiche l'attente pendant le lancement (le bouton garde son aspect et une phrase d'attente s'affiche, comme pour « Mettre à jour mon dossier »).

## Preuves attendues

- Test : un faux agent écrit un test qui crée un fichier marqueur hors de la copie, puis propose. Le marqueur n'existe pas après la proposition ; la proposition est en `awaiting`.
- Test : arbre identique à celui de Michel, tests lancés seuls, comportement actuel inchangé.
- Test : lancement sur clic avec une empreinte périmée, refusé, rien n'est lancé.
- Test : lancement sur clic valide, nouvelle proposition avec le résultat, l'ancienne empreinte ne valide plus.
- Test : niveau 3 inchangé.
- Tests front : `awaiting` affiché comme en attente, jamais comme passé ; la liste des fichiers de code est bornée.
- Portes : `go test ./...`, `go vet ./...`, `gofmt -l`, `vitest`, build du web, test d'hygiène.
