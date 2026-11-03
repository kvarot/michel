# Michel : interface guidée, design

Maquette de référence : [2026-11-03-michel-ui-guided-mockup.html](2026-11-03-michel-ui-guided-mockup.html).

## Pourquoi

Kévin : « L'interface est pauvre, ça donne pas envie, regarde comment est Salesforce. » Il veut quelque chose d'attirant, simple mais efficace, où chaque champ et chaque action se comprend, utilisable pas à pas par quelqu'un qui ne connaît pas l'informatique.

## Ce que la personne doit réussir en dix minutes (mots de Kévin)

« Voir les failles de son projet, savoir comment l'IA va les résoudre, voir résolu. Idem pour ses serveurs. Qu'est-ce qui est ou non exposé. »

Kévin a ensuite dit : « suis tes reco, ça sera plus simple, on ajustera si besoin ». Tout ce qui suit et n'est pas cité ci-dessus est donc **mon choix**, ajustable.

## Objectifs

1. Une personne novice fait les trois parcours sans aide extérieure : faille de projet, faille de serveur, exposition d'un serveur.
2. Michel a l'air d'un outil professionnel, au premier regard.
3. Tout ce qui existe reste accessible : rien n'est retiré à l'utilisateur confirmé, il passe en mode avancé.

## Non-objectifs

- **Pas de fonctions de CRM** (contacts, ventes, opportunités). Michel n'en a pas l'usage. Mon choix : on reprend de Salesforce ses formes (navigation à gauche, chemin par étapes, liste à traiter, statuts, aide au champ), pas ses fonctions. Kévin a demandé « les fonctions des plus grands CRM » avant de préciser le but en dix minutes : à lui de dire si une fonction précise lui manque.
- Pas de scan de ports depuis l'extérieur en première version (voir Exposition).
- Pas de nouveau moteur de détection ni de nouvelle action de correction : l'IA et ses garde-fous restent ceux du plan 5 et du plan 6.

## Anti-objectifs

- Une interface qui rassure à tort : dire « protégé » pour ce que Michel n'a pas vérifié.
- Du jargon non expliqué dans le mode simple (CVE, CVSS, port, paquet, SSH sans explication).
- Une action qui change un site ou un serveur sans que la personne sache quoi et sans son accord.

## Structure

Navigation à gauche, sur ordinateur ; en bas ou en menu sur téléphone :

| Entrée | Rôle | Vient de |
|---|---|---|
| À faire | Une seule liste, la plus urgente en haut, projets et serveurs mêlés | `TodayPage` |
| Mes projets | Projets, leurs failles | `SourcesPage`, `ProjectCard` |
| Mes serveurs | Serveurs, ce qui est exposé, failles, journaux | `ServersPage`, `ServerSheet` |
| Résolu | Ce qui a été corrigé et vérifié, avec dates | Nouveau, données existantes |
| Réglages, aide | Réglages, revoir le guide, mode avancé | `SettingsPanel` |

Chaque ligne d'À faire dit en français courant ce qui se passe, où, et porte une seule action nommée par son effet.

## Le chemin d'une faille

Sur toute faille, projet ou serveur, le même chemin visible en haut : **Trouvée, Solution proposée, Ton accord, Corrigée, Vérifiée**. C'est l'élément marquant de l'interface. Il se construit sur les états existants (`fixView.js`, `groupOf`, `isFinal`), sans nouvel état côté serveur si possible.

Sous le chemin, deux blocs :

- **Ce que ça veut dire** : le risque, en une ou deux phrases sans jargon.
- **Ce que l'IA va faire** : ce qu'elle touche, où (sur une copie à part), ce qu'elle vérifie, et le fait que rien ne change sans accord. Bouton « Lancer la correction ». Ce texte doit être vrai pour chaque cas (projet, serveur, niveaux de `FixSettings`) : le constructeur le vérifie dans le code et les docs, sinon il dit moins.

« Vérifiée » n'apparaît que si le nouveau contrôle a confirmé (`rescan_clean`). Sinon le chemin le dit et la faille reste à faire.

## Exposition d'un serveur (nouvelle lecture)

Michel ne connaît pas aujourd'hui les services qui écoutent sur un serveur : cette partie demande du travail côté Go.

**Mon choix pour la lecture :** une commande de plus dans l'inventaire SSH existant (`internal/collect`), en lecture seule, `ss -tln` ou équivalent, dans les mêmes garanties que le plan 6 (rien écrit sur le serveur, aucun essai d'un autre moyen, « non vu » dit en clair si la commande manque). Seuls l'adresse d'écoute et le port sont gardés. Pas de nom de processus : il demande des droits que Michel ne demande pas.

**Trois colonnes, dans ces mots :**

- **Ouvert à tous** : écoute sur toutes les adresses (`0.0.0.0`, `::`) ou une adresse publique.
- **Réservé** : écoute sur `127.0.0.1` ou `::1` (« réservé au serveur »), ou sur une adresse privée (« réservé au réseau privé »).
- **Non vérifié** : le pare-feu de l'hébergeur, toujours affiché, et tout ce que la lecture n'a pas pu voir.

Le titre dit **« joignable si aucun pare-feu ne le bloque »** tant que Michel n'a pas vérifié depuis l'extérieur. C'est une limite à ne jamais masquer : un service peut être listé ouvert et bloqué par l'hébergeur.

**Noms et verdicts :** table embarquée, déterministe, sans IA : 80 et 443 site web, normal ; 22 connexion d'administration, normal ; 3306, 5432, 6379, 11211, 27017, 9200 bases et caches, « à fermer » ; le reste « service non reconnu, à vérifier ». Le constructeur vérifie ces ports et la formulation. Un service « à fermer » ouvert à tous devient une ligne d'À faire et compte comme une faille de serveur si les règles (`serverrules`) le permettent sans détour.

**Docs à mettre à jour :** `docs/servers*.md`, `docs/security/network-egress*.md` (ce qui revient du serveur).

**Plus tard, non prévu ici :** un essai depuis l'extérieur, qui lèverait « non vérifié », avec l'accord de la personne et seulement sur ses serveurs.

## Mode avancé

Interrupteur dans Réglages, retenu par navigateur (`lib/storage.js`), éteint par défaut. Il montre ce que le mode simple cache : CVE, paquets, versions, commandes, réglages fins, le détail des journaux. Tout composant existant y reste joignable. Mode simple et avancé utilisent les mêmes pages, pas deux interfaces à maintenir.

## Guide

- **Premier lancement :** trois étapes visibles (ajouter un projet ou un serveur, premier contrôle, première faille lue), reprises où on s'était arrêté, ignorables, à revoir depuis l'aide.
- **Aide au champ :** un « ? » sur chaque champ et chaque action qui n'est pas évident, texte court : à quoi ça sert, quoi mettre, ce qui se passe si on se trompe. Clé i18n par champ, FR et EN.
- **Écrans vides :** ils disent quoi faire et portent l'action.
- Pas de visite guidée à bulles qui masque l'écran.

## Apparence

- Palette de base : encre `#14304F` (navigation, titres), bleu `#1B62B5` (actions), rouge `#B3261E`, ambre `#9A5B00`, vert `#0F6B52`, fonds `#F4F7FA` et `#FFFFFF`, filets `#D3DDE8`. Équivalents pour le thème sombre, qui reste.
- Typographie : pas de police téléchargée, la CSP l'interdit. La voix de Michel (`--m-voice`, serif déjà en place) pour ses phrases et les titres-verdicts, la police système pour l'interface. C'est ce qui évite l'air de gabarit.
- Une gravité est toujours une couleur et un mot. Clavier, contraste AA, `prefers-reduced-motion`, 16 px de marge sur téléphone, pas de défilement horizontal.
- Vuetify reste. Pas de nouvelle dépendance sans raison écrite.

## Contraintes

- Vue 3 Options API, JS/JSDoc, Vuetify 4, Vite, Vitest ; logique testable dans `web/src/lib/*View.js`, comme aujourd'hui.
- FR et EN à égalité. Tout texte français passe un lecteur non spécialiste avant la revue de code (règle du plan 7).
- Rien d'un plan précédent ne s'affaiblit : pas de ligne de journal brute affichée, pas de données de journaux vers un agent IA, masquage conservé, confirmations du plan 7 conservées, jetons et mises au point d'accès inchangés.
- Reprendre les remarques mineures reportées de la tâche 9 du plan 7 (voir le registre du plan 7).
- Aucun nom ni chemin de projet privé dans le dépôt ; aucun vrai serveur dans les tests.
- À vérifier dans un vrai navigateur, à la largeur d'un téléphone et d'un ordinateur, en clair et en sombre. Android Studio est installé pour le test de la PWA.

## Ordre proposé

1. Socle : thème, navigation, mode avancé, aide au champ.
2. À faire et Résolu.
3. Chemin de la faille, projets puis serveurs.
4. Exposition : lecture Go, puis écran.
5. Guide du premier lancement, écrans vides.
6. Essai par une personne fictive novice, sur le conteneur jetable : les trois parcours de bout en bout, en navigateur.

## Laissé au constructeur

Découpage des composants, détail de la navigation sur téléphone, forme de l'API d'exposition, routes.

## Rattacher un projet à GitHub, Bitbucket ou GitLab

Kévin : « Il faut demander à l'utilisateur s'il a Git, Bitbucket, pour le rattacher s'il souhaite. » La raison : sans cela, le dernier pas du parcours projet (fusionner la correction) demande de savoir se servir de Git. Le reste de cette section est **mon choix**.

- **La question :** dans le guide du premier lancement et dans les réglages de chaque projet : « Ton projet est-il sur GitHub, Bitbucket, GitLab ou un service semblable ? » Réponses : oui, non, je ne sais pas. Michel propose la réponse en lisant le dépôt distant du projet, sans réseau, et n'affiche jamais un mot de passe ou un jeton présent dans l'adresse. Rien n'est rattaché sans un oui. La réponse se change à tout moment.
- **Sans rattachement :** tout marche comme aujourd'hui, et la page dit clairement ce qu'il restera à faire à la main.
- **Rattaché :** après l'accord sur une correction, un bouton « Envoyer la correction sur Bitbucket » envoie **seulement** la branche `michel/fix-…`, sans jamais forcer ni toucher une autre branche. La page ouvre ensuite le lien pour demander la fusion sur le site, en un clic pour la personne. Chaque envoi demande son propre clic. Pour un service non reconnu, la page donne le nom de la branche.
- **Pas de jeton en première version :** Michel utilise les accès Git déjà en place sur l'ordinateur et n'en enregistre aucun. Si l'envoi échoue, la page dit quoi faire, sans répéter la sortie brute. Créer la demande de fusion par l'API viendra plus tard.
- **Après la fusion sur le site :** le dossier local doit recevoir la correction pour que le contrôle la prouve. Un bouton « Mettre à jour mon dossier » fait une mise à jour sans fusion (`--ff-only`), seulement sur la branche principale et un dossier sans modification en cours ; sinon la page explique pourquoi et ne touche à rien.
- **Michel ne fusionne toujours jamais.** Ces deux boutons sont les seules écritures vers le dépôt distant et le dossier du projet. Ils lèvent, pour un projet rattaché et sur clic, la règle du plan 5 « Michel ne pousse pas et ne lance rien dans ton dossier » : `docs/fix*.md` et l'inventaire `docs/security/network-egress*.md` le disent. Chaque action est inscrite au journal d'audit.
