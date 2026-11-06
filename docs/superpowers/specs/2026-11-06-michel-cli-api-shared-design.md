# Logique partagée entre CLI et API — design

Date : 2026-11-06. Point « doublons CLI/API » de l'audit du 2026-11-05.

## Problème

Une même règle métier est écrite deux fois : une fois dans une commande cobra (`internal/cli`), une fois dans un handler HTTP (`internal/api`). Une cartographie a trouvé 12 cas. Dans 9 d'entre eux, les deux copies ont déjà divergé. Le cas le plus grave est l'ajout de projet. La page refuse un dossier système, le dossier personnel, le dossier de données de Michel, un partage réseau ou un lien. Elle refuse aussi un second projet actif sur le même dossier. `michel project add` ne contrôle rien de tout ça.

## Principe

Chaque règle vit une seule fois, dans son paquet métier (`project`, `target`, `decide`, `watch`, `fix`, `source`). Le CLI et l'API ne gardent que leur plomberie : lire les flags ou le JSON, traduire les erreurs en messages ou en codes HTTP, afficher. Les événements d'audit d'une opération sont écrits par la fonction métier. Ainsi, les deux entrées laissent la même trace.

Quand les deux copies diffèrent, la règle la plus protectrice gagne, sauf mention contraire ci-dessous.

## Décisions par cas

1. **Ajout de projet** : une fonction `project.Register` fait les contrôles de nom, de dossier et de doublon, l'ajout et l'audit. Les contrôles de dossier de la page (dossiers interdits, réseau, liens, `EvalSymlinks`) passent dans le paquet `project`. Le CLI garde une seule différence : il rend absolu un chemin relatif avant de l'envoyer à `Register`. Si l'audit échoue, le projet est purgé, dans les deux cas. La raison d'un refus est enregistrée sous forme de clé i18n, pas de texte anglais. Une erreur de stockage est auditée `error`, dans les deux cas.
2. **Modification de projet** : une seule fonction, qui audite. L'action d'audit est `project.update` pour les deux. L'ancien `project.set` du CLI reste lisible dans l'historique. Les refus sont audités dans les deux cas. La plage 0..3 du niveau de fix n'est contrôlée que par le paquet `project`.
3. **Projet actif** : `project.Repo.GetActive` sert aux commandes sur les failles, les décisions et le consentement, côté CLI comme côté page. Un projet retiré n'y est plus visible. Seules les commandes qui gèrent le projet lui-même (`project set`, réactivation, `project remove`, `list`) voient les projets retirés.
4. **Dernier et prochain contrôle** : `watch.ProjectStatus` rend le dernier scan et le prochain contrôle. L'API ne garde plus sa requête SQL. La date est toujours rendue en RFC 3339 UTC.
5. **Décision « fix » sur une faille d'exposition serveur** : le refus passe dans `decide.Validate`, pour les deux entrées.
6. **Règles d'autorisation d'un serveur** : une seule fonction. Elle relit le fichier de politique pour savoir quelles règles sont déjà là (une règle ajoutée à la main reste à la personne). Elle ne fait rien sans fichier de politique. Le verrou en mémoire reste côté page. Le CLI est un autre processus, et la relecture du fichier suffit.
7. **Ajout, modification et retrait de serveur, confiance dans la clé d'hôte** : une fonction métier par opération, avec les valeurs par défaut, l'ordre des contrôles, les retours en arrière et l'audit. Les noms de champs dans la liste `changed` de l'audit suivent la page (`fix_level`, `site_url`). Le CLI reçoit les champs que seule la page savait changer, seulement si c'est sans risque pour ses flags. Sinon, la fonction les accepte et le CLI ne les expose pas.
8. **Consentement IA d'un projet pour le fix** : une fonction rend l'état (lignes, prêt, refus). La page garde son bouton « passer en mode standard ». Le CLI continue de refuser `strict_local`, avec un message qui renvoie à la page ou à la politique.
9. **Sources : ajout depuis la découverte, ignorer, ajout d'une source perso** : une fonction métier par opération, avec son audit.

## Hors champ

- Le comportement visible ne change pas, sauf pour les divergences tranchées ci-dessus.
- Pas de nouvelle commande ni de nouvelle route.
- Les textes nouveaux sont rares (les messages de refus du CLI pour l'ajout de projet). Ils passent par la relecture FR.
