# michel audit reseal — design

Date : 2026-11-06. Suite de la revue du batch B d'audit (point 4).

## Problème

Avec `integrity_protection: required`, la marque scellée (`audit_anchor.sealed_*`) dit où commencent les sceaux. Deux cas légitimes la laissent fausse pour toujours :

- `michel.db` est recréée ou restaurée alors que `secrets/` est gardé : la clé existe, la marque n'a jamais été posée.
- la clé est créée dans le magasin de secrets, puis le commit de la marque échoue.

`michel audit verify` échoue alors à chaque fois (« marque scellée manquante ou fausse »), sans issue.

Une réparation automatique est exclue : de l'extérieur, ce cas est identique à l'attaque « marque vidée et sceaux effacés » (`TestSealedAnchorRemovedFails`). Réparer en silence cacherait cette attaque.

## Solution

Une commande explicite, décidée par la personne : `michel audit reseal`.

- Sans `--yes` : Michel vérifie le journal, dit ce qui ne va pas et ce que la commande ferait. Rien n'est écrit.
- Avec `--yes` : Michel repose la marque après le dernier événement. Les événements déjà présents passent « avant les sceaux » : ils ne sont plus couverts par les sceaux. Michel enregistre ensuite l'événement `audit.reseal`, scellé, avec la raison de l'échec, l'ancien début des sceaux et le nombre d'événements qui ne sont plus couverts. La trace reste dans le journal.

Refus :

- `integrity_protection: none` : il n'y a pas de sceaux.
- la clé des sceaux ne peut pas être lue : `reseal` ne crée pas de clé.
- le journal passe la vérification : rien à faire.
- la chaîne elle-même est cassée (`prev_hash` ou `hash` faux) ou des événements ont disparu (fin tronquée) : ce sont des preuves, `reseal` ne les efface pas. Michel dit de garder la base telle quelle.

`reseal` n'accepte que les échecs de sceaux : marque fausse ou absente, sceau manquant, sceau faux.

## Vérification après un reseal

Un événement avant le début des sceaux n'est pas vérifié par les sceaux, même s'il en porte un (fait avec une ancienne clé, par exemple). Avant ce changement, ce cas n'existait pas : la marque était posée à la création de la clé, avant tout sceau. Le message de `verify` pour ces événements dit qu'ils datent d'avant les sceaux et ne sont pas couverts.

## Hors champ

- Une ligne `audit_anchor` absente (point 5 de la revue).
- Les événements non scellés quand la clé ne se charge pas (point 6, choix documenté).
