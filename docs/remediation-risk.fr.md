# Score de risque de remédiation

Read in English: [remediation-risk.md](remediation-risk.md)

Michel donne à chaque constat un score de risque de 0 à 100 et une recommandation. La règle est publique, déterministe et identique à chaque exécution : les mêmes éléments donnent toujours le même score.

**Le modèle IA ne peut jamais modifier ces valeurs.** Le modèle peut expliquer un score, mais le score, ses termes et les seuils viennent uniquement du fichier de politique et des réglages du projet.

## Termes

Chaque terme ajoute des points quand sa condition est vraie. Les points sont additionnés et plafonnés à 100.

| Terme | Points | Condition |
| --- | --- | --- |
| `major_jump` | +40 | Le correctif demande un saut de version majeure. |
| `breaking` | +25 | Le changelog annonce des changements incompatibles. Un changelog sans titres de version lisibles n'est pas évalué : il ajoute 0, et l'explication le dit. |
| `direct` | +10 | Le paquet est une dépendance directe du projet. |
| `many_call_sites` | +15 | Le code appelle le paquet à plus d'endroits que `many_call_sites_threshold` (10, strictement plus). |
| `no_tests` | +20 | Aucun test n'utilise le paquet lui-même. Seul un test couvrant qui importe ou appelle le paquet (méthode `callsite`) annule ce terme ; un test qui mentionne seulement le nom d'un fichier utilisant le paquet (méthode `reference`) est une preuve faible et ne l'annule pas. |
| `core_package` | +20 | Le paquet figure parmi les paquets cœur du projet. |

Quand la taille du saut est impossible à déterminer (`unknown`), `major_jump` ajoute 0 et l'analyse enregistre `major_jump_unknown: 0` : le manque est visible au lieu d'être compté comme sans risque. Un saut inconnu n'est jamais non plus une correction automatique : quel que soit le score, la recommandation est `handoff` (ou `report_only` sans version corrigée), et l'analyse enregistre `jump_unknown_handoff: 1`. Ce marqueur, comme `thresholds_fallback`, n'ajoute pas de points : le score ne change pas.

## Seuils

| Score | Recommandation |
| --- | --- |
| moins de 30 (`auto_fix_below`) | `auto_fix` |
| de 30 à 60 inclus (`handoff_up_to`) | `handoff` |
| plus de 60 | `handoff`, avec un avertissement |

Quand aucune version corrigée n'existe, la recommandation est `report_only`. Le score est tout de même calculé et affiché, et l'avertissement peut quand même apparaître avec `report_only` quand le score dépasse 60.

Une surcharge de projet qui rendrait les seuils incohérents (`auto_fix_below` pas inférieur à `handoff_up_to`) est refusée par `project set` ; si elle était malgré tout stockée, le calcul revient aux seuils de la politique et enregistre `thresholds_fallback: 1`.

## Où vivent les valeurs

Les valeurs par défaut sont dans la section `risk` du fichier de politique (voir `config.example.yaml`) :

```yaml
risk:
  major_jump: 40
  breaking: 25
  direct: 10
  many_call_sites: 15
  no_tests: 20
  core_package: 20
  many_call_sites_threshold: 10
  auto_fix_below: 30
  handoff_up_to: 60
```

Chaque terme doit être compris entre 0 et 100, `many_call_sites_threshold` vaut au moins 1, et `0 <= auto_fix_below < handoff_up_to <= 100`. Une politique invalide est refusée au démarrage.

## Réglages par projet

Un projet peut désigner ses paquets cœur et surcharger n'importe quelle valeur ci-dessus (les clés sont les noms du tableau et du YAML) :

```
michel project set my-shop --core-package symfony/http-kernel --core-package react
michel project set my-shop --risk major_jump=10 --risk no_tests=30
```

`--core-package` remplace toute la liste ; `--risk` change une valeur et conserve les autres surcharges. Les analyses stockées gardent une empreinte de ces réglages (et des valeurs de la politique) : après un changement, elles sont recalculées au scan suivant ou avec `michel analyze --project my-shop`. Les clés inconnues et les valeurs hors de 0..100 sont refusées. Chaque changement est consigné dans le journal d'audit sous `project.set` (noms des champs seulement, jamais le contenu des commandes).
