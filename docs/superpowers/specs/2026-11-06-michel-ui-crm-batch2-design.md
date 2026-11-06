# Michel : interface « CRM de la sécurité », deuxième lot

Date : 2026-11-06. Suite du premier lot (`2026-11-05-michel-ui-crm-design.md`), qui renvoyait à « un lot suivant » ce qui demande du stockage nouveau : l'historique d'une faille, la courbe des failles ouvertes dans le temps et les rapports. Kévin délègue les choix (« on suit tes reco ») : ils sont tous notés ici comme ceux du constructeur.

## Intention

Le premier lot dit où on en est aujourd'hui. Ce lot dit comment on en est arrivé là :

- pour une faille, ce qui lui est arrivé et quand ;
- pour le parc, si les failles ouvertes montent ou descendent ;
- pour une semaine ou un mois, ce qui a été trouvé, décidé, corrigé et prouvé.

Ce dernier point sert à montrer le travail de sécurité à quelqu'un d'autre, un client ou un associé. Le rapport doit donc pouvoir s'imprimer (et s'enregistrer en PDF depuis le navigateur) sans perdre son sens.

## Objectifs

### 1. Journal des changements d'une faille (serveur)

Aujourd'hui, `finding.status_changed_at` ne garde que le dernier changement d'état. Les passages vue → disparue → revenue sont perdus.

- Nouvelle table `finding_event` : `finding_id`, `at` (RFC 3339), `kind`, `detail` (JSON court, sans chemin ni secret). Clé : `finding_id` + `at` + `kind`, ou une colonne `seq` numérotée par le code. Pas de `rowid` ni d'`AUTOINCREMENT`.
- Valeurs de `kind` :
  - `seen` : première vue ;
  - `gone` : n'est plus trouvée ;
  - `back` : revient après `gone` ;
  - `reopened` : une décision est remplacée et la faille repasse « à traiter », avec la raison de la supersession dans `detail`.
- Écrits dans la même transaction que le changement de statut, aux endroits qui posent aujourd'hui `status_changed_at` : `scan.apply` (scans et plugins) et `decide.setStatus`.
- Les décisions et les tentatives de fix ont déjà leur propre historique (table `decision` avec `superseded_at`, table `fix_attempt` avec ses états). On ne les recopie pas : la chronologie les lit là où elles sont.
- Migration pour les failles existantes : un `seen` à `first_seen_at`. Plus un `gone` à `status_changed_at` pour celles qui sont `gone` aujourd'hui. Ce passé reconstitué est marqué `detail.reconstructed = true`, et la page le dit (« avant le JJ/MM, Michel ne gardait que le dernier changement »).

### 2. Chronologie dans la fiche d'une faille (page)

- `GET /api/v1/findings/{id}/timeline` rend une liste triée par date. Chaque entrée a un `kind`, un `at`, et des champs propres à son type :
  - les événements de `finding_event` ;
  - les décisions, avec leur action, leur auteur, leur échéance et leur remplacement ;
  - les tentatives de fix, avec leurs états marquants : lancée, proposée, approuvée, appliquée, prouvée, refusée, échouée.
- La fiche guidée (`#/fix?finding=<id>`) montre la chronologie sous la carte principale : une ligne par entrée, du plus récent au plus ancien, avec date et mots simples. Repliée au-delà de 10 entrées.
- Pas de nom de fichier ni de chemin dans la chronologie, au-delà de ce que la fiche montre déjà.

### 3. Courbe des failles ouvertes (page « Vue d'ensemble »)

- `GET /api/v1/stats/open?days=90` rend, pour chaque jour local des 90 derniers jours, le nombre de failles ouvertes de projets à la fin de ce jour, par gravité.
- « Ouverte » veut dire la même chose que sur la page Failles : pas `gone`, et pas décidée « ignorer ».
- Le calcul rejoue `finding_event` et les décisions. Avant la migration, il s'appuie sur le passé reconstitué. La partie reconstituée de la courbe est tracée en pointillés, avec une phrase qui le dit.
- Une carte « Failles ouvertes sur 90 jours » apparaît sous les tuiles : courbe empilée par gravité en SVG, avec un texte équivalent (début, fin, plus haut, plus bas).

### 4. Rapports de semaine et de mois (nouvelle page)

- Nouvelle entrée « Rapports » dans le groupe « Suivi » de la barre latérale, à l'adresse `#/reports?period=week|month&at=AAAA-MM-JJ`. Par défaut : la semaine précédente, complète, du lundi au dimanche en heure locale. Flèches pour passer à la période précédente ou suivante, sans dépasser la période en cours (marquée « en cours »).
- `GET /api/v1/reports?from=&to=` rend les agrégats de la période, calculés en Go :
  - failles trouvées, par gravité ;
  - failles disparues (corrigées hors Michel ou par Michel) ;
  - décisions prises, par action ;
  - correctifs proposés, appliqués et prouvés ;
  - ouvertes au début et à la fin, par gravité ;
  - la plus ancienne encore ouverte ;
  - contrôles faits et en échec, pour les projets et pour les serveurs ;
  - failles des serveurs trouvées et fermées, comptées à part ;
  - par projet, une ligne avec ses chiffres.
- La page dit tout ça en phrases courtes et en tableaux, avec un résumé en tête : « Cette semaine : 4 failles trouvées, 6 corrigées, 2 en attente de ta validation ».
- Un bouton « Imprimer » ouvre l'impression du navigateur. Une feuille de style d'impression cache la barre latérale et les boutons, et garde la gravité lisible en noir et blanc (mot + forme). Pas de génération de PDF côté serveur.
- Tout chiffre qui ne peut pas être lu s'affiche « non lu », jamais 0 (anti-objectif du premier lot).

## Non-objectifs

- Pas d'envoi des rapports par e-mail dans ce lot. Le digest quotidien reste le seul envoi. L'envoi mensuel pourra venir ensuite sur la même API.
- Pas de rapport par client ni par serveur seul : un rapport couvre tout le parc, avec une ligne par projet.
- Pas de nouvelle dépendance JS ou Go, pas de police téléchargée (CSP).
- La chronologie des failles de serveur reste sur la page Serveurs, comme au premier lot. Seuls les rapports comptent les failles des serveurs.

## Anti-objectifs

- Aucun chiffre inventé. Le passé reconstitué est toujours signalé comme tel.
- La gravité n'est jamais une couleur seule.
- Rien dans un rapport imprimé qui ne soit déjà visible sur la page : pas de chemin, pas de nom de machine, pas de secret.
- Une page lente ferait échouer le lot. Avec 5 000 failles et 1 an d'historique, les trois nouvelles routes répondent en moins d'une seconde sur ce PC. Index sur `finding_event(finding_id)` et sur `finding_event(at)`.

## Contraintes

- Règles constantes :
  - pas de nom de projet privé (test `internal/hygiene`) ;
  - SQL portable vers PostgreSQL (`?`, `ON CONFLICT`, dates RFC 3339 en TEXT, pas de `rowid`, `AUTOINCREMENT` ni `datetime()`) ;
  - tout texte français relu par un relecteur francophone non spécialiste, tutoiement ;
  - mêmes clés dans `en.json` et `fr.json` (front et catalogue Go) ;
  - jamais d'écriture dans les projets scannés.
- Migration numérotée après la dernière (`0028`). Les tests de comptage des migrations sont mis à jour.
- La logique de calcul vit dans des fonctions Go testées : rejouer les événements, découper les jours en heure locale, agréger la période. Côté front, dans des modules purs de `web/src/lib` couverts par vitest. Les composants restent minces.
- Accessibilité comme au premier lot : un seul `h1`, focus visible, graphiques avec texte équivalent, `prefers-reduced-motion`.
- Portes : `go test ./...`, staticcheck à 0, `npm test`, `npm run build`, `gofmt -l`.

## Choix du constructeur (Kévin a délégué)

- Une seule table d'événements sert à la fois à la chronologie et à la courbe, au lieu d'un instantané quotidien des comptes. C'est plus juste, et une faille qui revient est vue.
- Le passé est reconstitué depuis `first_seen_at` et `status_changed_at`, et signalé, plutôt que de laisser la courbe vide avant la migration.
- Rapport imprimable par le navigateur plutôt qu'un PDF serveur : pas de dépendance, et ce que tu imprimes est ce que tu vois.
- Semaine du lundi au dimanche, en heure locale du poste.

## Précisions après la relecture du constructeur (choix du constructeur)

1. **Dates des tentatives de fix.** `fix_attempt` n'a que `created_at` et `updated_at`. On ajoute donc la table `fix_attempt_event` (`attempt_id`, `seq`, `at`, `state`), écrite à chaque changement d'état d'une tentative, dans la même transaction. La chronologie montre ces états : lancée, proposée, approuvée, refusée, appliquée, corrigée et prouvée (`proven_fixed`), non concluante, échouée, retirée, remplacée, en attente (`held`). Elle cache `preparing`, `running` et `unknown`, sauf comme dernier état connu. Pour les tentatives existantes, la migration reconstitue un événement à `created_at` (lancée) et un autre à `updated_at` (état actuel), marqués comme reconstitués. Le compte « correctifs prouvés » d'un rapport compte les événements `proven_fixed` de la période.
2. **Points d'écriture de `finding_event`.**
   - Une seule fonction écrit l'événement. Elle est appelée partout où le statut change : `scan.apply` (insert et changements) et `decide.setStatus` (donc `Set`, `Supersede`, `expire`).
   - `seen` : première insertion.
   - `gone` : passage à `gone`.
   - `back` : sortie de `gone`, quel que soit le nouveau statut.
   - `reopened` : passage de `decided` à `pending`. `detail.reason` donne la raison : raison de la supersession, `due_reached` ou supersession explicite.
   - Sortie de `gone` avec une décision remplacée : deux lignes, `back` puis `reopened`.
   - `new` vers `pending` et `pending` vers `decided` ne sont pas des événements : la table `decision` donne déjà ces moments.
   - Les failles des serveurs ont aussi leurs événements. La courbe les exclut.
3. **« Ouverte » à un instant donné.**
   - Une faille est ouverte si elle n'est pas `gone` à cet instant et qu'aucune décision `ignore` n'est en vigueur à cet instant (entre `created_at` et `superseded_at`).
   - Une décision `fix` ou `defer` laisse la faille ouverte.
   - Les failles des serveurs sont exclues avec le même filtre que `ListFindings`.
   - La gravité utilisée est la gravité effective d'aujourd'hui, appliquée à tout l'historique. La page le dit en une phrase sous la courbe.
4. **Passé reconstitué.** Toute la courbe avant la date de la migration est marquée reconstituée (pointillés + phrase), même là où elle peut être fausse (une faille ouverte → disparue → revenue avant la migration paraît toujours ouverte).
5. **Chiffres des rapports.**
   - Contrôles des projets : table `scan` (statut et date de début). Contrôles des serveurs : ce que le stockage garde vraiment. Si un serveur ne garde que son dernier contrôle, le rapport compte ce qui tombe dans la période et dit « non lu » pour le reste, sans rien inventer.
   - « Corrigée par Michel » : la faille passe à `gone` alors qu'une de ses tentatives est déjà `applied` ou `proven_fixed`. Sinon, elle est « disparue hors Michel ».
   - « Plus ancienne encore ouverte » : par `first_seen_at`.
   - La page envoie `from` et `to` en dates locales (AAAA-MM-JJ, `to` inclus). Go les lit en `time.Local` : de `from` 00:00 à `to + 1` 00:00.
   - Les ouvertes « au début » et « à la fin » viennent du même calcul de rejeu que la courbe.
6. **Clés.** `finding_event` a la clé (`finding_id`, `seq`), et `fix_attempt_event` la clé (`attempt_id`, `seq`). `seq` = max + 1 par faille ou par tentative, calculé dans la transaction. La migration écrit des `seq` littéraux (1 pour `seen`, 2 pour `gone`), donc du SQL portable.

## Laissé au constructeur

Les mots exacts, le découpage des composants, la forme exacte des réponses JSON, et le nom des états d'une tentative à montrer dans la chronologie, en partant de ceux qui existent.
