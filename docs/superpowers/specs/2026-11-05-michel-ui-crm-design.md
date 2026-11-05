# Michel : interface « CRM de la sécurité », premier lot

Date : 2026-11-05. Demande de Kévin : « une interface pro, propre, fonctionnelle et moderne, type CRM mais orientée sécurité », avec trois références (un tableau de priorisation de vulnérabilités, un tableau de bord type SaaS à barre latérale, une chronologie d'activité avec fiche de compte). Kévin délègue les choix : ils sont notés ici comme ceux du constructeur.

## Intention

Que la personne voie en 30 secondes où elle en est : combien de failles ouvertes et de quelle gravité, ce qui attend sa validation, ce qui a été corrigé et vérifié, si un contrôle a échoué, et ce qu'elle doit faire maintenant. Puis qu'elle retrouve n'importe quelle faille dans une liste filtrable, comme une liste de dossiers dans un CRM.

## Objectifs de ce lot (front seulement, aucune modification du serveur Go)

1. **Coquille** : barre latérale claire de 248 px dès 960 px, en trois groupes (« Suivi » : Vue d'ensemble, Failles, Résolus ; « Parc » : Projets, Serveurs ; puis Réglages et l'aide). Pastilles de compte sur « Failles » (ouvertes) quand le nombre est connu. En dessous de 960 px, la barre du bas reste, avec au plus cinq entrées (Vue d'ensemble, Failles, Projets, Serveurs, Réglages ; Résolus reste joignable depuis la vue d'ensemble).
2. **Style** : cartes blanches à bord fin, rayon 12 px, titres en sans-serif gras (la police « livre » des titres disparaît), plus de densité, palette bleu marine conservée et contrastes AA vérifiés par `theme.test.js`. Aucune police téléchargée : la CSP garde la page sur son origine.
3. **Vue d'ensemble** (page « À faire » actuelle, même adresse `#/`) : au-dessus de la liste existante, une rangée de quatre tuiles :
   - failles ouvertes, avec la répartition par gravité (barre empilée + mots) ;
   - correctifs à valider (tentatives en état `proposed`) ;
   - corrigées et vérifiées sur 30 jours (tentatives `proven_fixed` dont `updated_at` tombe dans les 30 derniers jours) ;
   - parc surveillé : nombre de projets et de serveurs, contrôles en échec.

   Puis deux cartes : « Nouvelles et disparues » par semaine sur 8 semaines, calculées depuis `GET /digests?last=100` (somme des `new` et `gone` des projets de chaque envoi, semaine locale du `until`), et « Depuis quand elles sont ouvertes » (âge des failles ouvertes depuis `first_seen_at` : 0–30, 31–90, 91–180, plus de 180 jours). Puis des « signaux » cliquables qui ouvrent la liste filtrée : exploitée en ce moment (`kev`), forte chance d'être exploitée (`epss_percentile` ≥ 0,9), paquet malveillant (`malicious`), correctif disponible (`fixed_versions` non vide), pas encore de correctif. La liste « À faire » actuelle, le guide, les bandeaux restent, avec le nouveau style.
4. **Page Failles** (`#/findings`) : toutes les failles ouvertes des projets dans un tableau (gravité, faille en mots simples, projet, version installée → corrigée, vue depuis, état, signaux), avec recherche, filtres projet / gravité / état / signal, gardés dans l'adresse (`#/findings?project=…&severity=…&status=…&signal=…&q=…`) pour qu'un lien survive. Une ligne mène à la fiche guidée existante (`#/fix?finding=<id>`). En mode Expert, la ligne montre aussi l'identifiant et le score CVSS. Sur téléphone, le tableau défile dans sa boîte.

## Non-objectifs

- Pas de modification de l'API ni de la base. Ce qui demanderait du stockage nouveau (courbe des ouvertes dans le temps, historique d'une faille avec `status_changed_at`, rapports mensuels) vient dans un lot suivant.
- Les failles des serveurs restent sur la page Serveurs dans ce lot.
- Pas de nouvelle dépendance : graphiques en SVG ou en CSS.

## Anti-objectifs

- Aucun chiffre inventé ou « score » décoratif : chaque nombre vient d'une donnée de l'API, et un nombre qu'on ne peut pas lire s'affiche comme non lu, jamais comme zéro.
- La gravité n'est jamais une couleur seule (couleur + mot + forme, comme aujourd'hui).
- Ne pas perdre ce que le novice a validé : les phrases simples, le guide, « Michel ne surveille encore rien ».
- Pas de boutons vers des fonctions qui n'existent pas.

## Contraintes

- Règles constantes : pas de nom de projet privé (test `internal/hygiene`) ; tout texte français relu par un relecteur francophone non spécialiste, tutoiement ; mêmes clés en `en.json` et `fr.json`.
- La logique va dans des modules purs de `web/src/lib` couverts par vitest ; les composants restent minces.
- Accessibilité : un seul `h1` par page, focus visible, `aria-current`, filtres avec `label`, graphiques avec un texte équivalent, `prefers-reduced-motion` respecté.
- Portes : `npm test`, `npm run build`, `go test ./...` (le web est embarqué), `go vet`, `gofmt -l`.

## Laissé au constructeur

Les mots exacts, le découpage des composants, la façon de partager les lectures entre la vue d'ensemble et la page Failles.
