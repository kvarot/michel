# Plan 2 — points reportés et arbitrages (extrait du ledger de session, 2026-10-22)

Triage de la revue finale : tout ce qui n'a pas été corrigé dans la vague finale est reporté au plan 3 (décisions, digest, i18n) sauf mention contraire.

- Ruling: branche en place, pas de worktree — rien d'autre en cours dans ce dépôt — coût si faux : aucun.
- Task 1: Ruling: optionalDependencies et peerDependencies de la racine npm comptent comme directes — coût si faux : un paquet optionnel marqué direct au lieu de transitif.
- Task 1: minor (deferred): Composer provide/replace non modélisés (→ unknown) ; `packages` null en v3 = message trompeur ; tri des voisins à chaque PathTo ; erreurs WriteFile ignorées en test ; composer-runtime-api filtré (hors liste).
- Task 1: minor (deferred): doublons npm de même profondeur (workspaces) tranchés lexicalement ; addAll écrase la contrainte si un nom est dans dependencies et peerDependencies ; test dev-only synthétique (ne charge pas packages-dev).
- Task 2: minor (deferred): `<2.0` vs pré-version `2.0.0-beta` accepté (Composer exclut) ; opérateur + wildcard (`>=1.*`) traité comme préfixe (→ nil demandé dans le round).
- Task 2: minor (deferred): `1.0 - 2.x` → nil (avant : préfixe) ; borne haute non numérique dans hyphenRange laissée telle quelle.
- Task 3: Ruling: fichier `callsites_js.go` du plan = contrainte de build GOOS=js (défaut du plan) → renommé `callsites_npm.go` — coût si faux : aucun.
- Task 3: Ruling: la ligne `use` compte comme point d'appel ; les usages courts non qualifiés après import ne sont pas suivis en plan 2 (fixture du brief restaurée, Count attendu 2 au lieu de 3) — coût si faux : sous-estimation du nombre d'appels, pas du nombre de fichiers.
- Task 3: minor (deferred): double walk + relecture par paquet (cache par manifeste au plan suivant) ; snippet = début de ligne pour JS minifié ; caches compilés (var/cache, storage/framework/views) scannés sauf exclude ; `require( 'pkg' )` avec espaces / template literal / multi-ligne manqués ; `'pkg/` matche tout préfixe (noms courts) ; pas de check `..` sur manifestRelPath/pkg ; tests manquants (2 MiB, symlink, exclude en profondeur, manifeste JS imbriqué).
- Task 3: minor (deferred): clé psr-4 finissant en `_\` perd son `_` (TrimRight "\_") — strip `_` seulement si la clé ne finit pas par `\`.
- Task 4: Ruling: CallSites gagne TestFiles/TestHitCount/SourceFiles calculés avant le cap (modifie callsites.go, Task 3) — coût si faux : aucun.
- Task 4: minor (deferred): coût par paquet (re-walk + regex par nom) ; `\b` ASCII seulement ; mots communs (Http, Client) = preuve faible ; duplication des fixtures.
- Task 4: Ruling: Coverage.Unreadable = fichiers de TEST distincts illisibles (dédup par chemin) ; sources illisibles restent dans CallSites.Unreadable — coût si faux : aucun.
- Task 4: minor (deferred): retour d'erreur userFiles ne porte pas Unreadable (asymétrie).
- Task 5: Ruling: titre de version = ATX niveau 1-2 commençant par le token ; `###` jamais ; Unreleased/Next seulement si titre exact ; blocs ``` ignorés — coût si faux : changelogs exotiques (titres de version en `###`) non découpés → repli « premiers 4096 octets ».
- Task 5: minor (deferred): vendor/<pkg> symlinké hors racine suivi (Lstat/EvalSymlinks) ; `foo..bar` rejeté (sur-strict) ; tests manquants (installé non parsable, alias composer, faux positif breaking).
- Task 5: minor (deferred): `## Version 2.0.0` / `## Release 2.0.0` plus reconnus (règle « token en tête ») → autoriser un mot `version|release` optionnel ; `## Unreleased - date` ne ferme plus ; `BC breaks` (pluriel) non matché ; fence non fermée court jusqu'à EOF (CommonMark, à documenter).
- Task 6: Ruling: ScoreRisk retombe sur les seuils de la politique si les seuils fusionnés sont incohérents (Terms.thresholds_fallback=1) — coût si faux : aucun (défense en profondeur).
- Task 6: minor (deferred): Directness inconnue = 0 sans marqueur ; chaîne d'erreur capitalisée (ST1005) ; Warning sur report_only non documenté (demandé dans le round).
- Task 6: minor (deferred): erreur de normalizeExtras ignorée au scan (valeurs hors plage éditées à la main appliquées sans clamp) ; Terms.thresholds_fallback = drapeau, pas des points (doc).
- Task 7: minor (deferred): échecs d'écriture d'audit dans Errors mais pas dans Failed (exit 0) ; computed_at à la seconde (recalculs inutiles possibles) ; Notes non persistées (plan 3 : colonne ou affichage) ; scan --json sans info d'analyse ; changement de policy.Risk/CorePackages n'invalide pas l'analyse (documenter --force).
- Task 7: minor (deferred): ctx annulé avec zéro finding → pas d'événement finish ; chemin computed_at invalide non testé ; hook loadGraph global (pas de t.Parallel).
- Task 8: Ruling: « sans analyse » = formulation « pas encore vérifié » (plus honnête que `low`) — acceptée — coût si faux : aucun.
- Task 8: minor (deferred): cost peut atteindre 4-5 phrases (conséquence des fragments épinglés) ; glossaire cve/cvss/kev/lockfile/semver jamais affiché ; `findings --explain --json` ignore --explain ; pas de test direct de plural(0,1,2).
- Task 8: minor (deferred): ligne Versions FR mélange les styles de deux-points ; « recommandation : correction… » plus fluide.
- Final fix: Ruling: échantillons rot13 dans le test d'hygiène = trace déguisée → remplacés par un test de mécanisme (jeton aléatoire haché à la volée) — coût si faux : aucun.

## Risques résiduels (revue finale)
- Extraits de changelog et lignes « breaking » = texte attaquant-contrôlé stocké en base : assainis à la source (SanitizeText), à clôturer comme données dans les briefs et prompts (plans 4/7).
- Le score dépend des heuristiques (points d'appel, couverture, breaking) : constituer un corpus de fixtures (Setext, titres ###, templates Twig, App\Http) avant que le plan 6 agisse sur auto_fix.
- JSON d'analyse figé en snake_case ; project_id et inputs_hash présents ; toute nouvelle colonne = migration.
- Le catalogue i18n (plan 3) doit reprendre labels.go, les gabarits et les messages CLI sans changer les phrases épinglées.
- Notes / Unreadable encore non persistés (sauf changelog_note) : règle « quoi / pourquoi / quoi faire » incomplète sur analyse dégradée.
- Hygiène : un test par jetons ne voit pas le sens ; relire ledgers et exemples à la main.
- SQLite : SQL écrit à la main dans les repo ; rester portable (ON CONFLICT, ?, types simples, pas de rowid) en vue de l'adaptateur PostgreSQL du mode serveur (plan 6).
