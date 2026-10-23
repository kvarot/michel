# Plan 3 — points reportés et arbitrages (extrait du ledger de session, 2026-10-23)

Plan : décisions, digest quotidien, canaux de notification, secrets, page « Aujourd'hui ». Les lignes sont reprises du ledger de session (en anglais quand le ledger l'était) ; elles ne nomment aucun projet privé : les exemples utilisent `demo` ou « le projet de référence ». Tout ce qui est marqué *minor (deferred)* ou *open* est reporté aux plans suivants sauf mention contraire.

## Général

- Ruling: branche en place, pas de worktree — rien d'autre en cours dans ce dépôt — coût si faux : aucun.
- Ruling: commit trailer switches to 'Co-Authored-By: Claude Opus 5.5' for commits from Task 6 on (session model changed by the user) — coût si faux : trailer cosmétique.

## Task 1

- Ruling: status_changed_at is written on new→pending too (every status change counts) — the brief's 'second scan unchanged' line assumed pending→pending — coût si faux : aucun (digest n'utilise la date que pour gone).
- minor (deferred): exclude names accept glob chars (*?[]{}) → osv-scanner pattern g:**/<name> diverges from Michel's exact walk (reject them in normalizeExtras).
- minor (deferred): analyze Get returns nil for the 5 new lists but [] for older ones (one convention).
- minor (deferred): cli/scan.go passes EffectiveExclude although Run defaults nil to it; denied project add audit lacks exclude values; panic test does not cover a panic inside the write tx.

## Task 2

- minor (deferred): tutoiement guard's sovereignty-policy exclusion is vacuous (no .fr.md variant; match base name); i18n.Template ignores funcs on cached calls (document or key by lang only); keys_test deps/d receiver heuristic may false-positive; explainLang redundant now Lang is an alias; ~~~ fences ignored; golden test name says "IdenticalToPlan2" while FR half is a snapshot; withEntry mutates global catalogs without lock.

## Task 3

- Ruling: hygiene false positive on the French plural "<count> projets" right after a format verb (the two adjacent tokens hash to a machine path) → French reads "<count> de tes projets" — coût si faux : aucun. Wrapf method instead of _wrap key suffix: accepted.
- minor (deferred): messages_test ev[0] indexed before len check; French findings usage error only asserted negatively; no test for invalid --lang under French system locale; ambiguousPrefixMessage English wrapper kept for review_wave_test; "1 de tes projets" stiff; "Glossaire:" lacks French space (explain-owned); %q yields English quotes in French.

## Task 4

- minor (deferred): drop "(plan 3)" from cli.scan.warn_ignored_config and its test (final wave); scan summary could mention "N decisions to review".
- Ruling: ExpireDue only supersedes defers of findings in status decided (a gone finding keeps its decision, spec § 3.2) — coût si faux : un report échu sur une faille disparue n'est pas listé tant qu'elle ne revient pas.
- minor (deferred): decideOne reads the replaced decision before Set's tx (Set could return it); by-package decide not atomic and silent on partial progress; gone+due_reached path untested; no CLI decide→re-scan status assertion; TestDecideDeferDefaultShowsDate uses time.Now() (midnight UTC flake); scan text output silent on superseded.

## Task 5

- Ruling: FR footer « Détails : » instead of « Page : » (French review wording) accepted — coût si faux : aucun.
- minor (deferred): window bound truncated to the second (truncate now in Compute); toast "to review" double-counts new critical/high; scan --all --digest --json prints no digest; unknown severity missing from open breakdown; no banner when OSV db missing; --since / due dates in UTC not local day.

## Task 6

- minor (deferred): malformed addr denied without Attempt; secret stored before audit write; no test that decrypt without entropy fails.

## Task 7

- Ruling: enabled channel without allow rule fails at policy load (Validate) rather than at send — spec § 5.1 says Validate checks it; send-time refusal kept for disabled-channel test — coût si faux : aucun.
- minor (deferred): SMTP server reply text stored in digest_run.channels errors; non-ASCII display names not RFC 2047 encoded; page_url path not checked for tokens.
- minor (deferred): unavailableSecrets error string English and may include data-dir path; plainText lets U+FFFE/U+FFFF through (toast may fail).

## Task 8

- Ruling: GET / without token serves the shell (no data; bookmark/PWA must open it); wrong ?token= → 401 — coût si faux : aucun (API reste protégée).
- Ruling: empty AllowedHosts accepts loopback names on any port (tests); serve always fills the exact list — coût si faux : aucun en usage réel.
- Ruling: --open puts the token in the launcher's argv (visible to same-user processes) — accepted, same user already owns the token file — coût si faux : faible.
- minor (deferred): scrub untested and case-sensitive on Windows; nested analysis/decision project_id still in views; serve handles only os.Interrupt (add SIGTERM); localhost listen not verified as loopback IP after Listen; first-start token race; raw scan SQL in internal/api (move to scan.Repo); trailing >64KiB whitespace gives 400 not 413; 500s log nothing to stderr.

## Task 9

- Ruling: until = today is refused client-side (server reads YYYY-MM-DD as midnight UTC and wants it after now) — date picker min = tomorrow — coût si faux : aucun.
- Ruling: page "/" network-first (cached copy offline), assets cache-first; sw.js refreshes the precache on each online page load because sw.js bytes do not change between builds — coût si faux : aucun.
- Ruling: added GET /sw-manifest.json to internal/api static routes (the SW reads it; no data, no token) — coût si faux : aucun.
- open (fixed in round 1, 7fe1c8b): manifest.webmanifest served as text/plain → now application/manifest+json.
- open: make not installed here, Makefile conditional untested; PWA install prompt to confirm by Kévin.
- Ruling: add Severity to digest.Superseded/Due server side (option a) — coût si faux : un champ JSON de plus.
- minor (deferred): isoDay uses UTC calendar day (picker minimum may look like day after tomorrow late evening west of UTC).

## Risques résiduels

- Secrets sous Linux et macOS : fichiers en clair, protégés seulement par les droits du fichier (0600). Toute sauvegarde du dossier de données emporte les mots de passe SMTP, les clés de webhook et le jeton de la page. Le trousseau du système (libsecret, Keychain) reste dû.
- Notification Windows : le mode Ne pas déranger cache la bannière (constaté sur le poste de Kévin) ; le toast arrive dans le centre de notifications mais peut passer inaperçu. L'e-mail ou le webhook reste le canal fiable du matin.
- Installation de la PWA non confirmée : manifeste, icônes et service worker sont servis, mais l'invite d'installation n'a pas été observée sous automatisation ; à confirmer dans une fenêtre Chrome normale.
- Makefile : la condition « npm présent → make build lance make web » n'a pas été exécutée, `make` étant absent du poste de développement.
- Texte du serveur SMTP stocké dans les erreurs de canaux (`digest_run.channels`) : texte venu de l'extérieur, en base, potentiellement affiché par la page ; assaini à l'affichage mais non borné à des codes.
- `unavailableSecrets` peut mettre un chemin du dossier de données dans une erreur de canal stockée (règle de minimisation à resserrer).
- Fenêtre et échéances en jours UTC, pas en jours locaux : un report « jusqu'au 1er » peut échoir la veille au soir à l'ouest de UTC, et le sélecteur de date peut sembler commencer après-demain.
- Décision par paquet non atomique : une erreur au milieu laisse une partie des failles décidées sans le dire.
- Jeton de la page : `--open` le met dans la ligne de commande du navigateur (visible des processus du même utilisateur) ; une course possible au tout premier lancement de deux `serve`.
- `michel schedule` n'existe pas : la tâche planifiée est écrite à la main (doc `daily-digest`), sans vérification par Michel qu'elle tourne ; un matin où l'ordinateur était éteint n'est relancé que si l'option correspondante est cochée (le digest suivant couvre quand même toute la période).
- Hygiène : le test par empreintes ne voit pas le sens ; ledgers et docs relus à la main (agrégats seulement, projet dit « le projet de référence »).

## Run réel (contrôleur, 2026-10-23)
- Run réel: minor (deferred): `decide --package` affiche une ligne d'audit par faille (59 ici) ; un résumé avec le nombre suffirait.
- Run réel: minor (deferred): osv-scanner écrit trois avertissements `interpreting as regex/glob` par projet sur stderr (existant depuis le plan 1).
- Run réel: minor (deferred): le digest dit « le dernier scan de 2 projets n'a pas pu se terminer » pour des dossiers sans lockfile ; une formulation « rien à scanner » serait plus juste.
