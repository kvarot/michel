# Plan 1 — points reportés et arbitrages (extrait du ledger de session, 2026-10-22)

Revue finale (opus) : triage ligne par ligne dans la session ; à reprendre au plan 2 (analyse) sauf mention contraire. Risques résiduels listés en fin.

- Ruling: branche `feat/socle` créée en place, pas de worktree — dépôt neuf, aucun autre travail en cours — coût si faux : aucun.
- Task 1: review approved (sonnet). ⚠️ trailer vérifié présent ; `go 1.27.3` dans go.mod = instruction du contrôleur. Ruling: go.mod `go 1.27.3` accepté (toolchain auto) — coût si faux : aucun.
- Task 1: minor (deferred): root.go:158 fallback silencieux sur chemin relatif si os.UserConfigDir() échoue → à traiter dans Task 2 (PersistentPreRunE : erreur explicite si échec et flags absents).
- Task 1: minor (deferred): root_test version test uses Contains, flag defaults untested.
- Task 1: minor (deferred): lint grep `--exclude-dir=egress` matches any dir named egress.
- Task 2: minor (deferred): root.go:196 chemin dupliqué dans le message d'erreur (Load préfixe déjà) → à corriger dans Task 4 (PersistentPreRunE retouché).
- Task 2: minor (deferred): PersistentPreRunE bloque `help`/`completion` sur politique cassée → Task 4 : skip pour ces commandes.
- Task 2: minor (deferred): Validate n'applique pas les enums (classification, provider_policy, integrity_protection, retention, default_egress en standard) ; osv_path "" ou relatif accepté ; 2e document YAML ignoré.
- Task 2: minor (deferred): TestUnknownKeyIsError ne vérifie que err != nil ; TestDefaults ne vérifie pas ProviderPolicy / Isolated / HumanApproval.
- Task 3: minor (deferred): hostMatches `*.` suffixe vide (défense en profondeur, policy le refuse déjà) ; Host vide ; éviction O(n) au cap ; Allowed() exige un hostname nu (doc) ; contrat de concurrence de Sink.Record non documenté (→ Task 4 : logger thread-safe) ; dépendance au résolveur pour `localhost` ; pas de test -race.
- Task 4: Ruling: ancre de tête `audit.head` (count + hash) écrite après chaque Record, lue par Verify → raison "tail truncated" — checkpoints signés Ed25519 restent au plan audit avancé — coût si faux : un fichier de plus à protéger, pas de régression.
- Task 4: Ruling: pas d'événement app.start pour l'arbre de commandes `audit` (inspection doit marcher en lecture seule) — coût si faux : lancements de `audit` non tracés.
- Task 4: minor (deferred): json tags snake_case sur audit.Event ; DSN non échappé (url.URL) ; chmod 0600 des fichiers .db/-wal/-shm ; tests faibles (list ordering/seconds, --last 0, help/completion skip, prev_hash/evidence tamper) ; json.Unmarshal evidence ignoré ; deps.Close() erreur ignorée ; sink context.Background (timeout court) ; check "already applied" hors transaction ; pas de garde schéma plus récent ; détection commande par nom.
- Design: application FR/EN dès v1 (catalogue internal/i18n au plan digest/PWA ; messages CLI plan 1 migrés alors). Ruling: plan 1 reste en anglais, migration groupée — coût si faux : une passe de refactor des messages CLI.
- Task 4: minor (deferred): Verify lit rows puis audit.head sans snapshot (faux "tail truncated" possible si Record concurrent, auto-réparé) ; audit.head supprimé = ancre désactivée silencieusement (documenté) ; sortie de tests non collée en entier dans le rapport.
- Task 5: minor (deferred): add non atomique avec son audit ; échecs de Remove non audités ; chemins Windows (casse, séparateur final) non testés, même dossier enregistrable deux fois ; noms non trim ; `--json` expose test_cmd/install_cmd (→ masquer dans le plan digest/PWA) ; test denied n'affirme pas l'absence de TOKEN ; retours de run() ignorés.
- Task 6: Ruling: passerelle egress sans Timeout global (ResponseHeaderTimeout 30 s, TLS 15 s, Idle 90 s), bornes par contexte côté appelant ; osvdb : 15 min par écosystème — modifie internal/egress (Task 3) — coût si faux : un appel sans deadline peut pendre, chaque appelant doit poser un contexte.
- Task 6: Ruling: caps téléchargement 2 GiB, zip ≤ 2 000 000 entrées et ≤ 8 GiB décompressé — coût si faux : refus d'une base OSV légitime plus grosse, à relever par constante.
- Task 6: minor (deferred): SetBaseURLForTest exporté (préférer export_test.go ou option Deps) ; pas de check Content-Type ; Statuses renvoie toujours nil ; fetched_at écrit après rename (échec = base neuve sans stamp) ; erreurs ignorées dans les tests ; pré-check Allowed dupliqué avec le transport (tests doivent allowlister 2 hôtes).
- Task 6: minor (deferred): UncompressedSize64 déclaré, forgeable (le lecteur osv-scalibr ne doit pas s'y fier seul) ; échec d'écriture fetched_at après install = "kept" imprécis.
- Task 7: Ruling: zéro manifeste = scan `failed`, findings non touchés, exit 1, ErrNoManifests — coût si faux : un projet vidé volontairement garde ses findings jusqu'à suppression du projet.
- Task 7: Ruling: compteur Reappeared distinct de New — coût si faux : aucun.
- Task 7: minor (deferred): lignes `scan` laissées `running` après crash (balayage au prochain Run + defer/recover → plan suivant) ; lock_sha256 relu après DoScan (TOCTOU documenté) ; checkContent faux positif sur package-lock tout en link:true ; validation --project/--all cryptique ; style des messages d'erreur ; pas de test --all avec projet inactif ; fail() utilise ctx annulable pour l'audit ; citations module-cache approximatives ; test zéro egress ne couvre pas un http.DefaultClient dans une dépendance (→ transport deny-all en test, plan tests § 13).
- Task 7: minor (deferred): filtre post-DoScan sur rel path sensible à la casse (Windows) / racine symlinkée → findings possiblement `gone` (EqualFold ou traiter comme unread) ; JSON `scan` passé d'un tableau à {results, failures} (documenter dans Task 8).
- Task 8: Ruling: inventaire egress doit mentionner l'exception loopback `local.*` (doc sécurité complète) — coût si faux : aucun.
- Task 8: minor (deferred): offline-installation : note `.exe` Windows ; "checks the zip" trop mince (caps + install atomique).
- Final fix: Ruling: I2 « head en avance d'un = propre » NON appliqué, à raison : indiscernable d'une suppression du dernier événement ; head écrit après commit rend le cas impossible — coût si faux : aucun.
- Final fix: Ruling: garde supplémentaire `scan --project <inactif>` refusé — acceptée, cohérente avec le soft-delete — coût si faux : aucun.
- Final fix: minor (deferred): SQLITE_BUSY possible si plusieurs processus créent la base au même instant (plan 2).

## Risques résiduels (revue finale)
- Zéro egress = ce que voit le client de la passerelle ; GRPCClientConn d'osv-scanner et tout net.Dial de dépendance échappent → test egress niveau OS/conteneur (politique § 4.2.2, § 13).
- Bumps osv-scanner/osv-scalibr : relire getPlugins/setupAccessors/osvlocal ; garder PluginNetworkDisabled, PluginsNoDefaults, TransitiveScanning.Disabled affirmés par un test.
- SetMaxOpenConns(1) + sink d'audit synchrone : tout code tenant une transaction pendant Logger.Record ou un appel passerelle bloque → documenter ou connexion dédiée à l'audit.
- Chaîne d'audit : checkpoints signés Ed25519 et sauvegardes protégées encore dus (politique § 7).
- test_cmd/install_cmd et chemins en clair en SQLite et --json : masquage des secrets avant tout brief/digest/prompt.
- Lignes scan en running après crash : balayage + defer/recover à prévoir avant le digest.
- checkContent (sonde JSON maison) peut diverger d'osv-scalibr (npm workspaces link:true) → faux partial.
- Permissions fichiers 0640/0750, ACL héritées Windows : durcir + chiffrement au repos avant exposition PWA/API (classification health).
- Mémoire : osv-scalibr charge chaque all.zip en entier ; prévoir la RAM sur machine 8 Go.
