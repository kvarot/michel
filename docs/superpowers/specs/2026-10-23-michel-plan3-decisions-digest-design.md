# Michel — Design du plan 3 : décisions, digest, canaux, page « Aujourd'hui », i18n

**Date :** 2026-10-23
**Auteur :** Claude (brainstorming court, cadre fixé par Kévin)
**Statut :** rédigé en autonomie à partir du périmètre donné par Kévin ; chaque choix non dicté par le design v1 est marqué « mon choix » et reste à contester
**Design de référence :** `docs/superpowers/specs/2026-10-22-michel-design.md` (§ 4.3 Decision / DigestRun, § 4.8 digest, § 4.11 voix de Michel, § 5 langue) ; politique `docs/security/sovereignty-policy.md`
**Reports hérités :** `docs/superpowers/sdd/2026-10-22-michel-analyse/deferred-and-rulings.md`, `docs/superpowers/sdd/2026-10-22-michel-socle/deferred-and-rulings.md`

---

## 1. Intention

Les plans 1 et 2 produisent, chaque jour, une liste de failles expliquées. Il manque la boucle qui rend ça vivable : **décider une fois** par faille et ne plus la revoir tant que rien ne change, **lire le matin ce qui a bougé** depuis hier, par le canal de son choix, et **le voir sur une page** plutôt que dans un terminal. Le plan 3 livre cette boucle, en français et en anglais, Michel tutoie.

## 2. Périmètre (donné par Kévin) et ce qui reste dehors

Dedans :

1. Décisions par faille : Corriger / Reporter / Ignorer, justification, mémorisées, jamais redemandées sauf changement.
2. Digest quotidien « nouveautés depuis hier ».
3. Canaux au choix : toast (Windows ; Linux et macOS en meilleur effort), email SMTP, webhook générique.
4. Page PWA « Aujourd'hui » (Vue 3 + Vuetify, Options API, embarquée dans le binaire).
5. Catalogue i18n `internal/i18n` reprenant `labels.go`, le glossaire, les gabarits d'explication et les messages CLI (FR/EN, tutoiement).
6. Persistance de `Notes` et des `Unreadable` d'analyse.
7. Balayage des scans restés en `running`.
8. Colonnes manquantes via la migration `0004`.

Dehors (plans suivants) : briefs (plan 4), remédiation et statuts `proven_fixed` / `reported_fixed` (plan 6), web push / Telegram / Slack API (v1.1), planificateur `michel schedule install` et service utilisateur, onboarding guidé, coffre à secrets libsecret / Keychain, aide Cobra traduite (voir § 4.6).

Règles non négociables (Kévin) : aucune trace du projet privé dans le dépôt (test d'hygiène + relecture manuelle des ledgers, projet de référence nommé « demo » dans toute doc) ; SQL portable vers PostgreSQL ; relecteur francophone non spécialiste sur tout texte FR ; jamais d'écriture dans les projets scannés.

## 3. Décisions par faille

### 3.1 Modèle

Table `decision`, append-only (historique conservé, la dernière ligne non remplacée fait foi) :

| colonne | type | sens |
|---|---|---|
| `id` | TEXT PK (ULID) | |
| `finding_id`, `project_id` | TEXT | la faille et son projet (jamais de jointure inter-projets côté lecture) |
| `action` | TEXT | `fix` \| `defer` \| `ignore` |
| `justification` | TEXT | obligatoire pour `ignore`, libre sinon |
| `due_at` | TEXT | date RFC 3339 UTC, `defer` seulement ; vide sinon |
| `author` | TEXT | `cli` \| `web` (le nom d'utilisateur OS n'est pas stocké) |
| `created_at` | TEXT | RFC 3339 UTC |
| `seen_severity`, `seen_fixed_versions` | TEXT | **instantané** de ce qui était connu au moment de décider (gravité, versions corrigées JSON) |
| `superseded_at`, `superseded_reason` | TEXT | vide tant que la décision est en vigueur ; sinon `redecided` \| `severity_changed` \| `fixed_version_changed` \| `due_reached` \| `reappeared_changed` |

Pas de `rowid`, pas de type SQLite-spécifique, `?` et `ON CONFLICT` seulement : la table se rejoue telle quelle sur PostgreSQL.

### 3.2 Statuts d'une faille (complète § 4.3 du design)

`new` → `pending` → `decided` ; `gone` ; (`reported_fixed`, `proven_fixed` arrivent au plan 6). Règles de `applyScan` et des commandes :

- Une décision prise passe la faille en `decided` ; `actionable` (new + pending) ne la liste plus.
- **Re-scan, faille présente et `decided`** : si gravité et versions corrigées sont identiques à l'instantané → reste `decided`, rien à redire. Sinon → la décision est marquée `superseded` avec la raison, la faille repasse `pending`, et le digest la liste sous « décisions à revoir » avec l'ancienne décision et ce qui a changé. C'est la seule façon de « redemander ».
- **Report arrivé à échéance** (`due_at` ≤ maintenant) : décision `superseded(due_reached)`, faille `pending`. Cette mutation n'est faite que par deux écritures : le scan du projet (`applyScan`, même transaction) et `michel digest --send` (avant le calcul). Les lectures (`michel digest` sans `--send`, `GET /today`) sont **pures** : elles montrent le report sous « échéances » avec la mention « échue » sans rien changer. Chaque supersession (toutes raisons) écrit un événement d'audit `decision.superseded` `{finding_id, reason, previous_action}`.
- **Faille `decided` qui disparaît** : `gone` (la décision reste en vigueur, non supersédée : elle décrit le passé).
- **Faille `gone` qui réapparaît** : si une décision en vigueur existe et que l'instantané correspond → `decided` directement (on ne redemande pas) ; sinon `pending`, décision `superseded(reappeared_changed)`.
- Décider une faille `gone` est refusé avec explication (« elle n'est plus vue ; si elle revient, Michel te redemandera seulement si quelque chose a changé »).
- Chaque changement de statut écrit `finding.status_changed_at` (colonne nouvelle), ce qui permet « disparues depuis hier ».

### 3.3 Commandes

```
michel decide <id-ou-préfixe> fix|defer|ignore [--why "…"] [--until 2026-12-01 | --for 30d]
michel decide --project demo --package acme/lib fix|defer|ignore [--why …]     # toutes les failles actionnables de ce paquet dans ce projet
michel decisions --project demo [--status fix|defer|ignore|superseded] [--json]
```

- `ignore` sans `--why` est refusé (design v1 : justification obligatoire). `defer` sans échéance prend **30 jours** (mon choix : une valeur par défaut explicite vaut mieux qu'une question dont la réponse serait presque toujours la même ; affichée dans la confirmation). `fix` = « je vais corriger » : le plan 6 branchera la remédiation dessus.
- La décision par paquet existe parce que le premier scan d'un projet réel donne des centaines de failles, souvent dix avis sur le même paquet (mon choix, cohérent avec « le digest regroupe par paquet »).
- Chaque décision = événement d'audit `decision.set` (finding, action, échéance, auteur, justification passée par `SanitizeText` : la justification est précisément ce que l'audit doit garder ; elle ne contient jamais de code ni de secret, le texte est borné à 1 000 caractères).
- Une décision ne touche jamais au projet scanné ni à `osv-scanner.toml`.

## 4. Digest quotidien

### 4.1 Calcul (`internal/digest`)

`Compute(ctx, store, now, lang, opts) (Digest, error)` est **pur** (aucune écriture). Fenêtre : depuis le `until` du dernier `digest_run` enregistré, quel que soit le résultat de ses canaux (un canal en échec est signalé par l'exit code 1 et se rattrape avec `digest --send --since <date>`) ; sans aucun run, 24 h. Pas de plafond : après trois semaines d'absence, le digest dit « depuis le JJ/MM » et liste tout, rien n'est perdu. Par projet actif :

- **nouvelles** : `first_seen_at` dans la fenêtre, statut ≠ `gone` ;
- **disparues au re-scan** : statut `gone` et `status_changed_at` dans la fenêtre (libellé « disparues, sans preuve ») ;
- **décisions à revoir** : décisions `superseded` dans la fenêtre avec leur raison, sauf `redecided` (l'utilisateur vient de le faire lui-même) ;
- **échéances** : reports en vigueur dont `due_at` ≤ maintenant + 3 jours, les échus marqués « échue » ;
- **compteurs** : ouvertes (new + pending + decided fix/defer) par gravité, décidées par action, total ;
- **jours sans nouvelle critique** : jours depuis la `first_seen_at` de la critique la plus récente (ou depuis le premier scan) ; « 0 critique ouverte » affiché comme état à garder ;
- **mot de Michel** quand tout est propre (aucune nouveauté, aucune échéance) ; voix tutoyée, une idée par phrase.

Transversal : fraîcheur de la base OSV (date la plus ancienne des écosystèmes, bandeau « données périmées » au-delà de 7 jours), nombre de projets dont le dernier scan a échoué ou a été interrompu, lien vers la page « Aujourd'hui ». Sections `corrigées prouvées` et `déclarées corrigées` sont présentes dans la structure, vides tant que le plan 6 n'existe pas, et **non affichées** quand vides.

Regroupement par paquet pour l'affichage (une ligne par paquet : nombre d'avis, pire gravité, version installée → cible), identifiants OSV listés en dessous. Jamais de code, jamais de chemin absolu, jamais de commande déclarée du projet (`test_cmd`, `install_cmd`), jamais de secret.

### 4.2 Rendus

Trois rendus depuis la même structure, tous en `lang` :

- **texte** (CLI et corps du toast ; le toast ne prend que le titre et deux lignes) ;
- **HTML** email simple (CSS inline, sans image, sans script), avec sa version texte en `multipart/alternative` ;
- **JSON** versionné `{"michel_digest": 1, …}` pour le webhook et pour la page.

### 4.3 Enregistrement et déclenchement

Table `digest_run` : `id`, `since`, `until`, `projects` (JSON noms + compteurs), `summary` (JSON compteurs globaux), `channels` (JSON `[{name, type, result, error}]`), `lang`, `created_at`. Un `digest_run` est écrit même si aucun canal n'est configuré (c'est la borne « depuis hier »).

```
michel digest                 # calcule, affiche le texte, n'envoie rien, n'enregistre pas
michel digest --send          # calcule, envoie sur les canaux activés, enregistre le run (audit digest.run + notify.send par canal)
michel digest --json
michel scan --all --digest    # enchaîne digest --send après le scan (c'est la ligne de la tâche planifiée)
```

Mon choix : le digest reste une commande séparée que `scan --all --digest` enchaîne, plutôt qu'un déclenchement implicite ; le planificateur (plan ultérieur) lancera exactement cette ligne.

## 5. Canaux (`internal/notify`)

### 5.1 Interface et configuration

```go
type Notifier interface { Name() string; Type() string; Send(ctx context.Context, d digest.Digest) error; Test(ctx context.Context) error }
```

Configuration dans `config.yaml`, section nouvelle `notify` (clés inconnues refusées comme ailleurs) :

```yaml
notify:
  page_url: http://127.0.0.1:7331/   # lien « Aujourd'hui » mis dans les digests, jamais avec le jeton
  channels:
    - name: mail-perso          # identifiant libre, unique
      type: email
      enabled: true
      host: smtp.example.org
      port: 587                 # 587 = STARTTLS, 465 = TLS implicite ; rien d'autre
      from: michel@example.org
      to: [moi@example.org]
      username: moi
      password_secret: smtp-perso   # nom dans le magasin de secrets, jamais la valeur
      projects: []              # vide = tous les projets ; sinon liste de noms
    - name: hook-n8n
      type: webhook
      url: https://hooks.example.org/michel
      format: generic           # generic | slack | discord
      secret: hook-n8n          # nom du secret HMAC ; vide = non signé (refusé si url n'est pas https)
    - name: bureau
      type: toast
```

`policy.Validate` vérifie : noms uniques, type connu, port email ∈ {587, 465}, `to` non vide, url `https://` (ou `http://127.0.0.1` pour les tests), et **qu'une règle `network.allow` existe** pour l'hôte avec le purpose `notify.email` ou `notify.webhook` quand le canal est activé : l'erreur dit exactement la règle à ajouter.

```
michel notify test <name>      # envoie un message d'essai (contenu fixe, sans donnée), événement notify.test
michel notify list
```

### 5.2 Email

`net/smtp` de la bibliothèque standard, `PLAIN` après STARTTLS (587) ou TLS implicite (465), jamais en clair. La connexion TCP passe par `egress.Gateway.DialContext(ctx, purpose, "tcp", host:port)` (nouvelle méthode : même allowlist, même journal `egress.attempt`, refus si l'audit ne peut pas écrire). Contenu : sujet « Michel · <date> · N nouveautés », texte + HTML.

### 5.3 Webhook

`POST` JSON via `Gateway.Client("notify.webhook")`. En-têtes `Content-Type: application/json`, `X-Michel-Timestamp` (RFC 3339), `X-Michel-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + corps)>`, `User-Agent: michel/<version>`. Formats : `generic` = le JSON du digest ; `slack` = `{"text": "<texte>"}` ; `discord` = `{"content": "<texte>"}` (texte tronqué à 1 900 caractères pour Discord). Réponse 2xx = envoyé ; sinon erreur avec le code, sans le corps de réponse dans l'audit.

### 5.4 Toast

Sous-processus à liste fermée, sans chaîne libre venue de l'utilisateur :

- **Windows** : `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand <script>` ; le script charge `Windows.UI.Notifications.ToastNotificationManager` (WinRT, disponible dans Windows PowerShell 5.1), construit le XML du toast à partir de texte **échappé XML** et l'affiche avec l'AUMID de Windows PowerShell (astuce standard, pas d'enregistrement d'application). Deux lignes de texte, sans bouton.
- **Linux** : `notify-send "Michel" "<texte>"` si présent ; sinon erreur « notify-send absent ».
- **macOS** : `osascript -e 'display notification …'` (meilleur effort, non bloquant).

Un `Runner` injectable rend le canal testable sans afficher quoi que ce soit ; un test manuel sur la machine de Kévin est noté dans le ledger.

### 5.5 Secrets (`internal/secret`)

Mon choix, à contester : le design v1 prévoit DPAPI / libsecret / Keychain. Le plan 3 livre `internal/secret` avec l'interface `Store{ Set(name, value), Get(name), Delete(name), List() }` et :

- **Windows** : fichier `<data-dir>/secrets/<name>` chiffré par **DPAPI** (`CryptProtectData`, appel `syscall` sans cgo, portée utilisateur courant) ;
- **Linux / macOS** : fichier `<data-dir>/secrets/<name>` en clair, mode `0600`, et un avertissement clair à `secret set` (« stocké en clair, protégé par les droits du fichier ; le coffre système arrive avec le plan IA ») ; libsecret / Keychain restent dus (ledger).

```
michel secret set <name>        # valeur lue sur stdin (pipe) ou saisie masquée ; jamais en argument
michel secret list
michel secret delete <name>
```

Les noms sont `[a-z0-9-]{1,64}`. Aucune valeur n'apparaît dans l'audit (`secret.set` : nom seulement), ni dans `--json`, ni dans les erreurs.

### 5.6 Audit et minimisation

Un envoi = un événement `notify.send` (canal, type, hôte, résultat, taille du corps, identifiant du digest). Le corps n'est jamais journalisé. Les canaux ne reçoivent que : projets, compteurs, paquets, versions, identifiants OSV, échéances, lien PWA.

## 6. Page « Aujourd'hui » (`internal/api` + `web/`)

### 6.1 Serveur

`michel serve [--listen 127.0.0.1:7331] [--open]` : HTTP sur loopback seulement (refus de toute autre adresse sans `--unsafe-listen`, hors périmètre v1). Jeton local généré au premier `serve`, stocké dans `<data-dir>/api-token` (DPAPI sur Windows, `0600` ailleurs : même magasin que § 5.5, nom réservé `api-token`), passé une fois dans l'URL affichée (`http://127.0.0.1:7331/?token=…`), puis gardé par la page en `localStorage` et envoyé en `Authorization: Bearer`. En-têtes : `Cache-Control: no-store` sur l'API, CSP stricte (`default-src 'self'`), pas de CORS. `serve` journalise `api.start` ; chaque décision prise par la page = `decision.set` avec `author: web`.

API JSON (préfixe `/api/v1`, clés snake_case, mêmes structures que `--json` des commandes) :

| méthode | chemin | rôle |
|---|---|---|
| GET | `/today?lang=fr` | le digest du jour calculé à la volée (sans l'enregistrer) |
| GET | `/projects` | liste (sans `test_cmd` / `install_cmd` / chemin absolu : nom, classification, niveau, compteurs) |
| GET | `/projects/{name}/findings?status=&severity=` | liste avec la phrase « what » |
| GET | `/findings/{id}` | finding + analyse + trois phrases + décision en vigueur |
| POST | `/findings/{id}/decision` | `{action, why, until}` ; mêmes règles que la CLI |
| GET | `/digests?last=7` | historique des `digest_run` |
| GET | `/meta` | version, langue, fraîcheur OSV, nom de l'assistant |

Jamais d'extrait de code, jamais de chemin absolu du projet dans les réponses (les chemins de points d'appel sont relatifs).

### 6.2 Front

`web/` : Vite 8, Vue 3 (dernière stable publiée sur npm au 2026-10-23 : 3.5.44 ; 3.6 dès qu'elle est stable), Vuetify 4 (4.3.0), **Options API** partout, TypeScript non requis (JS + JSDoc, mon choix : moins de friction avec les composants Vuetify), `vite-plugin-vuetify`. Pas de store externe : un objet `api.js` et des composants à `data()`.

Écrans :

1. **Aujourd'hui** : titre voix de Michel (« Michel a trouvé 3 nouveautés cette nuit, 1 mérite ton attention »), bandeau OSV périmée, cartes par projet (nouvelles / à revoir / échéances / disparues / jours sans critique / « 0 critique » à garder), liste groupée par paquet, chaque ligne dépliable en fiche (trois phrases, faits, décision).
2. **Fiche faille** : les trois phrases, faits (chemin, versions, points d'appel relatifs, tests, changelog, score et termes), glossaire des termes employés, bloc décision (Corriger / Reporter avec date / Ignorer avec justification obligatoire, bouton désactivé tant que vide) ; « ce que ça va faire » avant, « ce que ça a fait » après, l'identifiant de l'événement d'audit à portée de clic.
3. **Réglages** minimaux : langue (FR/EN, persistée en `localStorage`, défaut = `assistant.lang`), thème clair/sombre (Vuetify), jeton.

PWA : `manifest.webmanifest` + `sw.js` écrit à la main qui ne met en cache que la coquille (`index.html`, assets hashés) et **jamais** `/api/` ; installable, hors ligne = coquille + message « lance `michel serve` ».

Tous les textes de l'interface viennent de `fr.json` / `en.json` **du front** (`web/src/i18n/`), relus par le relecteur francophone ; les textes générés (trois phrases, digest) arrivent déjà traduits de l'API.

### 6.3 Embarquement

`web/embed.go` : `//go:embed all:dist` ; `web/dist/.gitkeep` committé pour que `go build` passe sans Node ; `make web` = `npm ci && npm run build` dans `web/` ; `make build` dépend de `web` quand `npm` est présent, sinon construit sans front et `michel serve` répond sur `/` une page texte « interface non construite : `make web` » (API intacte). Le binaire de release embarque le front.

Tests : Go (`httptest`) pour chaque route, l'auth, la CSP, l'absence de chemins absolus et de commandes dans les réponses ; Vitest sur les fonctions pures du front (regroupement par paquet, titre de Michel, formatage des dates) ; vérification manuelle dans Chrome notée au ledger.

## 7. Catalogue i18n (`internal/i18n`)

- `fr.json` et `en.json` embarqués, mêmes clés, clés stables en `snake.dotted` (`cli.scan.summary.none`, `digest.title`, `explain.label.what`…). Test : chaque clé existe dans les deux langues, aucune clé vide, aucune clé référencée dans le code Go (`i18n.T(…, "…")` littéral) absente du catalogue, aucune clé du catalogue jamais référencée (hors gabarits).
- API Go : `type Lang` (reprend `explain.Lang`), `T(lang, key, args ...any) string` (`fmt.Sprintf`), `N(lang, key, n int, args ...any)` (pluriel : entrées `key.one` / `key.other`, règle FR 0 et 1 = singulier), `Resolve(flag, policyLang, systemLocale) Lang` (ordre : `--lang`, `assistant.lang` si `en`/`fr`, langue du système, `en`).
- **`assistant.lang` prend la valeur `auto` par défaut** (mon choix, pour honorer « défaut = langue du système » du design v1) : `Validate` accepte `auto | en | fr` ; une installation sans fichier de configuration sur un Windows en français passe donc en français. Qui veut l'anglais écrit `assistant.lang: en`.
- **Ce qui est stocké reste en anglais ou en code** : `scan.error`, `audit_event.evidence`, `analysis.notes`, `digest_run.channels[].error` sont écrits en anglais (texte de référence) ; les statuts (`interrupted`…) et raisons (`due_reached`…) sont des codes que l'affichage traduit. La base et la chaîne d'audit ne mélangent jamais les langues.
- Les gabarits `what/impact/cost` déménagent dans `internal/i18n/templates/<lang>/` et `explain` les charge via `i18n` ; `labels.go` et `glossary.go` deviennent des clés `explain.label.*` et `glossary.*`. **Les phrases épinglées par les tests du plan 2 ne changent pas** (test de non-régression : rendu identique avant/après sur les fixtures).
- **Messages CLI** : toute phrase imprimée par une commande (sorties, synthèses, erreurs d'usage, messages « quoi / pourquoi / quoi faire ») passe par le catalogue ; l'anglais reste le texte de référence, le français est écrit à la main, tutoiement. L'aide Cobra (`Short`, `Long`, descriptions de flags) **reste en anglais** dans ce plan (mon choix : Cobra construit l'arbre avant de lire `--lang`, le pré-parsing des arguments pour ça est une dette que je ne prends pas ici ; noté au ledger).
- **Garde de tutoiement** : test qui refuse, dans `fr.json`, les gabarits FR, le `fr.json` du front et les `*.fr.md` de `docs/` (hors citations), les tokens `vous`, `votre`, `vos`, `veuillez`.
- **Relecteur francophone non spécialiste** : un subagent relit chaque fichier FR produit ou modifié (catalogue, gabarits, front, docs) avec une consigne unique : « si une phrase demande une explication orale, propose une réécriture » ; ses retours sont appliqués avant la revue de code de la tâche.
- Langue du système : `LANG` / `LC_ALL` sur Linux et macOS, `GetUserDefaultUILanguage` sur Windows (mon choix : `golang.org/x/sys/windows` est déjà dans le graphe) ; `fr*` → `fr`, sinon `en`.

## 8. Persistance, balayage, migration `0004`

Une seule migration `0004_decisions_digest.sql` :

- `project` : `+ exclude TEXT NOT NULL DEFAULT '[]'` (liste de dossiers à ignorer, utilisée par `scan` et `analyze` à la place du `TODO(plan 3)` ; `michel project set --exclude a --exclude b`, `--exclude ''` vide) ;
- `finding` : `+ status_changed_at TEXT NOT NULL DEFAULT ''` (rempli au premier scan suivant pour les lignes existantes : `last_seen_at`) ;
- `analysis` : `+ notes TEXT '[]'`, `+ calls_unreadable INTEGER 0`, `+ calls_unreadable_paths TEXT '[]'`, `+ calls_test_files TEXT '[]'`, `+ calls_test_file_count INTEGER 0`, `+ calls_test_hit_count INTEGER 0`, `+ calls_source_files TEXT '[]'`, `+ coverage_skipped TEXT '[]'`, `+ coverage_unreadable INTEGER 0` : tout champ de `Analysis` qui sortait en `--json` sans colonne est désormais relu à l'identique (test aller-retour champ par champ) ;
- `scan` : rien de nouveau ; statut `interrupted` ajouté aux valeurs ;
- tables `decision` (§ 3.1) et `digest_run` (§ 4.3), index `decision(finding_id, created_at)`, `decision(project_id)`, `digest_run(created_at)`.

Balayage : `scan.SweepStale(ctx, db, now, maxAge)` passe en `interrupted` (`scan.error` = `Michel stopped before this scan finished`, traduit à l'affichage depuis le statut) toute ligne `running` démarrée depuis plus de **1 h** (mon choix : un scan réel dure quelques minutes ; 1 h laisse la place à deux processus concurrents) ; appelé au début de `scan`, `digest`, `serve` ; événement `scan.sweep` avec le nombre balayé. `scan.Run` ajoute `defer/recover` : une panique marque le scan `failed` avec la cause et remonte ensuite.

## 9. Souveraineté et sécurité, ce qui est enforcé

- Egress : deux purposes nouveaux (`notify.email`, `notify.webhook`), inventaire `docs/security/network-egress.md` mis à jour ; `DialContext` dans `egress` et test de frontière étendu (aucun `net.Dial` ailleurs) ; test : envoi vers un hôte hors allowlist refusé + audité, serveur SMTP et webhook de test sur loopback avec règle explicite.
- Secrets : jamais en argument, jamais dans l'audit, jamais dans `--json`, jamais dans une erreur ; test qui greppe les sorties.
- Page : loopback seul, jeton, CSP, `no-store`, pas de CORS, pas de code source du projet dans les réponses.
- Lecture seule des projets scannés : aucune écriture sous `project.path` (test existant étendu : le dossier fixture est comparé avant/après `decide`, `digest`, `serve`).
- Hygiène : test existant inchangé + ajout d'une empreinte pour le dossier parent des projets sur ce poste ; ledger relu à la main, projet de référence « demo » partout.

## 10. Ordre de réalisation (tâches du plan)

1. Migration `0004`, persistance `Notes` / `Unreadable`, `exclude` projet, `status_changed_at`, balayage + `recover`.
2. `internal/i18n` : catalogue, `Resolve`, migration de `labels.go`, glossaire et gabarits sans changer les phrases épinglées ; garde de tutoiement.
3. Messages CLI vers le catalogue (deux lots : scan/analyze/findings/finding, puis project/db/audit/racine) ; relecture FR.
4. Décisions : modèle, repo, règles `applyScan`, `michel decide` / `decisions`, API de décision côté Go.
5. Digest : calcul, trois rendus, `digest_run`, `michel digest`, `scan --all --digest` ; relecture FR.
6. `internal/secret` + `michel secret` ; `egress.DialContext`.
7. `internal/notify` : email, webhook, toast, section `notify` de la politique, `michel notify test|list`, envoi depuis `digest --send`.
8. `internal/api` + `michel serve` : routes, jeton, en-têtes, tests `httptest`.
9. `web/` : Vite + Vue + Vuetify, page Aujourd'hui, fiche, décision, réglages, PWA, embed, Vitest ; relecture FR du `fr.json` front.
10. Docs bilingues (`offline-installation`, `network-egress`, nouveau `docs/operations/daily-digest.md` + `.fr.md`, README), run réel sur le projet de référence (agrégats seuls), ledger, hygiène, `deferred-and-rulings.md` du plan 3.

## 11. Laissé au builder

- Découpage interne de `internal/digest` (calcul / rendu), noms des gabarits de digest (`text/template` ou code Go, au choix, tant que FR et EN sont écrits à la main).
- Détail de l'écran de décision dans la page (dialogue ou panneau), icônes, palette ; thème sombre souhaité.
- Forme exacte du script PowerShell du toast et de la détection de `notify-send`.
- Encodage de l'`HMAC` (hex), nom des en-têtes : ci-dessus est une proposition, à garder stable une fois documentée.
- Choix de la bibliothèque pour `GetUserDefaultUILanguage` (x/sys) ou lecture de `LANG` seulement sur Windows si plus simple.

## 12. Choix à contester (résumé)

1. Statut `decided` + instantané gravité/versions ; changement ⇒ `pending` + décision supersédée (§ 3.2).
2. `defer` sans date = 30 jours (§ 3.3).
3. Décision par paquet (`--project --package`) (§ 3.3).
4. Digest en commande séparée, `scan --all --digest` l'enchaîne (§ 4.3).
5. Secrets : DPAPI sur Windows, fichier `0600` ailleurs, coffre système reporté (§ 5.5).
6. Toast Windows via Windows PowerShell + WinRT, AUMID de PowerShell (§ 5.4).
7. Jeton d'API dans l'URL une fois puis `localStorage` (§ 6.1).
8. Front en JS + JSDoc, pas de TypeScript ; Vitest limité aux fonctions pures (§ 6.2).
9. Aide Cobra non traduite dans ce plan (§ 7).
10. Balayage des scans `running` après 1 h (§ 8).

Après relecture builder (2026-10-23), quatre arbitrages de plus :

11. Le calcul du digest est pur ; les reports échus ne sont supersédés que par le scan et par `digest --send` (§ 3.2).
12. Textes stockés en anglais ou en code, traduction à l'affichage seulement (§ 7).
13. `assistant.lang: auto` par défaut, langue du système consultée pour de vrai (§ 7).
14. Fenêtre du digest = depuis le dernier run enregistré, sans plafond, quel que soit le sort des canaux (§ 4.1).
