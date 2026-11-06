# Michel : lot B de l'audit (veille automatique, politique, journal d'audit)

Date : 2026-11-05. Origine : audit en lecture seule du 2026-11-05, points 03, 04, 05, 07, 08, 09. Kévin délègue les choix : ils sont notés ici comme ceux du constructeur.

## 1. Veille automatique dans `michel serve` (points 03 et 04)

### Pourquoi

Aujourd'hui `serve` envoie seul le résumé du matin, mais ne contrôle pas seul les projets ni ne lit les sources : il faut une tâche planifiée faite à la main (`docs/operations/daily-digest.md`). Un novice ne la fera pas, et le résumé décrit alors un état vieux. En plus, deux processus peuvent contrôler le même projet en même temps (`internal/scan/scan.go:372`, `:571`).

### Ce qui change

- Une boucle de veille dans `serve`, sur le modèle de celle du résumé (`internal/cli/digest_schedule.go` : tic d'une minute, « dû » calculé depuis la base, rien de perdu au redémarrage).
- Réglage `watch` dans la politique :
  - `watch.enabled` (vrai par défaut) ;
  - `watch.scan_at` (HH:MM, heure locale ; vide par défaut = 60 minutes avant `notify.digest_at`, donc 07:00 avec les réglages par défaut).
- Chaque jour, après `scan_at` : d'abord la lecture des sources activées, comme `michel source update` (consentement et règles réseau inchangés : une source sans consentement ou sans règle ne lit rien et le dit), puis le contrôle de chaque projet actif dont la veille est activée, l'un après l'autre. La lecture des sources est notée une fois par jour dans la base (`watch_day`), quel que soit le `serve` qui la fait. Si cette note ne peut pas être écrite, le tic suivant réessaie. Une lecture arrêtée avec `serve` ou en échec libère la journée : le prochain `serve` la refait (le même processus ne la refait pas, pour ne jamais boucler).
- Un projet est « dû » s'il n'a aucun contrôle commencé depuis l'heure de veille du jour (un contrôle lancé à la main après cette heure compte, un contrôle en échec aussi ; un contrôle arrêté avec `serve` (`interrupted`) ou resté « en cours » après un plantage (`running`) ne compte pas : après un redémarrage, le projet est contrôlé de nouveau).
- Par projet : `michel project set <nom> --auto-scan=false` (colonne `auto_scan`, vraie par défaut, migration). Un projet supprimé ou inactif n'est jamais contrôlé.
- Échec (dossier introuvable, illisible…) : le contrôle est enregistré en échec comme aujourd'hui ; Michel réessaie au plus 2 fois dans la journée, à 30 minutes d'écart (état en mémoire, comme les reprises du résumé) ; après, il attend le lendemain. Au redémarrage de `serve`, ce compte repart de zéro : un contrôle enregistré en échec compte comme celui du jour, donc le projet attend le lendemain ; un échec qui n'a rien pu enregistrer (base absente) est retenté une fois à chaque redémarrage, jamais en boucle. Le résumé et la page disent déjà les contrôles en échec.
- Exclusion entre processus (point 04) : un contrôle ne commence que s'il n'y a pas de contrôle `running` du même projet commencé depuis moins de `StaleScanAfter`, vérifié et inséré dans une même transaction immédiate ; sinon `ErrScanRunning` (« un contrôle de ce projet est déjà en cours »). La mise à jour de fin porte `AND status = 'running'` : un contrôle déjà marqué interrompu par un autre processus n'est pas réécrit en réussi.
- Horloge : tout est calculé en heure locale à partir des dates en base ; une horloge qui recule ne relance pas un contrôle déjà fait ce jour-là.
- Annulation : l'arrêt de `serve` annule le contrôle en cours (le contrôle annulable existe depuis le lot A).
- Consultation :
  - `michel watch status` : heure de veille, prochain passage, et pour chaque projet le dernier contrôle et le prochain ;
  - `GET /api/v1/projects` gagne `auto_scan` et `next_scan_at` ;
  - la carte d'un projet dit « Prochain contrôle : demain à 07:00 » (ou « veille coupée pour ce projet »).

### Non-objectifs

- Pas de fréquence par projet autre que quotidienne (on verra si quelqu'un le demande).
- Pas de nouveau démon : tout reste dans `serve`. Sans `serve`, la tâche planifiée documentée continue de marcher.
- Pas de téléchargement des bases OSV si `db.auto_update` est faux : comme aujourd'hui.

## 2. La politique sans accès concurrent (point 05)

`Reload` écrit `deps.Policy` sans verrou (`internal/cli/source.go:47`) pendant que la boucle du résumé et les alertes la lisent. La politique passe derrière un `atomic.Pointer[policy.Policy]` et un accesseur ; tous les lecteurs passent par lui. Aucun changement de comportement.

## 3. Journal d'audit (points 07, 08, 09)

- Point 08 : `Record` ne compte plus toute la table à chaque événement (`internal/audit/audit.go:103`) : le nombre d'événements est gardé dans l'ancre et incrémenté dans la transaction. Index `(action, target)`.
- Point 09 : une colonne `seq INTEGER NOT NULL UNIQUE`, remplie depuis l'ordre actuel par une migration, attribuée par `Record`, remplace `rowid` dans tous les tris (`audit/audit.go:86`, `audit/verify.go:44`, `api/targets.go:780`, `cli/audit.go:81`). `INSERT OR REPLACE` (`serverlog/unseen.go:240`) devient `ON CONFLICT … DO UPDATE`. Un test d'hygiène refuse `rowid`, `AUTOINCREMENT`, `INSERT OR REPLACE` et `datetime(` dans le SQL des migrations et du code, sauf les migrations déjà livrées qui les contiennent (liste fermée).
- Point 07 : `integrity_protection: required` est appliqué : chaque événement porte un HMAC-SHA256 de son empreinte, avec une clé gardée dans le coffre de secrets (créée au premier lancement). `michel audit verify` vérifie la chaîne et les HMAC ; une ancre absente alors qu'il y a des événements est un échec. Les événements antérieurs sans HMAC sont signalés comme « avant la protection », pas comme cassés. `integrity_protection: none` garde l'ancien comportement.

## Contraintes

- Règles constantes : pas de nom de projet privé ; SQL portable PostgreSQL ; textes en français relus, tutoiement ; jamais d'écriture dans les projets ; tout réseau par `internal/egress`.
- Une base existante doit s'ouvrir et continuer de marcher après les migrations ; test sur une base créée par l'ancienne version.
- Migrations à partir de `0024` (la `0023` est prise par la porte des tests).

## Preuves attendues

Tests : redémarrage de `serve` après l'heure (un seul passage), projet inaccessible (échec, 2 reprises max), deux processus sur un même projet (`ErrScanRunning`), contrôle interrompu non réécrit en réussi, projet désactivé ou supprimé jamais contrôlé, horloge reculée, absence de consentement réseau (la lecture des sources le dit, les contrôles hors ligne ont lieu), changement de `scan_at` pris en compte au tic suivant, annulation à l'arrêt ; politique sous accès concurrent ; `Record` sans `COUNT(*)` ; ordre par `seq` ; HMAC vérifié, ancre supprimée détectée, événements anciens acceptés.
