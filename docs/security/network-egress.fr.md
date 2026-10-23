# Inventaire des sorties réseau (plans 1 à 3)

🇬🇧 English version : [network-egress.md](network-egress.md)

Tout le trafic web sortant (HTTP) passe par la passerelle de sortie réseau (egress) (`internal/egress`), qui applique la politique `sovereignty.network` : refus par défaut, chaque requête vérifiée contre les règles `network.allow` (hôte et finalité), chaque tentative écrite dans le journal d'audit (`egress.attempt`).

## Destinations et finalités (purposes)

| Purpose | Destination | Quand |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (uniquement) | `michel db update` explicite, et seulement si une règle d'autorisation existe. |
| `osv.scan` | aucune | Jamais utilisé en pratique. Il existe pour que toute requête inattendue de la bibliothèque de scan (osv-scalibr) pendant un scan soit refusée et journalisée. |
| `notify.email` | le serveur SMTP d'un canal e-mail (`notify.channels[].host`) | `michel digest --send`, `michel scan --all --digest`, `michel notify test`. TCP via `Gateway.DialContext`, uniquement en STARTTLS (587) ou TLS implicite (465). La politique est refusée au chargement quand un canal activé n'a pas de règle. |
| `notify.webhook` | l'hôte de l'`url` d'un canal webhook | Mêmes commandes. POST HTTPS (http non chiffré seulement vers cet ordinateur), signé avec une clé secrète (HMAC-SHA256) ; les redirections ne sont pas suivies. |

Il n'y a aucune autre destination dans les plans 1 à 3 : pas de télémétrie, pas de remontée d'erreurs, pas de vérification de mise à jour, pas de fournisseur d'IA.

## Local seulement, sans réseau

| Quoi | Pourquoi ce n'est pas une sortie réseau |
|---|---|
| Notification sur le bureau (canal `toast`) | Un petit programme lancé sur la machine avec une ligne de commande fixe (Windows PowerShell 5.1 pris dans `%SystemRoot%`, `notify-send`, `/usr/bin/osascript`) ; le texte est transmis comme une donnée, sur l'entrée standard ou après `--`. Aucune connexion, aucune règle nécessaire. |
| `michel serve` (page « Aujourd'hui » et `/api/v1`) | N'écoute que sur une adresse locale (127.0.0.1, [::1] ou localhost ; toute autre adresse `--listen` est refusée). Il accepte les connexions venant de cet ordinateur et n'ouvre aucune connexion vers l'extérieur. L'API exige le jeton d'accès local. |
| Décisions, digest sans `--send`, secrets | Lisent et écrivent seulement le dossier de données. |

## Limites

- La passerelle revérifie chaque redirection contre la politique. Une redirection vers un hôte non autorisé est refusée.
- L'adresse de cet ordinateur lui-même (« loopback » : `127.0.0.1`, `::1`, `localhost`) est autorisée sans règle pour les finalités (« purposes ») dont le nom commence par `local.`. Aucune finalité de ce type n'est encore utilisée ; un webhook sur cette machine a quand même besoin de sa règle `notify.webhook`.
- `Gateway.DialContext` (connexions directes, utilisées par le canal e-mail) n'ouvre que du TCP (`tcp`, `tcp4`, `tcp6`) ; tout autre type de réseau (udp, unix, ip) est refusé. Il applique les mêmes règles d'autorisation et écrit le même événement `egress.attempt` que le HTTP, et refuse la connexion quand le journal d'audit ne peut pas être écrit.
- Un téléchargement de base est plafonné à 2 Gio.
- Un zip de base est rejeté au-delà de 2 000 000 d'entrées ou de 8 Gio décompressés.
- En cas d'échec de téléchargement ou de validation, l'ancienne base est conservée.

## Testé ou seulement déclaré

Testé (tests automatisés) :

- Un scan n'émet aucune requête réseau (test de scan sans sortie).
- Une redirection refusée est bloquée et auditée.
- `DialContext` refuse un hôte sans règle, un réseau autre que TCP, et bloque tout quand l'audit ne peut pas être écrit.
- `michel serve` refuse une adresse `--listen` qui n'est pas locale ; l'API refuse la requête (code 401) quand le jeton d'accès est absent.
- Les plafonds de téléchargement, de nombre d'entrées et de taille décompressée.

Seulement déclaré (aucun test ne le garantit aujourd'hui) :

- Une dépendance qui utiliserait directement `http.DefaultClient` ou `http.DefaultTransport` ne serait pas vue par la passerelle. `internal/egress/boundary_test.go` (lancé par `go test ./...` en CI, et par `make lint`) analyse le code de Michel hors de `internal/egress` et échoue sur `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, les littéraux `http.Client{}` et `http.Transport{}`, `net.Dial`, `net.DialTimeout`, `net.DialTCP/DialUDP/DialIP/DialUnix`, `net.Dialer{}`, `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer{}` et `smtp.Dial`, mais il ne lit pas les dépendances. Un test installant un transport par défaut qui refuse tout est prévu.

## Pas encore

- Proxy local pour les sous-processus (nécessaire quand les correctifs s'exécuteront dans un environnement isolé).
- Points de contrôle d'audit signés (le journal d'audit est chaîné par hachage et révèle toute altération, mais n'est pas signé).
- Trousseau du système pour les secrets sous Linux et macOS (libsecret, Keychain) : les secrets sont des fichiers chiffrés par DPAPI sous Windows, des fichiers en clair lisibles par ton seul compte (0600) ailleurs.
