# Inventaire des sorties réseau (plan 1)

🇬🇧 English version : [network-egress.md](network-egress.md)

Tout le HTTP sortant passe par la passerelle d'egress (`internal/egress`), qui applique la politique `sovereignty.network` : refus par défaut, chaque requête vérifiée contre les règles `network.allow` (hôte et finalité), chaque tentative écrite dans le journal d'audit (`egress.attempt`).

## Destinations et finalités (purposes)

| Purpose | Destination | Quand |
|---|---|---|
| `osv.db` | `osv-vulnerabilities.storage.googleapis.com` (uniquement) | `michel db update` explicite, et seulement si une règle d'autorisation existe. |
| `osv.scan` | aucune | Jamais utilisé en pratique. Il existe pour que toute requête inattendue de la bibliothèque de scan (osv-scalibr) pendant un scan soit refusée et journalisée. |
| `notify.email` | le serveur SMTP d'un canal e-mail (`notify.channels[].host`) | `michel digest --send`, `michel scan --all --digest`, `michel notify test`. TCP via `Gateway.DialContext`, uniquement en STARTTLS (587) ou TLS implicite (465). La politique est refusée au chargement quand un canal activé n'a pas de règle. |
| `notify.webhook` | l'hôte de l'`url` d'un canal webhook | Mêmes commandes. POST HTTPS (http simple seulement en loopback), signé en HMAC-SHA256 ; les redirections ne sont pas suivies. |

Il n'y a aucune autre destination dans le plan 1 : pas de télémétrie, pas de remontée d'erreurs, pas de vérification de mise à jour, pas de fournisseur d'IA.

## Limites

- La passerelle revérifie chaque redirection contre la politique. Une redirection vers un hôte non autorisé est refusée.
- Le loopback (`127.0.0.1`, `::1`, `localhost`) est autorisé sans règle pour les purposes préfixés `local.`. Aucun purpose de ce type n'est utilisé dans le plan 1.
- Un téléchargement de base est plafonné à 2 Gio.
- Un zip de base est rejeté au-delà de 2 000 000 d'entrées ou de 8 Gio décompressés.
- En cas d'échec de téléchargement ou de validation, l'ancienne base est conservée.

## Testé ou seulement déclaré

Testé (tests automatisés) :

- Un scan n'émet aucune requête réseau (test de scan sans sortie).
- Une redirection refusée est bloquée et auditée.
- Les plafonds de téléchargement, de nombre d'entrées et de taille décompressée.

Seulement déclaré (aucun test ne le garantit aujourd'hui) :

- Une dépendance qui utiliserait directement `http.DefaultClient` ou `http.DefaultTransport` ne serait pas vue par la passerelle. `internal/egress/boundary_test.go` (lancé par `go test ./...` en CI, et par `make lint`) analyse le code de Michel hors de `internal/egress` et échoue sur `http.DefaultClient`, `http.DefaultTransport`, `http.Get/Post/Head/PostForm`, les littéraux `http.Client{}` et `http.Transport{}`, `net.Dial`, `net.DialTimeout` et `net.Dialer{}`, mais il ne lit pas les dépendances. Un test installant un transport par défaut qui refuse tout est prévu.

## Hors plan 1

- Proxy local pour les sous-processus (nécessaire quand les correctifs s'exécuteront dans un environnement isolé).
- Points de contrôle d'audit signés (le journal d'audit est chaîné par hachage et révèle toute altération, mais n'est pas signé).
- Masquage des secrets.
