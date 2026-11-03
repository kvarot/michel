# Décisions, digest quotidien et page « Aujourd'hui »

🇬🇧 English version : [daily-digest.md](daily-digest.md)

Cette étape de Michel transforme la liste des failles en routine du matin : tu décides une fois quoi faire de chaque faille, Michel t'envoie chaque matin ce qui a changé depuis la dernière fois, et une page sur ton ordinateur montre la même chose. Tout ce qui suit tourne sur ta machine ; seuls les canaux e-mail et webhook que tu configures envoient quelque chose sur le réseau.

## Décisions

Une décision dit ce que tu comptes faire d'une faille :

| Action | Sens |
|---|---|
| `fix` | Tu vas mettre le paquet à jour. |
| `defer` | Plus tard. Michel te repose la question à la date prévue : dans 30 jours par défaut, ou `--for 45d`, ou `--until 2026-12-01`. |
| `ignore` | Elle ne te concerne pas. Une justification (`--why`) est obligatoire. |

```
michel decide <id-ou-préfixe> fix
michel decide <id-ou-préfixe> defer --for 45d --why "j'attends la prochaine version"
michel decide <id-ou-préfixe> ignore --why "la fonction vulnérable n'est jamais appelée"
michel decide --project demo --package acme/lib defer      # toutes les failles de ce paquet dans ce projet
michel decisions --project demo [--status fix|defer|ignore|superseded|all] [--json]
michel findings --project demo --status decided
```

- Une faille décidée sort de la liste des failles à traiter (statut `decided`). **Michel ne te repose pas la question** tant que rien ne change. Il te la repose (la décision passe en `superseded` et apparaît dans le digest parmi les décisions à revoir) seulement quand :
  - la gravité annoncée par l'avis de sécurité change ;
  - les versions qui corrigent la faille changent ;
  - la date d'un report est atteinte ;
  - une faille qui avait disparu revient différente.
- `--project` avec `--package` décide pour toutes les failles de ce paquet dans ce projet qui attendent une décision. Ajoute `--force` pour remplacer aussi les décisions déjà prises. Un paquet a souvent plusieurs avis de sécurité : c'est le moyen rapide de trier un premier scan qui trouve des centaines de failles. Michel l'écrit en une ligne de résumé (combien de failles, la décision, le premier et le dernier événement d'audit) ; `--verbose` affiche plutôt une ligne par faille.
- `--why` est facultatif pour `fix` et `defer`, obligatoire pour `ignore`, 1 000 caractères au plus. Il est gardé dans le journal d'audit : n'y mets jamais de code ni de mot de passe.
- Une faille qui n'est plus vue (statut `gone`) ne peut pas être décidée : si elle revient, Michel ne te redemande que si quelque chose a changé.
- Chaque décision est notée dans le journal d'audit (événement `decision.set`). Une décision ne touche jamais au dossier du projet.

## Le digest

Le digest est le résumé du matin.

```
michel digest                       # affiche ce qui a changé ; n'envoie rien, n'enregistre rien
michel digest --lang fr             # en français
michel digest --html > digest.html  # la version HTML de l'e-mail
michel digest --json                # JSON versionné {"michel_digest": 1, ...}
michel digest --send                # envoie sur chaque canal activé, puis l'enregistre
michel scan --all --digest          # scanne tous les projets actifs, puis fait digest --send
michel scan --all --update --digest # lit d'abord les sources activées (comme michel source update)
```

**Période couverte.** Un digest couvre tout ce qui s'est passé depuis la fin du dernier digest envoyé avec `--send`, que ses canaux aient réussi ou non (`serve` et `scan --digest` font exception : voir plus bas). La première fois, il couvre les 24 dernières heures. La période n'est pas plafonnée : après trois semaines d'absence, le digest dit « Tout ce qui a changé depuis le <date> » et liste tout. `--since AAAA-MM-JJ` impose le début, par exemple pour renvoyer après l'échec d'un canal.

**Failles que des pirates utilisent déjà** passe en premier, avant les projets, dès que la source `enrich.kev` est activée : toutes les failles de la liste KEV de la CISA (l'agence américaine de cybersécurité), ainsi que les paquets malveillants, tant qu'elles sont ouvertes ou que tu as décidé de les corriger, quelles que soient leur date et leur gravité. Celles que tu as reportées ou ignorées avec une raison ne sont comptées que sur une ligne. **À lire** vient après les projets : au plus 10 avis d'éditeurs non lus, publiés pendant la période et qui parlent des technologies que tu utilises. Les deux sont expliqués dans [sources.fr.md](../sources.fr.md).

**Rubriques**, pour chaque projet actif :

- une ligne de compteurs : failles ouvertes par gravité, tes décisions par action, nombre de jours sans nouvelle faille critique (quand il n'y en a aucune d'ouverte, le digest affiche « 0 faille critique ouverte » comme un bon état à conserver) ;
- **Nouvelles failles** : vues pour la première fois pendant la période ;
- **Plus vues au dernier scan** : une faille qui disparaît du fichier qui fixe les versions des dépendances (lockfile) n'est pas pour autant prouvée corrigée ;
- **Décisions à revoir** : les décisions que Michel a mises de côté, avec la raison (gravité changée, version corrigée changée, date atteinte, faille revenue différente) ;
- **Reports qui arrivent à échéance** : les reports dont la date tombe dans les 3 prochains jours, marqués « date dépassée » une fois passée.

Les failles sont regroupées par paquet : une ligne par paquet avec la gravité la plus haute, la version installée, la version à viser et les identifiants des avis. En haut du digest, un bandeau t'avertit quand la base de vulnérabilités hors ligne date de plus de 7 jours, ou quand le dernier scan d'un projet a échoué ou s'est arrêté avant la fin. Après `michel source update` (ou `scan --update`), une ligne **catalogue** dit combien de sources sont à jour et nomme celles que Michel n'a pas pu lire, celles qui attendent ton accord et celles qui ont une nouvelle version (« Catalogue : 6 sources à jour, feed.nginx injoignable. ») ; elle ne dit rien quand tout est à jour. Quand il n'y a rien de nouveau et aucune échéance, Michel le dit en une phrase. La dernière ligne donne le lien vers la page « Aujourd'hui » (`notify.page_url`, jamais avec le jeton d'accès).

**`--send`** commence par mettre fin aux reports dont la date est atteinte (ils deviennent des décisions à revoir), envoie le digest sur chaque canal activé, puis enregistre l'envoi (événement d'audit `digest.run`, plus un `notify.send` par canal). Un canal en échec n'empêche pas les autres ; la commande se termine alors avec le code 1. Avec `michel digest --send`, l'envoi est enregistré même sans aucun canal configuré : c'est le repère « depuis la dernière fois ». `scan --digest` et `serve` ne l'enregistrent que si un canal a reçu le digest (voir plus bas).

**Envoi par `michel serve`.** Tant que `michel serve` tourne, il envoie le digest une fois par jour, à l'heure `notify.digest_at` (heure locale, `08:00` par défaut ; `off` l'arrête). Si l'ordinateur était éteint à cette heure, le digest part dès que `serve` démarre. La tâche planifiée ci-dessus peut rester : les deux partagent le même enregistrement du dernier digest, et un digest déjà envoyé dans la même journée locale n'est pas renvoyé, quel que soit celui des deux qui l'a envoyé (`michel scan --all --digest` le dit alors et n'envoie rien). `michel digest --send`, lancé à la main, envoie toujours. `serve` et `scan --digest` ne comptent un digest comme envoyé que si au moins un canal l'a reçu. Sans canal, ou si tous les canaux échouent, rien n'est enregistré : le prochain digest repart de la même date et contient les mêmes éléments, rien n'est perdu (`serve` réessaie 15 minutes plus tard). Sans aucun canal configuré, activer une source de journaux reste possible, mais personne ne peut être prévenu : Michel le dit.

**Journaux des serveurs.** Quand les journaux d'un serveur sont lus (voir [servers.fr.md](../servers.fr.md)), le digest a une rubrique **Journaux des serveurs**, un bloc par serveur : les erreurs nouvelles ou revenues pendant la période, et celles qui arrivent bien plus souvent qu'avant (5 par serveur au plus, les plus graves d'abord), avec le nombre de fois où chacune a été lue. Une erreur déjà annoncée par une alerte reste listée. Un trou dans la lecture est indiqué avec ses dates, « du ... au ... » : un serveur qui n'est pas de production n'envoie aucune alerte quand Michel ne peut plus le lire, cette ligne est donc le moyen de l'apprendre. Le texte des erreurs n'y figure que si les réglages de journaux du serveur l'envoient dans les alertes (texte nettoyé, jamais une ligne de journal, une adresse, un email ni une URL avec paramètres) ; par défaut il n'y en a pas. Une fois par semaine, la rubrique rappelle aussi les réglages de journaux d'un serveur qui ne sont pas ceux qui sont recommandés. Un canal limité à certains projets n'en reçoit rien.

Un digest ne contient jamais de code, de chemin complet de fichier, de commande de test ou d'installation du projet (`test_cmd`, `install_cmd`), ni de secret : seulement des noms de projets, des compteurs, des paquets, des versions, des identifiants d'avis, des dates d'échéance et le lien de la page.

## Canaux

Les canaux se déclarent dans la section `notify` de `config.yaml` (voir `config.example.yaml`). Il n'y en a aucun par défaut.

```
michel notify list           # les canaux, et s'ils sont activés
michel notify test <nom>     # un message d'essai fixe, sans aucune donnée sur tes projets (audit notify.test)
```

### Notification sur le bureau (`toast`)

```yaml
notify:
  channels:
    - name: bureau
      type: toast
```

Une notification sur cet ordinateur : un titre et deux lignes, sans bouton. C'est un petit programme lancé sur ta machine, pas un accès réseau : Windows PowerShell 5.1 pris dans `%SystemRoot%` sous Windows, `notify-send` sous Linux (s'il est installé), `osascript` sous macOS (sans garantie). Le texte est transmis comme une donnée, jamais comme une commande. Sous Windows, le mode **Ne pas déranger** cache la bannière : la notification arrive quand même dans le centre de notifications.

### E-mail (SMTP)

```yaml
sovereignty:
  network:
    allow:
      - {host: smtp.example.org, purpose: notify.email}
notify:
  channels:
    - name: mail
      type: email
      host: smtp.example.org
      port: 587                    # 587 = STARTTLS, 465 = TLS implicite ; rien d'autre
      from: michel@example.org
      to: [moi@example.org]
      username: moi
      password_secret: smtp-mail   # un nom dans le coffre à secrets, jamais le mot de passe
      projects: []                 # vide = tous les projets
```

Michel n'envoie jamais d'e-mail en clair : le port 587 exige STARTTLS (la connexion devient chiffrée avant tout envoi), le port 465 est chiffré dès le départ (TLS 1.2 minimum). L'e-mail contient une partie texte et une partie HTML (sans image ni script). La connexion passe par la « passerelle réseau » de Michel, le seul point de sortie vers Internet, qui vérifie chaque règle (usage déclaré, ou finalité : `notify.email`).

### Webhook signé

Un webhook est une adresse web qui reçoit le digest, par exemple un outil d'automatisation ou une messagerie d'équipe.

```yaml
sovereignty:
  network:
    allow:
      - {host: hooks.example.org, purpose: notify.webhook}
notify:
  channels:
    - name: hook
      type: webhook
      url: https://hooks.example.org/michel
      format: generic              # generic | slack | discord
      secret: hook-key             # nom de la clé de signature (HMAC)
```

Michel envoie les données au format JSON (requête POST). `generic` envoie le JSON du digest (`{"michel_digest": 1, ...}`), `slack` envoie `{"text": "..."}`, `discord` envoie `{"content": "..."}` coupé à 1 900 caractères. L'URL doit commencer par `https://` (`http://` sans chiffrement n'est accepté que vers cette machine : 127.0.0.1, ::1, localhost). Les redirections ne sont pas suivies. Une réponse du serveur dont le code commence par 2 (200, 204...) veut dire « envoyé ».

En-têtes :

```
Content-Type: application/json
User-Agent: michel/<version>
X-Michel-Timestamp: 2026-10-23T06:30:12Z
X-Michel-Signature: sha256=<hex de HMAC-SHA256(clé, horodatage + "." + corps)>
```

La signature (un code calculé avec une clé secrète, appelé HMAC) prouve que le message vient bien de Michel et n'a pas été modifié. Elle porte sur l'horodatage, un point, puis le corps exact de la requête. `secret` est obligatoire, sauf si l'URL pointe vers cette machine. Si tu n'écris pas toi-même le programme qui reçoit le message, cette vérification ne te concerne pas ; sinon, voici un exemple de contrôle côté réception (Python, bibliothèque standard seulement) :

```python
import hashlib, hmac
from datetime import datetime, timezone

def from_michel(key: bytes, headers, body: bytes, max_age_s: int = 300) -> bool:
    ts = headers["X-Michel-Timestamp"]
    expected = "sha256=" + hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, headers.get("X-Michel-Signature", "")):
        return False
    sent = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return abs((datetime.now(timezone.utc) - sent).total_seconds()) <= max_age_s
```

Utilise le corps brut tel que reçu, avant de le lire comme du JSON. Le contrôle d'âge refuse un vieux message renvoyé plus tard par quelqu'un d'autre. `key` est la valeur que tu as enregistrée avec `michel secret set` (un retour à la ligne final est retiré à l'enregistrement).

### Règles réseau à ajouter

Par défaut, Michel n'a pas le droit d'utiliser le réseau. **Chaque canal e-mail ou webhook activé a besoin de sa propre règle** dans `sovereignty.network.allow`, avec l'hôte exact (ou `*.example.org`) et la finalité `notify.email` ou `notify.webhook`. Sans elle, Michel refuse de charger la politique, et le message d'erreur donne la règle à ajouter. Un canal désactivé (`enabled: false`) n'en a pas besoin. Une notification sur le bureau non plus.

### Secrets

Le coffre à secrets est l'endroit où Michel garde les mots de passe et les clés, hors de `config.yaml` : ils ne vont jamais dans ce fichier. Enregistre-les sous un nom, et mets ce nom dans le canal :

```
michel secret set smtp-mail                      # saisie masquée
printf '%s' "$HOOK_KEY" | michel secret set hook-key
michel secret list                               # les noms seulement, jamais les valeurs
michel secret delete hook-key
```

La valeur n'est jamais passée en argument (elle ne reste donc pas dans l'historique du terminal), jamais affichée, jamais écrite dans le journal d'audit (`secret.set` ne note que le nom). Un nom fait de 1 à 64 lettres minuscules, chiffres ou tirets ; `api-token` est réservé à `michel serve`. Sous Windows, chaque secret est un fichier de `<data-dir>/secrets/` chiffré par Windows (DPAPI) pour ton compte utilisateur. Sous Linux et macOS, c'est un fichier non chiffré que seul ton compte peut lire (droits 0600), et `secret set` te le rappelle ; l'usage du trousseau du système viendra plus tard.

## La page « Aujourd'hui »

```
michel serve                 # http://127.0.0.1:7331/
michel serve --open          # ouvre aussi le navigateur
michel serve --listen 127.0.0.1:8080
```

`michel serve` lance une page web et ses données **sur cet ordinateur seulement** : il accepte 127.0.0.1, [::1] ou localhost et refuse toute autre adresse, pour que personne d'autre sur le réseau ne puisse l'atteindre. Il n'ouvre aucune connexion vers l'extérieur. Ctrl+C l'arrête.

- **Lien avec jeton.** Au premier lancement, Michel crée un jeton d'accès (une sorte de mot de passe, gardé dans le coffre à secrets sous le nom `api-token`). `serve` affiche le lien qui le contient : `http://127.0.0.1:7331/?token=...`. Ouvre-le : la page garde le jeton dans le navigateur et l'enlève de la barre d'adresse. Garde ce lien pour toi. Le lien des digests (`page_url`) ne contient jamais le jeton : si la page le demande, colle le lien affiché par `serve`.
- **Ce qu'elle montre.** Pour chaque projet : ce qui demande ton attention, les compteurs, et pour chaque faille une fiche (les trois phrases, les faits, un glossaire). Tu peux décider `fix`, `defer` ou `ignore` depuis la fiche : mêmes règles que `michel decide`, avec `web` comme auteur dans le journal d'audit. La page existe en français et en anglais et suit le thème clair ou sombre du système (les deux se changent dans les réglages).
- **Installer la page.** Dans Chrome ou Edge, l'icône d'installation dans la barre d'adresse (ou menu > Installer la page en tant qu'application) ajoute Michel comme une application. La fenêtre s'ouvre alors même quand `michel serve` est arrêté, mais elle affiche que Michel ne répond pas.
- **Reconstruire la page.** La page est intégrée au programme. Pour la reconstruire depuis les sources : `make web` (nécessite Node et npm, deux outils de développement), puis `go build`. Sans npm, le programme se compile quand même et `serve` affiche une courte page de texte.

## Tâche planifiée (en attendant `michel schedule`)

`michel schedule` n'existe pas encore. En attendant, crée toi-même la tâche planifiée. La ligne à lancer chaque matin est :

```
michel scan --all --update --digest
```

Elle lit d'abord chaque source activée (les bases de failles OSV, les listes KEV et EPSS qui disent quelles failles sont attaquées ou probablement attaquées, et les autres informations complémentaires ; une source qui attend encore ton accord n'est pas contactée), puis scanne tous les projets actifs, puis envoie le digest. Une source illisible n'arrête pas le scan : Michel se sert des données précédentes, le digest le dit et la commande se termine avec le code 1. Lance-la **avec ton propre compte utilisateur** : les secrets sont chiffrés pour ce compte (Windows) ou lisibles par lui seul, et la notification sur le bureau a besoin de ta session ouverte. Si l'ordinateur est éteint à cette heure-là, rien n'est perdu : le digest suivant couvre tout depuis le précédent.

### Windows (Planificateur de tâches)

Dans un terminal (pas besoin de droits administrateur), avec le chemin de ton `michel.exe` :

```
schtasks /Create /TN "Michel daily digest" /SC DAILY /ST 06:30 /TR "\"C:\Tools\michel\michel.exe\" scan --all --update --digest"
schtasks /Run /TN "Michel daily digest"       # pour l'essayer tout de suite
schtasks /Query /TN "Michel daily digest" /V /FO LIST
schtasks /Delete /TN "Michel daily digest"    # pour la supprimer
```

La tâche ne tourne que quand ta session est ouverte, ce qui est nécessaire pour la notification sur le bureau. Pour rattraper un matin manqué parce que l'ordinateur était éteint : ouvre la tâche dans le Planificateur de tâches (`taskschd.msc`) > Paramètres, et coche « Exécuter la tâche dès que possible si un démarrage planifié est manqué ».

### Linux et macOS (cron, le planificateur de tâches de ces systèmes)

Lance `crontab -e`, puis ajoute la ligne :

```
30 6 * * * $HOME/bin/michel scan --all --update --digest >> $HOME/.local/state/michel-digest.log 2>&1
```

Crée d'abord le dossier du fichier de suivi (`mkdir -p ~/.local/state`). cron ne voit pas ta session de bureau : sous Linux, le canal `toast` (notification sur le bureau) échoue en général depuis cron ; utilise plutôt l'e-mail ou un webhook, ou le minuteur systemd ci-dessous (Linux seulement).

### Linux (minuteur systemd de l'utilisateur)

`~/.config/systemd/user/michel-digest.service` :

```ini
[Unit]
Description=Michel daily scan and digest

[Service]
Type=oneshot
ExecStart=%h/bin/michel scan --all --update --digest
```

`~/.config/systemd/user/michel-digest.timer` :

```ini
[Unit]
Description=Run Michel every morning at 06:30

[Timer]
OnCalendar=*-*-* 06:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Puis :

```
systemctl --user daemon-reload
systemctl --user enable --now michel-digest.timer
systemctl --user list-timers michel-digest.timer
journalctl --user -u michel-digest.service      # ce qu'ont affiché les derniers lancements
```

`Persistent=true` rattrape un matin manqué au démarrage suivant.

### Quand quelque chose échoue

- Le code de sortie 1 veut dire qu'un scan ou un canal a échoué ; les autres projets et canaux sont quand même passés. `michel audit list --last 30` montre `digest.run` et un `notify.send` par canal avec son résultat.
- Un canal en échec ne fait pas reculer la période : pour renvoyer la même période, lance `michel digest --send --since <AAAA-MM-JJ>`.
- `michel notify test <nom>` vérifie un canal tout seul, avec un message fixe.
