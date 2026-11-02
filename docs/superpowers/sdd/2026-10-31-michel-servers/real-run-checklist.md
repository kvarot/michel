# Plan 6 : test sur un vrai serveur

But : faire tourner Michel une première fois sur un vrai serveur, pour vérifier ce que le serveur SSH en mémoire ne peut pas prouver. Compte 1 à 2 heures.

Règles du run :

- **Un serveur jetable seulement** (VPS de test, snapshot fait avant). Jamais de production, jamais de serveur `hds`.
- **Un dossier de données jetable** : ta vraie installation de Michel ne voit rien de ce test.
- **Dans le ledger, seulement des chiffres et des résultats** : ni nom d'hôte, ni adresse, ni empreinte, ni version de client.

Remplace `<hôte>` et `<site>` par tes valeurs. Commandes en PowerShell, sauf les blocs marqués « sur le serveur ».

## Sans serveur jetable : le conteneur Docker

`test/docker-server` construit un Debian avec systemd, `sshd`, PHP-FPM et nginx. **Cette image n'a pas encore été construite ni lancée** : le PC où elle a été écrite n'a pas Docker. Attends-toi à devoir l'ajuster la première fois.

Le conteneur remplace les étapes 1 et 3 : le compte `michel`, le canari et `expose_php = On` sont déjà dans l'image. L'étape 2 (agent SSH et clé) reste à faire, avant ceci :

```powershell
docker build -t michel-test test\docker-server
docker run -d --name michel-test --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock -p 127.0.0.1:2222:22 -p 127.0.0.1:8080:80 michel-test
docker cp $env:USERPROFILE\.ssh\michel_test_ed25519.pub michel-test:/home/michel/.ssh/authorized_keys
docker exec michel-test sh -c "chown michel:michel /home/michel/.ssh/authorized_keys; chmod 600 /home/michel/.ssh/authorized_keys"
docker exec michel-test systemctl is-system-running --wait
docker exec michel-test ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
curl.exe http://127.0.0.1:8080/
```

`--privileged` donne au conteneur de larges droits sur la machine virtuelle de Docker : ne le lance que pour ce test, et garde `127.0.0.1` dans les `-p`. `systemctl is-system-running` peut répondre `degraded` : ce n'est pas bloquant si `curl.exe` répond `ok`.

Ensuite, suis la checklist avec ces différences :

| Étape | Dans le conteneur |
|---|---|
| Étape 4, ajout | `m target add 127.0.0.1 --user michel --port 2222 --env dev --interval manual --site-url http://127.0.0.1:8080 --name essai` |
| « Sur le serveur » | `docker exec -it michel-test bash` |
| Snapshot de l'étape 6 | `docker commit michel-test michel-test:propre` |
| Étape 6E, couper le site | `docker exec michel-test systemctl stop nginx` |
| Étape 9, nettoyage du serveur | `docker rm -f michel-test`, puis `docker rmi michel-test michel-test:propre` |

Ce test ne prouve pas tout : ni les réglages d'un vrai hébergeur, ni le mutualisé, ni le réseau réel. Dans ce cas, à l'étape 10, je reformule la ligne « les auteurs n'ont pas encore essayé » des guides au lieu de la retirer.

## 1. Ce qu'il te faut

- Debian ou Ubuntu récent, avec PHP-FPM dans `/usr/sbin` et un site qui répond. Michel ne prépare aucun script pour un PHP compilé sous `/opt`.
- De préférence `expose_php = On` dans le `php.ini` de FPM : c'est le cas de correction le plus simple.
- Un PHP sous la version corrigée de PHP2Shell, si possible (8.3.35 par exemple), pour voir l'alerte. Sinon, l'étape 7 reste sans objet.

## 2. Sur ton poste : agent SSH

Sur ce PC, le service `ssh-agent` est **arrêté et désactivé**. Michel ne peut pas se connecter sans lui. Dans un PowerShell administrateur :

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

Puis dans un PowerShell normal :

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\michel_test_ed25519
ssh-add $env:USERPROFILE\.ssh\michel_test_ed25519
```

## 3. Sur le serveur : utilisateur de test

Sur le serveur, en root (mets ta clé publique à la place de `<clé publique>`) :

```sh
adduser --disabled-password --gecos "" michel
install -d -m 700 -o michel -g michel /home/michel/.ssh
echo "<clé publique>" > /home/michel/.ssh/authorized_keys
chown michel:michel /home/michel/.ssh/authorized_keys
chmod 600 /home/michel/.ssh/authorized_keys
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Note l'empreinte `SHA256:…` affichée par la dernière commande. Le droit `sudo` vient plus tard, à l'étape 6.

Mets un **canari** dans un pool PHP-FPM, pour tester le masquage des secrets (adapte la version) :

```sh
echo 'env[DB_PASSWORD] = canari-michel-7391' >> /etc/php/8.3/fpm/pool.d/www.conf
systemctl reload php8.3-fpm
```

## 4. Ajouter le serveur et confirmer l'empreinte

Depuis la racine du dépôt :

```powershell
$d = "$env:USERPROFILE\michel-test"
New-Item -ItemType Directory -Force $d | Out-Null
function m { .\bin\michel.exe --data-dir $d --config "$d\config.yaml" --lang fr @args }
m target add <hôte> --user michel --env dev --interval manual --site-url https://<site> --name essai
m target trust essai
```

| Vérifie | Attendu |
|---|---|
| Empreinte affichée par `trust` | identique à celle de l'étape 3 |
| `m target check essai` **avant** confirmation | refus : l'empreinte n'est pas encore connue |
| `m target trust essai --fingerprint SHA256:AAAA` | refus, aucune connexion autorisée |

Confirme ensuite la vraie empreinte :

```powershell
m target trust essai --fingerprint SHA256:<empreinte>
```

Ce point teste aussi l'agent OpenSSH de Windows sur un vrai serveur : si la connexion échoue ici, note le message exact.

## 5. Vérification en lecture seule

Sur le serveur, pose un repère :

```sh
touch /tmp/michel-repere
```

Sur ton poste :

```powershell
m target check essai
```

`check` affiche la commande `michel source enable …` si une base manque. Lance-la, puis relance `check`.

| Vérifie | Attendu |
|---|---|
| PHP, nginx ou Apache, paquets, système | identiques à `php -v`, `nginx -v`, `dpkg -l` lancés à la main |
| PHP-FPM et ligne de commande | les deux vus, et Michel le dit |
| Liste « non vu » | fichiers illisibles par l'utilisateur `michel`, en clair, sans tentative de contournement |
| Fausses alertes | relis chaque faille : est-elle vraie sur ce serveur ? Compte les fausses |
| Durée | sous 5 minutes. Note la durée réelle |

Sur le serveur, rien ne doit être écrit par Michel :

```sh
find /etc /var/lib/michel /var/www /home/michel -newer /tmp/michel-repere 2>/dev/null
```

Une ligne `~/.ssh` ou système sans lien avec Michel n'est pas un échec : regarde laquelle.

Sur ton poste, le canari ne doit apparaître nulle part. Cette commande ne doit **rien** afficher :

```powershell
Get-ChildItem $d -Recurse -File | Select-String -SimpleMatch "canari-michel-7391" -List | Select-Object Path
```

Ensuite, ouvre la page (la commande affiche son adresse) :

```powershell
m serve
```

La page **Serveurs** doit dire « touché / pas touché / pas pu tout voir », et les textes doivent se lire sans connaissance technique.

## 6. Corrections

Fais un snapshot du serveur maintenant.

**A. Tu lances le script toi-même** (`executor: user`, le réglage par défaut). Sur `expose_php` :

1. **Préparer la correction**, relis les deux scripts, **Valider**.
2. **Copier** `appliquer`, lance-le en root sur le serveur. Attendu : code de sortie `0`.
3. **Je l'ai appliqué**. Attendu : `proven_fixed` après la nouvelle vérification.
4. Vérifie : la copie existe dans `/var/lib/michel/backups/<correction>/`, le fichier ne diffère que sur la ligne voulue.
5. Lance `annuler` : le fichier revient à l'identique (compare avec `sha256sum`), PHP est rechargé.

**B. La ligne a changé** (code 5). Prépare et valide de nouveau la correction. Avant de lancer le script, change à la main la ligne `expose_php` sur le serveur, puis lance `appliquer`. Attendu : code `5`, aucun fichier modifié. Remets la ligne.

**C. Michel lance le script, sans sudo.**

```powershell
m target set essai --executor michel
```

Attendu : Michel propose seulement la correction ; il ne la lance pas.

**D. Michel lance le script, avec sudo.** C'est un droit large, à retirer à l'étape 9. Sur le serveur, en root :

```sh
echo 'michel ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/michel-test
chmod 440 /etc/sudoers.d/michel-test
```

Sur ton poste :

```powershell
m target set essai --sudo nopasswd
```

Valide la correction `expose_php` sur la page. Attendu : chaque étape suivie sur la page, puis `proven_fixed`. Aucun script ne reste sur le serveur, seulement les sauvegardes.

**E. Le site tombe : retour arrière.** Remets `expose_php = On`, recharge PHP et lance `m target check essai`. Prépare la correction. Juste avant **Valider**, coupe le serveur web :

```sh
systemctl stop nginx
```

Attendu : la vérification du site échoue, Michel lance `annuler`, état *échoué* avec la cause « annulé », fichier revenu à l'identique. Rallume ensuite le serveur web. Si Michel refuse avant de lancer le script, note-le : le cas n'est alors pas testé de cette façon.

**F. Coupure pendant un script (facultatif).** Difficile à provoquer à la main. Si tu y arrives, attendu : état `unknown`, aucune annulation devinée, sortie par **J'ai vérifié le serveur**.

## 7. PHP2Shell, si ton PHP est touché

| Vérifie | Attendu |
|---|---|
| Faille | graves, CVE-2026-109618 et CVE-2026-109619, marquées comme déjà utilisées |
| Jugement | d'après la base de la distribution si PHP vient d'un paquet, pas d'après `php -v` seul |
| Réglage `session.upload_progress.enabled=0` | étiqueté « réduit le risque, ne corrige pas » ; la faille reste ouverte après |
| `memory_limit=-1` | jamais proposé |
| Mise à jour du paquet | bloquée tant que **Snapshot fait** n'est pas coché ; à blanc d'abord (`apt-get -s`) |

## 8. Fin du run

```powershell
m audit verify
```

Attendu : code de sortie `0`, événements `target.connect` présents, résultats cohérents avec ce que tu as fait. Relance la recherche du canari de l'étape 5 : toujours rien.

## 9. Nettoyage

Sur le serveur, en root, **après avoir relu ces lignes** (elles suppriment le droit sudo, le compte et les sauvegardes du test) :

```sh
rm /etc/sudoers.d/michel-test
sed -i '/canari-michel-7391/d' /etc/php/8.3/fpm/pool.d/www.conf
systemctl reload php8.3-fpm
deluser --remove-home michel
rm -r /var/lib/michel/backups
```

Sur ton poste :

```powershell
ssh-add -d $env:USERPROFILE\.ssh\michel_test_ed25519
Remove-Item -Recurse $env:USERPROFILE\michel-test
```

Le service `ssh-agent` reste activé : remets-le sur `Disabled` si tu ne t'en sers pas ailleurs.

## 10. Ce que tu me donnes ensuite

Pour chaque étape : réussi ou échoué, avec le message exact en cas d'échec (hôte retiré). Et aussi : système et branche de PHP, durée de `check`, nombre de failles, nombre de fausses alertes, nombre de « non vu ». Je corrige ce qui a échoué, j'écris les résultats dans le ledger et je retire des guides la ligne « les auteurs n'ont pas encore essayé » (`docs/servers.fr.md` et `docs/servers.md`).
