# Sources : où Michel lit ses données

🇬🇧 English version : [sources.md](sources.md)

Michel tient un registre unique des endroits où il lit : bases de failles, listes de failles déjà attaquées, avis de sécurité des éditeurs, outils d'analyse, skills et serveurs MCP. Chaque source est **désactivée** au départ, sauf les deux bases OSV de Composer et de npm. Une source ne contacte rien tant que tu n'as pas accepté les hôtes (les adresses de serveurs) qu'elle utilise. Tu gères le registre avec `michel source …` ou dans l'onglet **Sources** de la page locale (`michel serve`).

```
michel source list                # toutes les sources, leur sorte et leur état
michel source show enrich.kev     # hôtes, règle réseau, réglages, dernière lecture
michel source enable enrich.kev   # te demande ton accord, puis écrit la règle réseau
michel source update              # lit tout de suite les sources activées
michel source disable enrich.kev  # la désactive ; --forget retire aussi sa règle réseau
```

## Les sortes de sources

| Sorte | Ce qu'elle apporte | Exemples du catalogue |
|---|---|---|
| `osv` | Une base de failles hors ligne pour un écosystème, téléchargée en entier. Les scans s'en servent sans aucun accès réseau. | `osv.packagist`, `osv.npm` (activées au départ), `osv.pypi`, `osv.go`, … (23) |
| `enrichment` | Des informations en plus sur les failles trouvées : déjà attaquée (KEV), probabilité d'attaque (EPSS), score de gravité manquant (Vulnrichment, NVD, CIRCL). | `enrich.kev`, `enrich.epss`, `enrich.vulnrichment`, `enrich.nvd`, `enrich.circl` |
| `feed` | Des avis de sécurité d'éditeurs « À lire », triés selon les technologies que tu utilises. | `feed.nginx`, `feed.symfony`, `feed.postgresql`, … (55) |
| `plugin` | Un outil d'analyse installé sur ta machine, dont les résultats rejoignent la même liste : Michel lance lui-même Trivy et Semgrep, et se contente de lire les rapports de CodeQL et de ZAP. | `plugin.trivy`, `plugin.semgrep`, `plugin.codeql`, `plugin.zap` |
| `skill` | Une skill Claude Code, figée sur une version précise (un commit), installée après un aperçu. | `skill.trailofbits-code-audit`, `skill.claude-code-owasp` |
| `mcp` | Un serveur MCP, figé sur un commit ; Michel t'affiche la commande à lancer, c'est toi qui la lances. | `mcp.semgrep`, `mcp.safedep-vet`, `mcp.cve-search`, `mcp.wazuh` |

Une septième sorte, `reference`, regroupe des liens utiles que Michel ne lit jamais (OpenSSF, CVSS, listes « awesome »…), plus `discover.github`, qui cherche de nouveaux dépôts par sujet sur GitHub (voir « À découvrir »).

Le catalogue est intégré au programme. À chaque démarrage, Michel met le registre à jour : il ajoute les nouvelles entrées, réécrit celles qui ont changé (nom, adresse, hôtes, finalité, réglages du catalogue) et **garde tes choix** (activée ou non, masquée, technologies, tes réglages). Une entrée retirée du catalogue est masquée, jamais supprimée. `michel source reset <clé>` remet une entrée comme le catalogue la décrit ; `michel source add --kind …` ajoute une source à toi (désactivée au départ).

## États

| État | Ce que ça veut dire |
|---|---|
| `off` | Pas utilisée. |
| `waiting_consent` | Activée, mais un de ses hôtes n'a pas encore de règle réseau. Michel ne le contacte pas : `source update` affiche `· <clé> attend ton accord`, et le digest et la page le disent aussi. |
| `on` | Activée, et tous ses hôtes sont autorisés. |
| `hidden` | Retirée des listes (`source remove` sur une entrée du catalogue). `source reset <clé>` la fait revenir. |

Une source peut repasser d'elle-même en `waiting_consent` : quand un nouveau catalogue déplace une source vers un autre hôte, la règle écrite pour l'ancien hôte ne couvre pas le nouveau. Michel te redemande alors ton accord au lieu d'échouer sans rien dire.

## L'écran d'accord et la règle qu'il écrit

`michel source enable <clé>` (ou l'interrupteur de la page) liste chaque hôte que la source contacterait et qui n'a pas encore de règle, avec une phrase qui dit ce qui sort de ta machine :

- un téléchargement (OSV, KEV, EPSS, flux) : « Rien de tes projets ne part : c'est un téléchargement. » ;
- les enrichissements à la demande (Vulnrichment, NVD, CIRCL) : les numéros CVE de tes failles, rien d'autre ;
- skills, serveurs MCP et état des plugins : le nom du dépôt public et la version choisie (et, si tu as donné un jeton GitHub, GitHub sait que c'est toi) ;
- la découverte : le nom de quelques sujets.

Dans un terminal, tu réponds `y` ou `N` ; dans un script, `--yes` accepte. Sans terminal et sans `--yes`, Michel refuse et affiche le texte. Une fois ton accord donné, Michel :

1. écrit une règle par hôte dans `sovereignty.network.allow` de ton fichier de politique, par exemple `{host: www.cisa.gov, purpose: source.enrich}` ; il garde une copie (`config.yaml.bak`), conserve tes commentaires, et crée le fichier avec cette seule règle si tu n'en avais pas ;
2. relit la politique : la commande applique la règle tout de suite (un accord donné depuis la page ne demande pas de redémarrer `michel serve`) ;
3. note `source.consent` dans le journal d'audit (clé, hôtes, finalité, auteur), puis `source.enable`.

Un hôte déjà autorisé pour une autre source ne te demande rien (l'accord est quand même noté). Désactiver une source garde sa règle ; `disable --forget` la retire, et Michel refuse tant qu'une autre source activée a besoin de la même règle.

## Ce qui sort, source par source

| Source | Hôte | Finalité | Ce qui est envoyé |
|---|---|---|---|
| `osv.*` (23 bases) | `osv-vulnerabilities.storage.googleapis.com` | `osv.db` | Rien : la base entière de l'écosystème est téléchargée. |
| `enrich.kev` | `www.cisa.gov` | `source.enrich` | Rien : la liste KEV entière est téléchargée. |
| `enrich.epss` | `epss.empiricalsecurity.com` | `source.enrich` | Rien : le fichier du jour est téléchargé. |
| `enrich.vulnrichment` | `raw.githubusercontent.com` | `source.enrich` | Un numéro CVE par requête (failles sans gravité), 200 au plus par mise à jour. |
| `enrich.nvd` | `services.nvd.nist.gov` | `source.enrich` | Un numéro CVE par requête, 100 au plus par mise à jour, une requête toutes les 6 s (0,6 s avec le secret `nvd-api-key`, envoyé dans un en-tête). |
| `enrich.circl` | `vulnerability.circl.lu` | `source.enrich` | Un numéro CVE par requête, 200 au plus par mise à jour. |
| `feed.*` (55 flux) | le site de l'éditeur (27 hôtes), ou `api.github.com` pour les 28 flux lus dans les avis GitHub | `source.feed` | Rien d'autre que la demande du flux ; les avis GitHub portent ton jeton si tu en as donné un. |
| `skill.*`, `mcp.*` | `api.github.com`, `codeload.github.com` | `source.repo` | Le nom du dépôt et le commit choisi ; ton jeton GitHub si tu en as donné un. |
| `plugin.*` | aucun hôte à lui | `plugin.<clé>` (jamais autorisée) | Rien (voir « Plugins »). L'état de leur dépôt n'est lu que si `api.github.com` est déjà autorisé pour `source.repo`. |
| `discover.github` | `api.github.com` | `source.discover` | Le nom des sujets `mcp-security` et `claude-skills`. |

Chaque requête passe par la passerelle de sortie réseau et s'inscrit dans le journal d'audit (`egress.attempt`). L'inventaire complet, avec les plafonds et ce que les tests prouvent, est dans [network-egress.fr.md](security/network-egress.fr.md).

## KEV et EPSS

- **KEV** (`enrich.kev`) est la liste, tenue par l'agence américaine de cybersécurité (CISA), des failles que des pirates utilisent déjà. Une faille de cette liste porte `[KEV]` dans `michel findings`, `kev: yes` dans `michel finding`, une pastille rouge sur la page, et passe **en tête du digest** (« Failles que des pirates utilisent déjà, à corriger en premier »), tant qu'elle est ouverte ou que tu as décidé de la corriger. Celles que tu as reportées ou ignorées avec une raison reviennent en une seule ligne de compte, pas chaque matin. Un paquet malveillant (avis OSV `MAL-`) suit les mêmes règles.
- KEV n'ajoute **pas** de points au score de risque : le score mesure le risque de la correction, pas son urgence. KEV marque la faille comme urgente (« à corriger en premier ») et la place en tête de toutes les listes (voir [remediation-risk.fr.md](remediation-risk.fr.md)).
- Si une faille que tu as choisi d'ignorer ou de reporter entre dans la liste KEV, Michel te redemande : ta décision est remplacée (raison `kev_changed`) et la faille revient dans « décisions à revoir ».
- **EPSS** (`enrich.epss`) estime la probabilité qu'une faille soit attaquée dans les 30 jours. Michel ne l'affiche qu'à partir du 50ᵉ centile (« Risque qu'elle soit attaquée dans les 30 prochains jours : 12 %, plus que pour 95 % des failles connues. ») ; en dessous, il ne dit rien plutôt que d'afficher un chiffre trompeusement rassurant.

## « À lire » et tes technologies

Les flux apportent les avis des éditeurs. Ils ne créent jamais de faille (Michel ne connaît pas la version que tu fais tourner) ; ils forment une liste **À lire** dans le digest (10 avis au plus), sur la page « Aujourd'hui » et dans `michel source items`. Un avis est « à lire » quand sa source porte une de tes technologies, ou quand son titre en cite une (mot entier, majuscules ou non). Tes technologies viennent de trois endroits :

1. automatiquement, de tes lockfiles (`php`, `node`, `symfony`, `laravel`, `react`, `vue`…), recalculées à chaque scan ;
2. par projet : `michel project set <nom> --tech nginx --tech postgresql` ;
3. pour toute ta machine, pour ce qui n'est dans aucun projet : `michel tech add nginx`.

Un flux désactivé qui correspond à une de tes technologies est marqué « suggéré pour toi » sur la page ; Michel ne l'active jamais à ta place. `michel source read <id>` (ou `--all`) marque des avis comme lus. Les avis sont gardés 180 jours.

## Plugins

- **Trivy** (`plugin.trivy`) : Michel lance `trivy fs --scanners misconfig` (erreurs de réglage dans les fichiers Dockerfile, compose, Kubernetes) avec toutes les mises à jour coupées (`--skip-db-update`, `--skip-check-update`, `--offline-scan`) et son cache dans le dossier de données de Michel. La recherche de failles et de secrets n'est pas lancée.
- **Semgrep** (`plugin.semgrep`) : Michel lance `semgrep scan --metrics=off --disable-version-check` avec **seulement les règles que tu as placées** dans `<dossier de données>/plugins/semgrep/rules/` (fichiers YAML). Si le dossier est vide, il s'arrête et te le dit. Pour avoir des règles, télécharge-les toi-même, en dehors de Michel, par exemple depuis le registre Semgrep (`p/php`, `p/javascript`), et copie les fichiers YAML dans ce dossier.
- **CodeQL** et **ZAP** : lecture de rapport seulement, `michel source run plugin.codeql --project <nom> --input rapport.sarif`. CodeQL ne gère pas PHP ; ZAP attaque un site pour le tester, lance-le sur une copie de test.
- Michel lance un plugin activé dont le réglage `run` vaut `true` à la fin de `michel scan` d'un projet, ou quand tu le demandes avec `michel source run <clé> --project <nom>`. Un échec donne un avertissement, pas une erreur du scan.
- Leurs résultats rejoignent la même liste (sortes `config` et `code`), avec les mêmes décisions et le même digest. Seul un nouveau passage du même plugin sur le même projet peut les marquer disparus.

**Comment un outil est tenu à l'écart du réseau.** Michel ne lance jamais un outil depuis le dossier du projet : il le lance depuis `<dossier de données>/plugins/<outil>/`, avec des arguments fixes (aucun texte de ta part n'y est ajouté), un environnement réduit à une courte liste de variables (aucun secret, aucun jeton), un arrêt au bout de 30 minutes et une sortie coupée à 64 Ko. `HTTP_PROXY`, `HTTPS_PROXY` et `ALL_PROXY` pointent vers un **proxy de refus** local : il répond 403 à toute requête, refuse tout `CONNECT` et note chaque tentative comme un `egress.attempt` refusé, avec la finalité `plugin.<clé>`. C'est une **barrière journalisée, pas une garantie** : un outil qui ignore ces variables n'est pas arrêté par elle. Trivy et Semgrep eux-mêmes, et leurs règles, c'est toi qui les mets à jour, en dehors de Michel.

## Skills et serveurs MCP

- `michel source show <clé>` donne le dépôt, le commit choisi, la licence trouvée, la note et, après une mise à jour, l'état du dépôt (étoiles, dernière modification, archivé, nouvelle version).
- `michel source install <clé>` (une fois la source activée par `source enable <clé>`) télécharge l'archive du **commit choisi** (`codeload.github.com` ; 50 Mo compressés, 200 Mo et 5 000 fichiers une fois extraits, au plus ; chemins qui sortent du dossier et liens symboliques refusés, aucun fichier gardé exécutable) dans le dossier de données, puis montre un **aperçu** : fichiers et tailles, le début de `SKILL.md` (ou `README.md`), la licence (s'il n'y en a pas, Michel te dit de te renseigner sur ce que l'auteur autorise avant d'installer), ce qui sera écrit et où. Tu réponds `y` ou `N`.
- Une **skill** est copiée dans `~/.claude/skills/<nom>/` avec un fichier repère `.michel-source`. Michel refuse un dossier qui existe déjà sans ce repère, n'écrit jamais dans un projet, et `source remove` ne supprime qu'un dossier dont le repère correspond.
- Un **serveur MCP** est récupéré et figé pour lecture seulement. Michel n'écrit rien dans les réglages de Claude Code : il affiche la commande à lancer toi-même, `claude mcp add --scope user <nom> -- <commande> <arguments>`. Un serveur lancé par `npx` télécharge des fichiers au démarrage, hors du contrôle de Michel ; l'aperçu le dit.
- **Jamais de mise à jour automatique.** La mise à jour quotidienne lit l'état du dépôt ; quand le dernier commit diffère de celui choisi, la source affiche « nouvelle version ». `michel source upgrade <clé>` montre les fichiers ajoutés, modifiés et supprimés et ce qui change dans `SKILL.md`, puis installe après ton accord.

### Dépôts connus que Michel ne propose pas, et pourquoi

- Snyk : il envoie tes données à un tiers, ce que la politique de souveraineté interdit.
- Outils offensifs et de recherche sur des personnes (Burp, SecOps, Shodan, VirusTotal, Maigret) : hors du but, qui est de surveiller tes propres dépendances.
- Rétro-ingénierie (IDA, Ghidra, JADX) : même raison.
- Mobb : il envoie ton code pour le vérifier.
- Dépôts presque inconnus : pas assez de confiance pour les mettre dans un catalogue.

Tu peux quand même ajouter le dépôt que tu veux : `michel source add --kind skill --name <nom> --repo propriétaire/nom --pin <commit de 40 caractères>`.

## À découvrir

`discover.github` (désactivée au départ) cherche une fois par jour les sujets GitHub `mcp-security` et `claude-skills` et garde les dépôts que le registre ne connaît pas. Le digest et la page listent les nouveaux ; `michel source discover --add propriétaire/nom --kind skill --pin <sha>` en ajoute un (désactivé, à installer comme plus haut), `--ignore propriétaire/nom` le masque. Les listes « awesome » du catalogue sont de simples liens, jamais lus.

## Mise à jour quotidienne

`michel source update` lit les sources activées dans cet ordre : bases OSV, enrichissements (puis Michel recalcule les failles : KEV, EPSS, gravité), flux, dépôts, découverte. Une source qui attend encore ton accord ne fait aucune requête. Une source en échec garde ses données précédentes, les autres continuent, et la commande se termine avec le code 1. Pour KEV, EPSS, les flux et les bases, Michel demande seulement ce qui a changé depuis la dernière lecture : une source inchangée répond « pas modifié ».

La ligne planifiée lit d'abord les sources, puis scanne et envoie le digest :

```
michel scan --all --update --digest
```

Le digest a alors une ligne **catalogue** (sources à jour, sources illisibles, sources qui attendent ton accord, nouvelles versions, dépôts à découvrir), qui ne dit rien quand tout est à jour. Voir [daily-digest.fr.md](operations/daily-digest.fr.md).

## En cas de problème

- **« attend ton accord »** : la source est activée mais un hôte n'a pas de règle. Lance `michel source enable <clé>` et lis le texte, ou désactive-la (`source disable <clé>`, ou « désactiver » sur la page).
- **« Michel a atteint la limite de requêtes que GitHub autorise »** (noté `rate budget`) : une mise à jour fait au plus 50 requêtes GitHub sans jeton, 500 avec (`michel secret set github-token`). Chaque skill, serveur MCP ou plugin coûte 3 requêtes. Les sources pas lues aujourd'hui le seront à la prochaine mise à jour.
- **« état du dépôt non relevé, car Michel n'a pas encore ton accord pour contacter api.github.com »** : un plugin n'a pas d'hôte à lui ; l'état de son dépôt est lu dès qu'un accord pour une skill ou un serveur MCP a autorisé `api.github.com`.
- **Trivy ou Semgrep « n'est pas installé sur cette machine »** : Michel cherche le programme dans le `PATH` et ne le télécharge jamais. Installe-le toi-même, ou donne un rapport avec `--input`.
- **Trivy échoue sur sa propre base ou ses règles** : Michel le lance hors ligne, toutes mises à jour coupées. Mets Trivy à jour toi-même, en dehors de Michel, puis relance.
- **« Semgrep n'a rien à chercher »** : place tes règles YAML dans `<dossier de données>/plugins/semgrep/rules/`.
- **Une marque KEV manque sur une machine isolée** : KEV et EPSS sont rangés dans la base de Michel, pas dans des fichiers que tu peux copier (voir [offline-installation.fr.md](operations/offline-installation.fr.md)).
