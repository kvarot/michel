# Sources : où Michel lit ses données

🇬🇧 English version : [sources.md](sources.md)

Michel tient un registre unique des endroits où il lit : bases de failles, listes de failles déjà attaquées, avis de sécurité des éditeurs, outils d'analyse, skills et serveurs MCP. Chaque source est **désactivée** au départ, sauf les deux bases OSV de Composer et de npm. Une source ne se connecte à aucun serveur tant que tu n'as pas accepté les adresses de serveurs (les « hôtes ») qu'elle utilise. Tu gères le registre avec `michel source …` ou dans l'onglet **Sources** de la page locale (`michel serve`).

```
michel source list                # toutes les sources, leur type et leur état
michel source show enrich.kev     # hôtes, règle réseau, réglages, dernière lecture
michel source enable enrich.kev   # te demande ton accord, puis écrit la règle réseau
michel source update              # lit tout de suite les sources activées
michel source disable enrich.kev  # la désactive ; --forget retire aussi sa règle réseau
```

## Les types de sources

| Type | Ce qu'il apporte | Exemples du catalogue |
|---|---|---|
| `osv` | Une base de failles hors ligne pour un écosystème, téléchargée en entier. Les scans s'en servent sans aucun accès réseau. | `osv.packagist`, `osv.npm` (activées au départ), `osv.pypi`, `osv.go`, … (23) |
| `enrichment` | Des informations en plus sur les failles trouvées : déjà attaquée (KEV), probabilité d'attaque (EPSS), score de gravité manquant (Vulnrichment, NVD, CIRCL). | `enrich.kev`, `enrich.epss`, `enrich.vulnrichment`, `enrich.nvd`, `enrich.circl` |
| `feed` | Des avis de sécurité d'éditeurs « À lire », triés selon les technologies que tu utilises. | `feed.nginx`, `feed.symfony`, `feed.postgresql`, … (55) |
| `plugin` | Un outil d'analyse installé sur ta machine, dont les résultats s'ajoutent à la liste de tes failles : Michel lance lui-même Trivy et Semgrep, et se contente de lire les rapports de CodeQL et de ZAP. | `plugin.trivy`, `plugin.semgrep`, `plugin.codeql`, `plugin.zap` |
| `skill` | Une skill Claude Code, bloquée sur une version précise (un commit), installée après un aperçu. | `skill.trailofbits-code-audit`, `skill.claude-code-owasp` |
| `mcp` | Un serveur MCP, bloqué sur un commit ; Michel t'affiche la commande à lancer, c'est toi qui la lances. | `mcp.semgrep`, `mcp.safedep-vet`, `mcp.cve-search`, `mcp.wazuh` |

Un septième type, `reference`, regroupe des liens utiles que Michel ne lit jamais (OpenSSF, CVSS, listes de ressources « awesome »…), plus `discover.github`, qui cherche de nouveaux dépôts par sujet sur GitHub (voir « À découvrir »).

Le catalogue est intégré au programme. À chaque démarrage, Michel met le registre à jour : il ajoute les nouvelles entrées, réécrit celles qui ont changé (nom, adresse, hôtes, finalité — la raison pour laquelle l'hôte est contacté —, réglages du catalogue) et **garde tes choix** (activée ou non, masquée, technologies, tes réglages). Une entrée retirée du catalogue est masquée, jamais supprimée. `michel source reset <clé>` remet une entrée comme le catalogue la décrit ; `michel source add --kind …` ajoute une source à toi (désactivée au départ).

## États

| État | Ce que ça veut dire |
|---|---|
| `off` | Pas utilisée. |
| `waiting_consent` | Activée, mais un de ses hôtes n'a pas encore de règle réseau. Michel ne contacte pas cet hôte : `source update` affiche `· <clé> attend ton accord`, et le digest et la page le disent aussi. |
| `on` | Activée, et tous ses hôtes sont autorisés. |
| `hidden` | Retirée des listes (`source remove` sur une entrée du catalogue). `source reset <clé>` la fait revenir. |

Une source peut repasser d'elle-même en `waiting_consent`. C'est le cas quand une nouvelle version de Michel change l'adresse du serveur d'une source : ton ancien accord ne valait que pour l'ancienne adresse, donc Michel te redemande avant de contacter la nouvelle.

## L'écran d'accord et la règle qu'il écrit

`michel source enable <clé>` (ou l'interrupteur de la page) liste chaque hôte que la source contacterait et qui n'a pas encore de règle, avec une phrase qui dit ce qui sort de ta machine :

- un téléchargement (OSV, KEV, EPSS, flux) : « Rien de tes projets ne part : c'est un téléchargement. » ;
- les sources qui interrogent un numéro de faille à la fois (Vulnrichment, NVD, CIRCL) : les numéros CVE de tes failles, rien d'autre ;
- skills, serveurs MCP et état des plugins : le nom du dépôt public et la version choisie (et, si tu as donné un jeton GitHub, GitHub sait que c'est toi) ;
- la découverte : le nom de quelques sujets (et ton jeton GitHub si tu en as donné un).

Dans un terminal, tu réponds `y` (oui) ou `N` (non) ; dans un script, `--yes` accepte. Sans terminal et sans `--yes`, Michel refuse et affiche le texte. Une fois ton accord donné, Michel :

1. écrit une règle par hôte dans `sovereignty.network.allow` de ton fichier de politique, par exemple `{host: www.cisa.gov, purpose: source.enrich}` ; il garde une copie (`config.yaml.bak`), conserve tes commentaires, et crée le fichier de politique, avec cette seule règle, s'il n'existait pas ;
2. recharge la politique, donc la règle s'applique immédiatement (un accord donné depuis la page ne demande pas de redémarrer `michel serve`) ;
3. note `source.consent` dans le journal d'audit (clé, hôtes, finalité, auteur), puis `source.enable`.

Si un hôte est déjà autorisé pour une autre source, Michel ne te demande rien, mais note quand même ton accord dans le journal d'audit. Désactiver une source garde sa règle ; `disable --forget` la retire, et Michel refuse tant qu'une autre source activée a besoin de la même règle.

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
| `discover.github` | `api.github.com` | `source.discover` | Le nom des sujets `mcp-security` et `claude-skills` ; ton jeton GitHub si tu en as donné un. |

Chaque requête passe par la passerelle de sortie réseau et s'inscrit dans le journal d'audit (`egress.attempt`). L'inventaire complet, avec les plafonds et ce que les tests prouvent, est dans [network-egress.fr.md](security/network-egress.fr.md).

## KEV et EPSS

- **KEV** (`enrich.kev`) est la liste, tenue par l'agence américaine de cybersécurité (CISA), des failles que des pirates utilisent déjà. Une faille de cette liste porte `[KEV]` dans `michel findings`, `kev: yes` dans `michel finding`, une pastille rouge sur la page, et passe **en tête du digest** (« Failles que des pirates utilisent déjà, à corriger en premier »), tant qu'elle est ouverte ou que tu as décidé de la corriger. Celles que tu as reportées ou ignorées avec une raison ne sont comptées que sur une ligne, au lieu de revenir chaque matin. Un paquet malveillant (avis OSV `MAL-`) suit les mêmes règles.
- KEV n'ajoute **pas** de points au score de risque : ce score dit à quel point la correction risque de casser quelque chose, pas à quel point elle est urgente. KEV, lui, marque la faille « à corriger en premier » et la place en tête de toutes les listes (voir [remediation-risk.fr.md](remediation-risk.fr.md)).
- Si une faille que tu as choisi d'ignorer ou de reporter entre dans la liste KEV, Michel te redemande : ta décision est remplacée (raison `kev_changed`) et la faille revient dans « décisions à revoir ».
- **EPSS** (`enrich.epss`) estime la probabilité qu'une faille soit attaquée dans les 30 jours. Dans l'explication d'une faille (`michel finding`), Michel n'ajoute la phrase « Risque qu'elle soit attaquée dans les 30 prochains jours : 12 %, plus que pour 95 % des failles connues. » que si la faille est dans la moitié des failles connues dont la probabilité d'attaque est la plus haute ; en dessous, l'explication n'en dit rien plutôt que de donner un petit chiffre qui rassurerait à tort. La page, elle, affiche le chiffre EPSS d'une faille dès que Michel le connaît.

## « À lire » et tes technologies

Les flux apportent les avis des éditeurs. Ils ne créent jamais de faille (Michel ne connaît pas la version que tu fais tourner) ; ils forment une liste **À lire** dans le digest (10 avis au plus), sur la page « Aujourd'hui » et dans `michel source items`. Un avis est « à lire » quand sa source porte une de tes technologies, ou quand son titre en cite une (mot entier, majuscules ou non). Tes technologies viennent de trois endroits :

1. automatiquement, de tes fichiers de verrouillage des dépendances (lockfiles) : `php`, `node`, `symfony`, `laravel`, `react`, `vue`…, recalculées à chaque scan ;
2. par projet : `michel project set <nom> --tech nginx --tech postgresql` ;
3. pour toute ta machine, pour ce qui n'est dans aucun projet : `michel tech add nginx`.

Un flux désactivé qui correspond à une de tes technologies est marqué « suggéré pour toi » sur la page ; Michel ne l'active jamais à ta place. `michel source read <id>` (ou `--all`) marque des avis comme lus. Les avis sont gardés 180 jours.

## Plugins

- **Trivy** (`plugin.trivy`) : Michel lance `trivy fs --scanners misconfig` (erreurs de réglage dans les fichiers Dockerfile, compose, Kubernetes) avec toutes les mises à jour coupées (`--skip-db-update`, `--skip-check-update`, `--offline-scan`) et son cache dans le dossier de données de Michel. La recherche de failles et de secrets n'est pas lancée.
- **Semgrep** (`plugin.semgrep`) : Michel lance `semgrep scan --metrics=off --disable-version-check` avec **seulement les règles que tu as placées** dans `<dossier de données>/plugins/semgrep/rules/` (fichiers YAML). Si le dossier est vide, il s'arrête et te le dit. Pour avoir des règles, télécharge-les toi-même, en dehors de Michel, par exemple depuis le registre Semgrep (`p/php`, `p/javascript`), et copie les fichiers YAML dans ce dossier.
- **CodeQL** et **ZAP** : lecture de rapport seulement, `michel source run plugin.codeql --project <nom> --input rapport.sarif`. CodeQL ne gère pas PHP ; ZAP attaque un site pour le tester, lance-le sur une copie de test.
- Michel lance un plugin activé dont le réglage `run` vaut `true` à la fin de `michel scan` d'un projet, ou quand tu le demandes avec `michel source run <clé> --project <nom>`. Un échec donne un avertissement, pas une erreur du scan.
- Leurs résultats s'ajoutent à la liste de tes failles (de types `config` et `code`), avec les mêmes décisions et le même digest. Un résultat n'est marqué « disparu » que si le même plugin repasse sur le même projet et ne le retrouve plus.

**Comment un outil est tenu à l'écart du réseau.**

- Michel ne lance jamais un outil depuis le dossier du projet, mais depuis `<dossier de données>/plugins/<outil>/`.
- Les arguments sont fixes : aucun texte de ta part n'y est ajouté.
- L'outil ne reçoit qu'une courte liste de variables d'environnement : aucun secret, aucun jeton.
- Il est arrêté au bout de 30 minutes, et ce qu'il affiche est coupé à 64 Ko.
- Ses réglages de proxy (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) sont dirigés vers un **intermédiaire local qui refuse tout** (le « proxy de refus ») : chaque tentative de connexion est refusée et notée dans le journal avec la finalité `plugin.<clé>`.
- C'est un **garde-fou, pas une garantie** : un outil qui ignore ces réglages n'est pas arrêté.
- Trivy et Semgrep eux-mêmes, et leurs règles, c'est toi qui les mets à jour, en dehors de Michel.

## Skills et serveurs MCP

- `michel source show <clé>` donne le dépôt, le commit choisi, la licence trouvée, la note et, après une mise à jour, l'état du dépôt (étoiles, dernière modification, archivé, nouvelle version).
- `michel source install <clé>` (une fois la source activée par `source enable <clé>`) télécharge l'archive du **commit choisi** depuis `codeload.github.com` dans le dossier de données. Limites : 50 Mo compressés, 200 Mo et 5 000 fichiers une fois extraits. Michel refuse les chemins qui sortent du dossier et les liens symboliques, et ne rend aucun fichier exécutable. Il montre ensuite un **aperçu** : fichiers et tailles, le début de `SKILL.md` (ou `README.md`), la licence (s'il n'en trouve pas, Michel te conseille de vérifier ce que l'auteur autorise avant d'installer), ce qui sera écrit et où. Tu réponds `y` (oui) ou `N` (non).
- Une **skill** est copiée dans `~/.claude/skills/<nom>/` avec un fichier repère `.michel-source`. Michel refuse un dossier qui existe déjà sans ce repère, n'écrit jamais dans un projet, et `source remove` ne supprime qu'un dossier dont le repère correspond.
- Pour un **serveur MCP**, Michel télécharge son code et le bloque sur ce commit, sans jamais le lancer. Il n'écrit rien dans les réglages de Claude Code : il affiche la commande à lancer toi-même, `claude mcp add --scope user <nom> -- <commande> <arguments>`. Un serveur lancé par `npx` télécharge des fichiers au démarrage, hors du contrôle de Michel ; l'aperçu le dit.
- **Jamais de mise à jour automatique.** Chaque jour, Michel regarde seulement l'état du dépôt ; s'il y a un commit plus récent que celui choisi, la source affiche « nouvelle version ». `michel source upgrade <clé>` montre les fichiers ajoutés, modifiés et supprimés et ce qui change dans `SKILL.md`, puis installe après ton accord.

### Dépôts connus que Michel ne propose pas, et pourquoi

- Snyk : il envoie tes données à un tiers, ce que la politique de souveraineté interdit.
- Burp, SecOps, Shodan, VirusTotal, Maigret (outils d'attaque ou d'enquête sur des personnes) : hors sujet, Michel surveille tes propres dépendances.
- IDA, Ghidra, JADX (analyse de programmes déjà compilés) : hors sujet aussi.
- Mobb : il envoie ton code pour le vérifier.
- Dépôts presque inconnus : pas assez de confiance pour les mettre dans un catalogue.

Tu peux quand même ajouter le dépôt que tu veux : `michel source add --kind skill --name <nom> --repo propriétaire/nom --pin <commit de 40 caractères>`.

## À découvrir

`discover.github` (désactivée au départ) cherche les sujets GitHub `mcp-security` et `claude-skills` à chaque `source update` (donc une fois par jour avec la commande planifiée) et garde les dépôts que le registre ne connaît pas. Le digest et la page listent les nouveaux ; `michel source discover --add propriétaire/nom --kind skill --pin <sha>` en ajoute un (désactivé, à installer comme plus haut), `--ignore propriétaire/nom` le masque. Les listes « awesome » du catalogue sont de simples liens, jamais lus.

## Mise à jour quotidienne

`michel source update` lit les sources activées dans cet ordre : bases OSV, enrichissements (puis Michel recalcule les failles : KEV, EPSS, gravité), flux, dépôts, découverte. Une source qui attend encore ton accord ne fait aucune requête. Une source en échec garde ses données précédentes, les autres continuent, et la commande signale l'échec (code de sortie 1). Pour KEV, EPSS, les flux et les bases, Michel demande seulement ce qui a changé depuis la dernière lecture : une source inchangée répond « pas modifié ».

La commande à planifier met d'abord les sources à jour, puis scanne et envoie le digest :

```
michel scan --all --update --digest
```

Le digest a alors une ligne **catalogue** (sources à jour, sources illisibles, sources qui attendent ton accord, nouvelles versions, dépôts à découvrir), qui ne dit rien quand tout est à jour. Voir [daily-digest.fr.md](operations/daily-digest.fr.md).

## En cas de problème

- **« attend ton accord »** : la source est activée mais un hôte n'a pas de règle. Lance `michel source enable <clé>` et lis le texte, ou désactive-la (`source disable <clé>`, ou « désactiver » sur la page).
- **« Michel a atteint la limite de requêtes que GitHub autorise »** (noté `rate budget` dans le journal d'audit et dans `michel source show`) : une mise à jour fait au plus 50 requêtes GitHub sans jeton, 500 avec (`michel secret set github-token`). Chaque skill, serveur MCP ou plugin coûte 3 requêtes. Les sources pas lues aujourd'hui le seront à la prochaine mise à jour ; tu n'as rien à faire, sauf enregistrer un jeton si ça revient souvent.
- **« état du dépôt non relevé, car Michel n'a pas encore ton accord pour contacter api.github.com »** : sans gravité. Le plugin marche normalement ; seule la vérification « nouvelle version de l'outil » manque. Un plugin n'a pas d'hôte à lui : Michel lit l'état de son dépôt seulement après que tu as autorisé `api.github.com` en activant une skill ou un serveur MCP.
- **Trivy ou Semgrep « n'est pas installé sur cette machine »** : Michel cherche le programme dans le `PATH` et ne le télécharge jamais. Installe-le toi-même, ou donne un rapport avec `--input`.
- **Trivy s'arrête en erreur** : Michel le lance sans connexion et sans aucune mise à jour. Si ta version de Trivy a besoin de télécharger quelque chose pour travailler, elle ne peut pas le faire depuis Michel. Lance Trivy une fois toi-même, en dehors de Michel, ou mets-le à jour, puis relance.
- **« Semgrep n'a rien à chercher »** : place tes règles YAML dans `<dossier de données>/plugins/semgrep/rules/`.
- **Une marque KEV ou EPSS manque sur une machine isolée** : c'est normal, et il n'y a pas de solution aujourd'hui. KEV et EPSS sont rangés dans la base de Michel (`michel.db`), et aucune commande ne les exporte. Copier `michel.db` entier ne convient pas : il contient aussi tes projets, tes failles, tes décisions et ton journal d'audit, et remplacerait ceux de la machine isolée. Le scan marche sans ces marques (voir [offline-installation.fr.md](operations/offline-installation.fr.md)).
