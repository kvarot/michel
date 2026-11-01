# Michel

🇬🇧 English version : [README.md](README.md)

Veille quotidienne locale et open source des vulnérabilités connues dans les dépendances de tes projets (Composer, npm ; Go ensuite), avec le coût et les effets de bord de chaque correctif exposés pour que tu décides, une preuve avant tout statut « corrigé », et des fiches de correction compactes (Markdown, skill Claude Code, MCP) pour l'IA de code de ton choix.

État : plans 1 à 6 livrés. Plan 1 : scan hors ligne des lockfiles Composer et npm contre des bases OSV locales, stockage SQLite des findings, journal d'audit chaîné par hachage, passerelle réseau fermée par défaut. Plan 2 : analyse locale de chaque faille (comment le paquet est atteint, quelle mise à jour le corrige, où ton code l'utilise, quels tests le couvrent, journal des modifications local) avec un score de risque public, expliquée en trois phrases en français ou en anglais (`michel analyze`, `michel finding`). Plan 3 : décisions (corriger, reporter, ignorer ; Michel ne te redemande que si quelque chose change), un résumé quotidien (le « digest ») envoyé par e-mail, par webhook signé (envoi automatique vers une adresse web, avec une signature qui prouve l'origine) ou par notification sur le bureau, des secrets gardés hors du fichier de politique, et une page « Aujourd'hui » locale, installable comme une application (`michel decide`, `michel digest`, `michel serve`) ; tous les messages en français ou en anglais. Plan 4 : un registre unique des sources (`michel source`, page « Sources »). Il ajoute d'autres bases OSV, la lecture de `yarn.lock` et `pnpm-lock.yaml`, la liste des failles déjà attaquées (KEV, CISA) et leur probabilité d'attaque (EPSS), placées en tête du digest, les avis des éditeurs (« À lire »), les résultats de Trivy et de Semgrep, et des skills et serveurs MCP bloqués sur une version précise. Chaque source ne contacte ses hôtes qu'après ton accord. Plan 5 : fiches de correction (`michel brief`, MCP, skill) et un agent de correction : Claude Code prépare la correction sur une copie, Michel la vérifie et la teste, tu valides et tu obtiens une branche (page « Corriger », `michel fix`). Plan 6 : les serveurs (`michel target`, page Serveurs) : ce qui tourne sur tes serveurs en SSH, comparé aux failles des distributions et aux règles PHP (PHP2Shell compris), alertes et SMS, et corrections sous forme de scripts `appliquer` et `annuler` avec retour arrière. Pas encore : IA qui tourne sur ton ordinateur, planificateur intégré.

## Démarrage rapide

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # exige une règle réseau autorisée, voir docs/operations/offline-installation.fr.md
bin/michel project add /chemin/du/projet --name monprojet --classification sensitive
bin/michel scan --project monprojet
bin/michel findings --project monprojet --severity critical
bin/michel decide <id-ou-préfixe> defer --for 30d --why "au prochain sprint"
bin/michel digest --send      # ce qui a changé depuis le dernier digest, sur les canaux de notification
bin/michel serve --open       # la page « Aujourd'hui », sur cet ordinateur seulement
bin/michel audit verify
```

- Sources (registre, accord, KEV/EPSS, flux, plugins, skills, MCP) : `docs/sources.fr.md`
- Agent de correction (niveaux, accord, copie de travail, preuve, risques qui restent) : `docs/fix.fr.md`
- Serveurs (SSH, scripts, niveaux, SMS, dépannage) : `docs/servers.fr.md`
- Score de risque : `docs/remediation-risk.fr.md`
- Installation hors ligne et scripts : `docs/operations/offline-installation.fr.md`
- Décisions, digest quotidien, canaux, page « Aujourd'hui », tâche planifiée : `docs/operations/daily-digest.fr.md`
- Ce que le programme peut envoyer sur le réseau : `docs/security/network-egress.fr.md`
- Conception : `docs/superpowers/specs/2026-10-22-michel-design.md`
- Politique de souveraineté (autorité) : `docs/security/sovereignty-policy.md`

## Sources

Tout ce que Michel lit est rangé dans un seul registre. Toutes les sources sont désactivées au départ, sauf les bases OSV de Composer et de npm. Aucune ne se connecte à un serveur avant que tu aies accepté ses adresses (ses « hôtes ») ; quand tu acceptes, Michel écrit lui-même la règle réseau correspondante.

```
bin/michel source list                         # types et états
bin/michel source enable enrich.kev            # failles déjà attaquées (liste KEV) : demande ton accord, écrit la règle
bin/michel source update                       # lit tout de suite les sources activées
bin/michel scan --all --update --digest        # la commande à planifier : met à jour les sources, scanne, envoie le digest
bin/michel source enable skill.trailofbits-code-audit    # accord pour les hôtes GitHub
bin/michel source install skill.trailofbits-code-audit   # affiche un aperçu, puis te demande y (oui) ou N (non)
```

Les types de sources, ce qui est envoyé à chaque hôte, les plugins, les skills et les serveurs MCP : `docs/sources.fr.md`.

## Corriger

Sur la page, le bouton **Corriger** d'une faille la confie à un agent (Claude Code, que tu installes et où tu te connectes toi-même). Il travaille sur une copie de ton projet, dans le dossier de données de Michel, sans pouvoir lancer de commandes ni utiliser tes réglages ; Michel lance lui-même la mise à jour, l'installation (Composer, npm) et les tests, puis te montre la proposition en clair. **Valider** crée une branche `michel/fix-…` dans ton dépôt, rien d'autre : c'est toi qui la fusionnes, puis tu déploies comme d'habitude. La première fois, un écran d'accord (un par projet) te dit ce qui quitte ton ordinateur : le code de la copie, envoyé à Anthropic, et les noms de paquets, envoyés aux dépôts de paquets (Packagist, npm). Il dit aussi ce qui tourne sur ton ordinateur ; rien ne part vers une IA sans cet accord, et jamais pour un projet classé `health` (santé). Chaque projet choisit son niveau : signaler, expliquer (par défaut), préparer seul, ou appliquer les petites mises à jour sûres que tu as autorisées.

```
bin/michel serve --open                         # page « Aujourd'hui », puis « Corriger » sur une faille
bin/michel project set monprojet --test-cmd "vendor/bin/phpunit"   # pour que Michel puisse lancer tes tests
bin/michel brief <id-ou-préfixe>                # la fiche de correction, rien n'est envoyé
```

Les niveaux, l'accord, la copie de travail, ce que l'agent peut et ne peut pas faire, la preuve, le masquage et les risques qui restent : `docs/fix.fr.md`.

## Serveurs

Michel peut aussi te dire si tes **serveurs** sont touchés. Depuis la page **Serveurs**, il les trouve dans `~/.ssh/config` et PhpStorm, se connecte en SSH avec les clés de ton agent SSH (jamais un mot de passe), lit ce qui tourne (PHP, paquets, réglages : en lecture seule, rien d'installé, aucun secret conservé), le compare aux failles des distributions et à ses règles PHP (PHP2Shell compris), et t'alerte, par SMS si c'est urgent. Une correction, ce sont deux scripts lisibles, `appliquer` et `annuler` : rien n'est supprimé, chaque changement est sauvegardé avant, tu valides par empreinte, et une étape qui échoue est annulée. Ajouter un serveur, c'est ton accord pour ses règles réseau.

```
bin/michel target discover                      # serveurs trouvés dans ~/.ssh/config et PhpStorm
bin/michel target add monserveur --user deploy  # puis : michel target trust <id> --fingerprint SHA256:...
bin/michel target check <id>                    # suis-je touché ?
```

Préparer un utilisateur SSH et une clé, ce que Michel lit et ne lit jamais, les scripts et leurs actions, snapshot et sauvegardes, niveaux, SMS et dépannage : `docs/servers.fr.md`.

Licence : Apache-2.0.
