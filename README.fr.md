# Michel

🇬🇧 English version : [README.md](README.md)

Veille quotidienne locale et open source des vulnérabilités connues dans les dépendances de tes projets (Composer, npm ; Go ensuite), avec le coût et les effets de bord de chaque correctif exposés pour que tu décides, une preuve avant tout statut « corrigé », et des fiches de correctif compactes (Markdown, skill Claude Code, MCP) pour l'IA de code de ton choix.

État : plans 1 à 4 livrés. Plan 1 : scan hors ligne des lockfiles Composer et npm contre des bases OSV locales, stockage SQLite des findings, journal d'audit chaîné par hachage, passerelle réseau fermée par défaut. Plan 2 : analyse locale de chaque faille (comment le paquet est atteint, quelle mise à jour le corrige, où ton code l'utilise, quels tests le couvrent, journal des modifications local) avec un score de risque public, expliquée en trois phrases en français ou en anglais (`michel analyze`, `michel finding`). Plan 3 : décisions (corriger, reporter, ignorer ; Michel ne te redemande que si quelque chose change), un résumé quotidien (le « digest ») envoyé par e-mail, par webhook signé (envoi automatique vers une adresse web, avec une signature qui prouve l'origine) ou par notification sur le bureau, des secrets gardés hors du fichier de politique, et une page « Aujourd'hui » locale, installable comme une application (`michel decide`, `michel digest`, `michel serve`) ; tous les messages en français ou en anglais. Plan 4 : un registre unique des sources (`michel source`, page « Sources »). Il ajoute d'autres bases OSV, la lecture de `yarn.lock` et `pnpm-lock.yaml`, la liste des failles déjà attaquées (KEV, CISA) et leur probabilité d'attaque (EPSS), placées en tête du digest, les avis des éditeurs (« À lire »), les résultats de Trivy et de Semgrep, et des skills et serveurs MCP bloqués sur une version précise. Chaque source ne contacte ses hôtes qu'après ton accord. Pas encore : fiches de correctif, correctifs automatiques, IA, planificateur intégré.

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

Licence : Apache-2.0.
