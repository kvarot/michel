# Michel

🇬🇧 English version : [README.md](README.md)

Veille quotidienne locale et open source des vulnérabilités connues dans les dépendances de tes projets (Composer, npm ; Go ensuite), avec le coût et les effets de bord de chaque correctif exposés pour que tu décides, une preuve avant tout statut « corrigé », et des fiches de correctif compactes (Markdown, skill Claude Code, MCP) pour l'IA de code de ton choix.

État : plans 1, 2 et 3 livrés. Plan 1 : scan hors ligne des lockfiles Composer et npm contre des bases OSV locales, stockage SQLite des findings, journal d'audit chaîné par hachage, passerelle réseau fermée par défaut. Plan 2 : analyse locale de chaque faille (comment le paquet est atteint, quelle mise à jour le corrige, où ton code l'utilise, quels tests le couvrent, journal des modifications local) avec un score de risque public, expliquée en trois phrases en français ou en anglais (`michel analyze`, `michel finding`). Plan 3 : décisions (corriger, reporter, ignorer ; Michel ne te redemande que si quelque chose change), un résumé quotidien (le « digest ») envoyé par e-mail, par webhook signé (envoi automatique vers une adresse web, avec une signature qui prouve l'origine) ou par notification sur le bureau, des secrets gardés hors du fichier de politique, et une page « Aujourd'hui » locale, installable comme une application (`michel decide`, `michel digest`, `michel serve`) ; tous les messages en français ou en anglais. Pas encore : fiches de correctif, correctifs automatiques, IA, planificateur intégré.

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

- Score de risque : `docs/remediation-risk.fr.md`
- Installation hors ligne et scripts : `docs/operations/offline-installation.fr.md`
- Décisions, digest quotidien, canaux, page « Aujourd'hui », tâche planifiée : `docs/operations/daily-digest.fr.md`
- Ce que le programme peut envoyer sur le réseau : `docs/security/network-egress.fr.md`
- Conception : `docs/superpowers/specs/2026-10-22-michel-design.md`
- Politique de souveraineté (autorité) : `docs/security/sovereignty-policy.md`

Licence : Apache-2.0.
