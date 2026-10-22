# Michel

🇬🇧 English version : [README.md](README.md)

Veille quotidienne locale et open source des vulnérabilités connues dans les dépendances de vos projets (Composer, npm ; Go ensuite), avec le coût et les effets de bord de chaque correctif exposés pour que vous décidiez, une preuve avant tout statut « corrigé », et des fiches de correctif compactes (Markdown, skill Claude Code, MCP) pour l'IA de code de votre choix.

État : plans 1 et 2 livrés. Plan 1 : scan hors ligne des lockfiles Composer et npm contre des bases OSV locales, stockage SQLite des findings, journal d'audit chaîné par hachage, passerelle réseau fermée par défaut. Plan 2 : analyse locale de chaque finding (comment le paquet est atteint, quelle mise à jour le corrige, où votre code l'utilise, quels tests le couvrent, journal des modifications local) avec un score de risque public, expliquée en trois phrases en français ou en anglais (`michel analyze`, `michel finding`). Pas encore : décisions, digest quotidien, fiches de correctif, correctifs automatiques, IA.

## Démarrage rapide

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # exige une règle réseau autorisée, voir docs/operations/offline-installation.fr.md
bin/michel project add /chemin/du/projet --name monprojet --classification health
bin/michel scan --project monprojet
bin/michel findings --project monprojet --severity critical
bin/michel audit verify
```

- Score de risque : `docs/remediation-risk.fr.md`
- Installation hors ligne et scripts : `docs/operations/offline-installation.fr.md`
- Ce que le programme peut envoyer sur le réseau : `docs/security/network-egress.fr.md`
- Conception : `docs/superpowers/specs/2026-10-22-michel-design.md`
- Politique de souveraineté (autorité) : `docs/security/sovereignty-policy.md`

Licence : Apache-2.0.
