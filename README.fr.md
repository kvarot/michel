# Michel

🇬🇧 English version : [README.md](README.md)

Veille quotidienne locale et open source des vulnérabilités connues dans les dépendances de vos projets (Composer, npm ; Go ensuite), avec le coût et les effets de bord de chaque correctif exposés pour que vous décidiez, une preuve avant tout statut « corrigé », et des fiches de correctif compactes (Markdown, skill Claude Code, MCP) pour l'IA de code de votre choix.

État : plan 1 (fondations) implémenté : scan hors ligne des lockfiles Composer et npm contre des bases OSV locales, stockage SQLite des findings, journal d'audit chaîné par hachage, passerelle réseau fermée par défaut. Pas encore : pas de correctif, pas de digest quotidien, pas d'IA.

## Démarrage rapide

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # exige une règle réseau autorisée, voir docs/operations/offline-installation.fr.md
bin/michel project add /chemin/du/projet --name monprojet --classification health
bin/michel scan --project monprojet
bin/michel findings --project monprojet --severity critical
bin/michel audit verify
```

- Installation hors ligne et scripts : `docs/operations/offline-installation.fr.md`
- Ce que le programme peut envoyer sur le réseau : `docs/security/network-egress.fr.md`
- Conception : `docs/superpowers/specs/2026-10-22-michel-design.md`
- Politique de souveraineté (autorité) : `docs/security/sovereignty-policy.md`

Licence : Apache-2.0.
