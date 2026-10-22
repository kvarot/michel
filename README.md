# Michel

🇫🇷 Version française : [README.fr.md](README.fr.md)

Local-first, open-source daily watch for known vulnerabilities in your projects' dependencies (Composer, npm; Go next), with the cost and side effects of each fix laid out so you decide, proof before any "fixed" status, and compact fix briefs (Markdown, Claude Code skill, MCP) for the coding AI of your choice.

Status: plans 1 and 2 delivered. Plan 1: offline scan of Composer and npm lockfiles against local OSV databases, SQLite findings store, hash-chained audit log, deny-by-default network gateway. Plan 2: local analysis of each finding (how the package is reached, which upgrade fixes it, where your code uses it, which tests cover it, local changelog) with a public risk score, explained in three sentences in English or French (`michel analyze`, `michel finding`). Still missing: decisions, daily digest, fix briefs, automatic fixes, AI.

## Quick start

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # needs a network allow rule, see docs/operations/offline-installation.md
bin/michel project add /path/to/project --name myproject --classification sensitive
bin/michel scan --project myproject
bin/michel findings --project myproject --severity critical
bin/michel audit verify
```

- Risk score: `docs/remediation-risk.md`
- Offline installation and scripting: `docs/operations/offline-installation.md`
- What the program may send over the network: `docs/security/network-egress.md`
- Design (French): `docs/superpowers/specs/2026-10-22-michel-design.md`
- Sovereignty policy (French, authoritative): `docs/security/sovereignty-policy.md`

License: Apache-2.0.
