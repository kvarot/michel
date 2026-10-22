# Michel

🇫🇷 Version française : [README.fr.md](README.fr.md)

Local-first, open-source daily watch for known vulnerabilities in your projects' dependencies (Composer, npm; Go next), with the cost and side effects of each fix laid out so you decide, proof before any "fixed" status, and compact fix briefs (Markdown, Claude Code skill, MCP) for the coding AI of your choice.

Status: plan 1 (foundation) implemented: offline scan of Composer and npm lockfiles against local OSV databases, SQLite findings store, hash-chained audit log, deny-by-default network gateway. Not yet: no fix, no daily digest, no AI.

## Quick start

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # needs a network allow rule, see docs/operations/offline-installation.md
bin/michel project add /path/to/project --name myproject --classification health
bin/michel scan --project myproject
bin/michel findings --project myproject --severity critical
bin/michel audit verify
```

- Offline installation and scripting: `docs/operations/offline-installation.md`
- What the program may send over the network: `docs/security/network-egress.md`
- Design (French): `docs/superpowers/specs/2026-10-22-michel-design.md`
- Sovereignty policy (French, authoritative): `docs/security/sovereignty-policy.md`

License: Apache-2.0.
