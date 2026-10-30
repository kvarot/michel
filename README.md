# Michel

🇫🇷 Version française : [README.fr.md](README.fr.md)

Local-first, open-source daily watch for known vulnerabilities in your projects' dependencies (Composer, npm; Go next), with the cost and side effects of each fix laid out so you decide, proof before any "fixed" status, and compact fix briefs (Markdown, Claude Code skill, MCP) for the coding AI of your choice.

Status: plans 1 to 4 delivered. Plan 1: offline scan of Composer and npm lockfiles against local OSV databases, SQLite findings store, hash-chained audit log, deny-by-default network gateway. Plan 2: local analysis of each finding (how the package is reached, which upgrade fixes it, where your code uses it, which tests cover it, local changelog) with a public risk score, explained in three sentences in English or French (`michel analyze`, `michel finding`). Plan 3: decisions (fix, defer, ignore; never asked again unless something changes), a daily digest sent by email, signed webhook or desktop notification, secrets kept outside the policy file, and a local "Today" page installable as an app (`michel decide`, `michel digest`, `michel serve`); every message in English or French. Plan 4: a registry of sources (`michel source`, Sources page): more OSV databases, `yarn.lock` and `pnpm-lock.yaml`, CISA KEV and EPSS at the head of the digest, vendor advisories to read, Trivy and Semgrep findings, pinned skills and MCP servers; each source contacts its hosts only after your consent. Still missing: fix briefs, automatic fixes, AI, a built-in scheduler.

## Quick start

```
go build -o bin/michel ./cmd/michel
bin/michel db update          # needs a network allow rule, see docs/operations/offline-installation.md
bin/michel project add /path/to/project --name myproject --classification sensitive
bin/michel scan --project myproject
bin/michel findings --project myproject --severity critical
bin/michel decide <id-or-prefix> defer --for 30d --why "next sprint"
bin/michel digest --send      # what changed since the last digest, on the notify channels
bin/michel serve --open       # the Today page, on this computer only
bin/michel audit verify
```

- Sources (registry, consent, KEV/EPSS, feeds, plugins, skills, MCP): `docs/sources.md`
- Risk score: `docs/remediation-risk.md`
- Offline installation and scripting: `docs/operations/offline-installation.md`
- Decisions, daily digest, channels, Today page, scheduled task: `docs/operations/daily-digest.md`
- What the program may send over the network: `docs/security/network-egress.md`
- Design (French): `docs/superpowers/specs/2026-10-22-michel-design.md`
- Sovereignty policy (French, authoritative): `docs/security/sovereignty-policy.md`

## Sources

Everything Michel reads lives in one registry. All sources are off except the Composer and npm OSV databases, and none contacts anything before you accept its hosts; your consent writes the network rule for you.

```
bin/michel source list                         # kinds and states
bin/michel source enable enrich.kev            # exploited in the wild (CISA KEV): asks your consent, writes the rule
bin/michel source update                       # read the enabled sources now
bin/michel scan --all --update --digest        # the scheduled line: sources, scans, digest
bin/michel source enable skill.trailofbits-code-audit    # consent to the GitHub hosts
bin/michel source install skill.trailofbits-code-audit   # preview, then y/N
```

The kinds, what leaves for each host, plugins, skills and MCP servers: `docs/sources.md`.

License: Apache-2.0.
