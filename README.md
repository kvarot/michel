# Michel

🇫🇷 Version française : [README.fr.md](README.fr.md)

Local-first, open-source daily watch for known vulnerabilities in your projects' dependencies (Composer, npm; Go next), with the cost and side effects of each fix laid out so you decide, proof before any "fixed" status, and compact fix briefs (Markdown, Claude Code skill, MCP) for the coding AI of your choice.

Status: plans 1 to 7 delivered. Plan 1: offline scan of Composer and npm lockfiles against local OSV databases, SQLite findings store, hash-chained audit log, deny-by-default network gateway. Plan 2: local analysis of each finding (how the package is reached, which upgrade fixes it, where your code uses it, which tests cover it, local changelog) with a public risk score, explained in three sentences in English or French (`michel analyze`, `michel finding`). Plan 3: decisions (fix, defer, ignore; never asked again unless something changes), a daily digest sent by email, signed webhook or desktop notification, secrets kept outside the policy file, and a local "Today" page installable as an app (`michel decide`, `michel digest`, `michel serve`); every message in English or French. Plan 4: a registry of sources (`michel source`, Sources page): more OSV databases, `yarn.lock` and `pnpm-lock.yaml`, CISA KEV and EPSS at the head of the digest, vendor advisories to read, Trivy and Semgrep findings, pinned skills and MCP servers; each source contacts its hosts only after your consent. Plan 5: fix briefs (`michel brief`, MCP, skill) and a fix agent: Claude Code prepares the fix on a copy, Michel checks and tests it, you approve and get a branch (Fix page, `michel fix`). Plan 6: servers (`michel target`, Servers page): what runs on your servers over SSH, compared with the distributions' advisories and PHP rules (PHP2Shell included), alerts and SMS, and fixes as `apply` and `undo` scripts with rollback. Plan 7: server logs (Logs block of the server sheet): Michel reads the log files you declare over SSH, filters them on the server, and warns you by itself about PHP, PostgreSQL and application errors, with no log line kept or sent. Still missing: an AI that runs on your computer, a scheduler for project scans.

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

Adding and checking a project also work from the page: My projects, "Add a project" and "Check this project" (the same pass as `michel scan`, run in the background). The test command and the classification stay on the command line.

- Sources (registry, consent, KEV/EPSS, feeds, plugins, skills, MCP): `docs/sources.md`
- Fix agent (levels, consent, work copy, proof, residual risks): `docs/fix.md`
- Servers (SSH, scripts, levels, SMS, troubleshooting, logs): `docs/servers.md`
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

## Fix

On the page, the **Fix** button of a finding hands it to an agent (Claude Code, which you install and log in to yourself). It works on a copy of your project in Michel's data folder, without being able to run commands or use your settings; Michel runs the update, the install (Composer, npm) and the tests itself, then shows you the proposal in plain words. Without attachment to a Git service, **Approve** creates a branch `michel/fix-…` in your repository, nothing else (see [docs/fix.md](docs/fix.md) for the attached case): you merge it, then deploy as usual. The first time, a consent screen (one per project) tells you what leaves your computer: the code of the copy, sent to Anthropic, and package names, sent to the package registries (Packagist, npm). It also says what runs on your computer; nothing goes to an AI without it, and never for a project classified `health`. Each project chooses its level: report, explain (default), prepare alone, or apply the safe minor updates you allowed.

```
bin/michel serve --open                         # Today page, then "Fix" on a finding
bin/michel project set myproject --test-cmd "vendor/bin/phpunit"   # so that Michel can run your tests
bin/michel brief <id-or-prefix>                 # the fix brief, nothing sent
```

Levels, consent, the work copy, what the agent can and cannot do, the proof, masking and residual risks: `docs/fix.md`.

## Servers

Michel can also tell you whether your **servers** are affected. From the **Servers** page it finds them in `~/.ssh/config` and PhpStorm, signs in over SSH with the keys of your SSH agent (never a password), reads what runs there (PHP, packages, settings: read-only, nothing installed, no secret kept), compares it with the distributions' advisories and its PHP rules (PHP2Shell included), and alerts you, by SMS if it is urgent. A fix is two readable scripts, `apply` and `undo`: nothing is deleted, every change is saved first, you validate by fingerprint, and a failed configuration step is rolled back (for a package, your snapshot is the way back). Adding a server is your consent for its network rules.

```
bin/michel target discover                      # servers found in ~/.ssh/config and PhpStorm
bin/michel target add myserver --user deploy    # then: michel target trust <id> --fingerprint SHA256:...
bin/michel target check <id>                    # am I affected?
```

Preparing an SSH user and a key, what Michel reads and never reads, the scripts and their actions, snapshot and backups, levels, SMS and troubleshooting: `docs/servers.md`.

Michel can also **read the logs** you declare and warn you by itself about errors, without keeping or sending a single log line. It works from the Logs block of the server sheet, only while your computer is on and `michel serve` runs. What is read, what leaves the server, how long it is kept and what to put in your record of processing activities (the GDPR document where you note what you do with personal data): `docs/servers.md`, section 13. This is not legal advice: have your data protection officer (DPO) or a lawyer check it.

License: Apache-2.0.
