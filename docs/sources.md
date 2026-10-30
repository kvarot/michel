# Sources: where Michel reads its data

🇫🇷 Version française : [sources.fr.md](sources.fr.md)

Michel keeps one registry of the places it reads: vulnerability databases, lists of exploited flaws, vendor advisories, analysis tools, skills and MCP servers. Every source is **off** by default except the two OSV databases of Composer and npm. A source contacts nothing until you have accepted the hosts it uses. Manage the registry with `michel source …` or on the **Sources** tab of the local page (`michel serve`).

```
michel source list                # every source, its kind and its state
michel source show enrich.kev     # hosts, network rule, settings, last read
michel source enable enrich.kev   # asks your consent, then writes the network rule
michel source update              # reads the enabled sources now
michel source disable enrich.kev  # turns it off; --forget also removes its network rule
```

## The kinds of sources

| Kind | What it gives | Catalog examples |
|---|---|---|
| `osv` | An offline vulnerability database for one ecosystem, downloaded in full. Scans use it without any network. | `osv.packagist`, `osv.npm` (on by default), `osv.pypi`, `osv.go`, … (23) |
| `enrichment` | Extra facts on the findings: exploited in the wild (KEV), chance of exploitation (EPSS), a missing severity score (Vulnrichment, NVD, CIRCL). | `enrich.kev`, `enrich.epss`, `enrich.vulnrichment`, `enrich.nvd`, `enrich.circl` |
| `feed` | Vendor security advisories to read ("To read"), filtered by the technologies you use. | `feed.nginx`, `feed.symfony`, `feed.postgresql`, … (55) |
| `plugin` | An analysis tool on your machine whose findings join the same list: Trivy and Semgrep are run by Michel, CodeQL and ZAP reports are only read. | `plugin.trivy`, `plugin.semgrep`, `plugin.codeql`, `plugin.zap` |
| `skill` | A Claude Code skill, pinned to a commit, installed after a preview. | `skill.trailofbits-code-audit`, `skill.claude-code-owasp` |
| `mcp` | An MCP server, pinned to a commit; Michel shows the line to run, you run it. | `mcp.semgrep`, `mcp.safedep-vet`, `mcp.cve-search`, `mcp.wazuh` |

A seventh kind, `reference`, holds useful links Michel never reads (OpenSSF, CVSS, "awesome" lists…), plus `discover.github`, which searches GitHub topics for new repositories (see "To discover").

The catalog is embedded in the binary. At each start Michel brings the registry in line with it: new entries are added, changed ones rewritten (name, url, hosts, purpose, catalog settings), and **your choices are kept** (on or off, hidden, technologies, your settings). An entry the catalog drops is hidden, never deleted. `michel source reset <key>` puts one entry back as the catalog has it; `michel source add --kind …` adds your own (it starts off).

## States

| State | Meaning |
|---|---|
| `off` | Not used. |
| `waiting_consent` | Turned on, but one of its hosts has no network rule yet. Michel does not contact it: `source update` prints `· <key> waits for your consent`, and the digest and the page say so too. |
| `on` | Turned on and every host allowed. |
| `hidden` | Removed from the lists (`source remove` on a catalog entry). `source reset <key>` brings it back. |

A source can go back to `waiting_consent` on its own. This happens when a new version of Michel changes the server address of a source: your former consent covered only the old address, so Michel asks again before contacting the new one.

## The consent screen and the rule it writes

`michel source enable <key>` (or the switch on the page) lists each host the source would contact that has no rule yet, with one sentence saying what leaves:

- a download (OSV, KEV, EPSS, feeds): "Nothing from your projects leaves: it is a download.";
- on-demand enrichments (Vulnrichment, NVD, CIRCL): the CVE numbers of your findings, nothing else;
- skills, MCP servers and plugin status: the name of the public repository and the chosen version (and, if you set a GitHub token, GitHub knows it is you);
- discovery: the names of a few topics.

On a terminal you answer `y` or `N`; in a script `--yes` accepts. Without a terminal and without `--yes`, Michel refuses and prints the text. Once you accept, Michel:

1. writes one rule per host into `sovereignty.network.allow` of your policy file, for example `{host: www.cisa.gov, purpose: source.enrich}`; it keeps a copy (`config.yaml.bak`), keeps your comments and creates the file with only that rule if you had none;
2. reloads the policy, so the command takes the rule at once (a consent given on the page needs no restart of `michel serve`);
3. records `source.consent` in the audit log (key, hosts, purpose, who), then `source.enable`.

A host already allowed by another source asks nothing (the consent is still recorded). Turning a source off keeps its rule; `disable --forget` removes it, and is refused while another enabled source needs the same rule.

## What leaves, source by source

| Source | Host | Purpose | What is sent |
|---|---|---|---|
| `osv.*` (23 databases) | `osv-vulnerabilities.storage.googleapis.com` | `osv.db` | Nothing: the whole database of the ecosystem is downloaded. |
| `enrich.kev` | `www.cisa.gov` | `source.enrich` | Nothing: the whole KEV list is downloaded. |
| `enrich.epss` | `epss.empiricalsecurity.com` | `source.enrich` | Nothing: the file of the day is downloaded. |
| `enrich.vulnrichment` | `raw.githubusercontent.com` | `source.enrich` | One CVE number per request (findings without severity), 200 at most per update. |
| `enrich.nvd` | `services.nvd.nist.gov` | `source.enrich` | One CVE number per request, 100 at most per update, one request every 6 s (0.6 s with the `nvd-api-key` secret, sent as a header). |
| `enrich.circl` | `vulnerability.circl.lu` | `source.enrich` | One CVE number per request, 200 at most per update. |
| `feed.*` (55 feeds) | the vendor's site (27 hosts), or `api.github.com` for the 28 feeds read from GitHub advisories | `source.feed` | Nothing but the request for the feed; GitHub advisories carry your token if you set one. |
| `skill.*`, `mcp.*` | `api.github.com`, `codeload.github.com` | `source.repo` | The repository name and the pinned commit; your GitHub token if set. |
| `plugin.*` | none of its own | `plugin.<key>` (never allowed) | Nothing (see "Plugins"). Their repository state is read only if `api.github.com` is already allowed for `source.repo`. |
| `discover.github` | `api.github.com` | `source.discover` | The topic names `mcp-security` and `claude-skills`. |

Every request goes through the egress gateway and is written to the audit log as `egress.attempt`. The full inventory, with caps and what the tests prove, is in [network-egress.md](security/network-egress.md).

## KEV and EPSS

- **KEV** (`enrich.kev`) is CISA's list of vulnerabilities attackers already use. A finding on it shows `[KEV]` in `michel findings`, `kev: yes` in `michel finding`, a red chip on the page, and goes to the **head of the digest** ("Exploited in the wild, fix these first"), as long as it is open or decided "fix". The ones you deferred or ignored with a reason come back as one count line, not every morning. A malicious package (OSV `MAL-` advisory) follows the same rules.
- KEV does **not** add points to the risk score: this score says how likely the fix is to break something, not how urgent it is. KEV marks the finding "fix this first" and puts it first in every list (see [remediation-risk.md](remediation-risk.md)).
- If a finding you decided to ignore or defer appears on the KEV list, Michel asks you again: the decision is superseded (`kev_changed`) and the finding is back in "decisions to review".
- **EPSS** (`enrich.epss`) estimates the chance a vulnerability is exploited within 30 days. Michel shows this figure only when the flaw is in the half of known flaws with the highest chance of exploitation ("Chance of exploitation within 30 days: 12%, higher than 95% of known flaws."); below that, it shows nothing rather than a small number that would wrongly reassure.

## "To read" and your technologies

Feeds bring vendor advisories. They never create a finding (Michel does not know the version you run); they make a **To read** list in the digest (10 items at most), on the Today page and in `michel source items`. An item is "to read" when its source is tagged with one of your technologies, or when its title names one (whole word, any case). Your technologies come from three places:

1. automatic, from your lockfiles (`php`, `node`, `symfony`, `laravel`, `react`, `vue`…), recomputed at each scan;
2. per project: `michel project set <name> --tech nginx --tech postgresql`;
3. global, for what is in no project: `michel tech add nginx`.

A feed that is off but matches one of your technologies is marked "suggested for you" on the page; Michel never turns it on itself. `michel source read <id>` (or `--all`) marks items as read. Items are kept 180 days.

## Plugins

- **Trivy** (`plugin.trivy`): Michel runs `trivy fs --scanners misconfig` (setting mistakes in Dockerfile, compose, Kubernetes files) with the update switches off (`--skip-db-update`, `--skip-check-update`, `--offline-scan`) and its cache in Michel's data folder. Vulnerability and secret scanning are not run.
- **Semgrep** (`plugin.semgrep`): Michel runs `semgrep scan --metrics=off --disable-version-check` with **only the rules you put** in `<data dir>/plugins/semgrep/rules/` (YAML files). With an empty folder it stops and says so. To get rules, download them yourself, outside Michel, for example from the Semgrep registry (`p/php`, `p/javascript`), and copy the YAML files into that folder.
- **CodeQL** and **ZAP**: report reading only, `michel source run plugin.codeql --project <name> --input report.sarif`. CodeQL does not handle PHP; ZAP attacks a site to test it, run it on a test copy.
- Michel runs an enabled plugin with `run: true` at the end of `michel scan` of a project, or on demand with `michel source run <key> --project <name>`. A failure is a warning, not an error of the scan.
- Their findings join the same list (kinds `config` and `code`), with the same decisions and digest. Only a new run of the same plugin on the same project can mark them gone.

**How a tool is kept off the network.**

- Michel never runs a tool from the project folder, but from `<data dir>/plugins/<tool>/`.
- The arguments are fixed: no text of yours is added.
- The tool gets only a short list of environment variables: no secret, no token.
- It is stopped after 30 minutes, and its output is cut at 64 KB.
- Its proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) point to a **local go-between that refuses everything** (the "refusal proxy"): every connection attempt is refused (403, and `CONNECT` refused) and logged as a denied `egress.attempt` with purpose `plugin.<key>`.
- It is a **safeguard, not a guarantee**: a tool that ignores these settings is not stopped.
- Trivy and Semgrep themselves, and their rules, are updated by you, outside Michel.

## Skills and MCP servers

- `michel source show <key>` gives the repository, the pinned commit, the licence found, the note and, after an update, its state (stars, last push, archived, new version).
- `michel source install <key>` (once the source is enabled with `source enable <key>`) downloads the archive of the **pinned commit** (`codeload.github.com`, 50 MB compressed, 200 MB and 5,000 files extracted at most; paths leaving the folder and symbolic links refused, no executable bit kept) into the data folder, then shows a **preview**: files and sizes, the start of `SKILL.md` (or `README.md`), the licence ("Licence not found: check it before installing." when none), what will be written and where. You answer `y` or `N`.
- A **skill** is copied to `~/.claude/skills/<name>/` with a `.michel-source` marker file. Michel refuses a folder that exists without its marker, never writes inside a project, and `source remove` deletes only a folder whose marker matches.
- For an **MCP server**, Michel downloads its code and pins it to the commit, without ever starting it. Michel writes nothing in Claude Code's settings: it prints the line to run yourself, `claude mcp add --scope user <name> -- <command> <args>`. A server started with `npx` downloads at start-up, outside Michel's control; the preview says it.
- **Never an automatic update.** Each day Michel only reads the repository state; when there is a newer commit than the pinned one, the source shows "new version". `michel source upgrade <key>` shows the files added, changed and removed and the change of `SKILL.md`, then installs after your consent.

### Known repositories Michel does not offer, and why

- Snyk: it sends your data to a third party, against the sovereignty policy.
- Burp, SecOps, Shodan, VirusTotal, Maigret (attack tools, or tools to investigate people): off topic, Michel watches your own dependencies.
- IDA, Ghidra, JADX (analysis of already compiled programs): off topic too.
- Mobb: it sends code to be checked.
- Nearly unknown repositories: not enough trust to put them in a catalog.

You can still add any repository yourself: `michel source add --kind skill --name <name> --repo owner/name --pin <40-character commit>`.

## To discover

`discover.github` (off by default) searches the GitHub topics `mcp-security` and `claude-skills` once a day and keeps the repositories the registry does not know. The digest and the page list the new ones; `michel source discover --add owner/name --kind skill --pin <sha>` adds one (off, to install as above), `--ignore owner/name` hides it. The "awesome" lists of the catalog are links only, never read.

## Daily update

`michel source update` reads the enabled sources in this order: OSV databases, enrichments (then the findings are recomputed: KEV, EPSS, severity), feeds, repositories, discovery. A source still waiting for your consent makes no network request. A source that fails keeps its previous data, the others go on, and the command exits 1. KEV, EPSS, feeds and databases send `If-None-Match` or `If-Modified-Since`: an unchanged source answers "not modified".

The scheduled line reads the sources first, then scans and sends the digest:

```
michel scan --all --update --digest
```

The digest then has a **catalog** line (sources up to date, sources that could not be read, waiting for your consent, new versions, repositories to discover), silent when everything is current. See [daily-digest.md](operations/daily-digest.md).

## Troubleshooting

- **"waits for your consent"**: the source is on but a host has no rule. Run `michel source enable <key>` and read the text, or turn it off (`source disable <key>`, or "turn off" on the page).
- **"the GitHub request budget is spent"** (recorded as `rate budget` in the audit log and in `michel source show`): one update spends at most 50 GitHub requests without a token, 500 with one (`michel secret set github-token`). Each skill, MCP server or plugin costs 3 requests. The sources not read today are read at the next update; there is nothing to do, except set a token if it happens often.
- **"repository state not read, no network rule for api.github.com yet"**: harmless. The plugin works as usual; only the "new version of the tool" check is missing. A plugin has no host of its own: Michel reads its repository state only once you allowed `api.github.com` by enabling a skill or an MCP server.
- **Trivy or Semgrep "is not installed on this machine"**: Michel looks for the program on the `PATH` and never downloads it. Install it yourself, or give a report with `--input`.
- **Trivy stops with an error**: Michel runs it without a connection and with every update turned off. If your Trivy version needs to download something to work, it cannot do so from Michel. Run Trivy once yourself, outside Michel, or update it, then run it again.
- **"Semgrep has no rules to run"**: put your YAML rules in `<data dir>/plugins/semgrep/rules/`.
- **A KEV or EPSS mark is missing on an isolated machine**: this is expected, and there is no fix today. KEV and EPSS live in Michel's database (`michel.db`), and no command exports them. Copying the whole `michel.db` does not work: it also holds your projects, findings, decisions and audit log, and would replace those of the isolated machine. Scans work without these marks (see [offline-installation.md](operations/offline-installation.md)).
