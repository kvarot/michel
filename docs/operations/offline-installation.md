# Offline installation

🇫🇷 Version française : [offline-installation.fr.md](offline-installation.fr.md)

Michel scans lockfiles against OSV databases stored on disk. A scan never touches the network. Only `michel db update` and `michel source update` (or `scan --update`) do, and only for the hosts you explicitly allowed.

## Build

Requires Go 1.27 or later.

```
go build -o bin/michel ./cmd/michel        # Linux, macOS
go build -o bin/michel.exe ./cmd/michel    # Windows
bin/michel version
```

The Today page (`michel serve`) is embedded in the binary. To rebuild it from `web/`, run `make web` (needs Node and npm; `make build` does it automatically when npm is present) before `go build`. Without it the binary still builds and `michel serve` shows a short text page.

## First run and config location

Michel reads `config.yaml` and stores its data (SQLite store, OSV databases) in `<user config dir>/michel/`, where the user config dir is the Go `os.UserConfigDir()`:

| OS | Folder |
|---|---|
| Linux | `~/.config/michel/` (or `$XDG_CONFIG_HOME/michel/`) |
| macOS | `~/Library/Application Support/michel/` |
| Windows | `%AppData%\michel\` |

Override with `--config <file>` and `--data-dir <dir>` (both must be given if no user config dir exists). Without a config file, the built-in `strict_local` defaults apply: all outbound network is denied. `config.example.yaml` lists every default. Michel refuses to start on an unreadable policy file.

The OSV databases live in `<data-dir>/osv/` unless `db.osv_path` is set.

## Updating the databases (connected machine)

Downloads are denied by default. Add an allow rule to `config.yaml`:

```yaml
sovereignty:
  network:
    allow:
      - host: osv-vulnerabilities.storage.googleapis.com
        purpose: osv.db
```

Then:

```
michel db update
michel db status
```

`db update` downloads the `all.zip` of each enabled ecosystem from the OSV bucket (`Packagist/all.zip` and `npm/all.zip` by default), checks the zip, installs it atomically (the previous database is kept on any failure) and writes a `fetched_at` file next to each zip: `<osv root>/osv-scalibr/<ecosystem>/fetched_at` (RFC 3339 date). `db status` shows `STALE` when that date is older than 7 days. A database copied by other means, without the `fetched_at` file, is used normally but shows no date and is reported `STALE`.

## Copying to an isolated machine

1. On the connected machine, run `michel db update`.
2. Copy the whole `osv/` folder (including the `fetched_at` files) to the isolated machine, at `<data-dir>/osv/` or anywhere you point `db.osv_path` to.
3. On the isolated machine, no allow rule is needed. Check with `michel db status`.

## Other databases, KEV and EPSS

The OSV databases Michel downloads are those of the enabled `osv.*` sources: `osv.packagist` and `osv.npm` by default. `michel source enable osv.pypi` (for example) adds one, after your consent to the OSV bucket; `michel source update` (or `scan --update`) then downloads every enabled database, not only Packagist and npm. They all land in the same `osv/` folder, one sub-folder per ecosystem, so the copy above carries them too. Michel reads only Composer and npm lockfiles today (`composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`): the other databases wait for their readers.

KEV and EPSS (`enrich.kev`, `enrich.epss`) are not files: `source update` stores them in Michel's database (`<data-dir>/michel.db`), next to your findings and decisions. There is no command to export or import them in this version, so they cannot be carried to an isolated machine on their own. Without them, a scan works the same; findings simply have no "exploited in the wild" mark and no EPSS figure. See [sources.md](../sources.md).

## Scanning

```
michel project add /path/to/project --name myproject --classification sensitive
michel scan --project myproject
michel findings --project myproject [--status new] [--severity critical]
michel audit verify
michel audit list --last 20
```

`scan` looks for `composer.lock`, `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml` files, skipping any `vendor/` and `node_modules/` directory. A folder without any lockfile is recorded as `empty`, not as a failure. A missing OSV database makes the scan fail before anything else, with the command to fix it. A corrupt manifest is recorded as failed (scan status `partial`) and the other manifests are still scanned. `audit verify` checks the hash chain of the audit log. `audit list` must not show any `egress.attempt` event after an offline scan.

## Analysis

```
michel analyze --project myproject [--force]
michel analyze --all
michel scan --project myproject [--no-analyze]
```

`analyze` reads only the project's own files (never the network, never an AI). For each new or pending finding it works out how the package is reached (direct or transitive, through which packages), which upgrade fixes it and whether your version constraint allows it, where your code uses the package, which tests cover that code, what the local changelog says, and a risk score with a recommendation (`auto_fix`, `handoff`, `report_only`; see [remediation-risk.md](../remediation-risk.md)). `scan` runs it automatically unless `--no-analyze` is given. `--force` recomputes analyses that are still fresh. Search quality depends on the dependencies being installed locally (`vendor/`, `node_modules/`): without them Michel falls back to a weaker name search and says so.

## One finding in detail

```
michel finding <id-or-prefix> [--lang fr] [--json]
michel findings --project myproject --severity critical --explain
```

`finding` prints three sentences: What (how the package is used in your code), Impact (how serious and how likely it concerns you), Cost (size of the upgrade, changelog, tests, what Michel may do). An id prefix is enough when it is unambiguous. `findings --explain` prints the same What sentence under each row.

## Language

`--lang en|fr` (any command that prints text for you) overrides `assistant.lang` of the policy file, which defaults to `auto`: the language of the system, English if it is not French. The language only changes the wording; the facts, the score and the JSON keys are the same. Texts stored in the data folder (scan errors, channel errors, audit evidence) stay in English.

## Decisions, digest, notifications and the Today page

```
michel decide <id-or-prefix> fix|defer|ignore [--why "..."] [--for 30d | --until YYYY-MM-DD]
michel decide --project myproject --package vendor/lib defer
michel decisions --project myproject [--status superseded]
michel digest [--send] [--since YYYY-MM-DD] [--html | --json]
michel scan --all --digest
michel notify list
michel notify test <channel>
michel secret set|list|delete <name>
michel serve [--listen 127.0.0.1:7331] [--open]
```

None of these needs the network, except `digest --send`, `scan --all --digest` and `notify test` on an email or webhook channel, which need an allow rule for that channel's host. Everything is described in [daily-digest.md](daily-digest.md), including how to schedule the daily run.

## Per-project settings

```
michel project set myproject --core-package vendor/core --core-package other-lib
michel project set myproject --risk major_jump=50 --risk many_call_sites_threshold=20
```

`--core-package` replaces the whole list of packages whose upgrade is riskier for this project (`--core-package ''` clears it). `--exclude <folder-name>` (repeatable) replaces the list of folder names that scans and analyses skip at any depth, on top of `vendor/` and `node_modules/` (`--exclude ''` clears it), for example `michel project set myproject --exclude fixtures --exclude legacy`. `--risk key=value` overrides one value of the `risk.*` policy section for this project only; other overrides are kept. Stored analyses keep a fingerprint of these settings, so they are recomputed on the next scan or `michel analyze --project myproject`; `--force` is not needed. The keys and thresholds are described in [remediation-risk.md](../remediation-risk.md) and listed in `config.example.yaml`.

## Scripting

`michel scan --json` prints one object:

```json
{
  "results": [
    {
      "scan_id": "...", "project": "myproject", "status": "ok",
      "manifests": [{"rel_path": "composer.lock", "ecosystem": "Packagist", "lock_sha256": "...", "packages": 120, "findings": 40}],
      "new": 0, "still": 40, "reappeared": 0, "gone": 0,
      "by_severity": {"critical": 4, "high": 10, "medium": 20, "low": 6}
    }
  ],
  "failures": [{"project": "...", "error": "..."}]
}
```

`failures` lists projects whose scan could not run at all; it is empty on success. Severities with no finding are omitted from `by_severity`.

`michel analyze --json` prints one object:

```json
{
  "results": [{"project": "myproject", "analyzed": 42, "skipped": 3, "failed": 0, "duration_ms": 1234}],
  "failures": []
}
```

`michel finding <id> --json` prints `{"finding": {...}, "analysis": {...}, "explanation": {...}}`. `finding` is the stored finding (id, package, versions, severity, status...). `analysis` is `null` until the finding is analyzed; its keys are snake_case and stable:

```json
{
  "finding_id": "...", "project_id": "...", "computed_at": "...", "michel_version": "...", "inputs_hash": "...",
  "path": {"directness": "direct|transitive|unknown", "via": [], "constraint": "^1.2"},
  "has_root_manifest": true,
  "upgrade": {"target": "1.2.5", "jump": "patch|minor|major|unknown|none", "constraint_allows": true},
  "calls": {"sites": [{"file": "src/Http/ApiClient.php", "line": 41, "is_test": false}], "count": 3,
            "quality": "psr4|name|low|noautoload|import", "namespaces": [], "unreadable": 0,
            "unreadable_paths": [], "test_files": [], "test_file_count": 0, "test_hit_count": 0, "source_files": []},
  "coverage": {"test_files": [], "count": 0, "method": "callsite|reference|none", "skipped": [], "unreadable": 0},
  "changelog": {"source": "...", "excerpt": "...", "available": true, "breaking": false, "breaking_lines": [], "note": ""},
  "risk": {"score": 30, "recommendation": "auto_fix|handoff|report_only", "warning": false, "terms": {"no_tests": 20, "direct": 10}}
}
```

Code lines themselves are never included. `explanation` holds the three sentences (`what`, `impact`, `cost`) in the requested language.
