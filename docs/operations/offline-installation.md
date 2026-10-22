# Offline installation

🇫🇷 Version française : [offline-installation.fr.md](offline-installation.fr.md)

Michel scans lockfiles against OSV databases stored on disk. A scan never touches the network. Only `michel db update` does, and only if you explicitly allow it.

## Build

Requires Go 1.27 or later.

```
go build -o bin/michel ./cmd/michel        # Linux, macOS
go build -o bin/michel.exe ./cmd/michel    # Windows
bin/michel version
```

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

`db update` downloads `Packagist/all.zip` and `npm/all.zip` from the OSV bucket, checks the zip, installs it atomically (the previous database is kept on any failure) and writes a `fetched_at` file next to each zip: `<osv root>/osv-scalibr/<ecosystem>/fetched_at` (RFC 3339 date). `db status` shows `STALE` when that date is older than 7 days. A database copied by other means, without the `fetched_at` file, is used normally but shows no date and is reported `STALE`.

## Copying to an isolated machine

1. On the connected machine, run `michel db update`.
2. Copy the whole `osv/` folder (including the `fetched_at` files) to the isolated machine, at `<data-dir>/osv/` or anywhere you point `db.osv_path` to.
3. On the isolated machine, no allow rule is needed. Check with `michel db status`.

## Scanning

```
michel project add /path/to/project --name myproject --classification health
michel scan --project myproject
michel findings --project myproject [--status new] [--severity critical]
michel audit verify
michel audit list --last 20
```

`scan` looks for `composer.lock` and `package-lock.json` files, skipping any `vendor/` and `node_modules/` directory. A missing OSV database makes the scan fail before anything else, with the command to fix it. A corrupt manifest is recorded as failed (scan status `partial`) and the other manifests are still scanned. `audit verify` checks the hash chain of the audit log. `audit list` must not show any `egress.attempt` event after an offline scan.

## Scripting

`michel scan --json` prints one object:

```json
{
  "results": [
    {
      "scan_id": "...", "project": "myproject", "status": "ok",
      "manifests": [{"rel_path": "composer.lock", "ecosystem": "Packagist", "lock_sha256": "...", "packages": 136, "findings": 21}],
      "new": 0, "still": 215, "reappeared": 0, "gone": 0,
      "by_severity": {"critical": 12, "high": 66, "medium": 116, "low": 21}
    }
  ],
  "failures": [{"project": "...", "error": "..."}]
}
```

`failures` lists projects whose scan could not run at all; it is empty on success. Severities with no finding are omitted from `by_severity`.
