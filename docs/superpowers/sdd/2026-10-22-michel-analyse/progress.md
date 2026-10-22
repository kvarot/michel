# Plan 2 (analyse) - first real analysis on the reference project

Date: 2026-10-22. Binary: `michel dev` (branch `feat/analyse`, `go build -o bin/michel.exe ./cmd/michel`). Only aggregates are published here: no project name, path, package, version or package-specific sentence.

## Commands run

```
michel version
michel analyze --project <ref> --force
michel findings --project <ref> --severity critical --explain
michel finding <id> [--lang fr] [--json]      (once per finding, to compute the aggregates)
michel audit verify
michel audit list --last 400
```

Configuration unchanged from plan 1 (`<config-dir>/michel/config.yaml`, default data dir).

## analyze --force

| project | analyzed | skipped | failed | duration |
|---|---|---|---|---|
| the reference project | 215 | 0 | 0 | 1m56s |

A second run without `--force` analyzed 0, skipped 215, failed 0 in 28 ms (analyses are fresh).

## Aggregates (215 findings, 12 critical)

- Path: 70 direct, 145 transitive.
- Recommendation: `auto_fix` 114, `handoff` 100 (of which 10 with `warning`), `report_only` 1.
- Call-site quality: `psr4|import` 214 (99.5 %: 76 psr4, 138 import), `name` 0, `low` 1.
- Local changelog available: 65 of 215 (30 %).
- At least one covering test: 13 of 215 (6 %); method `callsite` 5, `reference` 8, `none` 202.
- Upgrade target known: 214 of 215. Declared version constraint known: 70 of 215 (the direct dependencies; a transitive package has no constraint of its own in the project manifest).

Reading: the dependencies are installed locally, so the call-site search ran at full quality for nearly all findings. Test coverage is low because most vulnerable packages are build or tooling dependencies that no test imports; the changelog is available only when the package is present in `vendor/` or `node_modules/` with a changelog file.

## Three sentences, fictional finding

Fixture project `demo`, package `acme/lib` (not a real package).

EN:

```
acme/lib 1.2.0 — high — ACME-2026-0002 — project demo — composer.lock

What: acme/lib 1.2.0 is used in 2 places in your code, for example src/Foo.php:12.
Impact: This flaw is serious. Michel is fairly sure it matters to you.
Cost: A small patch update (1.2.0 → 1.2.5). No breaking change found in the changelog. 1 test file covers the code that uses it. Michel can try this fix for you (level 2). Constraint allows it: a plain update is enough.
```

FR (`--lang fr`):

```
Quoi : acme/lib 1.2.0 est utilisé à 2 endroits de ton code, par exemple src/Foo.php:12.
Impact : Cette faille est grave. Michel est assez sûr qu'elle te concerne.
Coût : Une petite mise à jour corrective (1.2.0 → 1.2.5). Aucun changement incompatible trouvé dans le journal des modifications. 1 fichier de test couvre le code qui l'utilise. Michel peut tenter cette correction pour toi (niveau 2). Ta contrainte l'autorise : une simple mise à jour suffit.
```

The wording is the unit-test sample of the explain package; real renderings on the reference project were read locally and are not reproduced.

## Audit

- `michel audit verify`: `audit: 252 events verified`, exit code 0.
- Whole log checked (`audit list --last 400`, by action): `app.start`, `project.add`, `scan.start`/`scan.manifest`/`scan.finish`, `analyze.start`/`analyze.finish`. No `egress.attempt`: neither scan nor analysis made a network request.
- Note: every CLI invocation records one `app.start`, so a loop of `michel finding` calls (one per finding) floods `audit list --last 30` with `app.start` lines; that is expected, not an error.

