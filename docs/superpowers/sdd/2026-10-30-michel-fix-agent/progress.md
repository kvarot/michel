# Plan 5 (fix agent) - real run on a demo project

Date: 2026-10-31. Binary: built from `feat/fix-agent` at 2c38f10 (`npm run build` in `web/`, then `go build`). Only aggregates are published here. The real run was performed by the controller with a throw-away data folder and policy file (both absent at start, so the default `strict_local` policy), on a project created for the occasion and registered as `demo`: a git repository holding a `composer.json` / `composer.lock` with one dependency, a public library in an older version with known advisories. Never a private project. Claude Code 2.1.314, with the user's own login, launched by Michel.

## Steps

```
michel source enable osv.packagist --yes
michel source update                                     (7 s)
michel project add <folder> --name demo --fix-level 1 --classification internal
michel scan --project demo
michel serve                                             then, on the page:
  Fix page -> first finding -> "OK, répare"
  consent dialog in strict_local -> "Passer en mode standard et autoriser les IA externes" (ruling 41)
  Michel's own update on the pristine copy, then Claude Code
  agent: reads Michel's data through MCP, edits composer.json, propose_fix
  "Valider"
michel audit verify
```

1. Scan of `demo`: 1 lockfile, 14 findings (6 high, 8 medium).
2. The consent dialog explained `strict_local` and offered the switch; the click recorded `policy.mode` then `ai.consent`.
3. Michel ran its own update on the copy as committed (`composer update <package>:^<target> --with-all-dependencies --no-scripts --no-plugins --no-interaction`), then launched Claude Code.
4. The agent consulted Michel through MCP, raised the constraint in `composer.json` to the fixed version and called `propose_fix` after about 40 s.
5. Michel: tests not run (no test command configured for `demo`); re-scan of the copy: the advisory was gone; proposal recorded with versions 7.4.0 to 7.4.3, risk 30, and its fingerprint.
6. "Valider": `fix.approve` ok, then `fix.apply` refused by Michel (finding 2). No branch was created; the working tree, the index and the history of `demo` were unchanged (0 changes, 1 commit).
7. `audit verify`: 44 events verified, exit code 0.

## Aggregates

| item | value |
|---|---|
| time from start to proposal | 40 s (`fix.start` to `fix.propose`) |
| audit events by action | `egress.attempt` 21, `app.start` 6, `source.read` 2, `source.consent` 1, `source.enable` 1, `project.add` 1, `scan.start` 1, `scan.manifest` 1, `scan.finish` 1, `analyze.start` 1, `analyze.finish` 1, `api.start` 1, `policy.mode` 1, `ai.consent` 1, `fix.start` 1, `fix.propose` 1, `fix.approve` 1, `fix.apply` 1 |
| `egress.attempt` by host (all allowed, 0 denied) | `api.github.com` 8, `codeload.github.com` 7 (Composer archive downloads), OSV bucket 2, `packagist.org` 2, `repo.packagist.org` 1, `api.anthropic.com` 1 (one CONNECT tunnel, reused by Claude Code) |
| `egress.attempt` by purpose (derived from the hosts: only `osv.packagist` was enabled) | `osv.db` 2, `fix.install` 18, `agent.claude` 1 |
| files in the proposal | 170 (`composer.json`, `composer.lock` and 168 files under `vendor/`, finding 1) |
| writes in the `demo` project | none (apply refused): git status clean, 1 commit, no new branch |
| tests | not run (no test command) |
| audit chain | 44 events, `audit verify` exit 0 |

## Findings (to fix in the final wave)

1. **Important - install output in the proposal.** Michel's install writes `vendor/` into the copy; the snapshot (`add -A`) stages it, since `vendor/` is neither ignored nor tracked in Base. The proposal lists 170 files, and a branch would commit `vendor/` into the user's repository. Install output folders not tracked in Base (`vendor`, `node_modules`, Composer's `vendor-dir`) must stay out of the snapshot and the diff, or installs must run only in the scratch folder.
2. **Important - apply refused by the mask-token check** with the cause "the change holds a placeholder standing for a secret": a false positive, most likely a `[secret-…]`-shaped string in the `vendor/` files, or a too broad `HasToken`. To recheck after finding 1; `HasToken` must match only Michel's own token shape.
3. **Important (UX) - a refusal by Michel is shown as the user's refusal.** The attempt became `refused` and the page said "Tu as refusé la dernière proposition" although the user clicked "Valider". Michel's refusal must be a distinct outcome (`failed` with a plain cause), never the user's refusal wording.
4. **Minor - the agent answers in English** to a French user: the first prompt must ask the agent to write its messages and summary in the user's language.

Note (declared, not a defect): only the first CONNECT of Claude Code is recorded. Claude Code reuses one tunnel, and the proxy cannot see the requests inside a CONNECT tunnel, so the audit has one `egress.attempt` per tunnel, not per request.
