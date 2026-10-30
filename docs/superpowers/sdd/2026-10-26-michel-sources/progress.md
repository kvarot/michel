# Plan 4 (sources registry) - real run on the reference projects

Date: 2026-10-30. Binary: `michel dev` (branch `feat/sources` at 7f5c840, `npm run build` in `web/`, then `go build`). Only aggregates are published here: no project name, path, package, version or package-specific sentence. The real run was performed by the controller on the author's projects of this machine, registered under neutral names `ref1` to `ref9`, with a throw-away data folder and policy file (both absent at start), never writing into the projects.

## Commands run

```
michel source list (--json)
michel source enable osv.packagist --yes      (one key per call: the command takes one key, see observations)
michel source enable osv.npm --yes
michel source enable enrich.kev --yes
michel source enable enrich.epss --yes
michel source update
michel project add <folder> --name refN --fix-level 1   (9 folders)
michel scan --all --update --digest --json
michel findings --project refN --json                   (9 projects, counted locally)
michel source items --json
michel source show skill.trailofbits-code-audit
michel source enable skill.trailofbits-code-audit --yes
michel source install skill.trailofbits-code-audit      (answered N at the preview)
michel digest
michel audit verify
michel audit list --last 5000 --json                    (counted locally)
```

## Aggregates

| item | value |
|---|---|
| catalog sources (version 4) | 114: feed 55, osv 23, reference 21, enrichment 5, plugin 4, mcp 4, skill 2 |
| states at start | off 112, waiting_consent 2 (the two OSV databases enabled by default for Composer and npm) |
| states at the end | on 5, off 109 |
| policy file | created by the first `source enable` (it did not exist), then a `.bak` at each rewrite; 3 allow rules after the four enrichment/OSV enables (one OSV bucket host shared by both OSV databases, CISA, EPSS); skill enable added the two GitHub hosts |
| `source update` (first) | 10 s, 4 sources ok, 0 failed |
| items read | Packagist 7 389 advisories, npm 230 949 advisories, KEV 1 764 rows, EPSS 397 508 rows |
| `scan --all --update --digest` | 595 s total (update, scan, analysis, digest); exit code 1 = "not clean" because of one `partial` project (known plan 1 residual), no error printed |
| update inside the chained scan | 1 updated (KEV), 3 skipped `not_modified` (both OSV databases, EPSS), 0 waiting for consent, 0 failed; apply ran: 0 finding changed, 0 newly KEV, 0 superseded |
| projects | 9 registered: 6 `ok`, 2 `empty` (no lockfile, new status), 1 `partial` |
| lockfiles read | 43 |
| findings after the first scan | 1 893 (critical 120, high 799, medium 794, low 180), all new |
| findings with an EPSS score | 1 819 / 1 893 |
| findings on the KEV list | 4 (one advisory, one project, four lockfiles) |
| digest head « exploitées activement » | 4 lines (identical text: same advisory in four lockfiles of one project, see observations) |
| `source items` (reading list) | 0 (no feed enabled in this run) |
| `source show skill.trailofbits-code-audit` | hosts, missing rule, licence, pinned commit, note printed |
| `source install` preview | 18 files, 43.9 KB, licence CC-BY-SA-4.0 from LICENSE, start of SKILL.md shown; answered N ⇒ exit code 3, `~/.claude/skills` unchanged (listing compared before/after) |
| `audit verify` | 146 events verified, exit code 0 |

## Audit

- Events by action: `scan.manifest` 43, `app.start` 31, `egress.attempt` 11, `project.add` 9, `scan.start` 9, `scan.finish` 9, `source.read` 8, `analyze.start` 7, `analyze.finish` 7, `source.consent` 5, `source.enable` 5, `digest.run` 1, `source.install` 1.
- `egress.attempt` by host (all `allowed`, 0 denied): OSV bucket 4, EPSS 4, CISA 2, codeload.github.com 1.

## Writes under the project folders

None attributable to Michel. The manual treeDigest (SHA-256 of the sorted list of path, size and mtime of every entry under the projects folder) differed before/after because the folders were in use during the run: 258 entries changed between 08:54 and 09:05 local time, before the scan began at 09:08 (git objects, refs and worktrees, IDE files, edits in one project). Changes went on after the run, until 09:30. Between 09:05:30 and 09:20, 5 entries changed: three hook files of another assistant session under `.git/` (09:05), one project file (09:06, before the scan), and one IDE settings file (09:12, the only one inside the scan window 09:08–09:18). These are paths and times Michel's commands do not produce. The automated `treeDigest` tests remain the proof; a clean manual check needs idle folders.

## Observations from the run (deferred, see deferred-and-rulings.md)

- `source enable` takes one key; the plan's run line passes four. Several keys per call (one consent screen) would match the plan and the page.
- The digest head repeats one identical line per lockfile when the same KEV advisory sits in several lockfiles of one project; grouping by (project, advisory) or naming the lockfile would read better.
- osv-scanner still prints `interpreting as regex/glob` warnings on stderr (pre-existing since plan 1).
- `scan --all` exits 1 quietly when one project is `partial`: correct by the plan 1 rule, but nothing on stdout in `--json` mode says which project made it unclean except its `status`.
- The old EPSS host rule stays in a policy file that consented before the move (see Task 10 part 1 minor).
