# Fix: an agent prepares the fix, you approve it

🇫🇷 Version française : [fix.fr.md](fix.fr.md)

Michel finds the flaws and explains them. With plan 5 it can also have them fixed: Claude Code works on a **copy** of your project, Michel checks what it did, runs the tests itself, and shows you a proposal in plain words. Nothing reaches your repository before you click **Approve**, and even then Michel only creates a branch: you merge it and deploy as usual (with PhpStorm, for example).

Why: for a flaw such as Php2shell, you had to read articles to understand you were affected, look for others to learn how to fix it, hand them to an AI, then fix it yourself. Three steps by hand: **find** (am I affected, where), **understand** (in plain words, why me), **fix** (what to change, then check). The fix agent does these steps for you, and you keep the last word.

Everything is done from the page (`michel serve`, **Fix** button on a finding of the Today page, then **OK, fix it** or a message to the agent). The command line exists for scripts only:

```
michel brief <finding>             # the fix brief (find, understand, fix), nothing sent
michel fix consent <project> --yes # the project's AI consent (also asked on the page)
michel fix prepare <finding>       # start an attempt and follow it
michel fix status [<attempt>]      # attempts, or one attempt with its proposal and conversation
michel fix approve <attempt>       # approve the proposal status showed, create the branch
michel fix refuse <attempt>        # refuse; the finding goes back to your decisions
michel fix clean                   # remove the copies of the attempts that are over
```

## The four levels

Each project has its own level (`fix_level`, 0 to 3, default 1), set on the page (**Fix settings** of the project) or with `michel project set <name> --fix-level N`.

| Level | Name | What Michel does |
|---|---|---|
| 0 | Report | The digest and the page, nothing more. |
| 1 | Explain | The brief in three steps; the **Fix** button starts an agent when you ask (with the AI consent). |
| 2 | Prepare | An agent prepares, on its own, a fix for each eligible finding; it waits for your approval. |
| 3 | Apply what I allowed | Like 2, and Michel creates the branch without a click for the fixes that meet your rules; the others wait for you. |

Level 1 is enough to fix from the page: **Fix** is a click, not a setting. Levels 2 and 3 only add the initiative, and need the project's AI consent; without it, Michel stays at level 1 and says so.

**Which findings are handled alone at level 2**: an open finding of a dependency (not deferred or ignored), with a known fixed version, without an attempt in progress or a refused proposal. Exploited flaws (KEV) first, then by severity. `scan --all` puts them in a queue; `michel serve` takes them in order, **one attempt at a time per project**, and **at most 3 attempts started alone per day and per project**. If `serve` is not running, nothing starts.

**Automatic rule (level 3)**: it only counts if you checked the box "Apply safe minor updates on my behalf" of the project (`--auto-fix-minor`). Michel (never the agent) then creates the branch without asking you, only when all six points hold:

- the change touches only dependency files (`composer.json` and `composer.lock`, or `package.json` and `package-lock.json`, or `yarn.lock`, `pnpm-lock.yaml`), no code;
- the jump is small: a patch or a minor version, not a major one (for example not 7 to 8);
- the risk score is below the project's `auto_fix_below` (default 30, see [remediation-risk.md](remediation-risk.md));
- the re-scan of the copy no longer sees the flaw;
- the tests passed ("not run" is not enough);
- the agent changed nothing after Michel's own update: what is applied is exactly that update, read from the proposal's commit.

Otherwise the proposal waits for you. "Apply" means "create the branch", never merge or deploy.

## The consent screen: what leaves your computer

Claude Code sends what it reads to Anthropic: it is an external AI provider in the sense of the [sovereignty policy](security/sovereignty-policy.md). So the first **Fix** on a project shows a consent screen, one per project. It says:

- what leaves: the files of the copy the agent reads, the flaw's sheet (secrets masked) and your messages; a key saved in these files goes with them; the excluded files do not leave;
- what runs: "Michel runs composer/npm and your tests on a copy, with your Windows rights; the code written by the agent runs." (see "Residual risks");
- that the project is classified sensitive, when it is (the default): secrets are masked in the flaw's sheet and in what Michel shows, not in the files the agent reads, and the excluded files are not copied;
- each host that has no allow rule yet:
  - Anthropic, purpose `agent.claude`: `api.anthropic.com` (the API) and `platform.claude.com` (where a subscription login renews its token);
  - the package registries, purpose `fix.install`: `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com` (the archives Composer downloads), `registry.npmjs.org`;
- that accepting turns on external AI providers in your policy (`ai.external_providers_enabled`), when it is off.

When you accept, Michel:

1. writes one rule per host in `sovereignty.network.allow` of your policy file (with a `config.yaml.bak` copy);
2. turns `ai.external_providers_enabled` on if needed;
3. reloads the policy, without restart;
4. stores the project's consent;
5. records `ai.consent` in the audit log (hosts, purposes, classification, who).

A project classified `health` is always refused, consent or not.

### When your policy is `strict_local`

`strict_local` (the default) means nothing leaves your computer and no external AI is used. Michel never leaves that mode on its own. On the page, the consent screen explains what `strict_local` protects and offers an explicit button, "Switch to standard mode and allow external AI". That click writes `sovereignty.mode: standard` and `ai.external_providers_enabled: true` in one edit of the policy file (with its `.bak`, to go back), records `policy.mode` in the audit log, then gives the project's consent. You keep a precise frame: only the hosts listed, only the projects you consent to. `michel fix consent` on the command line refuses under `strict_local`: switch the mode yourself in the file first, or use the page.

## The work copy

The agent never works in your folder. For each attempt Michel makes, in its data folder:

1. a **private mirror** of your repository (`<data>/fix-mirrors/<project>/<attempt>.git`, `git clone --bare --local`, which only reads your repository). The agent never sees it;
2. the **agent's copy** (`<data>/worktrees/<project>/<attempt>/`): a fresh git repository filled with the files of your last commit, **without history**, without remote and without any absolute path, in one commit "michel: base".

The copy holds only the files of your last commit. So left out are: whatever git ignores or does not track, `.env*`, `*.pem`, `*.key`, `id_*` files (in every folder, ignoring case), the folders you excluded (`michel project set <name> --exclude <folder>`), symbolic links and special files. A copy is capped at 30,000 files, 256 MiB per file and 4 GiB in all; a larger project is refused (see "Troubleshooting"). During the preparation Michel writes nothing in your project (checked by a test).

Before the agent starts, Michel runs its secret detectors on the files of the copy. Michel does not hold the agent for what they find: the agent starts and can read those files. A secret written in your code is reported in the conversation as it starts ("2 secrets seem written in your code (…): the agent can read them") with the relative files, so that you can keep them out: take the secret out of the code (into an environment variable or a `.env` file, which is never copied), or exclude the folder or folders that hold it (the message names them; `--exclude` takes folder names, not files).

## What the agent can and cannot do

Michel starts Claude Code itself, in the background, with a closed command line, an allowlisted environment and its working folder in the copy. It uses your existing Claude Code login (subscription or key: Michel neither reads nor passes it on), but **none** of your settings, hooks, plugins, other MCP servers, `CLAUDE.md` or memory, and none of the copy's (a project's `.claude/` is untrusted): no setting source is loaded, hooks are off, only Michel's MCP server is declared (strict).

The agent **can**:

- read, search, edit and write files **in the copy** (Read, Glob, Grep, Edit, Write);
- ask Michel through its MCP server (`michel mcp`): `list_findings`, `get_finding`, `get_brief`, `get_call_sites`, `get_changelog_excerpt`, `get_attempt`, and `propose_fix`, the only tool that writes, and only in Michel's store, for this attempt (a token bound to the attempt is required).

The agent **cannot**:

- run any command: it has **no Bash** tool at all; Michel runs the update, the install and the tests itself;
- use the web (WebFetch, WebSearch off): the useful articles are in the brief;
- write in `vendor/`, `node_modules/`, `.git/`, `.claude/` or `.mcp.json`, or read your Claude Code files (`~/.claude`, `~/.claude.json`) and your keys (`~/.ssh`);
- approve, apply, change a setting or the policy: there is no such tool, approval only goes through the local API with its token.

An attempt runs at most 20 minutes and at most 50 exchanges with the agent (an exchange = one answer or one action of the agent), then its process tree is stopped. The agent is asked to write to you in the language of Michel (its messages and the summary of its proposal); code stays as it is. Repository content, advisories and articles are passed to the agent as untrusted data, never as Michel's instructions. Conversations are kept 30 days, with secrets masked.

## What Michel runs itself

At the start, on the copy still as you committed it (before the agent sees it), Michel runs the planned update, with a closed command line:

- Composer: `composer update <package>:^<version> --with-all-dependencies --no-scripts --no-plugins --no-interaction` (`composer require … --update-with-all-dependencies` for a major jump, `composer update <package> --with-dependencies` for a transitive dependency);
- npm: `npm install <package>@<version> --save-exact --ignore-scripts --no-audit --no-fund` (`npm update <package>` for a transitive dependency).

There is no update for a yarn or pnpm lockfile: the agent works from the project's files as they are.

Its result is Michel's first message in the conversation. What this update installs (`vendor/`, `node_modules/`) is removed from the copy right after. It is never part of the proposal nor of the branch, unless your repository already versions files in that folder. The proposal holds the manifest and the lockfile (plus what the agent changed). When the agent proposes (`propose_fix`), Michel takes one snapshot of the copy, once and for all (later writes of the agent are ignored), rebuilds that snapshot in a scratch folder (`<data>/fix-tmp/<attempt>/`, never the agent's copy), and there:

1. installs the dependencies (`composer install --no-scripts --no-plugins` or `npm ci --ignore-scripts`), from scratch;
2. runs the project's tests, if you declared a command (`michel project set <name> --test-cmd "vendor/bin/phpunit"`, split into words without a shell);
3. scans the result again.

Only **Composer and npm** are installed. A yarn or pnpm project is read and can be fixed, but Michel runs neither yarn nor pnpm: the proposal comes **without install or tests**, and the page says so. Before any install, Michel refuses the project settings that would make the install run code from the project or go elsewhere (npm settings outside a short allowlist, local or VCS Composer repositories, non-https downloads, old npm lockfiles, lockfile entries without integrity…): nothing is installed and the tests are not run, the page says why. These commands run with a Michel home folder (`<data>/fix-home`), never your real one, behind the allow proxy (purpose `fix.install`).

## The proposal and the validation by fingerprint

A proposal is fixed once made: a summary in plain words, the diff **computed by Michel** from the frozen snapshot (not copied from the agent), the files touched, the commands Michel ran, the test result (`passed`, `failed` or `not_run`), the re-scan of the copy (a flaw found by an external tool (Semgrep, Trivy…) cannot be re-scanned on the copy: the page says Michel could not check it), the risk, and a fingerprint of the whole (SHA-256: a code that changes as soon as any detail of the content changes). If the agent goes on and proposes again, the new proposal replaces the old one (`superseded`) and the page reloads it.

Michel refuses a change that touches a file outside the copy (`..`, absolute path, link), a protected file or an excluded file: the attempt is `failed`, the cause is said in plain words, nothing is applied.

**Approve** carries the fingerprint of the proposal you read. If the agent replaced it in between, the fingerprint no longer matches: Michel applies nothing (error code 409) and shows you the new one. On the command line, `michel fix approve` without `--hash` approves the proposal `michel fix status` last showed, and refuses when it changed since.

## The branch, then you deploy

Applying = Michel builds **one commit** of its own in the mirror (author Michel, parent = your real commit, the agent's own commits are ignored), then fetches it from your repository into the branch `michel/fix-<short id>`. No checkout, no merge: your current branch, your working tree and your index do not move (checked by a test, even with modified files or another branch checked out). It is the only write Michel makes in your project, and only after your approval: objects and one ref in its `.git`.

The page then says: "The branch michel/fix-… is ready. Merge it, then deploy with PhpStorm as usual." Michel never merges and never deploys.

## The proof

- Tests `passed` and a clean re-scan **in the copy** are required for an automatic application (level 3), and shown for the others.
- **`proven_fixed`**: after you merged, during a `michel scan` of your project, the tool that found the flaw looks again and no longer sees it **and** the branch's commit is in the current branch of your repository (Michel checks it read-only, `git merge-base --is-ancestor`). That tool is the scan of your dependencies for a dependency; for a flaw found by an external tool (Semgrep, Trivy…), it is that tool, which runs at the end of the scan.
- The flaw gone without that commit, or the commit merged while the tool still sees the flaw: the attempt is `inconclusive`, with the reason.
- If that tool did not look during this scan (off, not set to run during the scan, failed; for a dependency, a folder with no dependency file), Michel concludes nothing: the attempt stays `applied` until a scan where it looks. Running the tool alone (`michel source run`, or an imported report) concludes nothing either.
- Michel does not rerun the tests after the merge, because it never runs anything in your folder: the tests ran on the copy, before the merge. A local scan sees the merge, not the deployment: Michel says "fixed in your code" and reminds you to deploy; it does not claim the server is up to date.

The states you will see on the page: `preparing` → `proposed` → `approved` or `refused` → `applied` → `proven_fixed` or `inconclusive`; `failed` from `preparing`, `proposed` or `approved` (with its cause: the agent stopped, Michel refused the change or could not create the branch); `superseded` when a newer proposal replaces one.

## Masking, and its limit

Before anything Michel gives reaches the agent (brief, MCP answers) Michel masks secrets: AWS keys, GitHub tokens, PEM keys, `.env`-style values, password/secret/token/key assignments, passwords in connection URLs; the absolute paths of your computer become relative paths. Each secret is replaced by a token `[secret-<random>-N]`. The table linking the tokens to the real values stays in Michel's secret store (DPAPI-encrypted on Windows, a file readable by you only elsewhere) and is never sent. The audit records how many values were masked and of which kind, never the values.

- The page and the API never unmask: a secret shows as a token there.
- Michel **never** unmasks into a commit: a change that holds a token is refused (the agent may have copied it from the brief). At the proposal, the agent is told and can propose again; should one reach the branch step, Michel creates no branch and the attempt is `failed` with that cause (it is Michel's refusal, not yours). If a fix really needs a secret value in code, you add it by hand.
- The diff shown on the page is masked, but the branch holds the change as written: a password-like line of your own code is not a reason to refuse the change.
- **The limit**: the files of the copy are **not** masked. The copy holds your real code, and Claude Code reads it, so it goes to Anthropic. What protects your secrets is that the excluded files are not copied; a secret written in a committed file is read by the agent. That is why Michel reports those in the conversation; the report comes once the agent has started, so take a secret out of the code before you start a fix. Secret detection is never perfect: some forms (XML `<password>`, YAML block values, a password with an unencoded `@` in a URL…) can slip through.

## Server fixes (plan 6)

A finding of a **server** (a PHP setting, a package) has its own fix, described in [servers.md](servers.md): no work copy and no branch, but two scripts, `apply` and `undo`, that you validate by fingerprint and that you or Michel run on the server.

- The level is set **per server** (`--level` of `michel target add|set`), not per project. Michel prepares known fixes alone; the agent is only used to discuss a case, with a consent **per server** (the preprod's when one is linked) and never for a server of kind `hds`.
- Level 3 runs without a click only the settings of Michel's own rules at their advised value, never a package; a package upgrade always waits for your **Snapshot done**.
- A fix whose outcome Michel cannot tell ends in the state `unknown`: check the server, then `michel fix resolve <attempt>` (or **I checked the server** on the page).
- One fix at a time per server: while a fix is under way, checked after its script or `unknown`, no other is prepared or run on that server.

## Residual risks

- **Install and tests run with your rights, without a sandbox.** `composer`/`npm` and your tests run on the copy as you, on your computer; when the agent changed code, the tests run that code. Michel hardens what it can (no install scripts, no plugins, settings allowlists, folders reset before each install, scratch folder, a Michel home folder, the proxy), but it is not an isolated environment: a hostile project or a hostile change could reach what you can reach. An isolated environment (Docker) is planned for a later plan.
- **A tool that ignores the proxy.** Claude Code, git, composer, npm and the tests get `HTTPS_PROXY`/`HTTP_PROXY` toward Michel's allow proxy. But a program can ignore that proxy and open its own connections: Michel would neither stop nor record it. The proxy is a safeguard, not a guarantee.
- **Claude Code changes.** Michel relies on options of Claude Code to keep the agent away from your settings. It refuses a version that lacks them, but cannot guarantee that a future version honours them the same way. Claude Code still reads its login in your user folder (your profile).
  - Options used (tested with version 2.1.314): `--setting-sources ""`, `--strict-mcp-config`, `--restricted`, `--tools`, the permission rules, and the variables that turn off `CLAUDE.md`, memory and the non-essential traffic.
- **Anthropic reads the copy's code**, as said on the consent screen.
- **The agent's text must not be taken at its word.** It is shown, never executed; its proposal is checked by Michel, and you decide.

## Troubleshooting

| What you see | What to do |
|---|---|
| "Claude Code is not installed on this computer" | Install it (https://claude.com/claude-code), then **Check again**. Meanwhile, read the brief (`michel brief <finding>`). Michel looks for `claude` on the PATH (or the program named by `MICHEL_CLAUDE_BIN`). |
| "Your version of Claude Code is too old" | `claude update`. Michel needs the options that keep your settings out of the agent. |
| "Claude Code is not logged in" | Run `claude` in a terminal and log in, then try again. |
| "…Michel needs your agreement…" | Read the consent screen and accept, or `michel fix consent <project> --yes`. |
| "Your policy is strict_local" | Use the button of the consent screen on the page, or set `sovereignty.mode: standard` yourself (see above). |
| "This project is classified health" | Never sent to an external AI. Read the brief and fix by hand. |
| "This project is not tracked by git" / "no commit yet" | Michel copies with git: put the project in git (and make a first commit). The brief stays available. |
| "Your project is too large" | Exclude big folders (`--exclude`), or fix by hand from the brief. |
| "…would make the install run programs from the project itself" | A setting of your project (npm, Composer) would run code during the install; Michel does not accept it, so nothing ran. Fix by hand, or remove that setting. |
| "Tests: not run", no test command | Set one: `michel project set <name> --test-cmd "…"`. |
| "Tests: not run", yarn or pnpm project | Michel does not install with yarn or pnpm: check your site yourself before merging. |
| "Tests: not run", install refused | The page says which setting blocks: remove it, or check your site yourself before merging. |
| "Michel refused the agent's change" | The agent touched a file outside the copy or a protected file. Nothing was applied; try again. |
| "Michel did not create the branch: the change held a placeholder…" | The change held a `[secret-…]` token instead of a secret. Nothing was applied; start a new fix. |
| "The proposal changed since you read it" | Read the new one, then approve it. |
| "A fix is already in progress on this project" | Finish or refuse it first. |
| Level 2: nothing starts | `michel serve` must run; the project needs its AI consent; at most 3 attempts started alone per day and per project. |

What leaves the computer, host by host: [security/network-egress.md](security/network-egress.md).
