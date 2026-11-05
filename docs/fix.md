# Fix: an agent prepares the fix, you approve it

🇫🇷 Version française : [fix.fr.md](fix.fr.md)

Michel finds the flaws and explains them. With plan 5 it can also have them fixed: Claude Code works on a **copy** of your project, Michel checks what it did, runs the tests itself, and shows you a proposal in plain words. Nothing reaches your repository before you click **Approve**, and even then, without attachment to a Git service, Michel only creates a branch (see "Attach your project to GitHub, Bitbucket or GitLab" below): you merge it and deploy as usual (with PhpStorm, for example).

Why: for a flaw such as Php2shell, you had to read articles to understand you were affected, look for others to learn how to fix it, hand them to an AI, then fix it yourself. Three steps by hand: **find** (am I affected, where), **understand** (in plain words, why me), **fix** (what to change, then check). The fix agent does these steps for you, and you keep the last word.

Everything is done from the page (`michel serve`, **Fix** button on a finding of the Today page, then **OK, fix it** or a message to the agent). The command line exists for scripts only:

```
michel brief <finding>             # the fix brief (find, understand, fix), nothing sent
michel fix consent <project> --yes # the project's AI consent (also asked on the page)
michel fix prepare <finding>       # start an attempt and follow it
michel fix status [<attempt>]      # attempts, or one attempt with its proposal and conversation
michel fix test <attempt> --yes    # run the tests of a proposal that waits for your go-ahead
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

- what leaves: the files of the copy the agent reads, the flaw's sheet (secrets masked) and your messages; when Michel recognises a possible key in these files, the agent does not start until you answer (see "The work copy"); a key Michel does not recognise, or one you choose to leave, goes with them; the excluded files do not leave;
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

Before anything leaves your computer, Michel runs its secret detectors on the files of the copy. When they find what has the shape of a key (a known format, such as an AWS key, or a value written out that looks like a secret on a sensitive name, such as `password` or `token`), the attempt stops in the state `held`, at every level and for every start, automatic ones included: no agent, no update, nothing leaves. The page, `michel fix prepare` and `michel fix status` say how many possible keys, in which files and on which lines, never the value.

Michel judges by the shape of what is written, without knowing whether the key is real. This judgement only decides the stop: Michel masks as much as ever on the page and in the sheet.

What stops the agent:

- a known format: AWS key, GitHub token, private key, Stripe live secret key (`sk_live_`, `rk_live_`), JSON Web Token, Slack token (`xoxb-` and its kin). Always, even when it is an example written in that format (`xoxb-your-bot-token`);
- a value of at least 8 characters, without a space, on a sensitive name (`password`, `token`, `api_key`, `DB_PASSWORD=`…), when it is not made of plain words: letters mixed with digits or signs, or letters that make no word (scattered capitals, 6 consonants in a row);
- the same in PHP: `define('DB_PASSWORD', '…')`, `'key' => 'base64:…'`, an array key such as `$config['password'] = '…'`, the third argument of `new PDO(…)` or `new mysqli(…)` and the same for `mysqli_connect(…)`, when written in quotes (these calls may span several lines, and a password written in pieces `'a' . 'b'` is read whole, even when a variable or a call comes between the pieces; comments between the arguments are skipped); and a password in a connection address;
- a default word with digits, in quotes or in an address (`password = 'admin123'`).

What does not stop the agent, even if it is a real key. Michel says so in a message for a line it saw, and the agent can read it:

- a line that talks about a password without showing one: a type, a variable, a call, a sentence, a value that is a template from end to end (`${X}`, `{{ x }}`, `<x>`, `%x%`, `$x`, `[x]`, `{x}`), an example such as `your-key-here`;
- a value without quotes read as code: holding `(`, `)`, `;`, `<`, `>` or a quote after `NAME=`, holding a bracket, a brace, `(`, `)`, `;`, `<`, `>` or `->` after `name:`. So `DB_PASSWORD=aB3;xY9!qZ` passes;
- a plain word, a sentence, plain words joined by dashes (`cheval-correct-batterie`), a value under 8 characters, a default word (`password = 'password'`), a default word with digits without quotes (`password: admin123`);
- a value with a part that is exactly `test`, `fake`, `mock`, `stub` or `dummy` (`sk_test_…`, `mock-kP9mW2xQ7vT`), or a placeholder (`your`, `example`, `xxx`…) with only words and numbers beside it;
- a value starting with `npm:`, `workspace:`, `file:`, `link:`, `^`, `~` or a validation word (`required|`, `nullable|`, `string|`, `sometimes|`), a value holding `://`, a path of short lowercase words (`/etc/ssl/private/server.key`), and the public hash of Laravel's old `UserFactory`;
- a value with no sensitive name beside it Michel can read: the arguments of a call other than those named above (for example `ldap_bind($c, 'uid', '…')`, `mysqli_real_connect(…)`, `->real_connect(…)`), a `new mysqli(…)`, `new PDO(…)` or `mysqli_connect(…)` call with an argument before the password that is nested deeper than three parentheses or holds an unclosed quote, a password built from a variable or a call, after `?:` or `??` or inside a function call, written in a heredoc or in a string over several lines (also when it is a piece of a chain of strings), a chain of strings that goes on after a line break not marked by a dot, or on the line after the `=`, a plain `key:`. In a chain of strings, Michel reads the pieces after the first only for an array key (`$c['password'] = 'a' . 'b'`), `'password' => …`, `define(…)` and the calls named above: after a plain name (`$password = 'a' . 'b'`, `password: 'a' . 'b'`) only the first piece is masked. Outside PHP, a dot followed by a number, or directly by a name, ends the chain (`d['password'] = 'a'.b.'c'`). A chain longer than 64 KiB is masked up to the end of the line where this limit falls, not beyond. A comma in the first argument of `new PDO(…)` can make Michel read the user name as the password, and hold on it by mistake.

When the attempt stops, you choose:

- **I will remove them first** (`michel fix withdraw <attempt>`): the attempt ends in the state `withdrawn`, its copy is removed and no agent starts. Take the key out of the code (into an environment variable or a `.env` file, which is never copied), commit, and start the fix again: the copy holds your last commit, so a key removed without a commit is still there. Excluding the folder that holds it works too (Michel's message names it; `--exclude` takes folder names, not files). A new start without any key found starts directly. After this no, automatic starts do not ask again while your last commit and your excluded folders stay the same, for any flaw of this project. Your own start searches and asks again.
- **Continue anyway** (`michel fix continue <attempt>`, in a terminal: Michel shows the list again and waits for you to type `yes`): the agent starts, can read those files, and what it reads reaches Anthropic.

The yes holds for that attempt only and is never stored: the next attempt searches and asks again. The audit log keeps counts only (`fix.hold`, `fix.hold.continue`, `fix.hold.withdraw`). The yes is refused, and the attempt ends `failed`, if the copy changed, if the search finds other hits, if your project has a new commit or another excluded folder, or if the flaw has left: start the fix again, Michel searches again. Michel never answers for you: no level 3 rule, worker or `michel mcp` session can, and `michel fix continue` needs a terminal. Michel cannot stop a person or a program running with your rights from going around that: faking a terminal, or calling the page in your place (see "Residual risks").

While an attempt waits, the project takes no other fix, its copy and its Git mirror stay in Michel's data folder, and its line stays in To do, ranked "Yours". The digest and, for an automatic start, a notification say it waits for your answer. With no answer after 14 days, the attempt ends as a no (`withdrawn`, copy removed, `fix.hold.withdraw` with `author: expired`): never as a yes.

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
2. runs the project's tests, if you declared a command (`michel project set <name> --test-cmd "vendor/bin/phpunit"`, split into words without a shell), **only when the snapshot is exactly the tree Michel's own update left** (the agent changed nothing else);
3. scans the result again.

### Tests on the agent's change wait for your click

As soon as the snapshot differs from the tree Michel's update left (the agent touched any file, a test, `phpunit.xml`, `package.json` or the manifest and lockfile included), running the tests would run code the agent wrote, on your computer, with your rights. Michel still installs (no script runs) and scans again (it only reads files), but it **does not run the tests**: the proposal's tests are `awaiting` ("waiting for your go-ahead"). A change limited to the manifest or the lockfile counts too: a package the agent added there would load its code during the tests. Michel's message and the page list the changed files that are neither the manifest nor the lockfile (10 at most, then "and N more"): those would run new code.

You read the change, then either:

- click **Run the tests** in the proposal (or `michel fix test <attempt>`: without `--yes` it lists the files and runs nothing; with `--yes` it runs the tests of the proposal `michel fix status` last showed, or `--hash`). The click carries the fingerprint of the proposal shown, like **Approve**: if the agent proposed something else in between, nothing runs (409). Michel rebuilds the proposal's files in a scratch folder of its own (`<data>/fix-tmp/<attempt>/tests-<random>`), installs, runs the tests, then records a **new proposal** with the same change, the same commit, the same re-scan and the tests' result. Its fingerprint changes, so an **Approve** sent for the old one is refused: you approve knowing the result. If the agent proposed again while the tests ran, the result is dropped and nothing is replaced. A run that a click gave is not run again: the agent can propose again. Each click is in the audit log (`fix.tests_run`: attempt, proposal, fingerprint, author, result, number of code files);
- or **Approve** without running them, as for a proposal whose tests were not run: the page says the tests did not run.

The agent cannot run the tests: no tool of `michel mcp` does it, and it only sees the status `awaiting`. Level 3 does not change: it already requires Michel's own tree. A proposal made before this rule keeps no copy of its files: it offers no button.

Only **Composer and npm** are installed. A yarn or pnpm project is read and can be fixed, but Michel runs neither yarn nor pnpm: the proposal comes **without install or tests**, and the page says so. Before any install, Michel refuses the project settings that would make the install run code from the project or go elsewhere (npm settings outside a short allowlist, local or VCS Composer repositories, non-https downloads, old npm lockfiles, lockfile entries without integrity…): nothing is installed and the tests are not run, the page says why. These commands run with a Michel home folder (`<data>/fix-home`), never your real one, behind the allow proxy (purpose `fix.install`).

## The proposal and the validation by fingerprint

A proposal is fixed once made: a summary in plain words, the diff **computed by Michel** from the frozen snapshot (not copied from the agent), the files touched, the commands Michel ran, the test result (`passed`, `failed`, `not_run` or `awaiting`), the re-scan of the copy (a flaw found by an external tool (Semgrep, Trivy…) cannot be re-scanned on the copy: the page says Michel could not check it), the risk, and a fingerprint of the whole (SHA-256: a code that changes as soon as any detail of the content changes). If the agent goes on and proposes again, the new proposal replaces the old one (`superseded`) and the page reloads it.

Michel refuses a change that touches a file outside the copy (`..`, absolute path, link), a protected file or an excluded file: the attempt is `failed`, the cause is said in plain words, nothing is applied.

**Approve** carries the fingerprint of the proposal you read. If the agent replaced it in between, the fingerprint no longer matches: Michel applies nothing (error code 409) and shows you the new one. On the command line, `michel fix approve` without `--hash` approves the proposal `michel fix status` last showed, and refuses when it changed since.

## The branch, then you deploy

Applying = Michel builds **one commit** of its own in the mirror (author Michel, parent = your real commit, the agent's own commits are ignored), then fetches it from your repository into the branch `michel/fix-<short id>`. No checkout, no merge: your current branch, your working tree and your index do not move (checked by a test, even with modified files or another branch checked out). Without attachment, it is the only write Michel makes in your project, and only after your approval: objects and one ref in its `.git`.

The page then says: "The branch michel/fix-… is ready. Merge it, then deploy with PhpStorm as usual." Michel never merges and never deploys.

## Attach your project to GitHub, Bitbucket or GitLab

Michel asks one question on the project's page: is this project on a Git service? **Nothing happens without a yes.** What Michel offers first is only a suggestion, never an answer. As long as you have not said yes, everything above stands: you merge and you send with your own tool.

To ask, Michel reads your project's address from its Git settings, without network. If that address holds a password or a token, Michel tells you so, and neither shows, keeps nor uses it. Your yes holds for that address only. It writes one network rule, for that host only. Answering no or "I don't know" later removes the rule, if Michel wrote it and no other attached project uses it. If the address changes, nothing leaves until you answer again.

A yes gives you two buttons. Nothing else starts them: no level, no scan, no background work and no command line.

**Send the fix**, on a fix with its branch:

- it sends only the branch `michel/fix-…` and the commits it needs, to your remote. Your main branch does not move;
- Michel never overwrites what is already on the service: if it refuses, Michel says so and stops;
- one click, one send. A second click sends nothing more when the branch is already there;
- it sends from a temporary copy in Michel's data folder (`<data>/fix-net/`), removed afterwards. That copy does not read your project's settings, so they can start no program. In your project, this button writes nothing;
- on GitHub, Bitbucket and GitLab (`github.com`, `bitbucket.org`, `gitlab.com`), the page then gives a link to ask for the merge. On any other service, it gives the branch's name. You accept on the site.

Michel stores no token. It uses the Git access already on this computer, and it cannot ask you for any: if it finds none, it says so, and you send once with your usual Git tool.

**Update my folder**, once the merge is accepted:

- it fetches the main branch of the remote, then moves your folder forward to that version (this is the command `git merge --ff-only`): nothing is mixed, your folder is only brought up to date;
- only when your folder is on its main branch, with no change in the files Git follows, and no merge in progress;
- no hook and no file conversion program (Git LFS for example) runs. If the update would need one, Michel refuses and leaves your files alone. It also refuses rather than overwrite a file that Git does not follow or ignores;
- what it writes in your project: the commits that arrive, your main branch, the mark Git keeps of the remote's state (`<remote>/<branch>`) and the files changed. When it refuses after fetching, the commits and that mark may already be written: your files and your branch have not moved.

**These two buttons lift, for an attached project and on your click, the rule "Michel does not push and runs nothing in your folder".** Without attachment, that rule stands entirely. Each click is recorded in the audit log, refusals included (`project.git.answer`, `project.git.push`, `project.git.update`). What git prints is neither shown nor kept, since it can hold private data: you see a sentence, and for more detail you use your usual Git tool.

**Michel still never accepts your fix**: you merge it, on the site or with your tool. It never deploys either. Updating your folder is not merging your fix: it brings back what you already accepted.

A partial copy of a repository (a "partial clone") cannot be attached: Git would fetch what it lacks on its own, so Michel neither sends nor updates there, and says so.

## The proof

- Tests `passed` and a clean re-scan **in the copy** are required for an automatic application (level 3), and shown for the others.
- **`proven_fixed`**: after you merged, during a `michel scan` of your project, the tool that found the flaw looks again and no longer sees it **and** the branch's change is in the current branch of your repository. Michel checks it read-only: the commit itself (`git merge-base --is-ancestor`), or, after a "Squash" or a "Rebase" on the host's site, which change the commit, the same patch (`git cherry`). That comparison ignores whitespace and where the lines are, so the same lines indented otherwise, or in another identical block, also count: a rare false "merged", and the tool below must still stop seeing the flaw. That tool is the scan of your dependencies for a dependency; for a flaw found by an external tool (Semgrep, Trivy…), it is that tool, which runs at the end of the scan.
- The flaw gone without that commit, or the commit merged while the tool still sees the flaw: the attempt is `inconclusive`, with the reason.
- If that tool did not look during this scan (off, not set to run during the scan, failed; for a dependency, a folder with no dependency file), Michel concludes nothing: the attempt stays `applied` until a scan where it looks. Running the tool alone (`michel source run`, or an imported report) concludes nothing either.
- Michel does not rerun the tests after the merge: it runs no program of your project, and "Update my folder" only brings the files there. The tests ran on the copy, before the merge. A local scan sees the merge, not the deployment: Michel says "fixed in your code" and reminds you to deploy; it does not claim the server is up to date.

The states you will see on the page: `held` (possible keys in the code: Michel waits for your answer) → `withdrawn` or `preparing`; `preparing` → `proposed` → `approved` or `refused` → `applied` → `proven_fixed` or `inconclusive`; `failed` from `preparing`, `held`, `proposed` or `approved` (with its cause: the agent stopped, Michel refused the change or could not create the branch, your project changed since the search); `superseded` when a newer proposal replaces one.

## Masking, and its limit

Before anything Michel gives reaches the agent (brief, MCP answers) Michel masks secrets: AWS keys, GitHub tokens, Stripe live keys, JSON Web Tokens, Slack tokens, PEM keys, `.env`-style values, password/secret/token/key assignments, passwords in connection URLs; the absolute paths of your computer become relative paths. Each secret is replaced by a token `[secret-<random>-N]`. The table linking the tokens to the real values stays in Michel's secret store (DPAPI-encrypted on Windows, a file readable by you only elsewhere) and is never sent. The audit records how many values were masked and of which kind, never the values.

- The page and the API never unmask: a secret shows as a token there.
- Michel **never** unmasks into a commit: a change that holds a token is refused (the agent may have copied it from the brief). At the proposal, the agent is told and can propose again; should one reach the branch step, Michel creates no branch and the attempt is `failed` with that cause (it is Michel's refusal, not yours). If a fix really needs a secret value in code, you add it by hand.
- The diff shown on the page is masked, but the branch holds the change as written: a password-like line of your own code is not a reason to refuse the change.
- **The limit**: the files of the copy are **not** masked. The copy holds your real code, and Claude Code reads it, so it goes to Anthropic. What protects your secrets is that the excluded files are not copied, and that the agent waits for your answer when Michel recognises a key in the others; a secret written in a committed file is read by the agent if Michel does not recognise it or if you choose to go on. Secret detection is never perfect: some forms (XML `<password>`, YAML block values, a password with an unencoded `@` in a URL…) can slip through. Michel does not search files over 1 MiB or binary files either. And what it recognises stops the agent only if the value has the shape of a key (see "The work copy").

## Server fixes (plan 6)

A finding of a **server** (a PHP setting, a package) has its own fix, described in [servers.md](servers.md): no work copy and no branch, but two scripts, `apply` and `undo`, that you validate by fingerprint and that you or Michel run on the server.

- The level is set **per server** (`--level` of `michel target add|set`), not per project. Michel prepares known fixes alone; the agent is only used to discuss a case, with a consent **per server** (the preprod's when one is linked) and never for a server of kind `hds`.
- Level 3 runs without a click only the settings of Michel's own rules at their advised value, never a package; a package upgrade always waits for your **Snapshot done**.
- A fix whose outcome Michel cannot tell ends in the state `unknown`: check the server, then `michel fix resolve <attempt>` (or **I checked the server** on the page).
- One fix at a time per server: while a fix is under way, checked after its script or `unknown`, no other is prepared or run on that server.

## Residual risks

- **Install and tests run with your rights, without a sandbox.** `composer`/`npm` and your tests run on the copy as you, on your computer; when the agent changed code, the tests run that code, but only after your click (**Run the tests**, `michel fix test`). Michel hardens what it can (no install scripts, no plugins, settings allowlists, folders reset before each install, scratch folder, a Michel home folder, the proxy), but it is not an isolated environment: a hostile project or a hostile change could reach what you can reach. An isolated environment (Docker) is planned for a later plan.
- **A tool that ignores the proxy.** Claude Code, git, composer, npm and the tests get `HTTPS_PROXY`/`HTTP_PROXY` toward Michel's allow proxy. But a program can ignore that proxy and open its own connections: Michel would neither stop nor record it. The proxy is a safeguard, not a guarantee.
- **Claude Code changes.** Michel relies on options of Claude Code to keep the agent away from your settings. It refuses a version that lacks them, but cannot guarantee that a future version honours them the same way. Claude Code still reads its login in your user folder (your profile).
  - Options used (tested with version 2.1.314): `--setting-sources ""`, `--strict-mcp-config`, `--restricted`, `--tools`, the permission rules, and the variables that turn off `CLAUDE.md`, memory and the non-essential traffic.
- **Anthropic reads the copy's code**, as said on the consent screen.
- **The answer about a key found is no proof that a person read it.** Michel takes this yes only through the page or a terminal, and its own automation never gives it. But a person or a program running with your rights (a script, a test of the project, code the agent wrote on another project) can fake a terminal or call the page with its token. That program could read the key directly anyway.
- **The agent's text must not be taken at its word.** It is shown, never executed; its proposal is checked by Michel, and you decide.
- **On an attached project, the SSH connection and your Git access manager are outside the proxy.** Over SSH, git and ssh open their own connection: Michel decides and records before git starts, but does not route it through itself and does not stop it. A Git access manager (Git Credential Manager, for example: the program that remembers your Git passwords) is a program of yours that git starts: it can open its own connections too. See [security/network-egress.md](security/network-egress.md).

## Troubleshooting

| What you see | What to do |
|---|---|
| "Claude Code is not installed on this computer" | Install it (https://claude.com/claude-code), then **Check again**. Meanwhile, read the brief (`michel brief <finding>`). Michel looks for `claude` on the PATH (or the program named by `MICHEL_CLAUDE_BIN`). |
| "Your version of Claude Code is too old" | `claude update`. Michel needs the options that keep your settings out of the agent. |
| "Claude Code is not logged in" | Run `claude` in a terminal and log in, then try again. |
| "…Michel needs your agreement…" | Read the consent screen and accept, or `michel fix consent <project> --yes`. |
| "Your policy is strict_local" | Use the button of the consent screen on the page, or set `sovereignty.mode: standard` yourself (see above). |
| "This project is classified health" | Never sent to an external AI. Read the brief and fix by hand. |
| "This project is not tracked by git" / "no commit yet" | Michel copies with git: the folder you added must be the main folder of a repository, with a first commit. The check and the brief stay available. |
| "Your project is too large" | Exclude big folders (`--exclude`), or fix by hand from the brief. |
| "…would make the install run programs from the project itself" | A setting of your project (npm, Composer) would run code during the install; Michel does not accept it, so nothing ran. Fix by hand, or remove that setting. |
| "Tests: waiting for your go-ahead" | The agent changed more than Michel's update. Read the change, then **Run the tests** (or `michel fix test <attempt> --yes`), or approve without them. |
| "Tests: not run", no test command | Set one: `michel project set <name> --test-cmd "…"`. |
| "Tests: not run", yarn or pnpm project | Michel does not install with yarn or pnpm: check your site yourself before merging. |
| "Tests: not run", install refused | The page says which setting blocks: remove it, or check your site yourself before merging. |
| "Michel refused the agent's change" | The agent touched a file outside the copy or a protected file. Nothing was applied; try again. |
| "Michel did not create the branch: the change held a placeholder…" | The change held a `[secret-…]` token instead of a secret. Nothing was applied; start a new fix. |
| "The proposal changed since you read it" | Read the new one, then approve it. |
| "A fix is already in progress on this project, or waits for your answer" | Answer it first, or finish it. It is in the list of fixes. |
| Level 2: nothing starts | `michel serve` must run; the project needs its AI consent; at most 3 attempts started alone per day and per project. |
| "This folder is not a Git repository" | Michel can check it and explain its flaws, but cannot prepare a fix or send one. |
| "This Git repository holds nothing saved yet" | Make a first commit: Michel needs it to prepare a fix or send one. |
| "Michel finds no usable address in this project" | It needs one https or SSH address, or one named `origin`. |
| "This folder is a partial copy of a repository" | Use your usual Git tool. For Michel to do it, it needs a full copy of the repository. |
| "This project is not attached to a Git service" | Answer yes on the project's page if you want to send your fixes there. |
| "The project's address changed since you agreed" | Look at the project's page and answer again. |
| "The network rule that allows this service was removed" | Answer the question again on the project's page. |
| "This fix has no branch to send" | A branch exists only after your approval, and until the fix is finished. |
| "This fix's branch changed or no longer exists" | Michel only sends what you approved. Start a new fix, or send the branch yourself. |
| "Michel is already working on this folder" | Wait for it to end, then try again. |
| "The service refused access, or Michel found no Git access on this computer" | Send once with your usual Git tool to save your access, then try again. |
| "This computer does not recognise this service, or its identity changed" | Connect once with your usual Git tool. If you already used to connect, ask for help: this change can be an attack. |
| "The service does not find this project, or your account has no access" | Check the address shown and that your account has access. |
| "The service refused this branch" | A branch of the same name may exist with other content, or a rule of the service forbids it. Look on the site. Michel never forces a send. |
| "Michel could not reach the service" | Check your Internet connection, then try again. A company proxy can also prevent it. Over https, Michel only reaches port 443 (the usual door of secure websites). |
| "The service did not answer in time" | Click again: if everything is already there, Michel sees it and sends nothing more. |
| "It failed for a reason Michel does not recognise" | Try with your usual Git tool. Michel does not show the detail, which may hold private data. |
| "Your folder is on branch …, not on the main branch …" | Go back to the main branch, then try again. |
| "Your folder is on no branch" | Put it back on its main branch, then try again. |
| "Michel does not know your folder's main branch" | Update with your usual Git tool. |
| "Your folder holds changes not saved yet" | Save them or set them aside, then try again. |
| "A merge or a pick is in progress in your folder" | Finish or cancel it, then try again. |
| "Your folder holds saved work that is not on the site" | Send it or settle this with your usual Git tool, then try again. Michel mixes nothing. |
| "A file in your folder would be overwritten by this update" | Move that file elsewhere, then try again. |
| "A file or folder that Git ignores … stands where this update writes" | Move it elsewhere, then try again. Careful: an update made by hand with Git can overwrite it without warning. |
| "This update would remove or replace a subfolder Git manages apart" | Move its content elsewhere, empty this subfolder without deleting it, then try again. Careful: an update made by hand with Git can erase what it holds. |
| "This update would run a file conversion program" | Update with your usual Git tool, then click **Check this project**. |
| "The update failed: Git stopped it" | Check your folder's state with your usual Git tool. |
| "The update stopped halfway" | Close any program that may hold a file open (an editor, an antivirus). Your folder held no change before the update: with your usual Git tool, cancel these changes, then try again. |

What leaves the computer, host by host: [security/network-egress.md](security/network-egress.md).
