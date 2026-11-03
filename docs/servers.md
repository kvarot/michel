# Servers: am I affected, and fix it without breaking anything

🇫🇷 Version française : [servers.fr.md](servers.fr.md)

Plan 6 lets Michel look at what really runs on your servers (PHP, the web server, the system packages, the PHP settings), compare it with known flaws and with a set of configuration rules, warn you, then prepare a fix as **two readable scripts, `apply` and `undo`**, that you validate. The question that started it: with a flaw such as PHP2Shell, "am I affected on my server?" Michel answers it without you typing a command.

Two fears guide everything: **a bug in production**, and worse, **a deletion**. Michel has no action that deletes anything, and every change is saved first and can be undone.

Everything is done from the **Servers** page (`michel serve`). The command line (`michel target …`, `michel fix resolve`) exists for scripts and for the cases listed below.

## Contents

1. [Find your servers](#1-find-your-servers)
2. [Prepare an SSH user and a key for Michel](#2-prepare-an-ssh-user-and-a-key-for-michel)
3. [Confirm the fingerprint](#3-confirm-the-fingerprint)
4. [What Michel reads, and never reads](#4-what-michel-reads-and-never-reads)
5. [Am I affected? The sources](#5-am-i-affected-the-sources)
6. [A fix: the scripts and their actions](#6-a-fix-the-scripts-and-their-actions)
7. [Who runs the script, and sudo](#7-who-runs-the-script-and-sudo)
8. [Preproduction, snapshot, backups](#8-preproduction-snapshot-backups)
9. [The four levels, and the agent](#9-the-four-levels-and-the-agent)
10. [Alerts and SMS](#10-alerts-and-sms)
11. [Troubleshooting](#11-troubleshooting)
12. [Limits you should know](#12-limits-you-should-know)
13. [Server logs: be warned without copying them](#13-server-logs-be-warned-without-copying-them)

## 1. Find your servers

**Find my servers** (or `michel target discover`) proposes a list; you tick, nothing is added alone. Michel looks in:

- `~/.ssh/config`: `Host`, `HostName`, `User`, `Port`, `IdentityFile` (the path, never the content of a key);
- the projects Michel already follows: PhpStorm's `.idea/deployment.xml` and `.idea/webServers.xml`, including servers that use a *saved SSH configuration* (PhpStorm's `sshConfigs.xml` and its options folder are read for the host, port and user only). This tells which project is deployed on which server, and in which remote folder. You can correct the link. PhpStorm's passwords live in the system's vault: Michel never looks for them.

All of these reads are read-only. Michel writes nothing in a project and nothing in `~/.ssh`.

You can also add a server by hand (`michel target add <alias|host> --user …`). Host names and IPv4 addresses only: an IPv6 literal is refused (use the host name).

**Adding a server is your consent for the network**: Michel then writes the two rules it needs in the policy file (`target.ssh` to the host, `target.http` to the site address if you gave one). Nothing else ever opens a connection to a server. Deleting the server removes the rules **Michel wrote**; a rule you wrote by hand is never removed.

A server has a *kind* (`vps`, `shared`, or `hds` for a server that hosts health data: it is then classified `health`, which cannot be changed) and a *role* (`prod`, `preprod`, `dev`).

## 2. Prepare an SSH user and a key for Michel

Michel signs in **with the keys of your SSH agent only**. It never reads a private key file, never stores a key, never asks or sends a password.

1. **Create a key** (or use one you have), preferably one just for Michel: `ssh-keygen -t ed25519 -f ~/.ssh/michel_ed25519`.
2. **Put the public key on the server**, in the `~/.ssh/authorized_keys` of the SSH user: `ssh-copy-id -i ~/.ssh/michel_ed25519.pub user@server`.
3. **Load the key in your agent**:
   - Windows: start the *OpenSSH Authentication Agent* service (Services, set to automatic), then `ssh-add $env:USERPROFILE\.ssh\michel_ed25519`.
   - Linux and macOS: `ssh-add ~/.ssh/michel_ed25519` (Michel uses `SSH_AUTH_SOCK`).
   - Pageant (PuTTY): put Pageant in its OpenSSH-compatible mode and give its pipe or socket to Michel with `ssh.agent_pipe` (see below). This path is **not tested** by the authors.
4. **Choose the user.** The rights of the SSH user decide what Michel can see and do; Michel works with them and never tries to get around a refusal. A dedicated user, with read access, is a good idea. A server where that user cannot read a file shows it in the "not seen" list.

`ssh.agent_pipe` (in the `ssh:` section of the policy file, see `config.example.yaml`): empty means the system agent. Otherwise, a Windows named pipe (`\\.\pipe\…`) or the full path of a local Unix socket, even on Windows. A socket must sit in a folder only you can write to: whoever controls it sees Michel's sign-in requests.

A server that accepts only a **password** cannot be used: Michel says so and shows how to install a key. It will not do password sign-in.

## 3. Confirm the fingerprint

The first time, Michel shows the server's **fingerprint** (`SHA256:…`). You compare it with the one your host gives you (or with what you get from the server yourself), then confirm on the page (`michel target trust <id> --fingerprint SHA256:…`). It can also come from your `~/.ssh/known_hosts`.

A confirmed fingerprint is kept by Michel and used **alone**: `known_hosts` is only consulted while no fingerprint is confirmed. After that, a server that shows another key is **refused**, always: see [host key changed](#host-key-changed). Never an automatic acceptance.

Each connection is written in the audit log (`target.connect`: server, user, fingerprint, duration, result).

## 4. What Michel reads, and never reads

Michel runs a **closed list of read commands**, built by itself, in one SSH session, and installs nothing on the server:

- system: `/etc/os-release`, `uname -r`;
- PHP: `php -v`, `php -m`, `php --ini`, and the PHP settings, for the command line and for each `php-fpm` it finds;
- web server: `nginx -v`, `apache2 -v` / `httpd -v`;
- packages: `dpkg-query`, `rpm -qa`, `apk info` according to the system;
- services that listen: `ss -tln`, and `/usr/sbin/ss -tln` only if the first answers that the command is not found (same program, installed elsewhere on some systems). Only the address and the port are kept, never the name of a process (that would need rights Michel does not ask for). TCP only. This runs on every kind of server, `hds` included, since it reads no file and no content ([What is exposed](#what-is-exposed));
- configuration files: only those PHP and the web server name, the `.user.ini` of the linked deployment folders, and the ones you add (capped in size).

What this check does **not** read, ever: data folders, databases, the homes of other users, logs, private keys, and anything that is not a configuration file. On a server of kind `hds` you cannot add any path to this check. Log files are a separate path: only the ones you declare, through their own filter, on every kind of server ([section 13](#13-server-logs-be-warned-without-copying-them)).

- **Secrets never get stored.** Values of `password`, `secret`, `key`, `token`, DSN and the known secret settings are masked before storage; the database keeps the directive name, a non-secret value, the file and the line, plus the file's fingerprint, never the raw file.
- **Symbolic links** are not followed to read a file outside what PHP names.
- What Michel could not read is listed as **not seen** ("`php.ini` unreadable with the user deploy"), in plain words. It never tries another way. Note: an unreadable `.user.ini` keeps all the settings findings of that server open, which is broad on purpose.
- Commands assume a POSIX login shell for the SSH user. The program lookup (`command -v`) asks for `sh` first, which every system has: if the login shell has no `command` (csh, tcsh), Michel sees it. The PHP lookup is then listed as **not seen**, and the server's PHP findings stay open: never "no PHP".
- Limits: 60 s per command, 5 min per collection, 1 MiB of output per command, 256 KiB per configuration file.

### PHP of the command line is not always the PHP of the site

The `php` in a terminal can be another version than the one serving the site (PHP-FPM, another `php.ini`, settings per site). Michel reads **both** when it finds them, and says when it only saw the command line. If you give the site address (`--site-url`), Michel also reads the `Server` and `X-Powered-By` headers with a plain GET, as a browser would. It cannot detect every case: see [limits](#12-limits-you-should-know).

### What is exposed

The **Exposure** part of the server sheet lists the services that wait for a connection, as the server itself sees them. Three columns:

- **Open to all**: the service listens on every address of the server (or on an address that is not private). Whoever can reach the server could connect, **if** nothing blocks the way.
- **Reserved**: the service listens only for the server itself (loopback), or only for a private network. It is not meant to be reached from outside.
- **Not verified**: what Michel did not or could not check. Two lines are always there: **the firewall of the host**, and **the services in UDP** (Michel reads only the services in TCP, the most common way to connect to a service; a service in UDP, the other way, does not appear).

How to read it:

- **The list is read from inside the server. It does not prove that the service can be reached from outside**: Michel does not check the firewall of the host, and says so in the third column. A service "open to all" is reachable only if no firewall stands in front of it.
- Michel judges a service by its **port number alone**; it never connects to it. A well-known database or cache port open to all opens a finding of medium severity, "to close", in the To do list, and never an alert. Any other port that is open is shown as "service not recognized, to check", without a finding. The port Michel uses to connect to the server counts as administration.
- On a server of kind `shared`, the services may be the host's or another customer's: they are shown, with a sentence that says so, and open no finding. On a server in a container or on shared infrastructure, the list can also show services that are not yours.
- **"I know, it is blocked or wanted"** (on the finding) records your reason, which is required, and the audit log keeps it. The service stays in its column, with "You said: …. Michel did not check it". To change your mind, decide again with `michel decide` (for example `defer`, which gives it back to you on the date you choose).
- **When a service is no longer seen open**, Michel says exactly that: it **does not see it open to all any more**, and the date is the last time it saw it open. This is not a fix and not a verification: the service may have moved to another port, or stopped, and Michel does not know whether it was closed. A finding of this kind is never counted as "fixed", and its path has no such step: on the **Resolved problems** page it stands apart, under "No longer seen open to all". Michel does not start a fix for it either: closing a service is your job.
- A service that stays open to all keeps its finding, even on a server where Michel would not open one today (a shared server, or a port that became the connection port), until it is no longer seen open, or you have marked it as blocked or wanted.
- **Not read is not "nothing is open".** If `ss` is missing from the server, fails, gives an answer Michel cannot read, or lists no service at all (which cannot be: Michel has just come in through one), the list is **not read**. The sheet says "not read" and keeps a note that stays as long as it stays so. A server without `ss` is never "clean": the note is permanent. Nothing is opened or closed from a list that was not read. "No service seen" and "not read" are two different answers.
- **The AI agent never receives this list** (nor the addresses and ports): the inventory sent to an agent has no listening service, and an exposure finding starts no agent.

### When

Once a day by default; per server: every N hours, or **only by hand**; **Check now** or `michel target check <id>` at any time. `michel serve` runs the schedule; if it is not running, the digest says so. **Without a connection**, when a database of flaws is updated, Michel compares again what it already stored: a new serious flaw on a version you run alerts immediately, and the next connection confirms it.

## 5. Am I affected? The sources

- **System packages**: the OSV databases of the distributions (Debian, Ubuntu, Alpine, AlmaLinux, Rocky, Red Hat…), **off by default**. Michel offers to enable the one that matches the server (`michel source enable osv.debian`, same consent as in [sources.md](sources.md)); `michel target check` prints the exact command when one is missing. The version is judged by the distribution's database, not by `php -v`: distributions fix without changing the upstream number.
- **PHP rules**: an embedded, versioned set of rules, deterministic (no AI). Each has a setting, a risky value, an advised value, a severity and a plain explanation: `display_errors` on in production, `expose_php`, `allow_url_include`, `open_basedir` empty on shared hosting, `session.cookie_secure`, a PHP branch no longer supported, and PHP2Shell. A setting that PHP only reads from the main configuration (`PHP_INI_SYSTEM`) is not "fixed" by a `.user.ini`.
- **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619, exploited in the wild): judged on the **version**. Fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35; a branch older than 8.2 is treated as unsupported and affected. Michel may offer `session.upload_progress.enabled=0`, labelled **"reduces the risk, does not fix"**: only the update fixes. It never offers `memory_limit=-1`.
- The list of PHP advisories embedded in Michel is as fresh as your version of Michel (update Michel to update it).
- A server where the PHP version could not be read gets a finding "PHP version unreadable": zero finding with an unknown release or unjudged packages is never shown as "clean".

The server sheet says **affected / not affected / could not see everything**, lists the flaws, and the "not seen" list. A flaw of a project's code shows where it is deployed ("deployed on: server X (prod)").

## 6. A fix: the scripts and their actions

A fix is never free text. It is a **sequence of typed actions from a closed list**, which Michel translates to a readable POSIX shell script (`sh`, dash and busybox compatible):

| Action | What it does | Undo |
|---|---|---|
| `backup_file` | copies a configuration file to the server's backup folder and brings the copy back to your computer | none needed |
| `set_directive` | sets a PHP setting in an allowed file: the `php.ini` PHP loads (and its other ini files), a PHP-FPM pool, or a `.user.ini` | puts the saved file back |
| `test_config` | `php-fpm -t`, or has PHP read the ini; a failure stops everything before any reload | none |
| `reload_service` | `systemctl reload` of a PHP-FPM service, never `restart` | reload after the files are put back |
| `package_upgrade` | upgrades **one** package to **one** exact version | **no script**: your snapshot is the way back |
| `check_site` | a GET on your site address, from your computer | none |

- **No action deletes anything.** No `rm`, no emptying, no database. The only file written is an existing configuration file, saved right before. If a setting is nowhere, Michel **appends a line** at the end of the loaded `php.ini` (or `.user.ini` on shared hosting), never a new file in `conf.d`.
- Each fix produces two scripts, `apply` and `undo`, plus a plain "what it does" text. A SHA-256 fingerprint covers the scripts and the list of checks, together with the server and the fix; **what you validate is exactly what runs**, and Michel re-checks before sending.
- `apply` protects itself: `set -eu`, and a `trap` that puts the saved files back and reloads if a step fails after a change, then exits with code `9`. The new copies are made, and each line checked, before the `trap` is set: code `5` (the line changed) always means nothing was changed. This holds when you run it yourself.
- Fixed order: backup, change, config test, reload, site check, new collection of the server. A step that fails stops everything.
- Michel only writes **PHP configuration**. For nginx and Apache, it reports and explains what to change; it writes nothing.
- **Not testable, no script.** A fix reloads PHP, and Michel will not do that without testing the configuration first. The test is only run with PHP binaries named `php` or `php-fpm` (with an optional version) under `/usr/bin`, `/usr/sbin`, `/usr/local/bin` or `/usr/local/sbin`. A PHP elsewhere (`/opt/…`, compiled by hand) gets **no script at all**, not even for you, and Michel explains why.
- A package upgrade is tried first with the package manager's dry run (`apt-get -s`, `dnf --assumeno`, `apk --simulate`). If it would remove or replace a package, or is a downgrade, or jumps to another PHP branch or a major version, the fix is **refused**: "the upgrade would remove X". Major upgrades are only explained.
- A file that is a symbolic link (for example Debian's `conf.d` links into `mods-available`) is never changed through the link: the script stops, "fix this file by hand".

### What happens when it fails

| Situation | What Michel does |
|---|---|
| A step fails after a change | the script puts the files back, reloads and exits `9`; state *rolled back*, an alert. Michel reads that code, or the script's last line, before any other code: a command failing with its own code (a reload exiting `5`) is never taken for "the line changed" |
| The site stops answering after a config fix | `undo` right away if Michel runs it; otherwise an urgent "run `undo` now" with the script shown |
| `undo` itself fails | urgent alert, with the saved copies to put back by hand |
| A **package** upgrade fails or the site dies after it | **never rolled back automatically**: state *failed*, urgent "restore your snapshot" |
| The script ran past its time limit, or the connection dropped | state **`unknown`**: Michel cannot say what changed, urgent alert, a new collection, and no guessed undo |

Time limits of a Michel-run script: **5 minutes** for configuration, **30 minutes** for packages. Michel never sends a signal to stop the script (killing `dpkg` midway is worse than waiting). But once the limit is past, it closes the connection: a command that still writes to its output may then stop. A package upgrade longer than 30 minutes can therefore be cut: keep your snapshot. A fix that failed is never run again: prepare a new one (new ID).

If you run a script yourself, these are its exit codes:

- `0`: fine.
- `3`: not run by the right user (root for `php.ini` or a pool, the SSH user for a `.user.ini`).
- `4`: this fix was already applied (for `undo`: a backup is missing).
- `5`: the line changed since the last check (nothing was changed).
- `6`: a file is a symbolic link.
- `7`: unsafe folder or backup.
- `8`: the **rollback failed** (urgent: look at the server).
- `9`: a step failed after the change; the files were put back and PHP reloaded.

Codes `3` to `7` always come before any change, with their line of explanation. See [troubleshooting](#11-troubleshooting).

## 7. Who runs the script, and sudo

- **`executor: user`** (default): the page shows the two scripts with a **Copy** button. You run them, then click **I applied it**, which starts a verification.
- **`executor: michel`**: after **Validate**, Michel sends the validated script over SSH (`sh -s`, nothing executable left on the server except backups) and follows each step.

Who runs it:

- A script that touches a file owned by root (`php.ini`, a pool) runs **entirely as root**. It checks first that it is root, and otherwise stops before any change with "run this script as root". With `executor: michel` and `sudo: nopasswd`, Michel sends it through `sudo -n sh -s` (never per line, and `-n` means it never waits for a password: if one is asked, the step fails and says so). Without `sudo`, it is proposed to you only.
- A `.user.ini` script runs as the **SSH user**, never as root.
- The text of the script does not depend on who runs it (same fingerprint).

## 8. Preproduction, snapshot, backups

- **Preproduction first**: if the server has a linked preprod, the fix runs there first. The production fix is **built again** from the production's own inventory (paths, versions, services), with its own fingerprint and its own Validate (or the level 3 rules). If the preprod is linked but does not show the finding, the fix is refused until you unlink it or check it again.
- **Snapshot**: before any script with `package_upgrade`, Michel blocks on **"make a snapshot of this server at your host"**; you tick **Snapshot done** (timestamped, audited). No tick, no run, even at level 3. Michel never gets access to your host account.
- **Backups**: on the server, a script run as root saves into `/var/lib/michel/backups/<fix>/` (a root-only folder), a `.user.ini` script into `~/.michel/backups/<fix>/`. Michel **never deletes** them, not even its own: empty them yourself when you want (`sudo rm -r /var/lib/michel/backups/<fix>`; the server sheet shows the size and says so). `undo` refuses a backup that root does not own. On your computer, each copy is kept **encrypted** (AES-256-GCM, key in Michel's secret store), 90 days. A copy whose key is lost reads "key lost"; the one on the server stays.
- Only **PHP configuration trees** are writable: the `php.ini` PHP loads, the other ini files it scans, a PHP-FPM pool, a `.user.ini`. A cPanel-style PHP tree that is not one of these is not writable. Root only writes in folders it owns that others cannot write, never under `/home`.

## 9. The four levels, and the agent

Each server has its own level (`--level`, default 1):

| Level | Name | What Michel does |
|---|---|---|
| 0 | Report | the alert and the sheet |
| 1 | Explain, prepare on request | the **Prepare the fix** button (default) |
| 2 | Prepare | prepares the scripts by itself for each flaw; they wait for your validation |
| 3 | Apply what I allowed | like 2, and runs without a click the fixes that follow all your rules |

**Level 3 rules**, all required, checked by Michel (never by an agent): `executor: michel`; the box "fix alone the known risky settings" ticked for this server; **only `set_directive` of Michel's embedded rules, to their advised value** (no package, no agent's proposal, never a `.user.ini`, which has no config test); a config test and a site check (so a `site_url`); `sudo: nopasswd` for a root file; a linked preprod proven first by Michel's **own** fix for this very finding; no other attempt running on the server (its script, or the checks after it) nor `unknown`; a testable binary. Fixes you prepared by hand may run alone if these rules hold. The digest and the alerts say what was applied alone and what was undone.

**One fix at a time per server.** While a fix is prepared, waits for your approval, runs, or is checked after its script (site, undo, new collection), or while its outcome is `unknown`, Michel prepares, approves by a rule and runs no other fix on that server, and the server cannot be removed. The same holds by hand: **Prepare the fix** says a fix is already in progress.

If the line changed (exit `5`), Michel checks the server again and prepares **one** new fix. If that one meets a changed line too, it prepares no other, even at level 3, and alerts you: you start the next try.

**The agent** (Claude Code, as in [fix.md](fix.md)) is only used to understand or discuss a case: a combined flaw, several possible settings, a choice between update and workaround. Michel alone prepares the known fixes (a rule to its advised value, a package to its fixed version). The agent never gets SSH access, sees only the **masked** inventory, cannot validate, and has no file tool: it proposes typed actions through one MCP tool, and Michel checks each action before assembling the scripts. The **consent is per server**, and it is the **preprod's** when a preprod is linked (it is its inventory that leaves). **You can revoke it** at any time. A server of kind `hds` (`health`) never gets an agent.

## 10. Alerts and SMS

Alerts use the channels of [daily-digest.md](operations/daily-digest.md) (mail, desktop notification, webhook), with a minimal content ("server X: 1 serious flaw", a link), never a detailed version or a setting. **A channel limited to some projects never receives a server alert.**

On a `generic` webhook, a server alert is `{"michel_server_alert": 1, "kind": "…", "title": "…", "text": "…"}`, not to be confused with the "a fix waits" message (`michel_fix_waiting`).

**SMS** is a channel type `sms` (`provider: freemobile` for the Free Mobile API, free for its subscribers, or `generic` for a paid provider through a signed POST). Its key sits in the secret store (`michel secret set sms-urgent`), never in the policy file; the Free Mobile login number is a plain field. It needs its own network rule (`notify.sms`). SMS is sent **only for the urgent**: a `prod` server with a flaw exploited in the wild (KEV) or critical, a rollback that failed, an `unknown` state, a package upgrade to restore from snapshot. An unfixed distribution advisory without KEV is never urgent. At most **3 SMS a day** (`sms_per_day`), all channels together, counted on **your local day**. The digest and mail carry the rest. A failed urgent alert is not resent (the digest lists it).

## 11. Troubleshooting

Michel shows these messages in your language; here is what to do.

| What you see | What it means, what to do |
|---|---|
| **No SSH agent with a key** | The agent is not running or holds no key. Windows: start the OpenSSH Authentication Agent service; then `ssh-add` your key. Or set `ssh.agent_pipe`. |
| **The server accepted none of the agent's keys** | Wrong user, or the public key is not in the server's `authorized_keys`. Test with `ssh user@host`. Michel does not use passwords. |
| **Password-only server** | Install a key (step 2) then retry; Michel will not use a password. |
| **Michel does not know the fingerprint yet** | Confirm it first (page, or `michel target trust <id> --fingerprint …`). |
| <a id="host-key-changed"></a>**The server shows another fingerprint: Michel did not connect** | Could be an **attack** (someone posing as your server) or a reinstall. Check with your host. Confirm the new fingerprint only if you know why it changed (`--replace`). Michel never connects meanwhile. |
| **The network policy does not allow this server** | The `target.ssh` rule was removed. Put the host back in `network.allow` with that purpose, or remove and add the server again. |
| **Michel could not reach the server** / **did not answer in time** | Address, port, firewall, server off. |
| **sudo asked for a password** | The script was not run, nothing changed. Set `sudo: nopasswd` for that user (only if you accept it), or run the script yourself as root. |
| **Michel cannot test the configuration: the PHP is not a system one** | The PHP is outside the system folders: no script, to avoid reloading PHP untested. Change the PHP setting by hand. |
| **To check its system packages Michel needs the source …** | Run the `michel source enable …` command shown. |
| **The PHP version could not be read** | Check that `php -v` works for the SSH user, then check again. |
| **The site stops answering after a fix, though it works** | If the site address redirects to another host (for example `www.`), the site check is refused by the network policy: only the address you gave has a rule. Give the final address as `site_url`. |
| **The file changed on the server since the last check** (exit 5) | Nothing was changed. Michel checks again and prepares a new fix, once. |
| **A fix could not be applied twice in a row, the file keeps changing** | Something else changes that file (a deploy tool, a hosting panel). Michel stops trying alone. Find what changes it, then prepare the fix by hand. |
| **The fix failed and was undone** (exit 9) | A step after the change failed (config test, reload); the files were put back. See the failed step on the page, fix its cause, then prepare a new fix. |
| **A file to change is a symbolic link** (exit 6) | Fix that file by hand. |
| **A folder or file can be changed by someone other than root** (exit 7) | Safety stop, nothing changed. Fix the rights, or the folder/backup that is not root's. |
| **The fix failed and could not be put back** (exit 8) | Urgent. Look at the server now; the saved copies are on the page and in the backup folder. |
| **Already applied** (exit 4) | Michel never runs the same fix twice. Prepare a new one. For `undo`, exit 4 means a backup is missing: nothing was put back. |
| **Not run by the right user** (exit 3) | Run it as root (or the SSH user for a `.user.ini`). |
| **The script gave no answer: state unknown** | Look at the server yourself (is the config valid, does the site answer?). Then say you checked: **I checked the server** on the page, or `michel fix resolve <attempt>`. The fix ends as failed; Michel changes nothing on the server. Until then the server accepts no new fix and cannot be deleted. |
| **A package upgrade failed / the site no longer answers after it** | No script can undo it: restore your snapshot, then check the server. |

## 12. Limits you should know

- The PHP of the command line may not be the site's PHP; Michel cannot always tell.
- The list of PHP advisories embedded in Michel is current only as Michel is updated.
- A script you run yourself is outside Michel's control: it protects itself, but you decide when and as whom to run it.
- nginx and Apache are reported and explained, never changed.
- BSD systems are not supported.
- The list of services that listen is read from inside, in TCP only, with `ss`: the firewall of the host and the services in UDP are not verified, and a server without `ss` stays "not read" ([What is exposed](#what-is-exposed)).
- A Pageant agent is untested.
- Debian records marked `unimportant` (no security impact in Debian, by its own security team) are not reported. Records with no verdict from Debian yet are.
- The authors ran this once from end to end on a throwaway Debian 13 container with systemd, sshd, PHP-FPM and nginx. Not tried yet: a hosting provider's real settings, shared hosting, a real network, and the Windows OpenSSH agent (that run used a test agent through `ssh.agent_pipe`). Try it first on a test server.
- The logs (section 13) were run for real on the same kind of container, with PHP-FPM, PostgreSQL and Monolog: at the default interval of 5 minutes, the alert came within 5 minutes of the error. Not tried: a real server, a real network, a server of kind `hds`, a server set to another time than UTC, and the Windows OpenSSH agent (that run also used a test agent through `ssh.agent_pipe`).

## 13. Server logs: be warned without copying them

This feature saves you from digging through logs to see the PHP, PostgreSQL and application errors. Michel reads the log files you declare, at regular intervals, and warns you by itself. By default **no log line and no message text leaves the server**: Michel gets only a few short items of an expected shape (level, error type, place in the code, number of times, path of the file read; the detail is below). The page for all of this is the **Logs** block of the server sheet.

**This is not legal advice: have your data protection officer (DPO) or a lawyer check it.** Logs can hold personal data, and health data on a server of kind `hds`. Michel reduces what leaves the server and says what it does; it does not decide whether this suits your obligations.

### What is read

- **Only what you declare and tick.** A server without a source is not read at all. **Look for logs on this server** proposes, from what Michel already knows, and creates nothing:
  - the `error_log` of PHP, command line and PHP-FPM, pools included. A FPM value holding `$pool` is **not proposed**: Michel does not know which pool name goes with it, so declare those files by hand;
  - `/var/log/postgresql/postgresql-*.log`, the default folder of Debian and Ubuntu. Michel does not read `postgresql.conf` here: on a server whose logs sit elsewhere, this proposal is wrong, so declare the real path by hand;
  - `storage/logs/*.log` and `var/log/*.log` under the remote folders of the linked projects.
- **A path you add by hand** must be absolute, without `..`. A `*` or a `?` is allowed in the file name only (`laravel-*.log`, for dated files): Michel then reads all the files that match, each with the place where Michel stopped reading it.
- **Try it** runs the filter once and shows exactly what would come back, without storing anything. It is the way to check that the chosen format suits the file.
- **No file written, nothing installed.** Michel sends a filter over SSH (`sh -s`, with `awk`, `tail`, `head`), run with the rights of the SSH user. If a tool is missing, the file is listed as not read: Michel never copies the file to filter it on your computer. The filtering happens on the server.
- **Never `sudo`.** An unreadable file is listed as not read, with the reason. The usual way out is to add the SSH user to the group that reads the logs: `adm` on Debian and Ubuntu (`sudo usermod -aG adm <user>`, effective at its next connection). PostgreSQL's files are readable by `adm` there. A PHP or application log has the group and rights your configuration gives it: if the SSH user cannot read it, change those rights in your configuration, Michel does not touch them. The same rules apply on a server of kind `hds`.
- **Shortcuts (symbolic links) are refused**, file by file, with a limit: Michel checks the file itself only, just before reading it. If a folder of the path is a shortcut (for example `current` in `current/storage/logs/app.log`), Michel follows it; and if someone swapped the file at the last moment, the new file would be read. Both need write access to that folder already. If the file itself is a shortcut, declare its real path.

### What leaves the server

| Format | Fields read | What to know |
|---|---|---|
| `php` | level, error type ("exception") if present, `file:line` | The message is ignored. Two different errors at the same line count as one. |
| `postgres` | severity, error code (`SQLSTATE`) if `%e` is in `log_line_prefix` | User, database, address, `DETAIL`, `STATEMENT`, `HINT` and `CONTEXT` never. See below for `%e`. |
| `monolog` (Laravel, Symfony…) | level, channel, exception class, `file:line` | Only the class and the place are taken from the context, by fixed rules. |
| `json` | the level and channel fields you name | A field is kept only if it is of a kind known in advance: a known level, a short identifier. |
| `text` | level only, by keywords or by a word you give | The alert just says how many errors. |

Michel also keeps the count per hour, by the date of the line when it can read one, and the dates when it first and last read the error. The sheet shows those read dates: an error read late carries the date of its read, not the date it was written. Only the first line of a multi-line error message counts. A `file:line` is given from the linked project's folder, otherwise it is the file name alone: a path such as `/home/<name>/…` does not come back as is in that place.

**For each log file read or not read**, Michel also gets its full path, including names matched by a `*` pattern that nobody declared (`client-jean_dupont.log`); for a file read, its file number (inode) and its position. It keeps them to resume at the right place, and the hour of the lines comes back too. **A path or a file name can therefore name a person.** These paths go neither in alerts nor in the summary.

**PostgreSQL and `%e`.** Without it, Michel sees the severity only. Put `%e` **last in `log_line_prefix`, right before the message**, for example `log_line_prefix = '%m [%p] %q%u@%d %e '`. Elsewhere in the prefix, it is not read. Michel explains how but changes nothing on the server.

**Never, under any setting:** a raw log line stored or sent, an IP address, an email address, a web address with parameters. Michel checks each item that comes back and throws away the one without the expected shape; the line is then counted as one that "could not be understood". A long number is left out too: in a type, a location or a channel, 7 digits in a row, or 3 or more groups of digits separated by `-`, `_` or `.`. That field is then removed, and the error is still counted by level. In a location, a folder made of a dotted number or holding a `.x` like a host name is left out the same way. A shorter number in a name, such as `Foo123456`, stays. In cleaned text, every word holding a digit becomes `[n]`. This does not necessarily remove names: see the limit below. No log data goes to an AI agent, on any server. The audit log holds no content: it says which server and source, the window, the volume, the number of records and a fingerprint of the result (`log.read`), and traces `log.source_add`, `log.settings` and `log.purge`.

**A limit.** A name written like an identifier (`jean_dupont`) can stay in the error type, the location or the channel, because Michel cannot tell it from a class name in a program. This takes a line written that way on purpose, or a real path or real file name holding that name.

**To see the detail**, the sheet gives the SSH command to copy (`grep` on the file, for the date of the error). Michel does not run it, and the lines stay on the server. It looks at the date of the latest known line of this error, in UTC (the world reference time). When that date is not known (no count left, or a line with no readable date, as always with `json`), it looks at the date of the last read. A server set to another time than UTC can make it miss lines around midnight: widen the search if so.

### Your choices, and what Michel recommends

| Setting | Recommended (default) | Other choices |
|---|---|---|
| Text of the message kept by Michel | None | Cleaned text |
| Text of the message in alerts | None | Cleaned text, only if the previous setting allows it |
| Retention | 90 days | 7 to 365 days, never shorter than the delay before "not seen again" |

- The recommended choice comes first. Any other asks for a **confirmation** that says what can leave and where it ends up: your computer, the recipient of the webhook, the mail provider. On a server of kind `hds` the warning is stronger and names health data: that data would end up outside the `hds` hosting, and the responsibility is yours. Michel does not block.
- While a setting differs, a **badge** stays on the sheet and on the list of servers, and the morning summary reminds you once a week. Choices, returns to the recommended one and confirmations are written to the audit log.
- **Cleaned text** is made on the server by the filter: quoted text, numbers, IP addresses, email addresses and web addresses are replaced, and the length is capped at 200 characters. It then goes through Michel's masking, which hides what looks like a secret, on your computer. **A name written without quotes can stay.** Cleaning reduces the risk and guarantees nothing.
- **Cleaned text is encrypted in Michel's database on Windows only**, like the other masked data. On Linux and macOS it is not encrypted: it is protected only by the rights of the data folder.
- The summary follows the alert setting: it holds text only if alerts do. **Setting the text kept by Michel back to "None"** erases at once the text kept for this server, and the erasure is written to the audit log. Setting only the alert text back to "None" stops sending it and erases nothing.
- **Erase the log data of this server** forgets everything Michel kept on your computer for this server, including errors you chose to ignore: if one comes back, it counts as new and is told again by your settings. Sources and settings stay. Read positions go: the next read starts from the end of the files. Nothing is erased on the server. Removing the server from Michel does the same, and forgets its sources and settings too.
- After the retention, counts, text and errors are purged. Only an error you chose to ignore keeps its record (without text), so that "stop warning me" holds.

### When you hear of it

- **Reading interval** per server: 5 minutes by default, from 1 minute to 24 hours, or only when you ask. Michel aims to warn you less than 10 minutes after an error that goes out at once: by default a critical error on `prod`, and also any level you set that way. An error sent to the summary has no such delay. With an interval above 10 minutes, this delay can be exceeded; the page says so.
- **"Only when I ask"** has no button on the page: the read is `michel target logs read <server>`. Nobody is warned in between.
- **This 10-minute delay holds only while your computer is on**, `michel serve` runs and the key is in the SSH agent. Michel cannot warn you when your computer is off. When it comes back on, Michel reads what was written meanwhile, within the volume limit described below. The morning summary then gives, with its dates, the period that was not read, when it lasted at least 30 minutes and at least two reading intervals.
- **"I can no longer read"**: if Michel fails 3 times in a row to read a server and has had no successful read for at least 30 minutes, it tells you, once per outage. At once on a `prod` server, in the summary on `preprod` and `dev`. A cause shared by all servers (SSH agent locked or absent) gives one alert. The sheet always shows the last successful read of each source.
  - **This also covers a server that answers but whose logs Michel cannot open:** no file of a source could be read, because the rights were lost (often after a rotation, when the new file has other rights), a tool is missing, or the read of the file failed. The same holds for a file that was unreadable from the start. On a `prod` server, the alert gives the cause; elsewhere the digest gives the dates only. The other sources of the server are still read. When the rights come back, the outage ends and Michel reads on from where it stopped.
  - **What does not count as a failure:** a file that is absent (Michel waits for it), and a shortcut or a folder in place of the file. They stay in the "not read" list of the sheet, and nobody is warned. With a `*` pattern, one file read is enough for a good read: the files it could not open are listed on the sheet.
- **Who is warned, by default:** on `prod`, a critical error at once, an ordinary error in the summary; on `preprod` and `dev`, both in the summary; warnings and information nowhere. All of it can be changed per server. On the row of an error, in the Logs block, the button **Stop warning me about this one** stops the warnings for that one and erases at once the text Michel kept for it, if any.
- **What "critical" means:** for PHP, fatal errors (fatal, parse, compile, core, catchable and recoverable fatal); for PostgreSQL, `PANIC` and `FATAL`; for Monolog and `json`, emergency, emerg, alert, critical, crit, fatal and panic; for `text`, the same words in capitals, or `[emerg]`, `[alert]`, `[crit]`, `[critical]`, `[fatal]`. **An "ordinary" error** (level `error`): `ERROR` and `ERREUR` for PostgreSQL; error, err and severe elsewhere. PHP has no such level: its lines are critical, warnings or information. A pattern of your own on a `text` log always gives `error`.
- **Not too many alerts:** one per new error, grouped by read; again only if it comes back after being "not seen again" for 7 days (adjustable; not seeing an error for 7 days does not prove it is fixed), or if it reaches 10 times the previous hour and at least 100 occurrences. At most 10 messages of errors per hour and per server (this setting is not on the page: see the end of this section). A message groups all the errors of a read, however many: it shows 5, the most severe first, and counts the others, which are on the sheet. Once those 10 messages have gone, new errors wait for the summary, and a single message per hour says so. "I can no longer read", the alert about a log that is too big and that single message do not count in the 10. The count is kept in memory: restarting `michel serve` resets it.
- **Content of an alert:** `PDOException, Invoice.php:42, 37 times`, the server's name and a link to its page in Michel (never the access token). A webhook sends the same message to an outside service, with a marker and the kind of alert: the cleaned text is there only if you kept it and allowed it in alerts. SMS stays off for log errors unless you tick it per server and the SMS channel has `urgent: true`, because the 3 SMS a day should stay with flaws. With no channel configured you can still read a log, with a warning and a badge: nobody will be told.
- **Morning summary:** see [daily-digest.md](operations/daily-digest.md) for `notify.digest_at` (08:00 by default).
- **Not on the page:** the delay before "not seen again", the read caps, the spike threshold and the messages per hour change only through Michel's API, a technical request (`PATCH /api/v1/targets/<id>/logs/settings`, fields `resolve_after_days`, `read_cap_bytes` up to 64 MiB, `read_timeout_seconds` up to 300, `max_alerts_per_hour`, `spike_factor` from 2 to 1000, `spike_min`). Without a precise reason, keep the defaults.

### Rotation, volume and the `*` character

- **First read:** from the end of the files present when you activate the source. Michel does not go back through the past. A file that appears later is read from its start.
- **Rotation** (when a log is archived and replaced by a new file): if the file was replaced (another file number, or inode) or got shorter, Michel starts at the beginning of the new file. What was left unread in the old one is lost, unless your `*` pattern also covers the old one; then the old one is read again from its start: what was already read is counted a second time, uses volume and can look like a spike. The sheet shows the rotation. With the `copytruncate` option of logrotate (the tool that archives logs) the file stays the same: Michel sees the rotation only if the file is shorter than its position at the next read. If it has already grown past that position, the beginning of the new content is missed and nothing says so. If you can choose, prefer the `create` option.
- **Volume:** at most 5 MiB (about 5 MB) and 30 seconds per source and per read, adjustable. Past 5 MiB, Michel jumps to the end and says how much it did not read. A read that goes past 30 seconds fails: the position does not move, it is tried again at the next interval, and repeated failures end in "I can no longer read". The sheet says how much was left out, and the next summary gives one line per server with the total for its period. If errors of level `error` go out at once on this server, an alert goes too, at most once an hour per source. If that level goes nowhere on this server, the summary says nothing about it and only the sheet shows it.
- **`*` patterns:** at most 50 files per read, and the 5 MiB are shared between them. Michel takes "newest" to mean **the last name in alphabetical order**, not the file changed last. It suits dated names (`laravel-2026-11-02.log`). It does not suit a pattern such as `app.log*`: the older numbered files come after `app.log` in that order, so they are read first and use the available volume; the sheet states the volume left out. **Past 50 files, Michel drops the first names, and `app.log` is the first: the file being written is then no longer read.** Declare `app.log` alone, or choose a pattern that does not match the numbered copies.

### For your record of processing activities

The record of processing activities is the GDPR document where you note what you do with personal data. To help you fill it in, with the same reminder: this is not legal advice, have your DPO check it.

| Question | Answer |
|---|---|
| Purpose | Detecting operating errors. The aim is not to follow people, but a name can stay in what is kept: a path, a file name matched by a `*` pattern, a type or a location (see above). |
| Data read | The log files you declare, on the server, with the rights of the SSH user |
| Data taken out | Level, type, `file:line`, channel, counts per hour and dates, hour of the lines. The path of each log file read, including names matched by a `*` pattern, its file number (inode) and position. Cleaned text only if you choose it |
| Where it is kept | Michel's database, on your computer. Encrypted text on Windows only |
| How long | 90 days by default, 7 to 365 |
| Who receives it | You, through the channels you configured: mail, desktop notification, webhook, SMS if you tick it for this server and the channel has `urgent: true`. Their providers receive the same content |
| Trace | Michel's audit log, without content |
| Erasure | Automatic at the end of the retention, or the button of the sheet. Nothing is ever erased on the server |

Fixed rules: no agent (Claude Code, see section 9) on a server of kind `hds`; no log data is passed to an AI, on any kind of server; the read uses the same network way out as the checks (`target.ssh`). Useful commands: `michel target logs list <server>` and `michel target logs read <server>`.

Network destinations: [security/network-egress.md](security/network-egress.md) (`target.ssh`, `target.http`, `notify.sms`). Fix levels for code: [fix.md](fix.md).
