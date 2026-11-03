# Decisions, daily digest and the Today page

🇫🇷 Version française : [daily-digest.fr.md](daily-digest.fr.md)

This part of Michel turns the list of findings into a daily routine: you decide once what to do about each finding, Michel sends you every morning what changed since the last time, and a local page shows the same on your screen. Everything below runs on your computer; only the email and webhook channels you configure send anything over the network.

## Decisions

A decision says what you will do about a finding:

| Action | Meaning |
|---|---|
| `fix` | You will update the package. |
| `defer` | Later. Michel asks again at the due date: 30 days by default, or `--for 45d`, or `--until 2026-12-01`. |
| `ignore` | It does not matter to you. A justification (`--why`) is required. |

```
michel decide <id-or-prefix> fix
michel decide <id-or-prefix> defer --for 45d --why "waiting for the next release"
michel decide <id-or-prefix> ignore --why "the vulnerable function is never called"
michel decide --project demo --package acme/lib defer      # every finding of that package in the project
michel decisions --project demo [--status fix|defer|ignore|superseded|all] [--json]
michel findings --project demo --status decided
```

- A decided finding leaves the list of findings to handle (status `decided`). **Michel never asks again** while nothing changes. It asks again (the decision becomes `superseded` and shows in the digest as a decision to review) only when:
  - the advisory's severity changes,
  - the fixed versions change,
  - the due date of a deferral is reached,
  - a finding that had disappeared comes back different.
- `--project` with `--package` decides on every finding of that package in the project that waits for a decision. Add `--force` to also replace decisions already taken. A package often carries several advisories, so this is the quick way through a first scan with hundreds of findings. It prints one summary line (how many findings, the decision, the first and last audit events); `--verbose` prints one line per finding instead.
- `--why` is optional for `fix` and `defer`, required for `ignore`, at most 1,000 characters. It is kept in the audit log: never put code or a secret in it.
- A finding that is no longer seen (status `gone`) cannot be decided: if it comes back, Michel asks only if something changed.
- Every decision is an audit event `decision.set`. A decision never touches the project folder.

## The digest

```
michel digest                       # print what changed; sends nothing, records nothing
michel digest --lang fr             # in French
michel digest --html > digest.html  # the email's HTML version
michel digest --json                # versioned JSON {"michel_digest": 1, ...}
michel digest --send                # send on every enabled channel, then record it
michel scan --all --digest          # scan every active project, then digest --send
michel scan --all --update --digest # read the enabled sources first (as michel source update)
```

**Window.** A digest covers everything since the end of the last digest sent with `--send`, whatever the result of its channels (`serve` and `scan --digest` are the exception: see below). The first time, it covers the last 24 hours. There is no cap: after three weeks away, the digest says "Everything that changed since <date>" and lists it all. `--since YYYY-MM-DD` forces the start, for example to send again after a channel failed.

**Exploited in the wild** comes first, above the projects, once `enrich.kev` is on: every finding on CISA's KEV list (or a malicious package) that is open or decided "fix", whatever its window and severity. The ones you deferred or ignored with a reason come back as one count line. **To read** comes after the projects: at most 10 unread vendor advisories of the window, about the technologies you use. Both are explained in [sources.md](../sources.md).

**Sections**, for each active project:

- a counter line: open findings by severity, your decisions by action, days without a new critical finding ("0 critical open" is shown as a state to keep);
- **New**: findings first seen in the window;
- **Gone at the last scan, without proof of a fix**: a finding that disappears from the lockfile is not proven fixed;
- **Decisions to review**: decisions Michel put aside, with the reason (severity changed, fixed version changed, date reached, came back changed);
- **Due dates**: deferrals whose date falls within the next 3 days, marked overdue once passed.

Findings are grouped by package: one line per package with the worst severity, the installed version, the target version and the advisory ids. Above the projects, a banner warns when the offline database is more than 7 days old, and when a project's last scan failed or was interrupted. After `michel source update` (or `scan --update`), a **catalog** line says how many sources are up to date and names those that could not be read, that wait for your consent or that have a new version ("Catalog: 6 sources up to date, feed.nginx unreachable."); it stays silent when everything is current. When nothing is new and nothing is due, Michel says so in one sentence. The last line links to the Today page (`notify.page_url`, never with the access token).

**`--send`** first takes the deferrals whose date is reached out of force (they become decisions to review), sends the digest on every enabled channel, then records the run (audit `digest.run`, one `notify.send` per channel). A channel that fails does not stop the others; the command then exits with code 1. With `michel digest --send` a run is recorded even with no channel configured: it is the "since last time" mark. `scan --digest` and `serve` record it only when a channel received the digest (see below).

**Sent by `michel serve`.** While `michel serve` runs, it sends the digest once a day, at `notify.digest_at` (local time, `08:00` by default; `off` stops it). If the computer was off at that hour, the digest goes out as soon as `serve` starts, after the first round of reading the logs (2 minutes at most), so that it holds what was written meanwhile and the periods that could not be read. The scheduled task above can stay: both use the same record of the last digest, and a digest already sent on the same local day is not sent again, whichever of the two sent it (`michel scan --all --digest` then says so and sends nothing). `michel digest --send`, run by hand, always sends. `serve` and `scan --digest` count a digest as sent only when at least one channel received it. With no channel, or with every channel failing, nothing is recorded: the next digest starts at the same date and holds the same elements, so nothing is lost (`serve` tries again 15 minutes later, and only on the channels that did not get it yet that day). Without any channel configured nobody receives the digest: only `michel scan --all --digest` says so (on the error output), while `serve` shows nothing and sends nothing.

**Server logs.** When a server's logs are read (see [servers.md](../servers.md)), the digest has a **Server logs** section, one block per server: the errors that are new or came back in the window, then the most frequent ones of the period, however few times they were read (at most 5 per server, the new and back ones first, then the most frequent), with how many times each was read. An error already told by an alert is still listed. A hole in the reading is listed with its dates, "between ... and ...": a server that is not a `prod` one sends no alert when Michel can no longer read it, so this line is how you learn it. The text of the errors is there only when the server's log settings send it in alerts (cleaned text, never a log line, an address, an email or a URL with parameters); by default there is none. Once a week, the section also reminds you of the log settings of a server that are not the recommended ones. A channel limited to some projects gets none of it.

A digest never contains code, absolute paths, the project's `test_cmd` / `install_cmd`, or a secret: only project names, counters, packages, versions, advisory ids, due dates and the page link.

## Channels

Channels are declared in the `notify` section of `config.yaml` (see `config.example.yaml`). There is none by default.

```
michel notify list           # the channels and whether they are enabled
michel notify test <name>    # a fixed test message, no data about your projects (audit notify.test)
```

### Desktop notification (`toast`)

```yaml
notify:
  channels:
    - name: desk
      type: toast
```

A notification on this computer: a title and two lines, no button. It is a local subprocess, not a network access: Windows PowerShell 5.1 from `%SystemRoot%` on Windows, `notify-send` on Linux (if installed), `osascript` on macOS (best effort). The text is passed as data, never as a command. On Windows, **do not disturb** hides the banner: the notification still lands in the notification center.

### Email (SMTP)

```yaml
sovereignty:
  network:
    allow:
      - {host: smtp.example.org, purpose: notify.email}
notify:
  channels:
    - name: mail
      type: email
      host: smtp.example.org
      port: 587                    # 587 = STARTTLS, 465 = implicit TLS; nothing else
      from: michel@example.org
      to: [me@example.org]
      username: me
      password_secret: smtp-mail   # a name in the secret store, never the password
      projects: []                 # empty = every project
```

Michel never sends mail unencrypted: port 587 requires STARTTLS, port 465 is TLS from the first byte (TLS 1.2 minimum). The mail holds a text part and an HTML part (inline CSS, no image, no script). The connection goes through the egress gateway (purpose `notify.email`).

### Signed webhook

```yaml
sovereignty:
  network:
    allow:
      - {host: hooks.example.org, purpose: notify.webhook}
notify:
  channels:
    - name: hook
      type: webhook
      url: https://hooks.example.org/michel
      format: generic              # generic | slack | discord
      secret: hook-key             # name of the HMAC signing key
```

Michel POSTs JSON. `generic` sends the digest JSON (`{"michel_digest": 1, ...}`), `slack` sends `{"text": "..."}`, `discord` sends `{"content": "..."}` cut to 1,900 characters. The url must be `https://` (plain `http://` only on this machine: 127.0.0.1, ::1, localhost). Redirects are not followed. A 2xx answer means sent.

Headers:

```
Content-Type: application/json
User-Agent: michel/<version>
X-Michel-Timestamp: 2026-10-23T06:30:12Z
X-Michel-Signature: sha256=<hex of HMAC-SHA256(key, timestamp + "." + body)>
```

The signature covers the timestamp, a dot, and the raw body bytes. `secret` is required unless the url is on this machine. To check on the receiving side (Python, standard library only):

```python
import hashlib, hmac
from datetime import datetime, timezone

def from_michel(key: bytes, headers, body: bytes, max_age_s: int = 300) -> bool:
    ts = headers["X-Michel-Timestamp"]
    expected = "sha256=" + hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, headers.get("X-Michel-Signature", "")):
        return False
    sent = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return abs((datetime.now(timezone.utc) - sent).total_seconds()) <= max_age_s
```

Use the raw body as received, before any JSON parsing. The age check refuses an old message replayed later. `key` is the value you stored with `michel secret set` (one trailing newline is dropped at storage).

### Allow rules

Network is denied by default. **Each enabled email or webhook channel needs its own rule** in `sovereignty.network.allow`, with the exact host (or `*.example.org`) and the purpose `notify.email` or `notify.webhook`. Without it Michel refuses to load the policy and the error prints the rule to add. A disabled channel (`enabled: false`) needs no rule. A toast needs none.

### Secrets

Passwords and signing keys never go in `config.yaml`. Store them under a name and put that name in the channel:

```
michel secret set smtp-mail                      # typed hidden
printf '%s' "$HOOK_KEY" | michel secret set hook-key
michel secret list                               # names only, never values
michel secret delete hook-key
```

The value is never an argument (so it stays out of the shell history), never printed, never in the audit log (`secret.set` records the name only). Names are 1 to 64 lowercase letters, digits or hyphens; `api-token` is reserved for `michel serve`. On Windows each secret is a file in `<data-dir>/secrets/` encrypted for your user account (DPAPI). On Linux and macOS it is a plain-text file readable by your account only (mode 0600), and `secret set` says so; the system keychain comes later.

## The Today page

```
michel serve                 # http://127.0.0.1:7331/
michel serve --open          # also opens the browser
michel serve --listen 127.0.0.1:8080
```

`michel serve` starts a page and its JSON API **on this computer only**: it accepts 127.0.0.1, [::1] or localhost and refuses any other address, so nobody else on the network can reach it. It makes no outbound connection. Ctrl+C stops it.

- **Token link.** The first start creates an access token (kept in the secret store as `api-token`). `serve` prints the link with the token: `http://127.0.0.1:7331/?token=...`. Open it; the page keeps the token in the browser and removes it from the address bar. Keep that link to yourself. The link in the digests (`page_url`) never carries the token: if the page asks for it, paste the link `serve` printed.
- **What it shows.** Per project: what needs your attention, the counters, and for each finding a sheet (the three sentences, the facts, a glossary). You can decide `fix`, `defer` or `ignore` from the sheet: same rules as `michel decide`, recorded with author `web`. The page is in English or French and follows the system's light or dark theme (both can be changed in the settings).
- **Install it.** In Chrome or Edge, the install icon in the address bar (or menu > Install page as app) adds Michel as an app (PWA). The app window then opens even when `michel serve` is stopped, and says that Michel does not answer.
- **Rebuilding the page.** The page is embedded in the binary. To rebuild it from the sources: `make web` (needs Node and npm), then `go build`. Without npm, the binary still builds and `serve` shows a short text page.

## Scheduled task (until `michel schedule`)

`michel schedule` does not exist yet. Meanwhile, create the scheduled task yourself. The line to run every morning is:

```
michel scan --all --update --digest
```

It first reads every enabled source (OSV databases, KEV, EPSS and the other enrichments; a source still waiting for your consent is not contacted), then scans every active project, then sends the digest. A source that cannot be read does not stop the scan: the previous data is used, the digest says so and the command exits with code 1. Run it **as your own user account**: the secrets are encrypted for that account (Windows) or readable by it only, and the toast needs your open session. If the computer is off at that time, nothing is lost: the next digest covers everything since the last one.

### Windows (Task Scheduler)

In a terminal (no administrator rights needed), with the path to your `michel.exe`:

```
schtasks /Create /TN "Michel daily digest" /SC DAILY /ST 06:30 /TR "\"C:\Tools\michel\michel.exe\" scan --all --update --digest"
schtasks /Run /TN "Michel daily digest"       # try it now
schtasks /Query /TN "Michel daily digest" /V /FO LIST
schtasks /Delete /TN "Michel daily digest"    # remove it
```

The task runs only while you are logged on, which is what the toast needs. To run a morning missed while the computer was off, open the task in Task Scheduler (`taskschd.msc`) > Settings and tick "Run task as soon as possible after a scheduled start is missed".

### Linux and macOS (cron)

`crontab -e`, then:

```
30 6 * * * $HOME/bin/michel scan --all --update --digest >> $HOME/.local/state/michel-digest.log 2>&1
```

Create the log folder first (`mkdir -p ~/.local/state`). cron does not see your desktop session: on Linux the `toast` channel usually fails from cron; use email or a webhook there, or the systemd timer below.

### Linux (systemd user timer)

`~/.config/systemd/user/michel-digest.service`:

```ini
[Unit]
Description=Michel daily scan and digest

[Service]
Type=oneshot
ExecStart=%h/bin/michel scan --all --update --digest
```

`~/.config/systemd/user/michel-digest.timer`:

```ini
[Unit]
Description=Run Michel every morning at 06:30

[Timer]
OnCalendar=*-*-* 06:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Then:

```
systemctl --user daemon-reload
systemctl --user enable --now michel-digest.timer
systemctl --user list-timers michel-digest.timer
journalctl --user -u michel-digest.service      # output of the last runs
```

`Persistent=true` runs a missed morning at the next start.

### When something fails

- Exit code 1 means a scan or a channel failed; the other projects and channels still went through. `michel audit list --last 30` shows `digest.run` and one `notify.send` per channel with its result.
- A failed channel does not move the window back: to send the same period again, run `michel digest --send --since <YYYY-MM-DD>`.
- `michel notify test <name>` checks one channel on its own, with a fixed message.
