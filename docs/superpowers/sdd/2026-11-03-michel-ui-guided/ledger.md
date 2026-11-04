# SDD ledger — plan: docs/superpowers/plans/2026-11-03-michel-ui-guided.md
Spec: docs/superpowers/specs/2026-11-03-michel-ui-guided-design.md. Branch feat/ui-guided. Owner opted out of questions ("suis tes reco"); merges into main are Claude's after final review, no force-push.
Plan rulings R1-R18 are in the plan itself.

## Pre-flight (table in git history of this note: preflight.md, 46 conflicts settled, plan at c6977aa)
Ruling: C1, the side navigation starts at 960 px through a tested `navMode(width)`, not `mdAndUp` — `md` is 840 in `web/node_modules/vuetify/lib/composables/display.js`, and changing thresholds would shift other pages — a tablet between 840 and 959 gets the bottom bar.
Ruling: C2, `jargonExceptions` starts empty at T3 and each task adding a key with `port`, `paquet` or `SSH` appends it, rule in Global Constraints, `texts.test.js` in T3 — the list cannot be written before the keys exist; today 5 keys in these families, none with jargon, parity 0 and 0 — a task forgets the list and goes red at its own gate.
Ruling: C3, `web/src/lib/helpView.js` is in T13 and T14 — the two-way test of T4 fails without it — none.
Ruling: C4, the API note wins except `manual`, where the local sentence of the mode wins; `api.logs.interval.manual` reworded; catalogues in T5, both gates — the API has one text and no mode, and that text promised a button — a CLI reader of the API sees the simple sentence.
Ruling: C5, the merge line and command only without `attempt.server`; a server in `applied` gets rank 5 and its own text; project line has word `À finir` — `server_exec.go` sets `applied` on servers and `stateView` sets `branch` on them; the word was missing, `À valider` would be untrue — one more word.
Ruling: C6, T6 writes and tests the exposure line with the literal kind; T13 only feeds `closed` and checks the real API shape — otherwise the line is written twice — the literal drifts from Go, caught by the T13 case.
Ruling: C7, `todo.exposure_cache` chosen by `finding.rule` — T11 gives the same kind to caches, and `TargetFindingView.Rule` is `f.OSVID` — none.
Ruling: C8, a row with `action: null` is terminal and stands alone, order `no_git`, `health`, `report_only` for a project, `plan.exposure` then `report_only` for a server; `plan.project.title_michel` on terminal plans; `expo.how` written at T9 so the key exists — the tables said both at once — T13 keeps the same text, a later rewording must touch one key.
Ruling: C9, `approval` covers level 1 and up except level 3 with the flag — `handlers.go` sets the two independently and `auto.go` requires both — none.
Ruling: C10, a row for no attempt and `gone`, three cases in the test; open exposure uses the no-attempt row — R2 names three cases — none.
Ruling: C11, T9 changes `failurePath` to take `target = null`; `isVerified` stays on the attempt — `ServerAttemptView.Target` is `TargetRef`, id and name — a caller forgets `target` and the note does not show.
Ruling: C12, `who`, `agent`, `hds` may say « IA », no server text says « l'IA » — R1 wants the absence said — none.
Ruling: C13, `agent` when neither `hds` nor `health` — `healthTarget` is kind or classification — none.
Ruling: C14a, `serverPlan` returns `warn` and the test reads it — Vitest has no component — the component could still not show it, seen in the browser step.
Ruling: C14b, `TestScanProvesAMergedFix`, `TestScanWritesNothingInTheProject`, `TestScanOutputUnchanged` run in `internal/cli` against the real `scanOneProject`, output captured before the extraction — a fake `Deps.ScanProject` cannot fail — slower tests.
Ruling: C14c, the three T11 refusal tests stay as guards, shown failing once by a temporary change not committed — `server.go:280`, `server_auto.go:31`, `serverInventoryView` already refuse — none.
Ruling: C15, `internal/api/targets.go` in T11, `ruleKeys` reads `set.Listen`, title test; `ListFindings`, `ListServerFindings`, `ApplyServerFindings` all named — `ruleKeys` reads only `Config` and `Upstream`, and `repo.go:227`, `:434`, `:511` are the only kind lists — none.
Ruling: C16, `TestDigestServersCountsExposure` in `internal/digest/servers_test.go`, `servers.go` unchanged — the digest counts only and its query has no kind filter — none.
Ruling: C17, `TestExposureRoutesNeedTheToken`, `TestProjectRunRoutesNeedTheToken` — same package, the second would not compile — none.
Ruling: C18, `POST /findings/{id}/fix` asserts 404 and zero attempts — `IsServerFinding` is false for this kind, so `lookup` answers — the sentence says « finding not found », true enough.
Ruling: C19, `ServerSheet.vue` in T15, `read` set on its cards — they show `FailurePath` without `FailureGuide` — none.
Ruling: C20, `expo.closed`, `database_note`, `cache_note` have exact texts in T13; normal row shows note and no word; on `shared` a `close` shows `check` and does not count — R8 makes no flaw on `shared`, so « À fermer » would claim one — the reader may want other words.
Ruling: C21, opaque tag backgrounds as palette tokens, mockup values in light (5.62, 4.89, 5.68, 4.91), computed 12 % over `surface` in dark (5.95, 6.54, 6.47, 6.06), in T1's AA test; `À valider` info, `Important` look — recomputed: 12 % tints give 4.29 and 4.05 on `background` — four more tokens.
Ruling: C22, a « Voir le changement » link on `FixProposal` shows the diff and test output — a project fix has no script, so no way back in simple mode — one more link.
Ruling: C23, `handlers.go` in T12, shared helper for `Validate` and `Apply` errors, route adds its own check — `decision` is about fifty lines and its `lookup` wants a project — T12 touches a working handler, its tests guard it.
Ruling: C24, on a server a line only for `new` or `pending`, no Go change — confirmed: `ApplyServerFindings` shares `apply`, which moves a due defer to `pending`, and `ExpireDue` does it at digest send — a deferral due between two checks stays hidden until the next check or digest.
Ruling: C25, « Puis, dans Mes projets, clique sur « Contrôler ce projet ». » with a link, EN « Check this project » — T14 builds that label there — label ahead of its button between T8 and T14, on a branch.
Ruling: C26, `fixView.test.js` in T8, one case per changed text — `stateLine` changed with no test — none.
Ruling: C27, the controller runs T16 Steps 2 and 3, both checklists named by path, the later first; ledger path corrected in Global Constraints — `implementer-common.md` forbids subagents, `.superpowers/` is this run's ledger and is git-ignored — none.
Ruling: C28 (14b), `MICHEL_TEST_LOCAL_REMOTE` removed, R33: struct field set by tests, compile-time constant for `serve`, `-tags michel_local_remote` built only by T16 — an environment variable widens a product check on any install, and `Makefile`, `README.md`, CI build without tags — T16 runs a binary differing by one constant, without a real network.
Ruling: C29 (14b), `TestAuthRequired`, `TestCrossOriginRefused` become `TestGitRoutesNeedTheToken`, `TestGitPostsRefuseCrossOrigin` — same collision as C17 in `package api` — none.
Ruling: C30 (14b), the `filter.*` and `core.worktree` check runs before `status`, R34 — tried on Git 2.46.2: `status` ran a local `clean` filter on a same-size change, the witness appeared — none.
Ruling: C31 (14b), `check-attr --source=<sha> -z filter -- <paths>`, in batches of 100, no `--stdin` — `ExecFunc` has no stdin and `defaultExec` sets it nil; tried: without `--source` an attribute the update brings reads `unspecified`, with it `lfs` — a Git too old for `--source` refuses with `update_failed`.
Ruling: C32 (14b), `core.sshCommand` read by a direct `d.exec()` with `userEnv` — `h.git` points `GIT_CONFIG_GLOBAL` at Michel's empty file, and neither `netGit` nor `workGit` lists `config` — none.
Ruling: C33 (14b), `workcopy.Deps.AllowLocalRemote` carries the `:file` of `GIT_ALLOW_PROTOCOL` — `Push` and `Update` had no way to know — none.
Ruling: C34 (14b), rule removal on purge goes in `fix.PurgeProject`, table rows stay in `project.Repo.Purge`; `policy.RemoveAllowRules` already exists — `project.Repo` has no policy, `internal/cli/project.go` calls `PurgeProject` just before — a purge from elsewhere leaves a rule.
Ruling: C35 (14b), `GitFailure` gains `Current`, `Default`, sanitized and capped — `api.git.not_default` takes two `%s` and the type held only a class — none.
Ruling: C36 (14b), a `Local` remote: `Reason` `other`, `Display` and `Host` from `Display()`, no rule, no gateway, page treats it as `other` — T16 uses it and nothing defined it — only T16's build reaches it.
Ruling: C37 (14b), `fix_push` by `ON CONFLICT DO NOTHING` — a second click writes the row again on a primary key — none.
Ruling: C38 (14b), `GitState` fields and the suggestion rule stand in 14e, statuses in 14f, routes and shapes in 14g — split tasks read only their own text — repeated shapes can drift, 14f tests pin them.
Ruling: C39 (14b), R35: `POST /projects/{name}/scan` answers 409 `api.git.busy` during a click, through `fix.GitBusy` — only the reverse was covered, and a check would read a folder being written — one more refusal.
Ruling: C40 (14b), « Contrôler » in `api.git.filter_hint` becomes « Contrôler ce projet » — same as C25 — none.
Ruling: C41 (14b), a global `http.<url>.proxy` is added to « Declared only » — tried on loopback: it wins over the `http.proxy` Michel passes — none, this only says it.
Ruling: C42 (14b), 14b split into 14b, 14c, 14d, 14e, 14f, screens become 14g, all references moved — one implementer could not hold five packages, the catalogue and the docs — more commits, no change in behaviour.
Ruling: C43 (14c), `mergeStep` returns `none` for a server already at T8 — T8 had only `manual`, and C5 forbids `git merge` on a server — none.
Ruling: C44 (14c), screens poll the project and attempt every 3 s while `scanning` — « le chemin se recharge » had no mechanism — local requests during a check.
Ruling: C45 (14c), `guideGitQuestion` returns `{name, mode}` so a folder without repository shows `git.none`; repositories first — it returned only repositories, so `git.none` could never show — none.
Ruling: C46 (14c), `git.suggest.unsupported` goes in `jargonExceptions`, `s.scans` named in T14 — the rule of C2 and the name `TestUpdateRefusedWhileScanning` needs — none.
- Task 1: dispatched, BASE c6977aa.
- Task 1: a9e6064, review clean, 3 minors deferred (high not tested on tag fills, main.js registration not tested, .m-tag padding left to the screens).
- Task 1: complete.
- Task 2: dispatched, BASE a9e6064.
- Task 2: 85dc2f4, FR 2 important 4 minor, review 2 minor, fix e31d0ee, controller fix e28b5cb (focus only on a page change; a route change inside a page kept stealing focus). Not seen: light theme, English, real data. Deferred: nav.help unchanged, header logo green.
- Task 2: complete.
- Task 3: dispatched, BASE e28b5cb.
- Task 3: 1b76996, review 4 important 4 minor, fix efec47d.
- Ruling R36: 27 keys with jargon visible in simple mode (`servers.*` 23, `srvfix.*` 4, listed in the Task 3 fix report) get rewritten in Task 15, and the jargon test then covers the whole catalog minus advanced-only families — a task per key would scatter the work, Tasks 9 and 13 touch some anyway — costs jargon on those screens until Task 15.
- Task 3: complete, scoped re-review running with Task 4.
- Task 4: dispatched, BASE efec47d.
- Task 3 re-review approved. Parked minor: `stripTechnicalIds` edge cleanup runs even when no id was removed ("Et voilà" loses "Et"), to fix with the next web fix round. Task 6 must not hide `ExploitedBanner` until its Urgent lines exist.
- Task 4: 4739542, review 2 critical 7 important 16 minor, fix 6fc5ab4, 6ee0867, c4cde86. 38 help ids.
- Ruling R37: the words on sudo and on automatic undo change, not the code — plan 6 behaviour is merged and reviewed; the help must be true — costs nothing on behaviour; to show Kévin: sudo also reads backups and simulates updates, a root script runs without a click at level 3 with auto_config, a server without site address has no outage detection, a software update is never undone.
- Noted: plan 6 spec line 89 still says "Jamais pour lire", historic, left. Dialog closing by Escape drops focus on body, to fix in Task 15. Non-specialist French pass running beside Task 5.
- Task 5: dispatched, BASE c4cde86.
- Task 4: French reader 8 important 4 minor, applied aaf5831. `help.settings.token` left: `michel serve` is never introduced, for Task 15. Task 4: complete.
- Task 5: 46f399d, review 3 minor; backticks fixed ecac929; parked: load() order not pinned by a test, refreshView can overwrite an action error. Real clipboard content not observed. Task 5: complete.
- Task 6: dispatched, BASE ecac929.
- Task 6: 431960b, review 5 important 4 medium 3 low. Fix round dispatched.
- Ruling R38: open project flaws are read from `GET /projects/{name}/findings`, one line per package and severity, overstated line only if that read fails — the digest's `new` holds only the window — costs one request per project.
- Ruling R39: R15 widened, À faire reads the detail of up to 20 servers even with 0 flaws — a clean server without its distribution database must not read "Rien à faire" — costs up to 20 requests on each load; above 20, the unseen note stays.
- Ruling R40: `DecisionPanel` joins the flaw view of `FixPage` in both modes — a novice must be able to defer or ignore what À faire names, above all when no fix is possible — costs one more block on that page, Task 8 places it under the path.
- Task 6 fix: f4f2c8a, e3f07db, 69feb4b. For Task 8: panel far down on a phone, `applied` project fix has no panel, simple-mode sheet shows `file:line`.
- Task 7: dispatched, BASE 69feb4b.
- Task 6 re-review not approved: N1 head "Rien à faire" over known blind spots, N2 `canDecide` looks at the attempt shown, N3 `applied` no panel, 3 French. Fix round 2 after Task 7 commits.
- Ruling R41: "Rien à faire" only when nothing is unseen, overriding the brief's older line — R39 and the anti-objective — costs a less calm head when a minor thing was not seen.
- Noted N4: a project scanned long ago has no age note; needs a date from Go; for Task 14 or later.
- Task 7: b70da74, review running. For Task 13: `resolvedLines` takes exposures but the page passes []; server detail drops `gone` findings and needs a real "gone" date.
- Task 6 fix 2: 635dac4. Task 6: complete. Browser not re-looked after fix 2.
- Task 7 fix: d1769d8: verified needs the flaw still gone, a third group "Revenues". F6 left for Task 13, F7 (empty package and osv id title) parked. Controller read the stat; no scoped re-review, final review covers. Task 7: complete.
- Task 8: dispatched, BASE d1769d8.
- Task 8: c5de278, review 1 critical 4 important 6 minor 5 French. Fix round dispatched.
- Ruling R42: the text says a key written in code stays in the copy and reaches Anthropic; the agent's start is not changed in this plan — plan 5 flow, to show Kévin first in the final report — costs a warning that comes after the start until he decides.
- Ruling R43: a code flaw has no rescan on the copy: "Vérifiée" needs `proven_fixed` and the flaw still gone, `rescan_clean` is required only where a rescan could run; the proposal says Michel could not check it on the copy, never "toujours là" — R2's rare case is every code flaw — costs relying on the post-merge scan alone.
- Ruling R44: on `applied`, step "Corrigée" is not done and not green: it reads ready, not yet in your code — the table in the plan was wrong — costs one more label.
- Task 8 fix: 9a947c6, 1dd13bd. Accepted: `inconclusive` stops at Corrigée. For Task 14 or a later fix: stored `rescan_ran` so a dependency flaw whose rescan failed does not say "toujours là"; CLI "toujours là" on a code flaw; `fix.chat.applied`. Plan R2 and its Task 8 table are superseded by R43, R44.
- Waiting on Kévin: hold the agent when a key is found in the code? Recommended yes. Not built until he answers.
- Task 9: dispatched, BASE 1dd13bd.
- Task 8 re-review not approved: 4 important 8 minor, written in W/task-8-rereview.md by the controller from the reviewer's message. N1: a code flaw almost never reaches `proven_fixed`, `Prove` runs before `runPlugins`. Fix round 2 after Task 9 commits.
- Task 9: 7b346f9, review 5 high 4 medium 3 low 7 French. Fix round after Task 8 fix 2.
- Ruling R45: `expo.how` drops the promise of a confirmation after a firewall block; `ss` from inside still sees it open — the plan's "inchangé" yields to truth — costs nothing.
- Ruling R46: the view gains `ecosystem` on `TargetFindingView` and the running attempt of a preprod on the production card; `Demander à l'agent` hidden when the API would refuse; "Préparer quand même" removed or made real, whichever the API supports — true page over frozen brief lines — costs small API fields.
- Task 8 fix 2: f7c7c6a, 5cdab86, a172aaa. `fix.Prove` takes `Pass{Scanned, Sources}`, an attempt waits when its tool did not look. Task 14's control must pass a real Pass. Parked: `SkippedKnown` in plugin/run.go can close a plugin vulnerability OSV starts reporting and so prove a fix; a code flaw whose tool does not run in `michel scan` stays `applied`, documented. Task 8: complete; final review covers fix 2.
- Task 9 fix: 3441242, d3e2169. Parked: a fix first started on the preprod's own card has no production link; refused page repeats a sentence. Task 9: complete, scoped re-review running.
- Task 10: dispatched, BASE d3e2169.
- Task 9 fix 2: 9915d1c. Task 9: complete. Left: `approval_*` says "sur ce serveur" for a preprod's settings; `servers.unknown.body_preprod` wording.
- Task 10: d802e69, review 1 important 3 minor, fix 57944dd: zero rows is not a read. A server without `ss` stays unread with a permanent note, to tell Kévin. Task 10: complete.
- Task 11: dispatched, BASE 57944dd.
- Task 11: 4434d02, review 3 important 3 minor. Fix dispatched.
- Ruling R47: a closed exposure is never "faille corrigée" nor "Vérifiée": digest count `NoLongerOpen`, Task 13's last step reads "Michel ne le voit plus ouvert à tous" — from inside a port can move or a service restart; overrides the brief's "servers.go ne change pas" and R2's exposure case — costs one more digest line.
- Ruling R48: "Clean" texts no longer say nothing is open; they say no flaw waiting — a server with a kept exposure or an unknown port could read "Rien n'est ouvert" — costs a less comforting word.
- Kévin: "je te donne les autorisation, agit en autonomie". Read as yes to the recommendation on keys found in code.
- Ruling R49: when `SecretHits` is not empty, the agent does not start: the attempt waits for an explicit yes, no automatic start at any level; new Task 8b — R42's question, recommended, authorised in general terms — costs one more click and a waiting attempt at levels 2 and 3 until answered.
- Task 11 fix: 58c03a0. Task 11: complete. For Task 13: `resolved.exposure` wording.
- Task 8b: dispatched, BASE 58c03a0.
- Task 8b: 6480179, e86b7b5; review running. Task 12: dispatched, BASE e86b7b5.
- Task 8b review: 1 critical 4 important 6 minor; no path starts an agent without a yes.
- Ruling R50: only strong hits hold the agent: a known key format, or a literal value that looks like a secret on a sensitive name; weak hits such as `password: string` or a sentence on a sensitive name do not hold and appear as one sentence — a hold on ordinary code teaches people to click yes and kills levels 2 and 3 — costs a real key of an unusual shape not holding, stated in the text.
- Ruling R51: an unanswered hold ends as a no after 14 days; `michel fix continue` needs a terminal and a typed word; no requeue after a no on the same commit — I1, I3, I4 — costs a retry to do by hand after 14 days.
- Task 12: 8e87a65; review running. To tell Kévin: go editing scripts left in the temp folder by the implementer, delete denied.
- Task 12 fix: 313567e. Task 12: complete.
- Task 8b fix: a88f917, 4a9c1b5, 1d8bbc5; re-review running. Task 8b: complete if approved.
- Task 13: dispatched, BASE 1d8bbc5.
- Task 13: afd9e22; review running. TestHeldDigestIsNotSentAgainToTheChannelsThatGotIt fails at about 23:20 on 963b4f5 alone: diagnosis running.
- Task 8b re-review not approved: strength rule N1-N8 (ordinary code on a bare name strong; PHP define, Stripe clients, JWT not seen at all; random letters weak). Masking not narrowed, expiry correct. Reviewer also ran the rule read-only on the 7 private projects, counts only, unasked: to tell Kévin. 5 of 7 hold at that point; lower bounds.
- Ruling R52: detectors widen for `define(...)`, `sk_live_`, `rk_live_`, JWT, `xox?-` — it only adds to masking, and a tracked wp-config reaching Anthropic unmasked is the worse risk — costs more chips in the diff. R50 stands for weak hits; the automated security note asking every hit to hold on automatic starts is declined for the reason of R50, stated in the final report.
- Task 13 review: 2 high 7 medium 8 low. Fix after Task 8b fix 2 ends, both edit fr.json.
- Ruling R53: in simple mode an explained "numéro d'accès" shows only inside "Que faire ?" and the dialog — two identical "Base de données" rows cannot be told apart otherwise — costs one small piece of jargon, explained.
- Test digest: 8a176d8, the test's clock only; production fine. `digest_at: "00:00"` can give two copies within an hour across midnight, allowed by R29.
- Task 8b fix 2: 14c42e8, cbca0c7. Task 8b: complete. Next to close, with final fixes: `$config['password'] = '…'` and `new mysqli(...)` unmasked. Noise rate on real code not measured.
- Task 13 fix: 008180f. Task 13: complete; final review covers it. "Michel t'en reparle demain" to soften in Task 15's text pass. Check `ServerLogs` TypeError against the real API in Task 16.
- Task 14: dispatched, BASE 008180f.
- Task 14: ccebcf0, review 3 high 5 medium 7 low, fix 0033c83. Task 14: complete. `queue` stays true. Path checked only when added.
- Task 14b: dispatched, BASE 0033c83.
- Task 14b: 87ff0b9, review running.
- Ruling R54: `project_remote.url` stores the address without its SSH user, and the comparison at each click ignores the user, the push reading it from the person's config — "never a credential stored" — costs a re-read of the config.
- Task 14c: dispatched, BASE 87ff0b9.
- Task 14b fix: 4592ded, `Address()`. Task 14b: complete. Plan updated for R54.
- Task 14c: f2e2964; review running.
- Ruling R55: a person's own `http."https://host".proxy` config can bypass Michel's proxy: stated as declared only in 14f, no refusal — it is the person's own setup, and SSH already goes directly — costs an egress not seen by the gateway. 14d's `Update` is named `UpdateFolder`, `workcopy.Update` exists.
- Task 14d: dispatched, BASE f2e2964.
- Task 14c review: 1 critical 1 high 2 medium 2 minor. Critical: a hostile project's `.git/config` with `extensions.partialClone`, a promisor remote and `core.sshCommand` runs a program on `rev-parse`, also in the older `copy.go:340`, `apply.go:526`, already on main. Fix after 14d ends: `GIT_NO_LAZY_FETCH=1`, refuse promisor keys, everywhere Michel runs git in a project. To tell Kévin.
- Task 14d: b5e5937; review running. Task 14c fix and hardening of all git calls: dispatched.
- Task 14d review: 1 critical 4 high 2 medium 5 low. Critical: merge overwrites ignored files with result `updated`. Fix after the hardening round ends, same package.
- Ruling R56: the patch id test stays, comment and R25's cost corrected: it ignores whitespace and position — a squash needs it — costs a rare false "merged" that the scan then contradicts.
- Task 14c fix and hardening: a5dc896, 34d62f9. One git runner, witnesses on every command; holes found beyond 14c on `fetch` and in a scanner's env, all closed. Remaining for a hostile project: its tests run in the copy by design; a scanner's git partly covered, Semgrep and Trivy real commands not observed. Partial clones get `failed`: to state in 14f. Task 14c: complete; final review covers it.
- Task 14d fix: d2a97fe. Task 14d: complete. `ignored`, `update_partial` classes for 14e. To do before merge: `internal/workcopy` tests at 440 s of go's 600 s limit: one prepared fixture copied per case. Stale `index.lock` gives update_failed each try.
- Task 14e: dispatched.
- Task 14e: 0784beb, with the 4 routes and R35; review running. 14f brief minus routes. Test speed-up running.
- Task 14e fix: 58baf09. Task 14e: complete. Still untested: a real scan after an update, for Task 16.
- Task 14f: dispatched, minus routes, plus R55 and partial clones in "Declared only".
- Workcopy tests: 1c9872d, 414 s to about 100 s, same 273 names.
- Task 14f: 212c542; review running. Task 14g: dispatched.
- Task 14f fix: 4efae0a. Task 14f: complete. Task 14g: 84c2a1a; review running. Task 15: dispatched.
