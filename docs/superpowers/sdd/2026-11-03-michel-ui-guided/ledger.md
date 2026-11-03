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
