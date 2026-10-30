# SDD ledger — plan: docs/superpowers/plans/2026-10-30-michel-fix-agent.md

Spec: docs/superpowers/specs/2026-10-30-michel-plan5-fix-agent-design.md (reachable). Started 2026-10-30. Execution method: subagent-driven (Kévin).

## Preflight scan
| rows | produces / consumes | finding |
|---|---|---|
| T1↔T4 | fix.ProposeInput, fix.Proposal (T1) / mcp Deps.Propose (T4) | ok (type in fix to avoid cycle) |
| T1↔T8 | fix.Repo, states, queue (T1) / Service, Worker (T8) | ok |
| T2↔T3,T4,T8,T9 | mask.Masker, StreamUnmasker, HasToken, ScanFiles | ok |
| T3↔T4 | brief.Build / get_brief | ok |
| T5↔T8 | workcopy.Prepare/Diff/Commit/Apply/IsMerged, scan.ScanDir / Propose, Apply, Prove | ok |
| T6↔T5,T7,T8 | allowproxy.Listen addr / Work.ProxyAddr, agent.Deps.ProxyAddr | ok — who starts the proxy: T8 service (ruling 1) |
| T7↔T8 | agent.Start/Spec/Event / fix.Deps.Agent | ok |
| T8↔T9 | errors typed, Worker / routes, goBackground | ok |
| T9↔T10 | routes + SSE / FixPage, stream.js | ok |
| T1↔T10 | PATCH /projects/{name} (T1) / settings UI (T10) | ok |
| T3 self | consumes feed items "Task 6 du plan 4" | ok (exists) |
| T4 self | michel mcp process runs Propose in its own process (cli wiring builds fix.Deps) | ruling 2 |
| T6 self | DialAddrForTest named in tests and interfaces | ok |
| T7 self | builder verifies Claude Code options; stop if isolation impossible | ok |
| T8 self | AgentHosts list incomplete ("…") | builder completes, documented in T11 |
| T10 self | manual check uses MICHEL_CLAUDE_BIN — must be defined by T7 agent.Deps.Binary default | ruling 3 |
| T11 self | real run with a demo project and real Claude Code | ok; controller does Step 2 |

Ruling 1: allowproxy instances (fix.install, agent.claude) are started by fix.Service per attempt and closed at the end — the plan names no owner — cost if wrong: one proxy per attempt instead of per serve process (minor overhead).
Ruling 2: `michel mcp` (separate process launched by Claude Code) calls fix.Propose directly on the shared store with fix.Deps built in internal/cli/mcp.go; serve learns of the proposal by polling the store for the SSE stream — no IPC needed — cost if wrong: up to ~1 s latency on the page.
Ruling 3: agent.Deps.Binary defaults to env MICHEL_CLAUDE_BIN when set, else `claude` on PATH (T7) — T10 manual check relies on it — cost if wrong: none.
Ruling 4: commit trailer Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com> (plan Global Constraints).
Task 1: BASE b6c6d11
Task 1: implementer DONE_WITH_CONCERNS ad17a23 (no red run seen; SetExternalProviders refuses under strict_local by validation)
Ruling 5: SetExternalProviders never changes sovereignty.mode; under strict_local enabling fails validation and leaves no file — spec § 7.3 « strict_local : refusé tant que l'utilisateur n'a pas activé » — the switch out of strict_local stays a user action; T8 maps it to ErrStrictLocal with the explanation — cost if wrong: one extra user step on strict_local installs.
Ruling 6: a proposal waiting for validation blocks that project's queue (one attempt at a time per project, spec § 7.1) — cost if wrong: slower level-2 throughput.
Task 1: FR review applied 57dde47
Task 1: review Approved (spec ✅). ⚠️ strict_local refusal → carried to T8 (ErrStrictLocal); queue pop/create serialization → carried to T8 (single Worker goroutine, or create attempt in same tx).
Task 1: minor (deferred): NextQueued pops before CreateAttempt — window/lost entry on crash (carry to T8).
Task 1: minor (deferred): project Purge leaves fix_* rows (diffs, clone_dir, messages) — carry to T8.
Task 1: minor (deferred): patchProject writes whole row from stale copy (same as CLI).
Task 1: minor (deferred): --auto-fix-minor help says needs level 2, not enforced; add/set help wording differ.
Task 1: minor (deferred): TestSetExternalProvidersCreatesFileWhenAbsent name no longer matches what it asserts.
Task 1: complete (commits b6c6d11..57dde47, review clean)
Task 2: BASE 57dde47
Task 2: implementer DONE 8f9c7db (security-review finding prefix-skip bypass fixed in-task, TestMaskDoesNotSkipValueStartingWithToken)
Task 2: security review (automated) 2 findings: (S1) Unmask replaces any token-shaped string — agent can plant [secret-N] in a file/command and get the real value written by Michel at apply (exfiltration path); (S2) env_value/assignment miss quoted values with spaces, case-sensitive env names, 8-char minimum with strong key names.
Ruling 7: Michel never unmasks into a commit or a branch: at apply, any mask token in the diff ⇒ proposal refused (ErrMaskToken); unmasking exists only for display to the user (page stream) — tokens get a per-Masker random nonce ([secret-<nonce>-N]) so they cannot be guessed or planted — supersedes spec § 8.3 "démasquage appliqué au commit" and plan T8 "démasquage" before apply — cost if wrong: an agent that legitimately needs a secret value in code cannot produce it (the user adds it by hand).
Task 2: security review (automated) 2 more: (S3) overlapping matches — lower-priority match dropped instead of merged, leaving part of a secret; (S4) quoted values cut at first quote/space/comma, bare env names like PASSWORD= not matched, 8-char minimum applied to keyword-anchored values.
Task 2: review Needs fixes — I1 token collision with literal tokens in input; I2 quoted values with spaces/separators leak. ⚠️ table "chiffrée" only by DPAPI on Windows, plain 0600 file on Linux.
Ruling 8: mask table on Linux stays protected by the existing secret store (0600 file, no encryption) until a keyring backend exists — same guarantee as every other Michel secret — cost if wrong: a local reader with the user's rights can read mask tables on Linux.
Ruling 9: fix round 1 of Task 2 also takes S3 (merge overlapping spans), the minors abs_path with spaces / ':'-lists, ScanFiles symlinks (Lstat, skip), bare TOKEN=/KEY= names, Load counts + Atoi error, StreamUnmasker concurrency doc — same files, security-relevant — cost if wrong: a longer round.
Task 2: fix round 1 BASE 8f9c7db
Ruling 10 (Kévin, 2026-10-30): push feat/fix-agent after each task and mirror this ledger to docs/superpowers/sdd/2026-10-30-michel-fix-agent/ledger.md (committed) — instruction directe — cost if wrong: none.
Task 2: security review (automated) on 89efc34: (S5) ${…}/%env( skip is prefix-based (fail-open: ${X:-secret}); (S6) unclosed quote ⇒ partial masking; (S7) env names without underscore before suffix (DBPASSWORD=, APPKEY=) no longer matched.
Task 2: fix round 1/5 (7 addressed, 0 open — nonce tokens, quoted values, merged spans, paths, symlinks, Load, doc; commits 8f9c7db..89efc34)
Ruling 11: fix round 2 of Task 2 takes S5-S7 plus the re-review minors with a leak (escaped quotes, backticks, own-nonce-only placeholder skip, pure ${NAME} skip only) and the common config forms (DB_PASS, SECRET_KEY_BASE, `pass` keyword, password in a connection URL user:pw@); after that, remaining detector gaps (XML <password>, YAML block scalars, dashed names) are a documented residual risk — policy § 8 « la détection automatique des secrets n'est jamais parfaite » and the copy itself is read by the agent anyway (spec § 7.2) — cost if wrong: some secret forms reach the brief/MCP/page unmasked.
Task 2: fix round 2 BASE 89efc34
Task 2: security review (automated) on 5c94c8f: (S8) url_password stops at first '@' / ':' — password containing '@' leaks its tail; (S9) denylist '.*PUBLIC_?KEY.*' lets PUBLIC_KEY_PASSWORD / X_PUBLIC_KEY_SECRET through.
Task 2: fix round 2/5 (6 addressed, 0 open — env suffixes, strict ref skip, quotes, own-token skip, pass/key keywords, url passwords; commits 89efc34..5c94c8f)
Ruling 12: S8 (raw '@' inside a URL password, partially masked) and S9 (denylist .*PUBLIC_?KEY.* — re-review probed GPG_PUBLIC_KEY_PASSWORD still masked by the assignment detector) are parked as residual detector gaps under ruling 11 — RFC 3986 requires '@' percent-encoded in userinfo; the second detector covers secret keywords — cost if wrong: an unencoded '@' password or a public-key-named secret reaches the brief unmasked.
Task 2: minor (deferred): ${{ secrets.X }} partially masked (noise); lowercase YAML secret_key_base:, PASSPHRASE=, KEY_ID= not matched; SORT_KEY/PRIMARY_KEY over-masked.
Task 2: complete (commits 57dde47..5c94c8f, review clean after 2 rounds)
Task 3: BASE 5c94c8f
Task 3: BASE corrected to 57e1b73 (after ledger mirror commit)
Task 3: implementer DONE 2c41bcc (refs derived from ids; reading via feed ListToRead; Build lang vs Markdown lang)
Task 3: security review (automated): (S10) skill written to global ~/.claude/skills embeds untrusted text (changelog breaking lines, reading titles, explanation, package/version) unfenced ⇒ prompt injection into every Claude Code session.
Ruling 13: keep the skill in ~/.claude/skills (never write in the scanned project, Global Constraints) but: every untrusted free text goes in a computed-length fenced data block under a line saying it is untrusted data, package/versions validated by regex before rendering, frontmatter description built only from validated fields, changelog in the skill reduced to counts + breaking lines inside the fence — cost if wrong: residual injection risk if a model ignores fences.
Task 3: FR + S10 fixes 2bda07c, 624af9b; open point: plugin findings skip package/version validation (package outside fence)
Task 3: security review (automated): (S11) validate() returns nil for non-dependency kinds, so Package/OSVID reach the skill frontmatter description unchecked; sanitize at the sink too (WriteSkill re-validates or refuses).
Task 3: review Needs fixes — I1 lines cut (200 runes, 6-line window) before masking ⇒ secret fragments leak. ⚠️ RemoveSkill on finding close → carry to T8; MCP get_brief must go through Build → carry to T4.
Ruling 14: advisory references derived from ids (osv.dev, nvd, GitHub advisories) instead of stored OSV references — the store keeps none; adding it is a scan-format change outside plan 5 — cost if wrong: links less specific than the advisory's own list.
Ruling 15: Task 3 fix round 1 also takes S11 (re-validate at the skill sink, refuse on failure, all kinds) and minors pkgRe leading '-'/'~', relDirRe spaces, composer require on major jump, Path validates ids, strip bidi/zero-width chars — same files — cost if wrong: longer round.
Task 3: minor (deferred): dead code Directness==""; CLI --remove-skill needs finding in store; DoneWhen lang vs Markdown lang; CLI re-Lstat instead of using RemoveOwnedDir bool.
Task 3: fix round 1 BASE 624af9b
Task 3: fix round 1/5 (7 addressed, 0 open — mask before cut, sink validation, pkg/dir patterns, composer require on major, Path ids, invisible chars; commits 624af9b..fc52bd4)
Task 3: minor (deferred): snippet window may shift a few lines when the cited line sits inside a multi-line secret (content still masked); lone \r not normalized; tests written after fixes (reviewer confirmed each would fail on old code).
Task 3: complete (commits 57e1b73..fc52bd4, review clean)
Task 4: BASE cf962fa
Ruling 16: attempt MCP token stored as SHA-256 in the secret store under `fix-token-<attempt id lowercased>` (Task 4 adds fix.SetAttemptToken/CheckAttemptToken; Task 8 creates it at Start) — no migration change — cost if wrong: token lookup through the secret store instead of SQL.
Ruling 17: in Task 4 `michel mcp` wires Deps.Propose to a func returning "not available until the fix service exists"; Task 8 replaces it with fix.Propose — cost if wrong: none.
Task 4: implementer DONE d7611b4 (env names fix.EnvAttempt/EnvToken; bad token still scopes reads to the attempt's project; arg `notes` per plan vs spec `details`)
Task 4: note for T8 — MCP process masks with its own in-memory table entries; harmless under ruling 7 (no unmask into commits; any token in diff ⇒ refuse); display unmask in serve only knows serve-side entries.
Task 4: minor (deferred): each michel mcp launch runs root setup (source.Sync + app.start audit event).
Task 4: FR applied be14cec
Task 4: review Approved. ⚠️ carried to T8: (a) MCP-created tokens share the stored prefix/numbering ⇒ display could resolve a wrong value; (b) Propose must refuse non-proposable attempt states and the token must be deleted when the attempt ends; (c) spec § 6 `details` vs plan `notes`.
Ruling 18: the MCP process masks with its own fresh Masker (own nonce, never saved), so tokens it creates are never resolved by the page's display unmasker (they show as tokens) — T8 must not pass the stored table to `michel mcp` — cost if wrong: agent text quoting a secret it saw via MCP shows a token on the page instead of the value.
Ruling 19: propose_fix argument stays `notes` (plan + fix.ProposeInput); spec § 6 `details` is the same field — cost if wrong: none.
Task 4: minor (deferred): cli/mcp_test.go:151 no-op ReplaceAll (escaped Windows path never checked); test_cmd may carry an absolute path to the agent; MCP version list stops at 2025-06-18 (add 2025-11-25); ctx only checked between lines (T7/T8 must close stdin/kill on timeout); notification with bad jsonrpc gets an error reply; Set/DeleteAttemptToken panic on nil store.
Task 4: complete (commits cf962fa..be14cec, review clean)
