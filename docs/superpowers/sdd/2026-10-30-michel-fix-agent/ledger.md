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
