# Michel audit batch A

Small, independent defects found by a read-only audit. Each item: a failing
test first, the minimal fix, the test passing, one commit. Branch
`fix/audit-batch-a`. Out of scope (another branch changes them):
internal/fix/service.go, internal/fix/repo.go, internal/workcopy,
internal/api/fix.go, internal/cli/fix.go, migrations, web/.

| Item | Defect | Proof |
|------|--------|-------|
| A02 | The fix agent's Glob and Grep are allowed with no path; denies cover only `~/.claude*` and `~/.ssh`. | `TestGeneratedSettingsAndMCPConfig` (allow is `Glob(./**)`, `Grep(./**)`; Read/Glob/Grep denied on credential files and on Michel's data folder entries other than the copies), `TestNoFileToolsSession` code-session allow line. |
| A06 | A scan cannot be cancelled: osv-scanner's DoScan takes no context. | `TestRunReturnsOnCancel`: an injected blocking scanner, ctx cancelled, Run returns within 1 s, the scan row is `interrupted`, no finding is written after the cancel. |
| A12 | `osvscanner.SetLogger` writes globals from Run and ScanDir with no shared lock. | `TestScannerCallsAreSerialized`: concurrent Run and ScanDir with a fake scanner that counts overlapping calls; never more than one. (No `-race` here: no C compiler on this PC.) |
| A10 | Audit write failures ignored on host-key refusals (API, CLI) and alert delivery (servercheck, serverlog). | `TestHostKeyRefusalAuditFailure` (api), `TestTargetTrustRefusalAuditFailure` (cli), `TestServerAlertAuditFailureIsLogged`, `TestServerLogAlertAuditFailureIsLogged` (cli, slog warning). |
| A11 | JSON read from the database decoded with the error ignored (decide, digest). | `TestDecisionWithBadJSONFailsToRead`, `TestSetWithBadFixedVersionsFails` (decide), `TestRunWithBadJSONFailsToRead`, `TestFinishWithBadSummaryFails` (digest). |
| A15 | On non-Windows the data folder and the SQLite files are not tightened. | `TestOpenTightensPermissions` (skipped on Windows). |
| A13 | CI runs only `go vet` and `go test`. | Read-through of `.github/workflows/ci.yml`: race, govulncheck, staticcheck on ubuntu; a node job (`npm ci`, `npm test`, `npm run build` in web/). |

Gates before the last commit: `go test ./... -count=1`, `go vet ./...`,
`gofmt -l .`, staticcheck once if the network allows.
