package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress/denyproxy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// RunTimeout bounds one run of a tool.
const RunTimeout = 30 * time.Minute

// ErrDisabled: the plugin source is off.
var ErrDisabled = errors.New("the plugin is off")

// RunDeps are the collaborators of RunPlugin. Exec nil runs the program for
// real (defaultExec); Proxy nil starts the deny proxy, recording into Audit.
type RunDeps struct {
	Store   *store.Store
	Audit   *audit.Logger
	Repo    *source.Repo
	DataDir string
	Now     func() time.Time
	Exec    func(ctx context.Context, name string, args, env []string, dir string) (stdout, stderr []byte, err error)
	Proxy   func() (addr string, close func())
	// Started, when set, receives the run id once the run is recorded, before
	// the tool starts (the API answers with it and lets the run go on).
	Started func(runID string)
}

// RunResult is the outcome of one run. ReportPath is local: it never
// reaches the API, --json or a message.
type RunResult struct {
	RunID        string `json:"run_id"`
	New          int    `json:"new"`
	Still        int    `json:"still"`
	Gone         int    `json:"gone"`
	SkippedKnown int    `json:"skipped_known"`
	ReportPath   string `json:"-"`
}

// RunPlugin runs the plugin e on project p, or with input != "" only reads
// that report, and records its findings (scan.ApplyExternal), the run
// (plugin_run) and an audit event plugin.run. A run detects the tool, starts
// the deny proxy, runs the tool from <data dir>/plugins/<tool>/ with an
// allowlisted environment (toolEnv) for RunTimeout at most, then reads its
// report. A vulnerability the OSV scan already reports for p is left out
// (SkippedKnown).
func RunPlugin(ctx context.Context, deps RunDeps, e source.Entry, p project.Project, input string) (RunResult, error) {
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	run := ExecFunc(deps.Exec)
	if run == nil {
		run = defaultExec
	}
	var res RunResult
	if !e.Enabled {
		return res, ErrDisabled
	}
	prov, err := forEntry(e, run, nil)
	if err != nil {
		return res, err
	}
	if input == "" && prov.args == nil {
		return res, ErrNotRunnable
	}
	dataDir := deps.DataDir
	if dataDir == "" {
		dataDir = filepath.Dir(deps.Store.Path())
	}
	db := deps.Store.DB()
	started := now()
	res.RunID = ulid.Make().String()
	if err := insertRun(ctx, db, res.RunID, e.ID, p.ID, started); err != nil {
		return res, fmt.Errorf("cannot record the run: %w", err)
	}
	if deps.Started != nil {
		deps.Started(res.RunID)
	}
	mode := "run"
	if input != "" {
		mode = "ingest"
	}
	row := runRow{status: RunFailed}
	argvHash := ""
	record := func(result string, extra map[string]any) error {
		ev := map[string]any{"key": e.Key, "project": p.Name, "tool_version": row.version, "argv_hash": argvHash, "mode": mode,
			"duration_ms": now().Sub(started).Milliseconds(), "findings": row.findings, "result": result}
		for k, v := range extra {
			ev[k] = v
		}
		if _, err := deps.Audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: "plugin", Action: "plugin.run", Target: e.Key, Result: result, Evidence: ev}); err != nil {
			return fmt.Errorf("cannot write the audit event: %w", err)
		}
		return nil
	}
	fail := func(err error) (RunResult, error) {
		row.status, row.finished, row.errText = RunFailed, now(), err.Error()
		if ferr := finishRun(context.WithoutCancel(ctx), db, res.RunID, row); ferr != nil {
			err = errors.Join(err, fmt.Errorf("cannot record the run: %w", ferr))
		}
		if aerr := record(RunFailed, map[string]any{"error": row.errText}); aerr != nil {
			err = errors.Join(err, aerr)
		}
		return res, err
	}

	report := input
	if input != "" {
		if abs, err := filepath.Abs(input); err == nil {
			report = abs
		}
	} else {
		proxy := deps.Proxy
		if proxy == nil {
			proxy = func() (string, func()) {
				addr, stop, err := denyproxy.Listen(deps.Audit.EgressSink(), e.Key)
				if err != nil {
					return "", func() {}
				}
				return addr, stop
			}
		}
		addr, stop := proxy()
		defer stop()
		if addr == "" {
			// Fail closed: no tool runs without the proxy.
			return fail(errors.New("cannot start the proxy that keeps the tool offline"))
		}
		// The tool works from its folder in the data folder, with its own
		// home there: what it writes (settings, logs, cache) stays out of
		// the project and of the user's home.
		dir := filepath.Join(dataDir, "plugins", prov.name)
		home := filepath.Join(dir, "home")
		if err := os.MkdirAll(home, 0o700); err != nil {
			return fail(fmt.Errorf("cannot prepare the tool's folder: %w", noPath(err)))
		}
		env := toolEnv(addr, home)
		prov.detectEnv, prov.dir = env, dir
		installed, version := prov.Detect(ctx)
		if !installed {
			return fail(ErrNotInstalled)
		}
		row.version = version
		rctx, cancel := context.WithTimeout(ctx, RunTimeout)
		report, err = prov.Run(rctx, p, dir, env)
		cancel()
		if prov.argv != nil {
			sum := sha256.Sum256([]byte(strings.Join(prov.argv, "\x00")))
			argvHash = hex.EncodeToString(sum[:])
		}
		row.log = string(prov.output)
		if err != nil {
			return fail(err)
		}
	}
	row.report = report
	external, err := prov.Ingest(ctx, report, p)
	if err != nil {
		return fail(err)
	}
	known, err := knownCVEs(ctx, db, p.ID)
	if err != nil {
		return fail(err)
	}
	findings := make([]scan.Finding, 0, len(external))
	seen := map[string]bool{}
	// Skipped is not « not seen »: a plugin finding that OSV now reports stays as it was.
	keep := map[string]bool{}
	for _, x := range external {
		if x.Kind == KindVulnerability && slices.ContainsFunc(append([]string{x.RuleID}, x.Aliases...), func(id string) bool {
			return known[strings.ToUpper(id)]
		}) {
			res.SkippedKnown++
			keep[toFinding(p.ID, e.Key, x).ID] = true
			continue
		}
		f := toFinding(p.ID, e.Key, x)
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		findings = append(findings, f)
	}
	row.findings = len(findings)

	var superseded []scan.Superseded
	err = func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res.New, res.Still, res.Gone, superseded, err = scan.ApplyExternalKeeping(ctx, tx, p.ID, e.Key, res.RunID, now(), findings, keep, nil)
		if err != nil {
			return err
		}
		row.status, row.finished = RunOK, now()
		if err := finishRun(ctx, tx, res.RunID, row); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		row.status = RunFailed
		return fail(fmt.Errorf("cannot store the findings: %w", err))
	}
	res.ReportPath = report
	// The findings are stored: a failing audit write does not undo them,
	// but it is reported (the result is returned with the error).
	var auditErrs []error
	for _, s := range superseded {
		if _, err := deps.Audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: "plugin", Action: "decision.superseded", Target: s.FindingID,
			Result: "ok", Evidence: map[string]any{"finding_id": s.FindingID, "project_id": s.ProjectID, "reason": s.Reason, "previous_action": s.Previous}}); err != nil {
			auditErrs = append(auditErrs, fmt.Errorf("%w: %v", ErrAudit, err))
		}
	}
	if err := record(RunOK, map[string]any{"new": res.New, "still": res.Still, "gone": res.Gone, "skipped_known": res.SkippedKnown}); err != nil {
		auditErrs = append(auditErrs, fmt.Errorf("%w: %v", ErrAudit, err))
	}
	return res, errors.Join(auditErrs...)
}

// ErrAudit: the findings are stored but an audit event could not be written.
var ErrAudit = errors.New("the findings are saved but the audit log cannot be written")

// toFinding is the stored finding of one result of the report.
func toFinding(projectID, sourceKey string, x ExternalFinding) scan.Finding {
	// A fingerprint (CodeQL's line hash) follows a moved line but does not
	// name the file: the identity is the file and the fingerprint.
	ref := x.Location
	if x.Fingerprint != "" {
		ref = fileOf(x.Location) + "#" + x.Fingerprint
	}
	severity := x.Severity
	if severity == "" {
		severity = "unknown"
	}
	aliases := x.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	return scan.Finding{ID: scan.FindingID(projectID, sourceKey, "", x.RuleID, ref), ProjectID: projectID, Kind: x.Kind,
		SourceKey: sourceKey, RuleID: x.RuleID, Location: x.Location, Fingerprint: x.Fingerprint, SeverityLabel: severity,
		CVSS: x.CVSS, Summary: x.Message, Aliases: aliases, FixedVersions: []string{}, DepGroups: []string{}}
}

// fileOf is a location without its ":line".
func fileOf(location string) string {
	if i := strings.LastIndexByte(location, ':'); i > 0 {
		if _, err := strconv.Atoi(location[i+1:]); err == nil {
			return location[:i]
		}
	}
	return location
}
