package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
	"gopkg.in/yaml.v3"
)

// Purpose is the egress purpose handed to osv-scanner. The policy has no rule
// for it, so any network attempt during a scan is denied and recorded.
const Purpose = "osv.scan"

// DefaultExclude lists the folders a scan never enters: installed
// dependencies, not the project's own manifests.
var DefaultExclude = []string{"node_modules", "vendor", ".git"}

// Scan statuses.
const (
	ScanOK      = "ok"
	ScanPartial = "partial"
	ScanFailed  = "failed"
	// ScanEmpty is a scan of a folder holding no lockfile Michel reads. It
	// is not an error: the project may have no dependencies yet.
	ScanEmpty = "empty"
)

// ErrNoManifests means the project folder holds no lockfile Michel reads.
var ErrNoManifests = errors.New("no composer.lock, package-lock.json, yarn.lock or pnpm-lock.yaml found")

// ErrEcosystemDisabled marks a lockfile whose OSV ecosystem is not enabled in
// the sources registry: it is left out of the scan and its findings are kept.
var ErrEcosystemDisabled = errors.New("ecosystem disabled")

// Deps are the collaborators of Run.
type Deps struct {
	Store   *store.Store
	Audit   *audit.Logger
	Gateway *egress.Gateway
	Now     func() time.Time
	Version string
	// LogHandler receives osv-scanner's logs. Nil discards them.
	LogHandler slog.Handler
	// DataDir is Michel's data folder, where the scanner override config
	// lives. Empty means the folder of the store.
	DataDir string
}

// ScannerConfigName is the per-folder osv-scanner configuration file. Michel
// never applies it: its ignore rules would hide findings with no trace.
const ScannerConfigName = "osv-scanner.toml"

// OverrideConfigName is the empty osv-scanner configuration Michel owns in
// its data folder and hands to every scan, so that no osv-scanner.toml
// found in a project is loaded.
const OverrideConfigName = "osv-scanner-override.toml"

const overrideContent = "# Owned by Michel: an empty osv-scanner configuration used for every scan so that\n" +
	"# no osv-scanner.toml inside a project can hide findings. Michel rewrites this file;\n" +
	"# decide on findings with Michel instead of editing it.\n"

// ensureOverrideConfig writes Michel's empty scanner configuration in
// dataDir when it is absent or was changed, and returns its path.
func ensureOverrideConfig(dataDir string) (string, error) {
	path := filepath.Join(dataDir, OverrideConfigName)
	if b, err := os.ReadFile(path); err == nil && string(b) == overrideContent {
		return path, nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dataDir, OverrideConfigName+".*.tmp")
	if err != nil {
		return "", err
	}
	_, werr := tmp.WriteString(overrideContent)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return "", errors.Join(werr, cerr)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		// Another scan may have written the same content meanwhile.
		if b, rerr := os.ReadFile(path); rerr == nil && string(b) == overrideContent {
			return path, nil
		}
		return "", err
	}
	return path, nil
}

// afterScanHook is a test hook run right after the scanner returns.
var afterScanHook func()

// Options tunes a scan.
type Options struct {
	OSVRoot string
	// Exclude lists folder names to skip. Nil means EffectiveExclude of the
	// project (the defaults plus the project's own list).
	Exclude []string
	// Ecosystems lists the enabled OSV ecosystems (osvdb.Enabled). A
	// lockfile of another ecosystem is not scanned. Nil means every
	// ecosystem of the lockfiles found.
	Ecosystems []string
}

// Result is the outcome of a scan of one project.
type Result struct {
	ScanID     string           `json:"scan_id"`
	Project    string           `json:"project"`
	Status     string           `json:"status"`
	Manifests  []ManifestResult `json:"manifests"`
	New        int              `json:"new"`
	Still      int              `json:"still"`
	Reappeared int              `json:"reappeared"`
	Gone       int              `json:"gone"`
	// Superseded counts the decisions this scan took out of force: the
	// finding changed, came back changed, or its deferral date was reached.
	Superseded int            `json:"superseded"`
	BySeverity map[string]int `json:"by_severity"`
	Errors     []error        `json:"-"`
	ErrorTexts []string       `json:"errors,omitempty"`
	// Warnings lists the osv-scanner.toml files met in the project
	// (relative paths). Michel does not apply them.
	Warnings []string `json:"warnings,omitempty"`
	// Swept counts the stale scans of any project marked interrupted
	// before this one started (see SweepStale).
	Swept int `json:"swept,omitempty"`
}

// lockfile names Michel reads, with their OSV ecosystem.
var lockfiles = map[string]string{
	"composer.lock":     "Packagist",
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"pnpm-lock.yaml":    "npm",
}

// scanPlugins limits osv-scanner to the extractors Michel supports.
var scanPlugins = []string{"php/composerlock", "javascript/packagelockjson", "javascript/yarnlock", "javascript/pnpmlock"}

// pluginEcosystem is the OSV ecosystem of each of scanPlugins.
var pluginEcosystem = map[string]string{
	"php/composerlock":           "Packagist",
	"javascript/packagelockjson": "npm",
	"javascript/yarnlock":        "npm",
	"javascript/pnpmlock":        "npm",
}

// globExcludes turns folder names into osv-scanner glob patterns matching the
// folder at any depth. Plain names are not used: osv-scanner resolves them
// against the current directory, which fails when the project is on another
// drive than the one Michel runs from.
func globExcludes(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "g:**/" + n
	}
	return out
}

type lockfile struct{ rel, abs, ecosystem string }

// findLockfiles walks the project and returns the lockfiles Michel reads,
// plus the relative paths of the osv-scanner.toml files it met.
func findLockfiles(root string, exclude []string) ([]lockfile, []string, error) {
	var out []lockfile
	configs := []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil // unreadable subfolder: skip it
		}
		if d.IsDir() {
			if path != root && slices.Contains(exclude, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ScannerConfigName {
			if rel, rerr := relPath(root, path); rerr == nil {
				configs = append(configs, rel)
			}
			return nil
		}
		if eco, ok := lockfiles[d.Name()]; ok {
			if d.Type()&fs.ModeSymlink != 0 {
				slog.Debug("skipping symlinked lockfile", "path", path)
				return nil
			}
			rel, rerr := relPath(root, path)
			if rerr != nil {
				slog.Debug("skipping lockfile outside the project", "path", path, "err", rerr)
				return nil
			}
			out = append(out, lockfile{rel: rel, abs: path, ecosystem: eco})
		}
		return nil
	})
	return out, configs, err
}

// errUnreadable is the cause given when a lockfile parses but the scanner
// read no package from it.
var errUnreadable = errors.New("the file is well-formed but no package could be read from it")

// checkContent tells whether a lockfile the scanner returned nothing for is
// merely empty (nil) or unreadable (an error).
func checkContent(name string, b []byte) error {
	switch name {
	case "yarn.lock":
		return checkYarn(b)
	case "pnpm-lock.yaml":
		return checkPnpm(b)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	if name == "composer.lock" {
		for _, k := range []string{"packages", "packages-dev"} {
			var list []json.RawMessage
			if raw, ok := doc[k]; ok && json.Unmarshal(raw, &list) == nil && len(list) > 0 {
				return errUnreadable
			}
		}
		return nil
	}
	for _, k := range []string{"packages", "dependencies"} {
		var m map[string]json.RawMessage
		if raw, ok := doc[k]; ok && json.Unmarshal(raw, &m) == nil {
			for key := range m {
				if key != "" {
					return errUnreadable
				}
			}
		}
	}
	return nil
}

// checkYarn: a v1 lockfile is empty when no line opens a package block; a
// berry lockfile (YAML) is empty when it holds only __metadata.
func checkYarn(b []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	first := ""
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			first = l
			break
		}
	}
	if strings.HasPrefix(first, "# THIS IS AN AUTOGENERATED FILE") || strings.Contains(first, "yarn lockfile v1") {
		for _, l := range lines {
			if l != "" && !strings.HasPrefix(l, "#") && l[0] != ' ' && l[0] != '\t' && strings.HasSuffix(strings.TrimRight(l, " \t"), ":") {
				return errUnreadable
			}
		}
		return nil
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if _, ok := doc["__metadata"]; !ok {
		return errors.New("neither a yarn v1 lockfile nor a yarn berry lockfile (no __metadata)")
	}
	if len(doc) > 1 {
		return errUnreadable
	}
	return nil
}

// checkPnpm: a pnpm lockfile is empty when it lists no package and none of
// its importers has a dependency.
func checkPnpm(b []byte) error {
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if _, ok := doc["lockfileVersion"]; !ok {
		return errors.New("not a pnpm lockfile (no lockfileVersion)")
	}
	if pk, _ := doc["packages"].(map[string]any); len(pk) > 0 {
		return errUnreadable
	}
	imps, _ := doc["importers"].(map[string]any)
	for _, imp := range imps {
		m, _ := imp.(map[string]any)
		for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			if d, _ := m[k].(map[string]any); len(d) > 0 {
				return errUnreadable
			}
		}
	}
	return nil
}

// Run scans one project offline and stores its findings.
func Run(ctx context.Context, deps Deps, p project.Project, opt Options) (Result, error) {
	res := Result{Project: p.Name, BySeverity: map[string]int{}}
	exclude := opt.Exclude
	if exclude == nil {
		exclude = EffectiveExclude(p)
	}
	// The walk only reads; its error is recorded once the scan row exists.
	found, configs, walkErr := findLockfiles(p.Path, exclude)
	enabled := func(eco string) bool { return opt.Ecosystems == nil || slices.Contains(opt.Ecosystems, eco) }
	var needed []string // ecosystems of the lockfiles found that are enabled
	for _, lf := range found {
		if enabled(lf.ecosystem) && !slices.Contains(needed, lf.ecosystem) {
			needed = append(needed, lf.ecosystem)
		}
	}
	if err := osvdb.Require(opt.OSVRoot, needed); err != nil {
		return res, fmt.Errorf("Michel cannot scan %s: %w. A scan never downloads anything; fetch the databases first", p.Name, err)
	}
	started := deps.Now().UTC()
	db := deps.Store.DB()
	swept, err := SweepStale(ctx, db, started, StaleScanAfter)
	if err != nil {
		return res, fmt.Errorf("Michel cannot scan %s: %w. Check that the data folder is writable", p.Name, err)
	}
	res.Swept = swept
	res.ScanID = ulid.Make().String()
	dbFetched := ""
	if sts, err := osvdb.Statuses(opt.OSVRoot, needed); err == nil {
		for _, s := range sts {
			if t := s.FetchedAt.UTC().Format(time.RFC3339); !s.FetchedAt.IsZero() && (dbFetched == "" || t < dbFetched) {
				dbFetched = t
			}
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO scan (id, project_id, started_at, osv_db_fetched_at, scanner_version, status)
		VALUES (?,?,?,?,?,?)`, res.ScanID, p.ID, started.Format(time.RFC3339), dbFetched, deps.Version, "running"); err != nil {
		return res, fmt.Errorf("Michel cannot record the scan: %w. Check that the data folder is writable", err)
	}
	// The scan result is already stored when most events are written; a
	// failing audit write must not hide it, but it is reported.
	record := func(action, target, result string, ev map[string]any) {
		if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "scan", Action: action, Target: target, Result: result, Evidence: ev}); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("cannot write the audit log: %w", err))
		}
	}
	if swept > 0 {
		record("scan.sweep", p.Name, "ok", map[string]any{"swept": swept, "max_age": StaleScanAfter.String()})
	}
	record("scan.start", p.Name, "ok", map[string]any{"project_id": p.ID, "osv_db_root": opt.OSVRoot})

	failWith := func(stored string, err error, ev map[string]any) (Result, error) {
		res.Status = ScanFailed
		_, _ = db.ExecContext(context.WithoutCancel(ctx), `UPDATE scan SET status=?, finished_at=?, error=? WHERE id=?`,
			ScanFailed, deps.Now().UTC().Format(time.RFC3339), stored, res.ScanID)
		ev["error"] = stored
		record("scan.finish", p.Name, ScanFailed, ev)
		return res, err
	}
	fail := func(err error) (Result, error) {
		return failWith(err.Error(), err, map[string]any{})
	}
	// A panic must not leave the scan "running": record it as failed with
	// its cause, then let it go on. A scan already stored keeps its status.
	defer func() {
		if r := recover(); r != nil {
			stored := fmt.Sprintf("panic: %v", r)
			upd, uerr := db.ExecContext(context.WithoutCancel(ctx), `UPDATE scan SET status=?, finished_at=?, error=? WHERE id=? AND status='running'`,
				ScanFailed, deps.Now().UTC().Format(time.RFC3339), stored, res.ScanID)
			if n, _ := rowsAffected(upd, uerr); n > 0 || uerr != nil {
				record("scan.finish", p.Name, ScanFailed, map[string]any{"error": stored, "reason": "panic"})
			}
			panic(r)
		}
	}()

	if len(configs) > 0 {
		res.Warnings = configs
	}
	if walkErr != nil {
		return fail(fmt.Errorf("Michel cannot read the folder %s: %w. Check that it still exists", p.Path, walkErr))
	}
	if len(found) == 0 {
		// Not an error: the project may have no dependencies yet. Existing
		// findings keep their status: an empty or unmounted folder proves
		// nothing about what was fixed.
		if _, err := db.ExecContext(ctx, `UPDATE scan SET status=?, finished_at=? WHERE id=?`,
			ScanEmpty, deps.Now().UTC().Format(time.RFC3339), res.ScanID); err != nil {
			return fail(fmt.Errorf("Michel cannot store the scan of %s: %w. Check that the data folder is writable", p.Name, err))
		}
		res.Status = ScanEmpty
		record("scan.finish", p.Name, ScanEmpty, map[string]any{"reason": "no_manifests", "ignored_config_files": configs})
		return res, nil
	}
	plugins := []string{}
	for _, pl := range scanPlugins {
		if enabled(pluginEcosystem[pl]) {
			plugins = append(plugins, pl)
		}
	}

	handler := deps.LogHandler
	if handler == nil {
		handler = slog.NewTextHandler(io.Discard, nil)
	}
	osvscanner.SetLogger(handler)
	dataDir := deps.DataDir
	if dataDir == "" {
		dataDir = filepath.Dir(deps.Store.Path())
	}
	// Without an override, osv-scanner loads any osv-scanner.toml next to a
	// lockfile and drops the vulnerabilities it ignores before Michel sees
	// them. Michel's own empty file replaces every per-folder config.
	override, err := ensureOverrideConfig(dataDir)
	if err != nil {
		return fail(fmt.Errorf("Michel cannot prepare the scanner configuration in %s: %w. Nothing was changed; check that the data folder is writable and run the scan again", dataDir, err))
	}
	// A lockfile of a disabled ecosystem is not read: its extractor is left
	// out, and nothing runs when no lockfile is left.
	var vr models.VulnerabilityResults
	var derr error
	if len(needed) > 0 {
		vr, derr = osvscanner.DoScan(osvscanner.ScannerActions{
			ConfigOverridePath:    override,
			DirectoryPaths:        []string{p.Path},
			Recursive:             true,
			CompareOffline:        true,
			DownloadDatabases:     false,
			LocalDBPath:           opt.OSVRoot,
			PluginNetworkDisabled: true,
			ShowAllPackages:       true,
			ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
				ExcludePatterns:    globExcludes(exclude),
				HTTPClient:         deps.Gateway.Client(Purpose),
				PluginsNoDefaults:  true,
				PluginsEnabled:     plugins,
				TransitiveScanning: osvscanner.TransitiveScanningActions{Disabled: true},
			},
		})
	}
	if afterScanHook != nil {
		afterScanHook()
	}
	if derr != nil && !errors.Is(derr, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(derr, osvscanner.ErrNoPackagesFound) {
		return fail(fmt.Errorf("the scanner failed on %s: %w. Nothing was changed; run the scan again", p.Name, derr))
	}

	findings, manifests := Normalize(p.ID, p.Path, vr)
	// Only lockfiles Michel's own walk accepted count (no symlinks, none
	// outside the project, ecosystem enabled), whatever the scanner returned.
	accepted := map[string]bool{}
	for _, lf := range found {
		accepted[lf.rel] = enabled(lf.ecosystem)
	}
	keptM := manifests[:0]
	for _, m := range manifests {
		if accepted[m.RelPath] || m.Err != nil {
			keptM = append(keptM, m)
		}
	}
	manifests = keptM
	keptF := findings[:0]
	for _, f := range findings {
		if accepted[f.ManifestRelPath] {
			keptF = append(keptF, f)
		}
	}
	findings = keptF
	index := map[string]int{}
	for i, m := range manifests {
		index[m.RelPath] = i
	}
	// Reconcile with the lockfiles Michel found itself: record hashes and
	// detect files the scanner skipped silently.
	for _, lf := range found {
		raw, rerr := os.ReadFile(lf.abs)
		i, ok := index[lf.rel]
		if !ok {
			manifests = append(manifests, ManifestResult{RelPath: lf.rel, Ecosystem: lf.ecosystem})
			i = len(manifests) - 1
			index[lf.rel] = i
			switch {
			case !enabled(lf.ecosystem):
				// Its findings are kept (unread): the scan did not look.
				manifests[i].Err = fmt.Errorf("%w: enable %s to scan %s", ErrEcosystemDisabled, source.KeyFor(source.KindOSV, lf.ecosystem), lf.rel)
			case rerr != nil:
				manifests[i].Err = fmt.Errorf("cannot read %s: %w", lf.rel, rerr)
			default:
				if cerr := checkContent(filepath.Base(lf.abs), raw); cerr != nil {
					manifests[i].Err = fmt.Errorf("cannot parse %s: %w", lf.rel, cerr)
				}
			}
		}
		if rerr == nil {
			sum := sha256.Sum256(raw)
			manifests[i].LockSHA256 = hex.EncodeToString(sum[:])
		}
		if manifests[i].Ecosystem == "" {
			manifests[i].Ecosystem = lf.ecosystem
		}
	}
	slices.SortStableFunc(manifests, func(a, b ManifestResult) int { return strings.Compare(a.RelPath, b.RelPath) })
	unread := map[string]bool{}
	for i := range manifests {
		if manifests[i].Err != nil {
			manifests[i].Error = manifests[i].Err.Error()
			unread[manifests[i].RelPath] = true
			res.Errors = append(res.Errors, manifests[i].Err)
			res.ErrorTexts = append(res.ErrorTexts, manifests[i].Error)
		}
	}
	for _, f := range findings {
		res.BySeverity[f.SeverityLabel]++
	}
	res.Manifests = manifests

	status := ScanOK
	if len(res.Errors) > 0 {
		status = ScanPartial
	}
	finished := deps.Now().UTC()
	var superseded []Superseded
	err = func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := insertManifests(ctx, tx, res.ScanID, manifests); err != nil {
			return err
		}
		current, err := currentDecisions(ctx, tx, p.ID)
		if err != nil {
			return err
		}
		res.New, res.Still, res.Reappeared, res.Gone, superseded, err = applyScan(ctx, tx, p.ID, res.ScanID, finished, findings, unread, current)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scan SET status=?, finished_at=?, error=? WHERE id=?`,
			status, finished.Format(time.RFC3339), strings.Join(res.ErrorTexts, "; "), res.ScanID); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		return fail(fmt.Errorf("Michel cannot store the scan of %s: %w. Nothing was changed; check that the data folder is writable and run it again", p.Name, err))
	}
	res.Status = status
	res.Superseded = len(superseded)

	// The audit logger opens its own transaction: the supersessions are
	// recorded once the scan is committed.
	for _, s := range superseded {
		record("decision.superseded", s.FindingID, "ok", map[string]any{
			"finding_id": s.FindingID, "project_id": s.ProjectID, "reason": s.Reason, "previous_action": s.Previous,
		})
	}
	for _, m := range manifests {
		result := "ok"
		ev := map[string]any{"ecosystem": m.Ecosystem, "packages": m.Packages, "findings": m.Findings, "lock_sha256": m.LockSHA256}
		if m.Err != nil {
			result, ev["error"] = "error", m.Error
		}
		record("scan.manifest", m.RelPath, result, ev)
	}
	record("scan.finish", p.Name, status, map[string]any{
		"new": res.New, "still": res.Still, "reappeared": res.Reappeared, "gone": res.Gone, "superseded": res.Superseded, "by_severity": res.BySeverity,
		"manifests": len(manifests), "duration_ms": finished.Sub(started).Milliseconds(),
		"ignored_config_files": configs,
	})
	return res, nil
}

// rowsAffected is the row count of an Exec result, 0 when it failed.
func rowsAffected(r sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func insertManifests(ctx context.Context, tx *sql.Tx, scanID string, ms []ManifestResult) error {
	st, err := tx.PrepareContext(ctx, `INSERT INTO scan_manifest (scan_id, rel_path, ecosystem, lock_sha256, package_count, error) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, m := range ms {
		if _, err := st.ExecContext(ctx, scanID, m.RelPath, m.Ecosystem, m.LockSHA256, m.Packages, m.Error); err != nil {
			return fmt.Errorf("cannot save manifest %s: %w", m.RelPath, err)
		}
	}
	return nil
}
