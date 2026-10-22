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

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
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
)

// Deps are the collaborators of Run.
type Deps struct {
	Store   *store.Store
	Audit   *audit.Logger
	Gateway *egress.Gateway
	Now     func() time.Time
	Version string
	// LogHandler receives osv-scanner's logs. Nil discards them.
	LogHandler slog.Handler
}

// Options tunes a scan.
type Options struct {
	OSVRoot string
	// Exclude lists folder names to skip. Nil means DefaultExclude.
	Exclude []string
}

// Result is the outcome of a scan of one project.
type Result struct {
	ScanID     string           `json:"scan_id"`
	Project    string           `json:"project"`
	Status     string           `json:"status"`
	Manifests  []ManifestResult `json:"manifests"`
	New        int              `json:"new"`
	Still      int              `json:"still"`
	Gone       int              `json:"gone"`
	BySeverity map[string]int   `json:"by_severity"`
	Errors     []error          `json:"-"`
	ErrorTexts []string         `json:"errors,omitempty"`
}

// lockfile names Michel reads, with their OSV ecosystem.
var lockfiles = map[string]string{
	"composer.lock":     "Packagist",
	"package-lock.json": "npm",
}

// scanPlugins limits osv-scanner to the two extractors Michel supports.
var scanPlugins = []string{"php/composerlock", "javascript/packagelockjson"}

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

func findLockfiles(root string, exclude []string) ([]lockfile, error) {
	var out []lockfile
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
		if eco, ok := lockfiles[d.Name()]; ok {
			out = append(out, lockfile{rel: relPath(root, path), abs: path, ecosystem: eco})
		}
		return nil
	})
	return out, err
}

// checkContent tells whether a lockfile the scanner returned nothing for is
// merely empty or unreadable.
func checkContent(name string, b []byte) error {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	unreadable := errors.New("the file is valid JSON but no package could be read from it")
	if name == "composer.lock" {
		for _, k := range []string{"packages", "packages-dev"} {
			var list []json.RawMessage
			if raw, ok := doc[k]; ok && json.Unmarshal(raw, &list) == nil && len(list) > 0 {
				return unreadable
			}
		}
		return nil
	}
	for _, k := range []string{"packages", "dependencies"} {
		var m map[string]json.RawMessage
		if raw, ok := doc[k]; ok && json.Unmarshal(raw, &m) == nil {
			for key := range m {
				if key != "" {
					return unreadable
				}
			}
		}
	}
	return nil
}

// Run scans one project offline and stores its findings.
func Run(ctx context.Context, deps Deps, p project.Project, opt Options) (Result, error) {
	res := Result{Project: p.Name, BySeverity: map[string]int{}}
	if err := osvdb.Require(opt.OSVRoot, osvdb.Ecosystems); err != nil {
		return res, fmt.Errorf("Michel cannot scan %s: %w. A scan never downloads anything; fetch the databases first", p.Name, err)
	}
	exclude := opt.Exclude
	if exclude == nil {
		exclude = DefaultExclude
	}
	started := deps.Now().UTC()
	res.ScanID = ulid.Make().String()
	dbFetched := ""
	if sts, err := osvdb.Statuses(opt.OSVRoot); err == nil {
		for _, s := range sts {
			if t := s.FetchedAt.UTC().Format(time.RFC3339); !s.FetchedAt.IsZero() && (dbFetched == "" || t < dbFetched) {
				dbFetched = t
			}
		}
	}
	db := deps.Store.DB()
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
	record("scan.start", p.Name, "ok", map[string]any{"project_id": p.ID, "osv_db_root": opt.OSVRoot})

	fail := func(err error) (Result, error) {
		res.Status = ScanFailed
		_, _ = db.ExecContext(context.WithoutCancel(ctx), `UPDATE scan SET status=?, finished_at=?, error=? WHERE id=?`,
			ScanFailed, deps.Now().UTC().Format(time.RFC3339), err.Error(), res.ScanID)
		record("scan.finish", p.Name, ScanFailed, map[string]any{"error": err.Error()})
		return res, err
	}

	found, err := findLockfiles(p.Path, exclude)
	if err != nil {
		return fail(fmt.Errorf("Michel cannot read the folder %s: %w. Check that it still exists", p.Path, err))
	}

	handler := deps.LogHandler
	if handler == nil {
		handler = slog.NewTextHandler(io.Discard, nil)
	}
	osvscanner.SetLogger(handler)
	vr, derr := osvscanner.DoScan(osvscanner.ScannerActions{
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
			PluginsEnabled:     scanPlugins,
			TransitiveScanning: osvscanner.TransitiveScanningActions{Disabled: true},
		},
	})
	if derr != nil && !errors.Is(derr, osvscanner.ErrVulnerabilitiesFound) && !errors.Is(derr, osvscanner.ErrNoPackagesFound) {
		return fail(fmt.Errorf("the scanner failed on %s: %w. Nothing was changed; run the scan again", p.Name, derr))
	}

	findings, manifests := Normalize(p.ID, p.Path, vr)
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
			if rerr != nil {
				manifests[i].Err = fmt.Errorf("cannot read %s: %w", lf.rel, rerr)
			} else if cerr := checkContent(filepath.Base(lf.abs), raw); cerr != nil {
				manifests[i].Err = fmt.Errorf("cannot parse %s: %w", lf.rel, cerr)
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
	err = func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := insertManifests(ctx, tx, res.ScanID, manifests); err != nil {
			return err
		}
		res.New, res.Still, res.Gone, err = applyScan(ctx, tx, p.ID, res.ScanID, finished, findings, unread)
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

	for _, m := range manifests {
		result := "ok"
		ev := map[string]any{"ecosystem": m.Ecosystem, "packages": m.Packages, "findings": m.Findings, "lock_sha256": m.LockSHA256}
		if m.Err != nil {
			result, ev["error"] = "error", m.Error
		}
		record("scan.manifest", m.RelPath, result, ev)
	}
	record("scan.finish", p.Name, status, map[string]any{
		"new": res.New, "still": res.Still, "gone": res.Gone, "by_severity": res.BySeverity,
		"manifests": len(manifests), "duration_ms": finished.Sub(started).Milliseconds(),
	})
	return res, nil
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
