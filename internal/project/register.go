package project

import (
	"context"
	"errors"
	"strings"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
)

// ErrDuplicateFolder is the refusal of a second active project on a folder.
var ErrDuplicateFolder = errors.New("an active project already uses this folder")

// RegisterRequest is what is asked to add a project: the raw name and path,
// the optional fields of michel project add, and the folders a project never
// touches.
type RegisterRequest struct {
	// Actor is who asks, as the audit names it.
	Actor          string
	Name           string
	Path           string
	Classification policy.Classification
	FixLevel       int
	FixLevelSet    bool
	AutoFixMinor   bool
	TestCmd        string
	InstallCmd     string
	CorePackages   []string
	Exclude        []string
	Tech           []string
	Folders        Folders
}

// RefusalError is a request Register refuses. Key is the catalog key of the
// reason, as the audit keeps it; Err, when set, is the error of the rule that
// refused, with its detail.
type RefusalError struct {
	Key string
	Err error
}

func (e *RefusalError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "project refused: " + e.Key
}

func (e *RefusalError) Unwrap() error { return e.Err }

// AuditError is an audit event Register could not write. After is the
// refusal or the storage error it was the trace of, nil after a project added
// (and purged since).
type AuditError struct {
	Err   error
	After error
}

func (e *AuditError) Error() string {
	if e.After != nil {
		return e.After.Error() + "; the audit log could not be written: " + e.Err.Error()
	}
	return e.Err.Error()
}

func (e *AuditError) Unwrap() []error {
	if e.After != nil {
		return []error{e.Err, e.After}
	}
	return []error{e.Err}
}

// Register adds a project, the one way the page and michel project add share:
// the name rule, the folder checks (the folder kept is the real one, links
// followed), no second active project on a folder, then the audit. Every
// refusal is audited denied with the key of its reason, a storage error
// error with its text; a project whose trace cannot be written is purged.
func Register(ctx context.Context, repo *Repo, log *audit.Logger, req RegisterRequest) (Project, error) {
	raw, name := strings.TrimSpace(req.Path), strings.TrimSpace(req.Name)
	// record writes the trace of a failure, and returns the failure.
	record := func(result, reason string, failure error) (Project, error) {
		// The audit keeps what was asked, bounded and without control characters.
		ev := map[string]any{"path": boundedForAudit(raw, maxPathLen), "reason": reason}
		if _, err := log.Record(ctx, audit.Event{Actor: req.Actor, Action: "project.add",
			Target: boundedForAudit(name, maxProjectName), Result: result, Evidence: ev}); err != nil {
			return Project{}, &AuditError{Err: err, After: failure}
		}
		return Project{}, failure
	}
	refuse := func(key string, cause error) (Project, error) {
		return record("denied", key, &RefusalError{Key: key, Err: cause})
	}
	failed := func(cause error) (Project, error) {
		// A storage error is no refusal: the audit keeps what went wrong.
		return record("error", boundedForAudit(cause.Error(), maxPathLen), cause)
	}
	if !validProjectName(name) {
		return refuse("api.project.bad_name", nil)
	}
	path, key := projectFolder(raw, req.Folders)
	if key != "" {
		return refuse(key, nil)
	}
	list, err := repo.List(ctx)
	if err != nil {
		return failed(err)
	}
	for _, p := range list {
		if p.Active && foldPath(p.Path) == foldPath(path) {
			return refuse("api.project.duplicate", ErrDuplicateFolder)
		}
	}
	added, err := repo.Add(ctx, Project{
		Name: name, Path: path, Classification: req.Classification,
		FixLevel: req.FixLevel, FixLevelSet: req.FixLevelSet, AutoFixMinor: req.AutoFixMinor,
		TestCmd: req.TestCmd, InstallCmd: req.InstallCmd,
		CorePackages: req.CorePackages, Exclude: req.Exclude, Tech: req.Tech,
	})
	if err != nil {
		if key := addRefusalKey(err); key != "" {
			return refuse(key, err)
		}
		return failed(err)
	}
	if _, err := log.Record(ctx, audit.Event{Actor: req.Actor, Action: "project.add", Target: added.Name, Result: "ok",
		Evidence: map[string]any{"path": added.Path, "classification": string(added.Classification), "fix_level": added.FixLevel}}); err != nil {
		// No project without its trace.
		_, _ = repo.Purge(ctx, added.ID)
		return Project{}, &AuditError{Err: err}
	}
	return added, nil
}

// addRefusalKey is the catalog key of a validation error of Add, "" for any
// other error.
func addRefusalKey(err error) string {
	switch {
	case errors.Is(err, ErrDuplicateName):
		return "api.project.duplicate"
	case errors.Is(err, ErrNotADirectory):
		return "api.project.not_dir"
	case errors.Is(err, ErrEmptyName):
		return "api.project.bad_name"
	case errors.Is(err, ErrInvalidFixLevel):
		return "cli.project.add.bad_fix_level"
	case errors.Is(err, ErrInvalidClassification):
		return "cli.project.add.bad_classification"
	case errors.Is(err, ErrInvalidExclude):
		return "cli.project.add.bad_exclude"
	case errors.Is(err, ErrInvalidTech):
		return "cli.project.add.bad_tech"
	case errors.Is(err, ErrInvalidSourceType), errors.Is(err, ErrInvalidRiskOverride):
		return "cli.project.add.invalid"
	}
	return ""
}

// boundedForAudit is s without control characters (newline and tab kept, as
// scan.SanitizeText does), cut at max runes.
func boundedForAudit(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)) {
			return -1
		}
		return r
	}, s)
	if rs := []rune(s); len(rs) > max {
		return string(rs[:max])
	}
	return s
}
