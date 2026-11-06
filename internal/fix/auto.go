package fix

import (
	"path"
	"slices"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// dependencyFiles are the only files a proposal applied without a click may
// touch (any folder).
var dependencyFiles = []string{"composer.json", "composer.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

// The kinds of a file a person reads before running the tests, in the
// order they are listed.
const (
	// FileManifest: the list of software of the project (composer.json,
	// package.json), which can also hold commands the tests run (scripts).
	FileManifest = "manifest"
	// FileLockfile: the fixed versions of that software.
	FileLockfile = "lockfile"
	// FileTests: a path that names tests, scripts or settings (test, spec,
	// script, phpunit, jest, vitest, config): what the test command loads.
	FileTests = "tests"
	// FileCode: any other file.
	FileCode = "code"
)

var (
	manifestNames = []string{"composer.json", "package.json"}
	lockfileNames = []string{"composer.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
	testsWords    = []string{"test", "spec", "script", "phpunit", "jest", "vitest", "config"}
)

// ReviewFile is a changed file a person reads before running the tests.
type ReviewFile struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// fileKind is the kind of a changed file (any folder, ignoring case).
func fileKind(f string) string {
	p := strings.ToLower(strings.ReplaceAll(f, `\`, "/"))
	base := path.Base(p)
	switch {
	case slices.Contains(manifestNames, base):
		return FileManifest
	case slices.Contains(lockfileNames, base):
		return FileLockfile
	}
	for _, w := range testsWords {
		if strings.Contains(p, w) {
			return FileTests
		}
	}
	return FileCode
}

// reviewFiles is every changed file with its kind, ordered: the manifests,
// the lockfiles, the tests, scripts and settings, then the rest (each group
// in the order of files). Every file is there: the manifest and the
// lockfile run code too (a script, a package added).
func reviewFiles(files []string) []ReviewFile {
	out := make([]ReviewFile, 0, len(files))
	for _, kind := range []string{FileManifest, FileLockfile, FileTests, FileCode} {
		for _, f := range files {
			if fileKind(f) == kind {
				out = append(out, ReviewFile{Path: f, Kind: kind})
			}
		}
	}
	return out
}

// ReviewFiles are the changed files of p, as reviewFiles orders them.
func ReviewFiles(p Proposal) []ReviewFile { return reviewFiles(p.Files) }

// MaxCodeFilesShown is how many files of kind FileCode a list names before
// "and N more"; every file of another kind is always named.
const MaxCodeFilesShown = 10

// ShownReviewFiles is the list as it is shown: every manifest, lockfile and
// tests file, the first MaxCodeFilesShown other files, and how many more.
func ShownReviewFiles(list []ReviewFile) (shown []ReviewFile, more int) {
	code := 0
	for _, f := range list {
		if f.Kind == FileCode {
			code++
			if code > MaxCodeFilesShown {
				more++
				continue
			}
		}
		shown = append(shown, f)
	}
	return shown, more
}

// AutoApplicable tells whether a proposal is applied without a click (spec
// § 4.1), checked by Michel and never by the agent: the project is at level
// 3 and its "apply safe minor updates alone" rule is checked; the change
// touches dependency files only (no code); the jump is patch or minor; the
// risk score is below the project's auto_fix_below; the re-scan of the copy
// is clean and its tests passed (not merely not run).
func AutoApplicable(p project.Project, prop Proposal, a analyze.Analysis, cfg policy.RiskConfig) bool {
	if p.FixLevel < 3 || !p.AutoFixMinor {
		return false
	}
	if len(prop.Files) == 0 {
		return false
	}
	for _, f := range prop.Files {
		base := strings.ToLower(path.Base(strings.ReplaceAll(f, `\`, "/")))
		ok := false
		for _, d := range dependencyFiles {
			if base == d {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if a.Upgrade.Jump != analyze.JumpPatch && a.Upgrade.Jump != analyze.JumpMinor {
		return false
	}
	if prop.Risk >= cfg.AutoFixBelow {
		return false
	}
	return prop.RescanClean && prop.TestsStatus == workcopy.TestsPassed
}
