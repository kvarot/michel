package fix

import (
	"path"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/workcopy"
)

// dependencyFiles are the only files a proposal applied without a click may
// touch (any folder).
var dependencyFiles = []string{"composer.json", "composer.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

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
