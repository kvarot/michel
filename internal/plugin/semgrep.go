package plugin

import (
	"os"
	"path/filepath"

	"github.com/kvarot/michel/internal/project"
)

// SemgrepArgs is Semgrep's command line: SARIF output, no metrics, no
// version check, and only the local rules of Michel's data folder (a
// registry ruleset would be downloaded).
var SemgrepArgs = func(out, projectPath, rulesDir string) []string {
	return []string{"scan", "--sarif", "--output", out, "--metrics=off", "--disable-version-check", "--config", rulesDir, projectPath}
}

// SemgrepRulesDir is the folder of Semgrep's rules, under the tool's folder.
const SemgrepRulesDir = "rules"

func semgrepRun(outDir, report string, p project.Project) ([]string, error) {
	rules := filepath.Join(outDir, SemgrepRulesDir)
	entries, err := os.ReadDir(rules)
	if err != nil || len(entries) == 0 {
		return nil, ErrNoRules
	}
	return SemgrepArgs(report, p.Path, rules), nil
}
