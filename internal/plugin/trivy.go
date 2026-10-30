package plugin

import (
	"os"
	"path/filepath"

	"github.com/kvarot/michel/internal/project"
)

// TrivyArgs is Trivy's command line: the misconfiguration scanner only (the
// OSV scan covers the packages), SARIF output, and every download switched
// off; its cache is Michel's, in the tool's data folder.
var TrivyArgs = func(out, projectPath, cacheDir string) []string {
	return []string{"fs", "--scanners", "misconfig", "--format", "sarif", "--output", out, "--skip-db-update",
		"--skip-java-db-update", "--skip-check-update", "--offline-scan", "--cache-dir", cacheDir, projectPath}
}

func trivyRun(outDir, report string, p project.Project) ([]string, error) {
	cache := filepath.Join(outDir, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, noPath(err)
	}
	return TrivyArgs(report, p.Path, cache), nil
}
