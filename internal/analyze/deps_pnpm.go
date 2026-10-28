package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmDep is a dependency of an importer: {specifier, version} since
// lockfile v6.
type pnpmDep struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Dependencies         map[string]any `yaml:"dependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
}

// loadPnpm reads pnpm-lock.yaml (v6 or v9) and the root package.json; without
// package.json the root importer gives the direct dependencies.
func loadPnpm(dir string) (*DepGraph, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "pnpm-lock.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}
	var lock struct {
		LockfileVersion any                     `yaml:"lockfileVersion"`
		Importers       map[string]pnpmImporter `yaml:"importers"`
		Packages        map[string]pnpmPackage  `yaml:"packages"`
		Snapshots       map[string]pnpmPackage  `yaml:"snapshots"`
		// v6 without workspace: the root importer is at the top level.
		pnpmImporter `yaml:",inline"`
	}
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: %s: %w", errFormat, err)
	}
	if lock.LockfileVersion == nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: %s: no lockfileVersion", errFormat)
	}
	g := &DepGraph{Ecosystem: "npm", Root: map[string]string{}, Requires: map[string][]string{}}
	for _, src := range []map[string]pnpmPackage{lock.Packages, lock.Snapshots} {
		for key, p := range src {
			name := pnpmName(key)
			if name == "" {
				continue
			}
			var deps []string
			for d := range p.Dependencies {
				deps = append(deps, d)
			}
			for d := range p.OptionalDependencies {
				deps = append(deps, d)
			}
			addRequires(g, []string{name}, deps)
		}
	}
	if err := rootFromPackageJSON(dir, g); err != nil {
		return nil, err
	}
	if g.HasRootManifest {
		return g, nil
	}
	root, ok := lock.Importers["."]
	if !ok && (len(lock.Dependencies) > 0 || len(lock.DevDependencies) > 0 || len(lock.OptionalDependencies) > 0) {
		root, ok = lock.pnpmImporter, true
	}
	if ok {
		for _, m := range []map[string]pnpmDep{root.Dependencies, root.DevDependencies, root.OptionalDependencies} {
			for n, d := range m {
				if _, seen := g.Root[n]; !seen {
					g.Root[n] = d.Specifier
				}
			}
		}
		g.HasRootManifest = true
	}
	return g, nil
}

// pnpmName is the package name of a packages or snapshots key: "/name@1.0.0"
// (v6), "name@1.0.0" (v9), either possibly followed by "(peer@x)".
func pnpmName(key string) string {
	key = strings.TrimPrefix(key, "/")
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	return specName(key)
}
