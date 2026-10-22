// Package analyze computes, offline and without AI, the facts a user needs to
// decide about a finding.
package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// Directness tells whether a package is a direct dependency of the project.
type Directness string

const (
	Direct     Directness = "direct"
	Transitive Directness = "transitive"
	Unknown    Directness = "unknown"
)

// DepGraph is the dependency graph read from a lockfile and its root manifest.
type DepGraph struct {
	Ecosystem string
	// Root maps direct dependencies to their constraint ("" if unknown).
	Root map[string]string
	// Requires maps a package to the packages it depends on.
	Requires map[string][]string
	// HasRootManifest is true when the root requirements are known.
	HasRootManifest bool
}

// DepPath describes how a package is reached from the root manifest.
type DepPath struct {
	Directness Directness
	// Via lists the direct dependency first, then intermediates; the target is
	// excluded. Empty when direct or unknown.
	Via []string
	// Constraint is the root constraint when the package is direct.
	Constraint string
}

// LoadDepGraph reads the lockfile (required) and root manifest (optional) found
// in manifestDir. ecosystem is "Packagist" or "npm".
func LoadDepGraph(manifestDir, ecosystem string) (*DepGraph, error) {
	switch ecosystem {
	case "Packagist":
		return loadComposer(manifestDir)
	case "npm":
		return loadNpm(manifestDir)
	}
	return nil, fmt.Errorf("unsupported ecosystem %q for dependency graph", ecosystem)
}

// PathTo returns the shortest path from a direct dependency to pkg (BFS, ties
// broken by lexical order of names).
func (g *DepGraph) PathTo(pkg string) DepPath {
	if g.Ecosystem == "Packagist" {
		pkg = strings.ToLower(pkg)
	}
	if c, ok := g.Root[pkg]; ok {
		return DepPath{Directness: Direct, Constraint: c}
	}
	if !g.HasRootManifest {
		return DepPath{Directness: Unknown}
	}
	roots := sortedKeys(g.Root)
	parent := map[string]string{}
	seen := map[string]bool{}
	queue := []string{}
	for _, r := range roots {
		seen[r] = true
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		deps := append([]string(nil), g.Requires[cur]...)
		sort.Strings(deps)
		for _, d := range deps {
			if seen[d] {
				continue
			}
			seen[d] = true
			parent[d] = cur
			if d == pkg {
				var via []string
				for p := cur; p != ""; p = parent[p] {
					via = append([]string{p}, via...)
				}
				return DepPath{Directness: Transitive, Via: via}
			}
			queue = append(queue, d)
		}
	}
	return DepPath{Directness: Unknown}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
