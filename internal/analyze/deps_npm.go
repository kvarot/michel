package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type npmEntry struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func loadNpm(dir string) (*DepGraph, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}
	var lock struct {
		LockfileVersion int                 `json:"lockfileVersion"`
		Packages        map[string]npmEntry `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	// v2 carries both "packages" and the legacy tree: use packages when present.
	if lock.Packages == nil {
		return nil, fmt.Errorf("unsupported package-lock.json lockfileVersion %d", lock.LockfileVersion)
	}
	g := &DepGraph{Ecosystem: "npm", Root: map[string]string{}, Requires: map[string][]string{}}
	// Plan 2 does not model npm's tree resolution: when a name appears at several
	// paths, the shallowest copy (fewest node_modules/ segments, then lexical
	// path order) is the hoisted one and provides Requires.
	paths := make([]string, 0, len(lock.Packages))
	for p := range lock.Packages {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		di, dj := strings.Count(paths[i], "node_modules/"), strings.Count(paths[j], "node_modules/")
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	for _, p := range paths {
		if p == "" {
			continue
		}
		i := strings.LastIndex(p, "node_modules/")
		if i < 0 {
			continue // workspace or link entry
		}
		name := p[i+len("node_modules/"):]
		if _, done := g.Requires[name]; done {
			continue
		}
		e := lock.Packages[p]
		deps := []string{}
		for d := range e.Dependencies {
			deps = append(deps, d)
		}
		for d := range e.OptionalDependencies {
			deps = append(deps, d)
		}
		g.Requires[name] = deps
	}
	if root, ok := lock.Packages[""]; ok {
		addAll(g.Root, root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies)
		g.HasRootManifest = true
		return g, nil
	}
	pj, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return g, nil
		}
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var root npmEntry
	if err := json.Unmarshal(pj, &root); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	addAll(g.Root, root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies)
	g.HasRootManifest = true
	return g, nil
}

func addAll(dst map[string]string, srcs ...map[string]string) {
	for _, s := range srcs {
		for k, v := range s {
			dst[k] = v
		}
	}
}
