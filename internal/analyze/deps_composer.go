package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type composerPkg struct {
	Name    string            `json:"name"`
	Require map[string]string `json:"require"`
}

func isComposerPlatform(name string) bool {
	return name == "php" || name == "composer-plugin-api" || name == "composer-runtime-api" ||
		strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-")
}

func loadComposer(dir string) (*DepGraph, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}
	var lock struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	g := &DepGraph{Ecosystem: "Packagist", Root: map[string]string{}, Requires: map[string][]string{}}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		name := strings.ToLower(p.Name)
		deps := []string{}
		for d := range p.Require {
			if !isComposerPlatform(d) {
				deps = append(deps, strings.ToLower(d))
			}
		}
		g.Requires[name] = deps
	}
	rootRaw, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return g, nil
		}
		return nil, fmt.Errorf("read composer.json: %w", err)
	}
	var root struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(rootRaw, &root); err != nil {
		return nil, fmt.Errorf("parse composer.json: %w", err)
	}
	for _, m := range []map[string]string{root.Require, root.RequireDev} {
		for name, c := range m {
			if !isComposerPlatform(name) {
				g.Root[strings.ToLower(name)] = c
			}
		}
	}
	g.HasRootManifest = true
	return g, nil
}
