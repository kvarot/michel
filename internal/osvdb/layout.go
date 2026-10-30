// Package osvdb manages the offline OSV vulnerability databases.
package osvdb

import (
	"context"
	"path/filepath"
	"slices"

	"github.com/kvarot/michel/internal/source"
)

// Host is the only host the databases are downloaded from.
const Host = "osv-vulnerabilities.storage.googleapis.com"

// Enabled returns the OSV ecosystems Michel watches: the ecosystem setting of
// every enabled, visible osv source of the registry. Catalog entries come
// first, in catalog order (Packagist, npm, PyPI...), so downloads and
// listings keep a stable, documented order; user entries follow in key
// order. The names
// are the directory names of the OSV bucket and of osv-scalibr's local
// matcher. An entry still waiting for consent counts: its database is wanted,
// and the download says which allow rule is missing. allowed is accepted for
// callers that hold it but does not filter.
func Enabled(ctx context.Context, r *source.Repo, allowed func(host, purpose string) bool) ([]string, error) {
	_ = allowed
	list, err := r.List(ctx, source.KindOSV, false)
	if err != nil {
		return nil, err
	}
	cat, _, err := source.Catalog()
	if err != nil {
		return nil, err
	}
	pos := map[string]int{}
	for i, c := range cat {
		pos[c.Key] = i
	}
	rank := func(e source.Entry) int {
		if i, ok := pos[e.Key]; ok {
			return i
		}
		return len(cat)
	}
	// List is in key order; a stable sort keeps it among user entries.
	slices.SortStableFunc(list, func(a, b source.Entry) int { return rank(a) - rank(b) })
	out := []string{}
	for _, e := range list {
		eco := e.Config.Str("ecosystem")
		if !e.Enabled || eco == "" || slices.Contains(out, eco) {
			continue
		}
		out = append(out, eco)
	}
	return out, nil
}

// ZipPath returns where osv-scalibr's local matcher looks for an ecosystem's
// archive when it is given root as its local database path:
// <root>/osv-scalibr/<ecosystem>/all.zip
// (osv-scalibr enricher/vulnmatch/osvlocal/matcher.go setupLocalDBDirectory
// appends "osv-scalibr"; zip.go newZippedDB appends <ecosystem>/all.zip).
func ZipPath(root, ecosystem string) string {
	return filepath.Join(root, "osv-scalibr", ecosystem, "all.zip")
}

// SetBaseURLForTest points downloads at another server (an httptest server)
// and returns a function that restores the real one. Tests only.
func SetBaseURLForTest(u string) (restore func()) {
	old := baseURL
	baseURL = u
	return func() { baseURL = old }
}

func fetchedAtPath(root, ecosystem string) string {
	return filepath.Join(root, "osv-scalibr", ecosystem, "fetched_at")
}
