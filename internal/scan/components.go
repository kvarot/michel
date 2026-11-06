package scan

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// Component is one package read in a manifest by the last complete scan.
type Component struct {
	ManifestRelPath string
	Ecosystem       string
	Name            string
	Version         string
	PURL            string
	// DepGroup is "dev" for a development dependency, "" otherwise.
	DepGroup string
}

// PURL returns the package URL of a package, or "" for an ecosystem Michel
// does not map. The "@" of an npm scope is written %40.
func PURL(ecosystem, name, version string) string {
	switch ecosystem {
	case "Packagist":
		return "pkg:composer/" + name + "@" + version
	case "npm":
		return "pkg:npm/" + strings.ReplaceAll(name, "@", "%40") + "@" + version
	case "Go":
		return "pkg:golang/" + name + "@" + version
	}
	return ""
}

// componentsOf lists every package of the accepted manifests, with the same
// relative paths as the findings. A package listed twice with the same
// version in a manifest is kept once, and is "dev" only if every entry is.
func componentsOf(vr models.VulnerabilityResults, root string, accepted map[string]bool) []Component {
	out := []Component{}
	index := map[[4]string]int{}
	for _, res := range vr.Results {
		rel, err := relPath(root, res.Source.Path)
		if err != nil || !accepted[rel] {
			continue
		}
		for _, pv := range res.Packages {
			p := pv.Package
			dep := ""
			if slices.Contains(pv.DepGroups, "dev") {
				dep = "dev"
			}
			key := [4]string{rel, p.Ecosystem, p.Name, p.Version}
			if i, ok := index[key]; ok {
				if dep == "" {
					out[i].DepGroup = ""
				}
				continue
			}
			index[key] = len(out)
			out = append(out, Component{
				ManifestRelPath: rel, Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version,
				PURL: PURL(p.Ecosystem, p.Name, p.Version), DepGroup: dep,
			})
		}
	}
	return out
}

// replaceComponents swaps the project's components for cs, all stamped with
// scanID. It runs in the transaction of a complete scan only.
func replaceComponents(ctx context.Context, tx *sql.Tx, projectID, scanID string, cs []Component) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_component WHERE project_id = ?`, projectID); err != nil {
		return fmt.Errorf("cannot clear the components: %w", err)
	}
	st, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO scan_component (project_id, manifest_rel_path, ecosystem, name, version, purl, dep_group, scan_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, c := range cs {
		if _, err := st.ExecContext(ctx, projectID, c.ManifestRelPath, c.Ecosystem, c.Name, c.Version, c.PURL, c.DepGroup, scanID); err != nil {
			return fmt.Errorf("cannot save component %s: %w", c.Name, err)
		}
	}
	return nil
}

// ListComponents returns the packages of the project's last complete scan
// and that scan's id (empty when none was stored), sorted by manifest,
// ecosystem, name, version.
func (r *Repo) ListComponents(ctx context.Context, projectID string) (string, []Component, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT manifest_rel_path, ecosystem, name, version, purl, dep_group, scan_id
		FROM scan_component WHERE project_id = ? ORDER BY manifest_rel_path, ecosystem, name, version`, projectID)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	scanID := ""
	cs := []Component{}
	for rows.Next() {
		var c Component
		if err := rows.Scan(&c.ManifestRelPath, &c.Ecosystem, &c.Name, &c.Version, &c.PURL, &c.DepGroup, &scanID); err != nil {
			return "", nil, err
		}
		cs = append(cs, c)
	}
	return scanID, cs, rows.Err()
}
