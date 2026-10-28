package source

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
)

// ListTech returns the technologies declared outside any project, sorted.
func ListTech(ctx context.Context, s *store.Store) ([]string, error) {
	rows, err := s.DB().QueryContext(ctx, `SELECT tag FROM tech ORDER BY tag`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the technologies: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("cannot read the technologies: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddTech declares a technology outside any project; declaring it twice is
// not an error. An invalid tag is refused with project.ErrInvalidTech.
func AddTech(ctx context.Context, s *store.Store, tag string) error {
	if _, err := project.NormalizeTech([]string{tag}); err != nil {
		return err
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO tech (tag, created_at) VALUES (?, ?) ON CONFLICT (tag) DO NOTHING`,
		tag, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("cannot save the technology %s: %w", tag, err)
	}
	return nil
}

// RemoveTech forgets a technology declared outside any project; an unknown
// tag is not an error.
func RemoveTech(ctx context.Context, s *store.Store, tag string) error {
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM tech WHERE tag = ?`, tag); err != nil {
		return fmt.Errorf("cannot remove the technology %s: %w", tag, err)
	}
	return nil
}

// DeclaredTech merges the technologies of p (declared and detected) with the
// global ones, sorted and unique. A global list that cannot be read is left
// out: the project's own tags still count.
func DeclaredTech(ctx context.Context, s *store.Store, p project.Project) []string {
	out := append(append([]string{}, p.Tech...), p.TechAuto...)
	if global, err := ListTech(ctx, s); err == nil {
		out = append(out, global...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TechAuto turns what a scan read into technology tags with rules: a rule
// without Package nor Prefix gives its tag when its ecosystem is in
// ecosystems or has packages ("php" for Packagist, "node" for npm); else it
// gives its tag when a package of its ecosystem is Package or starts with
// Prefix. packages maps an OSV ecosystem to its package names. The tags are
// sorted and unique, never nil.
func TechAuto(rules []TechRule, ecosystems []string, packages map[string][]string) []string {
	out := []string{}
	for _, r := range rules {
		pkgs := packages[r.Ecosystem]
		switch {
		case r.Package == "" && r.Prefix == "":
			if slices.Contains(ecosystems, r.Ecosystem) || len(pkgs) > 0 {
				out = append(out, r.Tag)
			}
		case slices.ContainsFunc(pkgs, func(p string) bool {
			return (r.Package != "" && p == r.Package) || (r.Prefix != "" && strings.HasPrefix(p, r.Prefix))
		}):
			out = append(out, r.Tag)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
