package gitrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

// ErrUnknownDiscovery means the repository is not in the "to discover" list.
var ErrUnknownDiscovery = errors.New("this repository is not in the list to discover")

// DiscoveryRepo stores the repositories found by topic (table discovery).
type DiscoveryRepo struct{ s *store.Store }

// NewDiscoveryRepo returns the discovery store of s.
func NewDiscoveryRepo(s *store.Store) *DiscoveryRepo { return &DiscoveryRepo{s: s} }

// KnownRepos lists the repositories the registry already has (setting
// repo of any entry, hidden ones included), lower case.
func KnownRepos(ctx context.Context, r *source.Repo) (map[string]bool, error) {
	list, err := r.List(ctx, "", true)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range list {
		if repo := e.Config.Str("repo"); repo != "" {
			out[strings.ToLower(repo)] = true
		}
	}
	return out, nil
}

// Save records the repositories found: a repository the registry knows
// (known, lower case keys) is left out; one seen before keeps its state and
// first sighting, its stars and description are refreshed. It returns how
// many were new.
func (r *DiscoveryRepo) Save(ctx context.Context, found []Discovery, known map[string]bool, now time.Time) (int, error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot save the discoveries: %w", err)
	}
	defer tx.Rollback()
	added := 0
	at := now.UTC().Truncate(time.Second).Format(time.RFC3339)
	for _, d := range found {
		if known[strings.ToLower(d.Repo)] {
			continue
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery WHERE repo = ?`, d.Repo).Scan(&n); err != nil {
			return 0, fmt.Errorf("cannot save the discoveries: %w", err)
		}
		if n == 0 {
			added++
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO discovery (repo, topic, stars, description, html_url, first_seen_at, state)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (repo) DO UPDATE SET stars = excluded.stars, description = excluded.description, html_url = excluded.html_url`,
			d.Repo, d.Topic, d.Stars, d.Description, d.HTMLURL, at, StateNew); err != nil {
			return 0, fmt.Errorf("cannot save the discoveries: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("cannot save the discoveries: %w", err)
	}
	return added, nil
}

// List returns the discoveries in state (every state when ""), most starred
// first.
func (r *DiscoveryRepo) List(ctx context.Context, state string) ([]Discovery, error) {
	q := `SELECT repo, topic, stars, description, html_url, first_seen_at, state FROM discovery`
	var args []any
	if state != "" {
		q += ` WHERE state = ?`
		args = append(args, state)
	}
	rows, err := r.s.DB().QueryContext(ctx, q+` ORDER BY stars DESC, repo`, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the discoveries: %w", err)
	}
	defer rows.Close()
	out := []Discovery{}
	for rows.Next() {
		var d Discovery
		if err := rows.Scan(&d.Repo, &d.Topic, &d.Stars, &d.Description, &d.HTMLURL, &d.FirstSeenAt, &d.State); err != nil {
			return nil, fmt.Errorf("cannot read the discoveries: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetState marks a discovery ignored or added (matched without case).
func (r *DiscoveryRepo) SetState(ctx context.Context, repo, state string) error {
	if state != StateNew && state != StateIgnored && state != StateAdded {
		return fmt.Errorf("unknown discovery state %q", state)
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE discovery SET state = ? WHERE LOWER(repo) = LOWER(?)`, state, repo)
	if err != nil {
		return fmt.Errorf("cannot update the discovery: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownDiscovery, repo)
	}
	return nil
}
