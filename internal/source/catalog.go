package source

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/project"
	"gopkg.in/yaml.v3"
)

// CatalogVersion is the version of the embedded catalog. Bump it whenever an
// entry's name, url, hosts, purpose or catalog settings change, so Sync
// rewrites them on existing databases.
const CatalogVersion = 1

//go:embed catalog/catalog.yaml
var catalogYAML []byte

// TechRule turns a package of a manifest into a technology tag: Package is
// an exact name, Prefix a name prefix ("symfony/"); with neither, every
// package of Ecosystem gives the tag.
type TechRule struct {
	Ecosystem string `yaml:"ecosystem"`
	Package   string `yaml:"package"`
	Prefix    string `yaml:"prefix"`
	Tag       string `yaml:"tag"`
}

type catalogEntry struct {
	Key     string         `yaml:"key"`
	Kind    Kind           `yaml:"kind"`
	Name    string         `yaml:"name"`
	URL     string         `yaml:"url"`
	Hosts   []string       `yaml:"hosts"`
	Purpose string         `yaml:"purpose"`
	Enabled bool           `yaml:"enabled"`
	Config  map[string]any `yaml:"config"`
	Tech    []string       `yaml:"tech"`
	Note    string         `yaml:"note"`
}

type catalogFile struct {
	Version   int            `yaml:"version"`
	Entries   []catalogEntry `yaml:"entries"`
	TechRules []TechRule     `yaml:"tech_rules"`
}

var (
	catalogOnce    sync.Once
	catalogEntries []Entry
	catalogRules   []TechRule
	catalogErr     error
)

// Catalog returns the entries and technology rules of the embedded catalog,
// parsed and checked once. Callers must not modify the returned slices.
func Catalog() ([]Entry, []TechRule, error) {
	catalogOnce.Do(func() {
		catalogEntries, catalogRules, catalogErr = parseCatalog(catalogYAML)
	})
	return catalogEntries, catalogRules, catalogErr
}

func parseCatalog(raw []byte) ([]Entry, []TechRule, error) {
	var f catalogFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("the embedded source catalog is invalid: %w", err)
	}
	if f.Version != CatalogVersion {
		return nil, nil, fmt.Errorf("the embedded source catalog has version %d, the code expects %d", f.Version, CatalogVersion)
	}
	seen := map[string]bool{}
	entries := make([]Entry, 0, len(f.Entries))
	for _, c := range f.Entries {
		e := Entry{
			Key: c.Key, Kind: c.Kind, Origin: OriginCatalog, Name: c.Name, URL: c.URL, Hosts: c.Hosts,
			Purpose: c.Purpose, Enabled: c.Enabled, Config: Config{Catalog: c.Config}, Tech: c.Tech,
			CatalogVersion: f.Version,
		}
		if err := validate(&e); err != nil {
			return nil, nil, fmt.Errorf("the embedded source catalog is invalid: %w", err)
		}
		if seen[e.Key] {
			return nil, nil, fmt.Errorf("the embedded source catalog lists %s twice", e.Key)
		}
		seen[e.Key] = true
		if c.Note != NoteKey(e.Key) {
			return nil, nil, fmt.Errorf("the embedded source catalog: %s has note %q, want %q", e.Key, c.Note, NoteKey(e.Key))
		}
		entries = append(entries, e)
	}
	for _, r := range f.TechRules {
		if r.Ecosystem == "" || !project.ValidTech(r.Tag) || (r.Package != "" && r.Prefix != "") {
			return nil, nil, fmt.Errorf("the embedded source catalog has an invalid tech rule %+v", r)
		}
	}
	return entries, f.TechRules, nil
}

// Sync brings the database in line with the embedded catalog: it inserts the
// missing entries and, for catalog entries written by an older catalog,
// rewrites name, url, hosts, purpose, kind and the catalog settings, without
// touching enabled, hidden, tech or the user settings. An entry dropped from
// a newer catalog is hidden, never deleted. User entries are left alone.
func Sync(ctx context.Context, r *Repo) (inserted, updated int, err error) {
	entries, _, err := Catalog()
	if err != nil {
		return 0, 0, err
	}
	return syncEntries(ctx, r, entries, CatalogVersion)
}

func syncEntries(ctx context.Context, r *Repo, entries []Entry, version int) (inserted, updated int, err error) {
	current, err := r.List(ctx, "", true)
	if err != nil {
		return 0, 0, err
	}
	byKey := make(map[string]Entry, len(current))
	for _, e := range current {
		byKey[e.Key] = e
	}
	now := time.Now()
	var writes []Entry
	inCatalog := map[string]bool{}
	for _, c := range entries {
		inCatalog[c.Key] = true
		c.CatalogVersion = version
		cur, ok := byKey[c.Key]
		switch {
		case !ok:
			c.ID, c.CreatedAt = "", time.Time{}
			c.Config = Config{Catalog: c.Config.Catalog, User: map[string]any{}}
			inserted++
		case cur.Origin == OriginCatalog && cur.CatalogVersion < version:
			cur.Kind, cur.Name, cur.URL, cur.Hosts, cur.Purpose = c.Kind, c.Name, c.URL, c.Hosts, c.Purpose
			cur.Config.Catalog, cur.CatalogVersion = c.Config.Catalog, version
			c = cur
			updated++
		default:
			continue
		}
		if err := r.prepare(&c, now); err != nil {
			return 0, 0, err
		}
		writes = append(writes, c)
	}
	for _, cur := range current {
		if cur.Origin == OriginCatalog && !inCatalog[cur.Key] && cur.CatalogVersion < version {
			cur.Hidden, cur.CatalogVersion = true, version
			if err := r.prepare(&cur, now); err != nil {
				return 0, 0, err
			}
			writes = append(writes, cur)
		}
	}
	if len(writes) == 0 {
		return 0, 0, nil
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot update the sources: %w", err)
	}
	defer tx.Rollback()
	for _, w := range writes {
		if err := upsert(ctx, tx, w); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("cannot update the sources: %w", err)
	}
	return inserted, updated, nil
}

// Reset puts catalog entries back to their catalog state: default enabled,
// shown, catalog tech, no user settings. With key it resets that entry (a
// user entry is refused with ErrUserEntry); with all it resets every catalog
// entry and, with purgeUser, deletes the user entries. It returns the number
// of entries reset or deleted. An installed skill is not uninstalled.
func Reset(ctx context.Context, r *Repo, key string, all, purgeUser bool) (int, error) {
	entries, _, err := Catalog()
	if err != nil {
		return 0, err
	}
	byKey := make(map[string]Entry, len(entries))
	for _, e := range entries {
		byKey[e.Key] = e
	}
	if !all {
		cur, err := r.Get(ctx, key)
		if err != nil {
			return 0, err
		}
		c, ok := byKey[key]
		if cur.Origin != OriginCatalog || !ok {
			return 0, fmt.Errorf("%w: %s", ErrUserEntry, key)
		}
		if err := resetOne(ctx, r, cur, c); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if _, _, err := Sync(ctx, r); err != nil {
		return 0, err
	}
	current, err := r.List(ctx, "", true)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, cur := range current {
		if c, ok := byKey[cur.Key]; ok && cur.Origin == OriginCatalog {
			if err := resetOne(ctx, r, cur, c); err != nil {
				return n, err
			}
			n++
		} else if cur.Origin == OriginUser && purgeUser {
			if err := r.Delete(ctx, cur.Key); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// resetOne rewrites cur from its catalog entry c, keeping the keys that
// record an installation (a reset never uninstalls).
func resetOne(ctx context.Context, r *Repo, cur, c Entry) error {
	user := map[string]any{}
	for _, k := range []string{"installed_sha", "install_dir"} {
		if v, ok := cur.Config.User[k]; ok {
			user[k] = v
		}
	}
	cur.Kind, cur.Name, cur.URL, cur.Hosts, cur.Purpose = c.Kind, c.Name, c.URL, c.Hosts, c.Purpose
	cur.Enabled, cur.Hidden, cur.Tech = c.Enabled, false, c.Tech
	cur.Config = Config{Catalog: c.Config.Catalog, User: user}
	cur.CatalogVersion = CatalogVersion
	_, err := r.Upsert(ctx, cur)
	return err
}
