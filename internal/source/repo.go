package source

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Repo reads and writes the source table.
type Repo struct {
	s *store.Store

	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, entropy: ulid.Monotonic(rand.Reader, 0)}
}

const sourceCols = `id, key, kind, origin, name, url, hosts, purpose, enabled, hidden, config_catalog, config_user, tech,
	catalog_version, last_read_at, last_read_result, last_read_error, last_read_items, last_read_etag, status, created_at, updated_at`

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type scanner interface{ Scan(...any) error }

func scanEntry(s scanner) (Entry, error) {
	var e Entry
	var kind, origin, hosts, cfgCat, cfgUser, tech, lastAt, status, created, updated string
	var enabled, hidden int
	if err := s.Scan(&e.ID, &e.Key, &kind, &origin, &e.Name, &e.URL, &hosts, &e.Purpose, &enabled, &hidden,
		&cfgCat, &cfgUser, &tech, &e.CatalogVersion, &lastAt, &e.LastReadResult, &e.LastReadError, &e.LastReadItems,
		&e.LastReadETag, &status, &created, &updated); err != nil {
		return Entry{}, err
	}
	e.Kind, e.Origin, e.Enabled, e.Hidden = Kind(kind), Origin(origin), enabled != 0, hidden != 0
	e.Hosts, e.Tech = []string{}, []string{}
	e.Config = Config{Catalog: map[string]any{}, User: map[string]any{}}
	e.Status = map[string]any{}
	for _, f := range []struct {
		name, raw string
		dst       any
	}{
		{"hosts", hosts, &e.Hosts}, {"config_catalog", cfgCat, &e.Config.Catalog}, {"config_user", cfgUser, &e.Config.User},
		{"tech", tech, &e.Tech}, {"status", status, &e.Status},
	} {
		if err := json.Unmarshal([]byte(f.raw), f.dst); err != nil {
			return Entry{}, fmt.Errorf("source %s has an unreadable %s %q: %w", e.Key, f.name, f.raw, err)
		}
	}
	for _, t := range []struct {
		raw string
		dst *time.Time
	}{{lastAt, &e.LastReadAt}, {created, &e.CreatedAt}, {updated, &e.UpdatedAt}} {
		if t.raw == "" {
			continue
		}
		v, err := time.Parse(time.RFC3339, t.raw)
		if err != nil {
			return Entry{}, fmt.Errorf("source %s has an unreadable date %q: %w", e.Key, t.raw, err)
		}
		*t.dst = v
	}
	return e, nil
}

// List returns the entries of kind ("" for every kind), ordered by kind then
// key. Hidden entries are left out unless includeHidden.
func (r *Repo) List(ctx context.Context, kind Kind, includeHidden bool) ([]Entry, error) {
	q := `SELECT ` + sourceCols + ` FROM source WHERE 1 = 1`
	var args []any
	if kind != "" {
		q += ` AND kind = ?`
		args = append(args, string(kind))
	}
	if !includeHidden {
		q += ` AND hidden = 0`
	}
	rows, err := r.s.DB().QueryContext(ctx, q+` ORDER BY key`, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the sources: %w", err)
	}
	defer rows.Close()
	var all []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the sources: %w", err)
	}
	out := make([]Entry, 0, len(all))
	for _, k := range Kinds {
		for _, e := range all {
			if e.Kind == k {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// Get returns the entry with key, or ErrNotFound.
func (r *Repo) Get(ctx context.Context, key string) (Entry, error) {
	e, err := scanEntry(r.s.DB().QueryRowContext(ctx, `SELECT `+sourceCols+` FROM source WHERE key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	if err != nil {
		return Entry{}, fmt.Errorf("cannot read source %s: %w", key, err)
	}
	return e, nil
}

// validate checks an entry before it is written and makes its lists and maps
// non-nil.
func validate(e *Entry) error {
	if !ValidKey(e.Key) {
		return fmt.Errorf("%w %q: use a prefix (osv, enrich, feed, plugin, skill, mcp, ref, discover), a dot and lowercase letters, digits or hyphens", ErrInvalidKey, e.Key)
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("%w %s: unknown kind %q", ErrInvalidEntry, e.Key, e.Kind)
	}
	if e.Origin != OriginCatalog && e.Origin != OriginUser {
		return fmt.Errorf("%w %s: unknown origin %q", ErrInvalidEntry, e.Key, e.Origin)
	}
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("%w %s: the name is empty", ErrInvalidEntry, e.Key)
	}
	if (len(e.Hosts) == 0) != (e.Purpose == "") {
		return fmt.Errorf("%w %s: hosts and purpose go together", ErrInvalidEntry, e.Key)
	}
	if e.Config.Catalog == nil {
		e.Config.Catalog = map[string]any{}
	}
	if e.Config.User == nil {
		e.Config.User = map[string]any{}
	}
	if err := checkConfig(e.Kind, e.Config.Catalog); err != nil {
		return fmt.Errorf("%s: %w", e.Key, err)
	}
	if err := checkConfig(e.Kind, e.Config.User); err != nil {
		return fmt.Errorf("%s: %w", e.Key, err)
	}
	tech, err := project.NormalizeTech(e.Tech)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Key, err)
	}
	e.Tech = tech
	if e.Hosts == nil {
		e.Hosts = []string{}
	}
	if e.Status == nil {
		e.Status = map[string]any{}
	}
	return nil
}

func jsonText(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Upsert validates e and writes it: a new key is inserted (with a new ID), an
// existing key is updated in place (its ID, creation date, last read and
// status are kept). It returns the entry as stored.
func (r *Repo) Upsert(ctx context.Context, e Entry) (Entry, error) {
	if err := r.prepare(&e, time.Now()); err != nil {
		return Entry{}, err
	}
	if err := upsert(ctx, r.s.DB(), e); err != nil {
		return Entry{}, err
	}
	return r.Get(ctx, e.Key)
}

// prepare validates e and fills its ID and dates.
func (r *Repo) prepare(e *Entry, now time.Time) error {
	if err := validate(e); err != nil {
		return err
	}
	now = now.UTC().Truncate(time.Second)
	if e.ID == "" {
		r.mu.Lock()
		id, err := ulid.New(ulid.Timestamp(now), r.entropy)
		r.mu.Unlock()
		if err != nil {
			return fmt.Errorf("cannot create a source id: %w", err)
		}
		e.ID = id.String()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	return nil
}

func upsert(ctx context.Context, ex execer, e Entry) error {
	var texts [5]string
	for i, v := range []any{e.Hosts, e.Config.Catalog, e.Config.User, e.Tech, e.Status} {
		t, err := jsonText(v)
		if err != nil {
			return fmt.Errorf("cannot save source %s: %w", e.Key, err)
		}
		texts[i] = t
	}
	_, err := ex.ExecContext(ctx, `INSERT INTO source (`+sourceCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, origin = excluded.origin, name = excluded.name,
			url = excluded.url, hosts = excluded.hosts, purpose = excluded.purpose, enabled = excluded.enabled,
			hidden = excluded.hidden, config_catalog = excluded.config_catalog, config_user = excluded.config_user,
			tech = excluded.tech, catalog_version = excluded.catalog_version, updated_at = excluded.updated_at`,
		e.ID, e.Key, string(e.Kind), string(e.Origin), e.Name, e.URL, texts[0], e.Purpose, boolInt(e.Enabled), boolInt(e.Hidden),
		texts[1], texts[2], texts[3], e.CatalogVersion, stamp(e.LastReadAt), e.LastReadResult, e.LastReadError,
		e.LastReadItems, e.LastReadETag, texts[4], stamp(e.CreatedAt), stamp(e.UpdatedAt))
	if err != nil {
		return fmt.Errorf("cannot save source %s: %w", e.Key, err)
	}
	return nil
}

// update runs an UPDATE on the entry with key and reports ErrNotFound when no
// row matched.
func (r *Repo) update(ctx context.Context, key, set string, args ...any) error {
	args = append(args, time.Now().UTC().Format(time.RFC3339), key)
	res, err := r.s.DB().ExecContext(ctx, `UPDATE source SET `+set+`, updated_at = ? WHERE key = ?`, args...)
	if err != nil {
		return fmt.Errorf("cannot save source %s: %w", key, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return nil
}

// SetEnabled records whether the user wants the entry.
func (r *Repo) SetEnabled(ctx context.Context, key string, on bool) error {
	return r.update(ctx, key, `enabled = ?`, boolInt(on))
}

// SetHidden hides a catalog entry (or shows it again).
func (r *Repo) SetHidden(ctx context.Context, key string, hidden bool) error {
	return r.update(ctx, key, `hidden = ?`, boolInt(hidden))
}

// Delete removes a user entry. A catalog entry is refused with ErrCatalogEntry.
func (r *Repo) Delete(ctx context.Context, key string) error {
	e, err := r.Get(ctx, key)
	if err != nil {
		return err
	}
	if e.Origin != OriginUser {
		return fmt.Errorf("%w: %s", ErrCatalogEntry, key)
	}
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM source WHERE key = ?`, key); err != nil {
		return fmt.Errorf("cannot delete source %s: %w", key, err)
	}
	return nil
}

// RecordRead stores the outcome of the last read of the entry.
func (r *Repo) RecordRead(ctx context.Context, key string, at time.Time, result, errText string, items int, etag string) error {
	return r.update(ctx, key, `last_read_at = ?, last_read_result = ?, last_read_error = ?, last_read_items = ?, last_read_etag = ?`,
		stamp(at), result, errText, items, etag)
}

// SetStatus stores the latest repository status of the entry.
func (r *Repo) SetStatus(ctx context.Context, key string, st map[string]any) error {
	if st == nil {
		st = map[string]any{}
	}
	t, err := jsonText(st)
	if err != nil {
		return fmt.Errorf("cannot save source %s: %w", key, err)
	}
	return r.update(ctx, key, `status = ?`, t)
}

// SetUserConfig replaces the user part of the settings; unknown keys are
// refused.
func (r *Repo) SetUserConfig(ctx context.Context, key string, user map[string]any) error {
	e, err := r.Get(ctx, key)
	if err != nil {
		return err
	}
	if user == nil {
		user = map[string]any{}
	}
	if err := checkConfig(e.Kind, user); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	t, err := jsonText(user)
	if err != nil {
		return fmt.Errorf("cannot save source %s: %w", key, err)
	}
	return r.update(ctx, key, `config_user = ?`, t)
}
