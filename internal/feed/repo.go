package feed

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// ErrItemNotFound: no item has that id.
var ErrItemNotFound = errors.New("feed item not found")

// Repo reads and writes feed_item.
type Repo struct {
	s       *store.Store
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, entropy: ulid.Monotonic(rand.Reader, 0)}
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Insert stores the items that are not stored yet (by source and guid) and
// returns how many were new. An empty ID gets a new one, an empty SeenAt
// the current time.
func (r *Repo) Insert(ctx context.Context, items []Item) (int, error) {
	return r.store(ctx, "", items, "")
}

// store inserts items in one transaction and, when sourceID and cutoff are
// set, purges the items of sourceID first seen before cutoff.
func (r *Repo) store(ctx context.Context, sourceID string, items []Item, cutoff string) (int, error) {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot store the feed items: %w", err)
	}
	defer tx.Rollback()
	n := 0
	for _, it := range items {
		added, err := r.insert(ctx, tx, it)
		if err != nil {
			return 0, err
		}
		n += added
	}
	if sourceID != "" && cutoff != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM feed_item WHERE source_id = ? AND seen_at < ?`, sourceID, cutoff); err != nil {
			return 0, fmt.Errorf("cannot purge the old feed items: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("cannot store the feed items: %w", err)
	}
	return n, nil
}

func (r *Repo) insert(ctx context.Context, ex execer, it Item) (int, error) {
	now := time.Now().UTC()
	if it.ID == "" {
		r.mu.Lock()
		id, err := ulid.New(ulid.Timestamp(now), r.entropy)
		r.mu.Unlock()
		if err != nil {
			return 0, fmt.Errorf("cannot create a feed item id: %w", err)
		}
		it.ID = id.String()
	}
	if it.SeenAt == "" {
		it.SeenAt = now.Truncate(time.Second).Format(time.RFC3339)
	}
	if it.Tech == nil {
		it.Tech = []string{}
	}
	tech, err := json.Marshal(it.Tech)
	if err != nil {
		return 0, fmt.Errorf("cannot store a feed item: %w", err)
	}
	res, err := ex.ExecContext(ctx, `INSERT INTO feed_item (id, source_id, guid, title, url, published_at, summary, tech, seen_at, read_at)
		VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (source_id, guid) DO NOTHING`,
		it.ID, it.SourceID, it.GUID, it.Title, it.URL, it.PublishedAt, it.Summary, string(tech), it.SeenAt, it.ReadAt)
	if err != nil {
		return 0, fmt.Errorf("cannot store a feed item: %w", err)
	}
	added, _ := res.RowsAffected()
	return int(added), nil
}

// when is the date an item counts from: its publication, else when Michel
// first saw it.
const when = `COALESCE(NULLIF(i.published_at, ''), i.seen_at)`

// listed is an item with the current technologies of its source.
type listed struct {
	Item
	sourceTech []string
}

func (r *Repo) list(ctx context.Context, since time.Time, unreadOnly bool) ([]listed, error) {
	q := `SELECT i.id, i.source_id, COALESCE(s.key, ''), COALESCE(s.name, ''), COALESCE(s.tech, '[]'), i.guid, i.title, i.url,
		i.published_at, i.summary, i.tech, i.seen_at, i.read_at
		FROM feed_item i JOIN source s ON s.id = i.source_id`
	var where []string
	var args []any
	if !since.IsZero() {
		where = append(where, when+` >= ?`)
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	if unreadOnly {
		where = append(where, `i.read_at = ''`)
	}
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY ` + when + ` DESC, i.id`
	rows, err := r.s.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the feed items: %w", err)
	}
	defer rows.Close()
	out := []listed{}
	for rows.Next() {
		var l listed
		var srcTech, tech string
		if err := rows.Scan(&l.ID, &l.SourceID, &l.SourceKey, &l.SourceName, &srcTech, &l.GUID, &l.Title, &l.URL,
			&l.PublishedAt, &l.Summary, &tech, &l.SeenAt, &l.ReadAt); err != nil {
			return nil, fmt.Errorf("cannot read the feed items: %w", err)
		}
		if json.Unmarshal([]byte(tech), &l.Tech) != nil || l.Tech == nil {
			l.Tech = []string{}
		}
		_ = json.Unmarshal([]byte(srcTech), &l.sourceTech)
		out = append(out, l)
	}
	return out, rows.Err()
}

// List returns the items of the existing sources counted from since (zero: all), only the unread
// ones with unreadOnly, newest first.
func (r *Repo) List(ctx context.Context, since time.Time, unreadOnly bool) ([]Item, error) {
	ls, err := r.list(ctx, since, unreadOnly)
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Item)
	}
	return out, nil
}

// ListToRead is List restricted to the items to read for tech (the declared
// technologies): their technologies or those of their source meet tech, or
// their title names one of them (MatchTech). An empty tech gives nothing.
func (r *Repo) ListToRead(ctx context.Context, since time.Time, unreadOnly bool, tech []string) ([]Item, error) {
	if len(tech) == 0 {
		return []Item{}, nil
	}
	ls, err := r.list(ctx, since, unreadOnly)
	if err != nil {
		return nil, err
	}
	out := []Item{}
	for _, l := range ls {
		title := l.Title
		if l.IsPageChange() {
			title = ""
		}
		all := append(slices.Clone(l.Tech), l.sourceTech...)
		if _, ok := MatchTech(title, all, tech); ok {
			out = append(out, l.Item)
		}
	}
	return out, nil
}

// Purge deletes the items of every source first seen more than Retention
// before now, and returns how many. It runs once per source update, so the
// items of a source that is no longer read go too.
func (r *Repo) Purge(ctx context.Context, now time.Time) (int, error) {
	cutoff := now.UTC().Add(-Retention).Format(time.RFC3339)
	res, err := r.s.DB().ExecContext(ctx, `DELETE FROM feed_item WHERE seen_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cannot purge the old feed items: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkRead marks the item id read at at; an item already read keeps its
// date. An unknown id is ErrItemNotFound.
func (r *Repo) MarkRead(ctx context.Context, id string, at time.Time) error {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE feed_item SET read_at = ? WHERE id = ? AND read_at = ''`,
		at.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("cannot mark the item as read: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	switch err := r.s.DB().QueryRowContext(ctx, `SELECT 1 FROM feed_item WHERE id = ?`, id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrItemNotFound
	case err != nil:
		return fmt.Errorf("cannot mark the item as read: %w", err)
	}
	return nil
}

// MarkAllRead marks every unread item read at at and returns how many.
func (r *Repo) MarkAllRead(ctx context.Context, at time.Time) (int, error) {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE feed_item SET read_at = ? WHERE read_at = ''`, at.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("cannot mark the items as read: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
