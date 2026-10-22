package project

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Repo reads and writes the project table.
type Repo struct {
	s *store.Store

	// DefaultClassification is used when a project is added without one.
	// Empty means the strictest level, sensitive.
	DefaultClassification policy.Classification

	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, entropy: ulid.Monotonic(rand.Reader, 0)}
}

const cols = `id, name, source_type, path, classification, fix_level, test_cmd, install_cmd, active, created_at`

func validClassification(c policy.Classification) bool {
	switch c {
	case policy.ClassPublic, policy.ClassInternal, policy.ClassConfidential, policy.ClassSensitive, policy.ClassHealth:
		return true
	}
	return false
}

// Add validates and stores p. Zero Classification, SourceType and an unset
// FixLevel (1) take their defaults. Active is always true on creation.
func (r *Repo) Add(ctx context.Context, p Project) (Project, error) {
	if strings.TrimSpace(p.Name) == "" {
		return Project{}, ErrEmptyName
	}
	if p.SourceType == "" {
		p.SourceType = SourceLocalPath
	}
	if p.SourceType != SourceLocalPath {
		return Project{}, fmt.Errorf("%w %q", ErrInvalidSourceType, p.SourceType)
	}
	if p.Classification == "" {
		p.Classification = r.DefaultClassification
		if p.Classification == "" {
			p.Classification = policy.ClassSensitive
		}
	}
	if !validClassification(p.Classification) {
		return Project{}, fmt.Errorf("%w %q", ErrInvalidClassification, p.Classification)
	}
	if p.FixLevel == 0 && !p.FixLevelSet {
		p.FixLevel = 1
	}
	if p.FixLevel < 0 || p.FixLevel > 3 {
		return Project{}, fmt.Errorf("%w (got %d)", ErrInvalidFixLevel, p.FixLevel)
	}
	if !filepath.IsAbs(p.Path) {
		return Project{}, fmt.Errorf("%w: %s", ErrNotADirectory, p.Path)
	}
	p.Path = filepath.Clean(p.Path)
	if fi, err := os.Stat(p.Path); err != nil || !fi.IsDir() {
		return Project{}, fmt.Errorf("%w: %s", ErrNotADirectory, p.Path)
	}
	p.Active = true

	var one int
	err := r.s.DB().QueryRowContext(ctx, `SELECT 1 FROM project WHERE name = ?`, p.Name).Scan(&one)
	if err == nil {
		return Project{}, fmt.Errorf("%w: %s", ErrDuplicateName, p.Name)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Project{}, fmt.Errorf("cannot read the project list: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	r.mu.Lock()
	id, err := ulid.New(ulid.Timestamp(now), r.entropy)
	r.mu.Unlock()
	if err != nil {
		return Project{}, fmt.Errorf("cannot create a project id: %w", err)
	}
	p.ID, p.CreatedAt = id.String(), now
	if err := r.insert(ctx, p); err != nil {
		return Project{}, err
	}
	return p, nil
}

func (r *Repo) insert(ctx context.Context, p Project) error {
	active := 0
	if p.Active {
		active = 1
	}
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO project (`+cols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.SourceType, p.Path, string(p.Classification), p.FixLevel,
		p.TestCmd, p.InstallCmd, active, p.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s", ErrDuplicateName, p.Name)
		}
		return fmt.Errorf("cannot save the project: %w", err)
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scan(s scanner) (Project, error) {
	var p Project
	var class, created string
	var active int
	if err := s.Scan(&p.ID, &p.Name, &p.SourceType, &p.Path, &class, &p.FixLevel, &p.TestCmd, &p.InstallCmd, &active, &created); err != nil {
		return Project{}, err
	}
	p.Classification = policy.Classification(class)
	p.Active = active != 0
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return Project{}, fmt.Errorf("project %s has an unreadable creation date %q: %w", p.Name, created, err)
	}
	p.CreatedAt = t
	return p, nil
}

// List returns all projects ordered by name.
func (r *Repo) List(ctx context.Context) ([]Project, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+cols+` FROM project ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("cannot read the project list: %w", err)
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get finds a project by id, then by name.
func (r *Repo) Get(ctx context.Context, nameOrID string) (Project, error) {
	for _, col := range []string{"id", "name"} {
		p, err := scan(r.s.DB().QueryRowContext(ctx, `SELECT `+cols+` FROM project WHERE `+col+` = ?`, nameOrID))
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Project{}, err
		}
	}
	return Project{}, fmt.Errorf("%w: %s", ErrNotFound, nameOrID)
}

// Remove deletes the project row. Scans and findings are removed by a later task.
func (r *Repo) Remove(ctx context.Context, nameOrID string) error {
	p, err := r.Get(ctx, nameOrID)
	if err != nil {
		return err
	}
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM project WHERE id = ?`, p.ID); err != nil {
		return fmt.Errorf("cannot remove the project: %w", err)
	}
	return nil
}
