package project

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
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

const cols = `id, name, source_type, path, classification, fix_level, test_cmd, install_cmd, active, created_at, core_packages, risk_overrides, exclude, tech, tech_auto`

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
	if err := normalizeExtras(&p); err != nil {
		return Project{}, err
	}

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
	core, err := json.Marshal(p.CorePackages)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	over, err := json.Marshal(p.RiskOverrides)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	exclude, err := json.Marshal(p.Exclude)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	tech, techAuto, err := marshalTech(p)
	if err != nil {
		return err
	}
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO project (`+cols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.SourceType, p.Path, string(p.Classification), p.FixLevel,
		p.TestCmd, p.InstallCmd, active, p.CreatedAt.UTC().Format(time.RFC3339), string(core), string(over), string(exclude),
		tech, techAuto)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: %s", ErrDuplicateName, p.Name)
		}
		return fmt.Errorf("cannot save the project: %w", err)
	}
	return nil
}

// marshalTech encodes the two technology lists as JSON text.
func marshalTech(p Project) (string, string, error) {
	tech, err := json.Marshal(p.Tech)
	if err != nil {
		return "", "", fmt.Errorf("cannot save the project: %w", err)
	}
	auto, err := json.Marshal(p.TechAuto)
	if err != nil {
		return "", "", fmt.Errorf("cannot save the project: %w", err)
	}
	return string(tech), string(auto), nil
}

type scanner interface{ Scan(...any) error }

func scan(s scanner) (Project, error) {
	var p Project
	var class, created, core, over, exclude, tech, techAuto string
	var active int
	if err := s.Scan(&p.ID, &p.Name, &p.SourceType, &p.Path, &class, &p.FixLevel, &p.TestCmd, &p.InstallCmd, &active, &created, &core, &over, &exclude, &tech, &techAuto); err != nil {
		return Project{}, err
	}
	p.Classification = policy.Classification(class)
	p.CorePackages, p.RiskOverrides = []string{}, map[string]int{}
	if err := json.Unmarshal([]byte(core), &p.CorePackages); err != nil {
		return Project{}, fmt.Errorf("project %s has unreadable core packages %q: %w", p.Name, core, err)
	}
	if err := json.Unmarshal([]byte(over), &p.RiskOverrides); err != nil {
		return Project{}, fmt.Errorf("project %s has unreadable risk overrides %q: %w", p.Name, over, err)
	}
	p.Exclude = []string{}
	if err := json.Unmarshal([]byte(exclude), &p.Exclude); err != nil {
		return Project{}, fmt.Errorf("project %s has an unreadable list of excluded folders %q: %w", p.Name, exclude, err)
	}
	if err := json.Unmarshal([]byte(tech), &p.Tech); err != nil {
		return Project{}, fmt.Errorf("project %s has an unreadable list of technologies %q: %w", p.Name, tech, err)
	}
	if err := json.Unmarshal([]byte(techAuto), &p.TechAuto); err != nil {
		return Project{}, fmt.Errorf("project %s has an unreadable list of detected technologies %q: %w", p.Name, techAuto, err)
	}
	if p.Tech == nil {
		p.Tech = []string{}
	}
	if p.TechAuto == nil {
		p.TechAuto = []string{}
	}
	_ = normalizeExtras(&p) // a stored JSON null becomes an empty value; unknown stored keys are left as they are
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

// Remove deactivates a project: it stays in the list with Active false and
// keeps its scans and findings (history is never lost by a plain remove).
// Removing an inactive project again is a no-op. It returns the project as
// it was before the call.
func (r *Repo) Remove(ctx context.Context, nameOrID string) (Project, error) {
	p, err := r.Get(ctx, nameOrID)
	if err != nil {
		return Project{}, err
	}
	if _, err := r.s.DB().ExecContext(ctx, `UPDATE project SET active = 0 WHERE id = ?`, p.ID); err != nil {
		return p, fmt.Errorf("cannot deactivate the project: %w", err)
	}
	return p, nil
}

// Purge deletes a project and its whole history (decisions, findings, scan manifests,
// scans, then the project row) in one transaction: either everything goes or
// nothing does. It returns the project as it was before the call.
func (r *Repo) Purge(ctx context.Context, nameOrID string) (Project, error) {
	p, err := r.Get(ctx, nameOrID)
	if err != nil {
		return Project{}, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return p, fmt.Errorf("cannot purge the project: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM decision WHERE project_id = ?`,
		`DELETE FROM analysis WHERE finding_id IN (SELECT id FROM finding WHERE project_id = ?)`,
		`DELETE FROM finding WHERE project_id = ?`,
		`DELETE FROM scan_manifest WHERE scan_id IN (SELECT id FROM scan WHERE project_id = ?)`,
		`DELETE FROM scan WHERE project_id = ?`,
		`DELETE FROM project WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, p.ID); err != nil {
			return p, fmt.Errorf("cannot purge the project: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return p, fmt.Errorf("cannot purge the project: %w", err)
	}
	return p, nil
}

// Update rewrites the editable fields of p (found by ID): classification,
// fix level, commands, core packages, risk overrides, excluded folders and
// technologies (declared and detected). Values are validated like in Add.
func (r *Repo) Update(ctx context.Context, p Project) error {
	if !validClassification(p.Classification) {
		return fmt.Errorf("%w %q", ErrInvalidClassification, p.Classification)
	}
	if p.FixLevel < 0 || p.FixLevel > 3 {
		return fmt.Errorf("%w (got %d)", ErrInvalidFixLevel, p.FixLevel)
	}
	if err := normalizeExtras(&p); err != nil {
		return err
	}
	core, err := json.Marshal(p.CorePackages)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	over, err := json.Marshal(p.RiskOverrides)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	exclude, err := json.Marshal(p.Exclude)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	tech, techAuto, err := marshalTech(p)
	if err != nil {
		return err
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE project SET classification = ?, fix_level = ?, test_cmd = ?, install_cmd = ?,
		core_packages = ?, risk_overrides = ?, exclude = ?, tech = ?, tech_auto = ? WHERE id = ?`,
		string(p.Classification), p.FixLevel, p.TestCmd, p.InstallCmd, string(core), string(over), string(exclude), tech, techAuto, p.ID)
	if err != nil {
		return fmt.Errorf("cannot save the project: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, p.ID)
	}
	return nil
}
