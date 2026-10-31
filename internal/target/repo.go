package target

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

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Repo reads and writes the target tables.
type Repo struct {
	s *store.Store

	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, entropy: ulid.Monotonic(rand.Reader, 0)}
}

const cols = `id, name, host, port, ssh_user, alias, host_key, kind, env, classification, fix_level, check_interval_s,
	preprod_id, executor, sudo, site_url, auto_config, active, last_check_at, created_at`

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("unreadable date %q in the server tables: %w", s, err)
	}
	return t, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func validClassification(c policy.Classification) bool {
	switch c {
	case policy.ClassPublic, policy.ClassInternal, policy.ClassConfidential, policy.ClassSensitive, policy.ClassHealth:
		return true
	}
	return false
}

// normalize checks t and fills the defaults: port 22, executor user, sudo
// none, env prod, classification health for an hds server and sensitive
// otherwise. A server of kind hds cannot have another classification.
func normalize(t *Target) error {
	if strings.TrimSpace(t.Name) == "" {
		return ErrEmptyName
	}
	if strings.TrimSpace(t.Host) == "" {
		return ErrEmptyHost
	}
	if t.Port == 0 {
		t.Port = 22
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("%w (got %d)", ErrInvalidPort, t.Port)
	}
	switch t.Kind {
	case KindHDS, KindVPS, KindShared:
	default:
		return fmt.Errorf("%w %q", ErrInvalidKind, t.Kind)
	}
	if t.Env == "" {
		t.Env = EnvProd
	}
	switch t.Env {
	case EnvProd, EnvPreprod, EnvDev:
	default:
		return fmt.Errorf("%w %q", ErrInvalidEnv, t.Env)
	}
	if t.Executor == "" {
		t.Executor = ExecUser
	}
	if t.Executor != ExecUser && t.Executor != ExecMichel {
		return fmt.Errorf("%w %q", ErrInvalidExecutor, t.Executor)
	}
	if t.Sudo == "" {
		t.Sudo = SudoNone
	}
	if t.Sudo != SudoNone && t.Sudo != SudoNopasswd {
		return fmt.Errorf("%w %q", ErrInvalidSudo, t.Sudo)
	}
	if t.FixLevel < 0 || t.FixLevel > 3 {
		return fmt.Errorf("%w (got %d)", ErrInvalidFixLevel, t.FixLevel)
	}
	if t.CheckInterval < 0 {
		t.CheckInterval = ManualOnly
	}
	if t.Kind == KindHDS {
		if t.Classification != "" && t.Classification != policy.ClassHealth {
			return ErrHDSIsHealth
		}
		t.Classification = policy.ClassHealth
	}
	if t.Classification == "" {
		t.Classification = policy.ClassSensitive
	}
	if !validClassification(t.Classification) {
		return fmt.Errorf("%w %q", ErrInvalidClass, t.Classification)
	}
	return nil
}

// Add validates and stores t. ID, Active and CreatedAt are set here. A zero
// FixLevel stays 0 and a zero CheckInterval is stored as 0 (Due counts it
// as DefaultCheckInterval); a negative one is stored as ManualOnly.
func (r *Repo) Add(ctx context.Context, t Target) (Target, error) {
	if err := normalize(&t); err != nil {
		return Target{}, err
	}
	var one int
	err := r.s.DB().QueryRowContext(ctx, `SELECT 1 FROM target WHERE name = ?`, t.Name).Scan(&one)
	if err == nil {
		return Target{}, fmt.Errorf("%w: %s", ErrDuplicateName, t.Name)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Target{}, fmt.Errorf("cannot read the server list: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r.mu.Lock()
	id, err := ulid.New(ulid.Timestamp(now), r.entropy)
	r.mu.Unlock()
	if err != nil {
		return Target{}, fmt.Errorf("cannot create a server id: %w", err)
	}
	t.ID, t.Active, t.CreatedAt = id.String(), true, now
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO target (`+cols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Name, t.Host, t.Port, t.User, t.Alias, t.HostKey, string(t.Kind), string(t.Env), string(t.Classification),
		t.FixLevel, int64(t.CheckInterval/time.Second), t.PreprodID, string(t.Executor), string(t.Sudo), t.SiteURL,
		boolInt(t.AutoConfig), boolInt(t.Active), ts(t.LastCheckAt), ts(t.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return Target{}, fmt.Errorf("%w: %s", ErrDuplicateName, t.Name)
		}
		return Target{}, fmt.Errorf("cannot save the server: %w", err)
	}
	return t, nil
}

type scanner interface{ Scan(...any) error }

func scanTarget(s scanner) (Target, error) {
	var t Target
	var kind, env, class, exec, sudo, last, created string
	var interval int64
	var auto, active int
	if err := s.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.User, &t.Alias, &t.HostKey, &kind, &env, &class, &t.FixLevel, &interval,
		&t.PreprodID, &exec, &sudo, &t.SiteURL, &auto, &active, &last, &created); err != nil {
		return Target{}, err
	}
	t.Kind, t.Env, t.Classification, t.Executor, t.Sudo = Kind(kind), Env(env), policy.Classification(class), Executor(exec), SudoMode(sudo)
	t.CheckInterval = time.Duration(interval) * time.Second
	t.AutoConfig, t.Active = auto != 0, active != 0
	var err error
	if t.LastCheckAt, err = parseTime(last); err != nil {
		return Target{}, err
	}
	if t.CreatedAt, err = parseTime(created); err != nil {
		return Target{}, err
	}
	return t, nil
}

// Get returns the server whose id or name is idOrName.
func (r *Repo) Get(ctx context.Context, idOrName string) (Target, error) {
	t, err := scanTarget(r.s.DB().QueryRowContext(ctx, `SELECT `+cols+` FROM target WHERE id = ? OR name = ? ORDER BY CASE WHEN id = ? THEN 0 ELSE 1 END LIMIT 1`,
		idOrName, idOrName, idOrName))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, fmt.Errorf("%w: %s", ErrNotFound, idOrName)
	}
	if err != nil {
		return Target{}, fmt.Errorf("cannot read the server: %w", err)
	}
	return t, nil
}

func (r *Repo) query(ctx context.Context, q string, args ...any) ([]Target, error) {
	rows, err := r.s.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the servers: %w", err)
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// List returns every server, by name.
func (r *Repo) List(ctx context.Context) ([]Target, error) {
	return r.query(ctx, `SELECT `+cols+` FROM target ORDER BY name`)
}

// Update rewrites the editable fields of t (found by ID), validated like in
// Add. The name, the creation date and the host key are not touched here (see
// SetHostKey).
func (r *Repo) Update(ctx context.Context, t Target) error {
	if err := normalize(&t); err != nil {
		return err
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE target SET host = ?, port = ?, ssh_user = ?, alias = ?, kind = ?, env = ?,
		classification = ?, fix_level = ?, check_interval_s = ?, preprod_id = ?, executor = ?, sudo = ?, site_url = ?,
		auto_config = ?, active = ?, last_check_at = ? WHERE id = ?`,
		t.Host, t.Port, t.User, t.Alias, string(t.Kind), string(t.Env), string(t.Classification), t.FixLevel,
		int64(t.CheckInterval/time.Second), t.PreprodID, string(t.Executor), string(t.Sudo), t.SiteURL,
		boolInt(t.AutoConfig), boolInt(t.Active), ts(t.LastCheckAt), t.ID)
	if err != nil {
		return fmt.Errorf("cannot save the server: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, t.ID)
	}
	return nil
}

// SetHostKey stores the fingerprint of the server's host key.
func (r *Repo) SetHostKey(ctx context.Context, id, fp string) error {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE target SET host_key = ? WHERE id = ?`, fp, id)
	if err != nil {
		return fmt.Errorf("cannot save the host key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// Remove deletes a server with its links and its stored inventories. Its
// findings and fix attempts stay in their tables.
func (r *Repo) Remove(ctx context.Context, id string) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot remove the server: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM target_project WHERE target_id = ?`,
		`DELETE FROM target_inventory WHERE target_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("cannot remove the server: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM target WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("cannot remove the server: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return tx.Commit()
}

// IsTargetID tells whether id is the id of a server. Reads that take an id
// which may be a project's or a server's use it to never mix the two.
func (r *Repo) IsTargetID(ctx context.Context, id string) bool {
	if id == "" {
		return false
	}
	var one int
	return r.s.DB().QueryRowContext(ctx, `SELECT 1 FROM target WHERE id = ?`, id).Scan(&one) == nil
}

// Link ties a server to a project; linking the same pair again replaces the
// remote directory.
func (r *Repo) Link(ctx context.Context, l Link) error {
	if !r.IsTargetID(ctx, l.TargetID) {
		return fmt.Errorf("%w: %s", ErrNotFound, l.TargetID)
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot link the server: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM target_project WHERE target_id = ? AND project_id = ?`, l.TargetID, l.ProjectID); err != nil {
		return fmt.Errorf("cannot link the server: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO target_project (target_id, project_id, remote_dir) VALUES (?,?,?)`,
		l.TargetID, l.ProjectID, l.RemoteDir); err != nil {
		return fmt.Errorf("cannot link the server: %w", err)
	}
	return tx.Commit()
}

// Unlink removes the link between a server and a project, if any.
func (r *Repo) Unlink(ctx context.Context, targetID, projectID string) error {
	if _, err := r.s.DB().ExecContext(ctx, `DELETE FROM target_project WHERE target_id = ? AND project_id = ?`, targetID, projectID); err != nil {
		return fmt.Errorf("cannot unlink the server: %w", err)
	}
	return nil
}

// Links returns the projects linked to a server, by project id.
func (r *Repo) Links(ctx context.Context, targetID string) ([]Link, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT target_id, project_id, remote_dir FROM target_project WHERE target_id = ? ORDER BY project_id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the links: %w", err)
	}
	defer rows.Close()
	out := []Link{}
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.TargetID, &l.ProjectID, &l.RemoteDir); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// TargetsOfProject returns the servers linked to a project, by name.
func (r *Repo) TargetsOfProject(ctx context.Context, projectID string) ([]Target, error) {
	return r.query(ctx, `SELECT `+cols+` FROM target WHERE id IN (SELECT target_id FROM target_project WHERE project_id = ?) ORDER BY name`, projectID)
}

// SaveInventory stores inv as the inventory of its server at inv.At; an
// inventory already stored at the same second is replaced.
func (r *Repo) SaveInventory(ctx context.Context, inv Inventory) error {
	if !r.IsTargetID(ctx, inv.TargetID) {
		return fmt.Errorf("%w: %s", ErrNotFound, inv.TargetID)
	}
	body, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("cannot save the inventory: %w", err)
	}
	at := inv.At.UTC().Truncate(time.Second).Format(time.RFC3339)
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the inventory: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM target_inventory WHERE target_id = ? AND at = ?`, inv.TargetID, at); err != nil {
		return fmt.Errorf("cannot save the inventory: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO target_inventory (target_id, at, body) VALUES (?,?,?)`, inv.TargetID, at, string(body)); err != nil {
		return fmt.Errorf("cannot save the inventory: %w", err)
	}
	return tx.Commit()
}

// LatestInventory returns the newest stored inventory of a server; ok is
// false when there is none.
func (r *Repo) LatestInventory(ctx context.Context, targetID string) (Inventory, bool, error) {
	var body string
	err := r.s.DB().QueryRowContext(ctx, `SELECT body FROM target_inventory WHERE target_id = ? ORDER BY at DESC LIMIT 1`, targetID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return Inventory{}, false, nil
	}
	if err != nil {
		return Inventory{}, false, fmt.Errorf("cannot read the inventory: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal([]byte(body), &inv); err != nil {
		return Inventory{}, false, fmt.Errorf("the stored inventory of server %s is unreadable: %w", targetID, err)
	}
	return inv, true, nil
}

// SetLastCheckAt records when the last check of a server succeeded.
func (r *Repo) SetLastCheckAt(ctx context.Context, id string, at time.Time) error {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE target SET last_check_at = ? WHERE id = ?`, ts(at), id)
	if err != nil {
		return fmt.Errorf("cannot save the date of the check: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

// Due returns the active servers whose last check is older than their check
// interval (never checked counts as due), by name. A zero interval counts as
// DefaultCheckInterval; a ManualOnly (negative) server is never due.
func (r *Repo) Due(ctx context.Context, now time.Time) ([]Target, error) {
	all, err := r.query(ctx, `SELECT `+cols+` FROM target WHERE active = 1 AND check_interval_s >= 0 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []Target{}
	for _, t := range all {
		if t.CheckInterval < 0 {
			continue
		}
		every := t.CheckInterval
		if every == 0 {
			every = DefaultCheckInterval
		}
		if t.LastCheckAt.IsZero() || !t.LastCheckAt.Add(every).After(now) {
			out = append(out, t)
		}
	}
	return out, nil
}
