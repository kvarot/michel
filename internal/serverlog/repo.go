package serverlog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
	"github.com/oklog/ulid/v2"
)

// Errors of the repository.
var (
	ErrNotFound        = errors.New("server log entry not found")
	ErrInvalidFormat   = errors.New("unknown log format")
	ErrInvalidPath     = errors.New("invalid log path")
	ErrInvalidSettings = errors.New("invalid log settings")
	ErrInvalidRecord   = errors.New("invalid log record")
	ErrInvalidNote     = errors.New("invalid log note")
)

// Repo reads and writes the server log tables.
//
// text_enc holds Record.Text masked, capped and encrypted by sealText (see
// privacy.go); the signatures of Repo stay plain. A raw log line never
// reaches Repo.
type Repo struct {
	s *store.Store

	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewRepo returns a Repo on s.
func NewRepo(s *store.Store) *Repo {
	return &Repo{s: s, entropy: ulid.Monotonic(rand.Reader, 0)}
}

// querier is what a *sql.DB and a *sql.Tx share.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

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
		return time.Time{}, fmt.Errorf("unreadable date %q in the server log tables: %w", s, err)
	}
	return t, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (r *Repo) newID(now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, err := ulid.New(ulid.Timestamp(now), r.entropy)
	if err != nil {
		return "", fmt.Errorf("cannot create an id: %w", err)
	}
	return id.String(), nil
}

func validLevel(l Level) bool {
	for _, v := range Levels {
		if l == v {
			return true
		}
	}
	return false
}

func validRoute(r Route) bool {
	return r == RouteImmediate || r == RouteDigest || r == RouteIgnored
}

func validStatus(s Status) bool {
	switch s {
	case StatusNew, StatusSeen, StatusResolved, StatusReopened, StatusIgnored:
		return true
	}
	return false
}

func validNoteKind(k string) bool {
	switch k {
	case NoteGap, NoteSkipped, NoteRotated, NoteUnseen, NoteRejected, NoteTooManyFiles:
		return true
	}
	return false
}

// ---- sources ----

const sourceCols = `id, target_id, path, format, level_field, channel_field, pattern, active, created_at`

// checkSource refuses an unknown format and any path ValidatePath refuses, the
// one validator of a declared path. The errors never repeat the path.
func checkSource(s Source) error {
	switch s.Format {
	case FormatPHP, FormatPostgres, FormatMonolog, FormatJSON, FormatText:
	default:
		return fmt.Errorf("%w %q", ErrInvalidFormat, s.Format)
	}
	return ValidatePath(s.Path)
}

// AddSource validates and stores s. ID and CreatedAt are set here.
func (r *Repo) AddSource(ctx context.Context, s Source) (Source, error) {
	if strings.TrimSpace(s.TargetID) == "" {
		return Source{}, fmt.Errorf("%w: no server", ErrNotFound)
	}
	if err := checkSource(s); err != nil {
		return Source{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	id, err := r.newID(now)
	if err != nil {
		return Source{}, err
	}
	s.ID, s.CreatedAt = id, now
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO log_source (`+sourceCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ID, s.TargetID, s.Path, string(s.Format), s.LevelField, s.ChannelField, s.Pattern, boolInt(s.Active), ts(s.CreatedAt))
	if err != nil {
		return Source{}, fmt.Errorf("cannot save the log source: %w", err)
	}
	return s, nil
}

// UpdateSource rewrites the path, format, fields and active flag of the
// source with s.ID. The server and the creation date do not change.
func (r *Repo) UpdateSource(ctx context.Context, s Source) error {
	if err := checkSource(s); err != nil {
		return err
	}
	res, err := r.s.DB().ExecContext(ctx, `UPDATE log_source SET path = ?, format = ?, level_field = ?, channel_field = ?, pattern = ?, active = ? WHERE id = ?`,
		s.Path, string(s.Format), s.LevelField, s.ChannelField, s.Pattern, boolInt(s.Active), s.ID)
	if err != nil {
		return fmt.Errorf("cannot save the log source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: source %s", ErrNotFound, s.ID)
	}
	return nil
}

// DeleteSource removes a source from Michel, with its positions, errors,
// counts and notes. Nothing is touched on the server.
func (r *Repo) DeleteSource(ctx context.Context, id string) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot delete the log source: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM log_bucket WHERE signature_id IN (SELECT id FROM log_signature WHERE source_id = ?)`,
		`DELETE FROM log_read WHERE signature_id IN (SELECT id FROM log_signature WHERE source_id = ?)`,
		`DELETE FROM log_signature WHERE source_id = ?`,
		`DELETE FROM log_cursor WHERE source_id = ?`,
		`DELETE FROM log_unseen WHERE source_id = ?`,
		`DELETE FROM log_failure WHERE source_id = ?`,
		`DELETE FROM log_note WHERE source_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("cannot delete the log source: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM log_source WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("cannot delete the log source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: source %s", ErrNotFound, id)
	}
	return tx.Commit()
}

// Sources lists the sources of a server, oldest first.
func (r *Repo) Sources(ctx context.Context, targetID string) ([]Source, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+sourceCols+`, path_at FROM log_source WHERE target_id = ? ORDER BY created_at, id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the log sources: %w", err)
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		var format, created, pathAt string
		var active int
		if err := rows.Scan(&s.ID, &s.TargetID, &s.Path, &format, &s.LevelField, &s.ChannelField, &s.Pattern, &active, &created, &pathAt); err != nil {
			return nil, fmt.Errorf("cannot read the log sources: %w", err)
		}
		s.Format, s.Active = Format(format), active != 0
		if s.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if s.PathAt, err = parseTime(pathAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---- cursors ----

// Cursors lists the read positions of a source, by file.
func (r *Repo) Cursors(ctx context.Context, sourceID string) ([]Cursor, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT source_id, file, file_id, offset_bytes, read_at FROM log_cursor WHERE source_id = ? ORDER BY file`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the log positions: %w", err)
	}
	defer rows.Close()
	var out []Cursor
	for rows.Next() {
		var c Cursor
		var at string
		if err := rows.Scan(&c.SourceID, &c.File, &c.FileID, &c.Offset, &at); err != nil {
			return nil, fmt.Errorf("cannot read the log positions: %w", err)
		}
		if c.ReadAt, err = parseTime(at); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveCursors stores the given positions, replacing those of the same source
// and file. Positions of other files are left alone.
func (r *Repo) SaveCursors(ctx context.Context, cs []Cursor) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log positions: %w", err)
	}
	defer tx.Rollback()
	for _, c := range cs {
		_, err := tx.ExecContext(ctx, `INSERT INTO log_cursor (source_id, file, file_id, offset_bytes, read_at) VALUES (?,?,?,?,?)
			ON CONFLICT (source_id, file) DO UPDATE SET file_id = excluded.file_id, offset_bytes = excluded.offset_bytes, read_at = excluded.read_at`,
			c.SourceID, c.File, c.FileID, c.Offset, ts(c.ReadAt))
		if err != nil {
			return fmt.Errorf("cannot save the log positions: %w", err)
		}
	}
	return tx.Commit()
}

// ---- settings ----

func checkSettings(s Settings) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidSettings, fmt.Sprintf(format, a...))
	}
	switch {
	case strings.TrimSpace(s.TargetID) == "":
		return bad("no server")
	case s.Interval != ManualInterval && (s.Interval < MinInterval || s.Interval > MaxInterval):
		return bad("the reading interval must be manual or between 1 minute and 24 hours")
	case s.RetentionDays < MinRetentionDays || s.RetentionDays > MaxRetentionDays:
		return bad("the retention must be between %d and %d days (got %d)", MinRetentionDays, MaxRetentionDays, s.RetentionDays)
	case s.AlertText && !s.StoreText:
		return bad("the text of alerts needs the text to be kept")
	case s.ResolveAfter <= 0:
		return bad("the delay before an error counts as resolved must be positive")
	case time.Duration(s.RetentionDays)*24*time.Hour < s.ResolveAfter:
		return bad("the retention cannot be shorter than the delay before an error counts as resolved")
	case s.ReadCap <= 0 || s.ReadCap > MaxReadCap:
		return bad("the read size cap must be positive and at most %d MiB", MaxReadCap>>20)
	case s.ReadTimeout <= 0 || s.ReadTimeout > MaxReadTimeout:
		return bad("the read timeout must be positive and at most %d seconds", int(MaxReadTimeout/time.Second))
	case s.SpikeFactor < MinSpikeFactor || s.SpikeFactor > MaxSpikeFactor:
		return bad("the spike factor must be between %d and %d", MinSpikeFactor, MaxSpikeFactor)
	case s.SpikeMin < MinSpikeMin || s.SpikeMin > MaxSpikeMin:
		return bad("the spike minimum must be between %d and %d", MinSpikeMin, MaxSpikeMin)
	case s.MaxAlertsPerHour < 1:
		return bad("the alert cap per hour must be at least 1")
	}
	for _, l := range Levels {
		if !validRoute(s.Routes[l]) {
			return bad("no valid rule for %s errors", l)
		}
	}
	return nil
}

const settingsCols = `target_id, interval_s, store_text, alert_text, retention_days, resolve_after_s, read_cap, read_timeout_s,
	max_alerts_per_hour, sms, route_critical, route_error, route_warning, route_info, spike_factor, spike_min`

// Settings returns the log settings of a server: the saved ones, or the
// defaults for its environment when none were saved.
func (r *Repo) Settings(ctx context.Context, targetID string) (Settings, error) {
	var s Settings
	var interval, resolve, timeout int64
	var store, alert, sms int
	var rc, re, rw, ri string
	err := r.s.DB().QueryRowContext(ctx, `SELECT `+settingsCols+` FROM log_settings WHERE target_id = ?`, targetID).Scan(
		&s.TargetID, &interval, &store, &alert, &s.RetentionDays, &resolve, &s.ReadCap, &timeout, &s.MaxAlertsPerHour, &sms, &rc, &re, &rw, &ri, &s.SpikeFactor, &s.SpikeMin)
	if err == nil {
		s.Interval, s.ResolveAfter, s.ReadTimeout = time.Duration(interval)*time.Second, time.Duration(resolve)*time.Second, time.Duration(timeout)*time.Second
		s.StoreText, s.AlertText, s.SMS = store != 0, alert != 0, sms != 0
		s.Routes = map[Level]Route{LevelCritical: Route(rc), LevelError: Route(re), LevelWarning: Route(rw), LevelInfo: Route(ri)}
		return s, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Settings{}, fmt.Errorf("cannot read the log settings: %w", err)
	}
	var env string
	err = r.s.DB().QueryRowContext(ctx, `SELECT env FROM target WHERE id = ?`, targetID).Scan(&env)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, fmt.Errorf("%w: %s", target.ErrNotFound, targetID)
	}
	if err != nil {
		return Settings{}, fmt.Errorf("cannot read the server: %w", err)
	}
	s = DefaultSettings(target.Env(env))
	s.TargetID = targetID
	return s, nil
}

// settingsOrDefault is Settings, except that the data of a server that no
// longer exists gets the prod defaults, so that it still expires.
func (r *Repo) settingsOrDefault(ctx context.Context, targetID string) (Settings, error) {
	s, err := r.Settings(ctx, targetID)
	if errors.Is(err, target.ErrNotFound) {
		s = DefaultSettings(target.EnvProd)
		s.TargetID = targetID
		return s, nil
	}
	return s, err
}

// SaveSettings validates and stores s.
func (r *Repo) SaveSettings(ctx context.Context, s Settings) error {
	if err := checkSettings(s); err != nil {
		return err
	}
	_, err := r.s.DB().ExecContext(ctx, `INSERT INTO log_settings (`+settingsCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (target_id) DO UPDATE SET interval_s = excluded.interval_s, store_text = excluded.store_text, alert_text = excluded.alert_text,
			retention_days = excluded.retention_days, resolve_after_s = excluded.resolve_after_s, read_cap = excluded.read_cap,
			read_timeout_s = excluded.read_timeout_s, max_alerts_per_hour = excluded.max_alerts_per_hour, sms = excluded.sms,
			route_critical = excluded.route_critical, route_error = excluded.route_error, route_warning = excluded.route_warning, route_info = excluded.route_info,
			spike_factor = excluded.spike_factor, spike_min = excluded.spike_min`,
		s.TargetID, int64(s.Interval/time.Second), boolInt(s.StoreText), boolInt(s.AlertText), s.RetentionDays, int64(s.ResolveAfter/time.Second),
		s.ReadCap, int64(s.ReadTimeout/time.Second), s.MaxAlertsPerHour, boolInt(s.SMS),
		string(s.Routes[LevelCritical]), string(s.Routes[LevelError]), string(s.Routes[LevelWarning]), string(s.Routes[LevelInfo]), s.SpikeFactor, s.SpikeMin)
	if err != nil {
		return fmt.Errorf("cannot save the log settings: %w", err)
	}
	return nil
}

// ---- signatures ----

const sigCols = `id, target_id, source_id, level, type, location, channel, status, first_at, last_at, last_alert_at, total`

func scanSignature(s interface{ Scan(...any) error }) (Signature, error) {
	var g Signature
	var level, status, first, last, alert string
	if err := s.Scan(&g.ID, &g.TargetID, &g.SourceID, &level, &g.Type, &g.Location, &g.Channel, &status, &first, &last, &alert, &g.Total); err != nil {
		return Signature{}, err
	}
	g.Level, g.Status = Level(level), Status(status)
	var err error
	if g.FirstAt, err = parseTime(first); err != nil {
		return Signature{}, err
	}
	if g.LastAt, err = parseTime(last); err != nil {
		return Signature{}, err
	}
	if g.LastAlertAt, err = parseTime(alert); err != nil {
		return Signature{}, err
	}
	return g, nil
}

func loadSignature(ctx context.Context, q querier, id string) (Signature, error) {
	g, err := scanSignature(q.QueryRowContext(ctx, `SELECT `+sigCols+` FROM log_signature WHERE id = ?`, id))
	if err != nil {
		return Signature{}, fmt.Errorf("cannot read the log error: %w", err)
	}
	return g, nil
}

// Signatures lists the errors of a server, latest first.
func (r *Repo) Signatures(ctx context.Context, targetID string) ([]Signature, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+sigCols+` FROM log_signature WHERE target_id = ? ORDER BY last_at DESC, id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the log errors: %w", err)
	}
	defer rows.Close()
	var out []Signature
	for rows.Next() {
		g, err := scanSignature(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read the log errors: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetStatus sets the status of an error (seen, ignored...). An ignored error
// loses its text in the same statement: it keeps its row, never its text.
func (r *Repo) SetStatus(ctx context.Context, id string, st Status) error {
	if !validStatus(st) {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidRecord, st)
	}
	q := `UPDATE log_signature SET status = ? WHERE id = ?`
	if st == StatusIgnored {
		q = `UPDATE log_signature SET status = ?, text_enc = NULL WHERE id = ?`
	}
	res, err := r.s.DB().ExecContext(ctx, q, string(st), id)
	if err != nil {
		return fmt.Errorf("cannot save the log error: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: error %s", ErrNotFound, id)
	}
	return nil
}

func spikes(st Settings, cur, prev int64) bool {
	return cur >= st.SpikeMin && cur >= int64(st.SpikeFactor)*prev
}

// Apply adds records read on src. It returns the errors seen for the first
// time (fresh), those that came back after being resolved (reopened), and
// those whose count in an hour just reached SpikeFactor times the hour before
// (10 by default), with at least SpikeMin occurrences (100 by default) (spiked, with SpikeHour the latest hour that did). An
// ignored error is counted but never returned. The text of a record is stored
// only when the server settings allow it, and never takes part in the identity.
func (r *Repo) Apply(ctx context.Context, src Source, recs []Record, now time.Time) (fresh, reopened, spiked []Signature, err error) {
	for _, rc := range recs {
		if !validLevel(rc.Level) || rc.Count <= 0 {
			return nil, nil, nil, fmt.Errorf("%w: level %q, count %d", ErrInvalidRecord, rc.Level, rc.Count)
		}
	}
	st, err := r.Settings(ctx, src.TargetID)
	if err != nil {
		return nil, nil, nil, err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot save the log records: %w", err)
	}
	defer tx.Rollback()
	var freshIDs, reopenedIDs, spikedIDs []string
	spikeHours := map[string]time.Time{}
	has := func(l []string, id string) bool {
		for _, v := range l {
			if v == id {
				return true
			}
		}
		return false
	}
	for _, rc := range recs {
		id := SignatureID(src.ID, rc.Level, rc.Type, rc.Location, rc.Channel)
		hour := rc.Hour.UTC().Truncate(time.Hour)
		var text []byte
		if st.StoreText && rc.Text != "" {
			if text, err = sealText(rc.Text); err != nil {
				return nil, nil, nil, err
			}
		}
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM log_signature WHERE id = ?`, id).Scan(&status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, `INSERT INTO log_signature (`+sigCols+`, text_enc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				id, src.TargetID, src.ID, string(rc.Level), rc.Type, rc.Location, rc.Channel, string(StatusNew), ts(now), ts(now), "", rc.Count, text)
			freshIDs = append(freshIDs, id)
		case err == nil:
			newStatus := Status(status)
			if newStatus == StatusIgnored {
				text = nil // an ignored error keeps its row, never its text
			}
			if newStatus == StatusResolved {
				newStatus = StatusReopened
				reopenedIDs = append(reopenedIDs, id)
			}
			_, err = tx.ExecContext(ctx, `UPDATE log_signature SET status = ?, total = total + ?, last_at = ?, text_enc = COALESCE(?, text_enc) WHERE id = ?`,
				string(newStatus), rc.Count, ts(now), text, id)
			if err == nil && has(reopenedIDs, id) {
				_, err = tx.ExecContext(ctx, `UPDATE log_signature SET reopened_at = ? WHERE id = ?`, ts(now), id)
			}
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot save the log records: %w", err)
		}
		// What the digest counts: by the time Michel read it, once.
		if _, err := tx.ExecContext(ctx, `INSERT INTO log_read (signature_id, read_at, count) VALUES (?,?,?)
			ON CONFLICT (signature_id, read_at) DO UPDATE SET count = log_read.count + excluded.count`, id, ts(now), rc.Count); err != nil {
			return nil, nil, nil, fmt.Errorf("cannot save the log counts: %w", err)
		}
		var before, prev int64
		if err := tx.QueryRowContext(ctx, `SELECT count FROM log_bucket WHERE signature_id = ? AND hour = ?`, id, ts(hour)).Scan(&before); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil, fmt.Errorf("cannot read the log counts: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count FROM log_bucket WHERE signature_id = ? AND hour = ?`, id, ts(hour.Add(-time.Hour))).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil, fmt.Errorf("cannot read the log counts: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO log_bucket (signature_id, hour, count) VALUES (?,?,?)
			ON CONFLICT (signature_id, hour) DO UPDATE SET count = log_bucket.count + excluded.count`, id, ts(hour), rc.Count); err != nil {
			return nil, nil, nil, fmt.Errorf("cannot save the log counts: %w", err)
		}
		if !spikes(st, before, prev) && spikes(st, before+rc.Count, prev) && !has(freshIDs, id) && !has(reopenedIDs, id) {
			at, known := spikeHours[id]
			if !known {
				spikedIDs = append(spikedIDs, id)
			}
			if !known || hour.After(at) {
				spikeHours[id] = hour
			}
		}
	}
	load := func(ids []string) ([]Signature, error) {
		var out []Signature
		for _, id := range ids {
			g, err := loadSignature(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			if g.Status == StatusIgnored {
				continue
			}
			out = append(out, g)
		}
		return out, nil
	}
	if fresh, err = load(freshIDs); err != nil {
		return nil, nil, nil, err
	}
	if reopened, err = load(reopenedIDs); err != nil {
		return nil, nil, nil, err
	}
	if spiked, err = load(spikedIDs); err != nil {
		return nil, nil, nil, err
	}
	for i := range spiked {
		spiked[i].SpikeHour = spikeHours[spiked[i].ID]
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, fmt.Errorf("cannot save the log records: %w", err)
	}
	return fresh, reopened, spiked, nil
}

// Resolve marks as resolved the errors of the given sources of one server with
// no occurrence for its delay (ResolveAfter), except ignored ones. It returns
// them. Only a source that was just read can say so: another one, of this server
// or not, may simply not have been read, or have failed. No source: nothing.
func (r *Repo) Resolve(ctx context.Context, targetID string, now time.Time, sourceIDs []string) ([]Signature, error) {
	if len(sourceIDs) == 0 {
		return nil, nil
	}
	read := make(map[string]bool, len(sourceIDs))
	for _, id := range sourceIDs {
		read[id] = true
	}
	st, err := r.settingsOrDefault(ctx, targetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.s.DB().QueryContext(ctx, `SELECT id, last_at, source_id FROM log_signature WHERE target_id = ? AND status IN (?,?,?)`,
		targetID, string(StatusNew), string(StatusSeen), string(StatusReopened))
	if err != nil {
		return nil, fmt.Errorf("cannot read the log errors: %w", err)
	}
	type cand struct {
		id     string
		last   time.Time
		source string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		var last string
		if err := rows.Scan(&c.id, &last, &c.source); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot read the log errors: %w", err)
		}
		if c.last, err = parseTime(last); err != nil {
			rows.Close()
			return nil, err
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	var due []string
	for _, c := range cands {
		if read[c.source] && !now.Before(c.last.Add(st.ResolveAfter)) {
			due = append(due, c.id)
		}
	}
	if len(due) == 0 {
		return nil, nil
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the log errors: %w", err)
	}
	defer tx.Rollback()
	var out []Signature
	for _, id := range due {
		// The status is checked again: it may have changed since the read.
		res, err := tx.ExecContext(ctx, `UPDATE log_signature SET status = ? WHERE id = ? AND status IN (?,?,?)`,
			string(StatusResolved), id, string(StatusNew), string(StatusSeen), string(StatusReopened))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve the log errors: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		g, err := loadSignature(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot resolve the log errors: %w", err)
	}
	return out, nil
}

// ---- notes ----

// AddNote stores a note about what could not be read.
func (r *Repo) AddNote(ctx context.Context, n Note) error {
	if !validNoteKind(n.Kind) {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidNote, n.Kind)
	}
	id, err := r.newID(time.Now().UTC())
	if err != nil {
		return err
	}
	_, err = r.s.DB().ExecContext(ctx, `INSERT INTO log_note (id, target_id, source_id, kind, from_at, to_at, amount) VALUES (?,?,?,?,?,?,?)`,
		id, n.TargetID, n.SourceID, n.Kind, ts(n.From), ts(n.To), n.Amount)
	if err != nil {
		return fmt.Errorf("cannot save the log note: %w", err)
	}
	return nil
}

// Notes lists the notes of a server, oldest first.
func (r *Repo) Notes(ctx context.Context, targetID string) ([]Note, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT target_id, source_id, kind, from_at, to_at, amount FROM log_note WHERE target_id = ? ORDER BY to_at, id`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the log notes: %w", err)
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		var n Note
		var from, to string
		if err := rows.Scan(&n.TargetID, &n.SourceID, &n.Kind, &from, &to, &n.Amount); err != nil {
			return nil, fmt.Errorf("cannot read the log notes: %w", err)
		}
		if n.From, err = parseTime(from); err != nil {
			return nil, err
		}
		if n.To, err = parseTime(to); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- retention and erasure ----

// Purge applies the retention of every server at now: counts, notes and
// errors older than the retention go, except ignored errors, which keep
// their row (so that "do not warn me again" holds) without text.
func (r *Repo) Purge(ctx context.Context, now time.Time) error {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT target_id FROM log_signature UNION SELECT target_id FROM log_note UNION SELECT target_id FROM log_source`)
	if err != nil {
		return fmt.Errorf("cannot read the log servers: %w", err)
	}
	var targets []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("cannot read the log servers: %w", err)
		}
		targets = append(targets, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, tid := range targets {
		st, err := r.settingsOrDefault(ctx, tid)
		if err != nil {
			return err
		}
		if err := r.purgeTarget(ctx, tid, ts(now.Add(-time.Duration(st.RetentionDays)*24*time.Hour))); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) purgeTarget(ctx context.Context, targetID, cutoff string) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot purge the log data: %w", err)
	}
	defer tx.Rollback()
	ign := string(StatusIgnored)
	steps := []struct {
		q    string
		args []any
	}{
		// Counts of errors that expire, then old counts of the others.
		{`DELETE FROM log_bucket WHERE signature_id IN (SELECT id FROM log_signature WHERE target_id = ? AND last_at < ?)`, []any{targetID, cutoff}},
		{`DELETE FROM log_read WHERE signature_id IN (SELECT id FROM log_signature WHERE target_id = ? AND last_at < ?)`, []any{targetID, cutoff}},
		{`DELETE FROM log_read WHERE read_at < ? AND signature_id IN (SELECT id FROM log_signature WHERE target_id = ?)`, []any{cutoff, targetID}},
		{`DELETE FROM log_bucket WHERE hour < ? AND signature_id IN (SELECT id FROM log_signature WHERE target_id = ?)`, []any{cutoff, targetID}},
		// Ignored errors keep their row without text; the others go.
		{`UPDATE log_signature SET text_enc = NULL WHERE target_id = ? AND status = ? AND last_at < ?`, []any{targetID, ign, cutoff}},
		{`DELETE FROM log_signature WHERE target_id = ? AND status <> ? AND last_at < ?`, []any{targetID, ign, cutoff}},
		{`DELETE FROM log_note WHERE target_id = ? AND to_at < ?`, []any{targetID, cutoff}},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s.q, s.args...); err != nil {
			return fmt.Errorf("cannot purge the log data: %w", err)
		}
	}
	return tx.Commit()
}

// EraseTarget removes all log data of a server held by Michel: errors
// (ignored ones too), counts, positions and notes. The sources and the
// settings stay, and nothing is touched on the server.
func (r *Repo) EraseTarget(ctx context.Context, targetID string) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot erase the log data: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM log_bucket WHERE signature_id IN (SELECT id FROM log_signature WHERE target_id = ?)`,
		`DELETE FROM log_read WHERE signature_id IN (SELECT id FROM log_signature WHERE target_id = ?)`,
		`DELETE FROM log_signature WHERE target_id = ?`,
		`DELETE FROM log_cursor WHERE source_id IN (SELECT id FROM log_source WHERE target_id = ?)`,
		`DELETE FROM log_unseen WHERE source_id IN (SELECT id FROM log_source WHERE target_id = ?)`,
		`DELETE FROM log_failure WHERE target_id = ?`,
		`DELETE FROM log_note WHERE target_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, targetID); err != nil {
			return fmt.Errorf("cannot erase the log data: %w", err)
		}
	}
	return tx.Commit()
}

// EraseText removes the stored text of every error of a server, and returns
// how many rows held some.
func (r *Repo) EraseText(ctx context.Context, targetID string) (int64, error) {
	res, err := r.s.DB().ExecContext(ctx, `UPDATE log_signature SET text_enc = NULL WHERE target_id = ? AND text_enc IS NOT NULL`, targetID)
	if err != nil {
		return 0, fmt.Errorf("cannot erase the log text: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ---- what a pass needs ----

// MarkAlerted records that the errors ids were told to the user at at.
func (r *Repo) MarkAlerted(ctx context.Context, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log alerts: %w", err)
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE log_signature SET last_alert_at = ? WHERE id = ?`, ts(at), id); err != nil {
			return fmt.Errorf("cannot save the log alerts: %w", err)
		}
	}
	return tx.Commit()
}

// HourCount returns how many times an error was read in an hour.
func (r *Repo) HourCount(ctx context.Context, signatureID string, hour time.Time) (int64, error) {
	var n int64
	err := r.s.DB().QueryRowContext(ctx, `SELECT count FROM log_bucket WHERE signature_id = ? AND hour = ?`, signatureID, ts(hour.UTC().Truncate(time.Hour))).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("cannot read the log counts: %w", err)
	}
	return n, nil
}

// LastRead returns the latest date a source of the server was read (zero when
// none was).
func (r *Repo) LastRead(ctx context.Context, targetID string) (time.Time, error) {
	var at sql.NullString
	err := r.s.DB().QueryRowContext(ctx, `SELECT MAX(read_at) FROM log_cursor WHERE source_id IN (SELECT id FROM log_source WHERE target_id = ?)`, targetID).Scan(&at)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read the log positions: %w", err)
	}
	return parseTime(at.String)
}

// TouchCursors says that the source was read at at: every position of it is
// still good then, so its read date moves, files that did not change included.
// The date of the last read is what tells a gap from a quiet log. The files in
// except were not opened by this read (unseen): their date stays the day they
// were last read.
func (r *Repo) TouchCursors(ctx context.Context, sourceID string, at time.Time, except []string) error {
	skip := make(map[string]bool, len(except))
	for _, f := range except {
		skip[f] = true
	}
	cs, err := r.Cursors(ctx, sourceID)
	if err != nil {
		return err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log positions: %w", err)
	}
	defer tx.Rollback()
	for _, c := range cs {
		if skip[c.File] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE log_cursor SET read_at = ? WHERE source_id = ? AND file = ?`, ts(at), sourceID, c.File); err != nil {
			return fmt.Errorf("cannot save the log positions: %w", err)
		}
	}
	return tx.Commit()
}

// PruneCursors removes the positions of a source whose file is not in keep: the
// files that are gone, and the placeholder of an activation once real files
// are known.
func (r *Repo) PruneCursors(ctx context.Context, sourceID string, keep []string) error {
	have, err := r.Cursors(ctx, sourceID)
	if err != nil {
		return err
	}
	kept := make(map[string]bool, len(keep))
	for _, f := range keep {
		kept[f] = true
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log positions: %w", err)
	}
	defer tx.Rollback()
	for _, c := range have {
		if kept[c.File] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM log_cursor WHERE source_id = ? AND file = ?`, sourceID, c.File); err != nil {
			return fmt.Errorf("cannot save the log positions: %w", err)
		}
	}
	return tx.Commit()
}

// RecordState stores a note about something that lasts (a gap in the reading,
// a file that cannot be read, too many files) without a new row per pass: when
// the latest note of the same server, source and kind is the same period, it
// is extended to n.To and takes n.Amount. For a gap the same period means the
// same start; for the others, a note that reaches n.From.
func (r *Repo) RecordState(ctx context.Context, n Note) error {
	if !validNoteKind(n.Kind) {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidNote, n.Kind)
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log note: %w", err)
	}
	defer tx.Rollback()
	var id, from, to string
	err = tx.QueryRowContext(ctx, `SELECT id, from_at, to_at FROM log_note WHERE target_id = ? AND source_id = ? AND kind = ? ORDER BY to_at DESC, id DESC LIMIT 1`,
		n.TargetID, n.SourceID, n.Kind).Scan(&id, &from, &to)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("cannot read the log notes: %w", err)
	}
	same := err == nil && ((n.Kind == NoteGap && from == ts(n.From)) || (n.Kind != NoteGap && to >= ts(n.From)))
	if same {
		newTo := ts(n.To)
		if to > newTo {
			newTo = to
		}
		if _, err := tx.ExecContext(ctx, `UPDATE log_note SET to_at = ?, amount = ? WHERE id = ?`, newTo, n.Amount, id); err != nil {
			return fmt.Errorf("cannot save the log note: %w", err)
		}
		return tx.Commit()
	}
	nid, err := r.newID(time.Now().UTC())
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO log_note (id, target_id, source_id, kind, from_at, to_at, amount) VALUES (?,?,?,?,?,?,?)`,
		nid, n.TargetID, n.SourceID, n.Kind, ts(n.From), ts(n.To), n.Amount); err != nil {
		return fmt.Errorf("cannot save the log note: %w", err)
	}
	return tx.Commit()
}

// WindowError is an error read in a period, for the digest.
type WindowError struct {
	Signature
	// Count is how many times it was read in the period.
	Count int64
	// Spiked says that an hour of the period reached the spike threshold.
	Spiked bool
	// ReopenedAt is when it last came back after being resolved (zero if never).
	ReopenedAt time.Time
}

// Window lists the errors of a server read in the period (since, until],
// ignored ones left out, the latest first. It counts by the time Michel read
// the errors, not by the hour written in the log, so that what is read after a
// digest is in the next one whatever its log hour, and each reading falls in
// exactly one period when the periods follow each other. last_alert_at plays
// no part: an error already told by an alert is still in the digest.
func (r *Repo) Window(ctx context.Context, targetID string, since, until time.Time) ([]WindowError, error) {
	wst, err := r.settingsOrDefault(ctx, targetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.s.DB().QueryContext(ctx, `SELECT `+sigCols+`, reopened_at FROM log_signature WHERE target_id = ? AND status <> ? ORDER BY last_at DESC, id`,
		targetID, string(StatusIgnored))
	if err != nil {
		return nil, fmt.Errorf("cannot read the log errors: %w", err)
	}
	var sigs []WindowError
	for rows.Next() {
		var g Signature
		var level, status, first, last, alert, reopened string
		if err := rows.Scan(&g.ID, &g.TargetID, &g.SourceID, &level, &g.Type, &g.Location, &g.Channel, &status, &first, &last, &alert, &g.Total, &reopened); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot read the log errors: %w", err)
		}
		g.Level, g.Status = Level(level), Status(status)
		w := WindowError{Signature: g}
		var perr error
		if w.FirstAt, perr = parseTime(first); perr == nil {
			if w.LastAt, perr = parseTime(last); perr == nil {
				w.LastAlertAt, perr = parseTime(alert)
			}
		}
		if perr == nil && reopened != "" {
			w.ReopenedAt, perr = parseTime(reopened)
		}
		if perr != nil {
			rows.Close()
			return nil, perr
		}
		sigs = append(sigs, w)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("cannot read the log errors: %w", err)
	}
	rows.Close()
	from := since.UTC().Truncate(time.Hour)
	var out []WindowError
	for _, w := range sigs {
		if err := r.s.DB().QueryRowContext(ctx, `SELECT COALESCE(SUM(count), 0) FROM log_read WHERE signature_id = ? AND read_at > ? AND read_at <= ?`,
			w.ID, ts(since), ts(until)).Scan(&w.Count); err != nil {
			return nil, fmt.Errorf("cannot read the log counts: %w", err)
		}
		if w.Count == 0 {
			continue
		}
		// Spikes stay by the hour of the log: an hour is compared with the one before it.
		buckets, err := r.s.DB().QueryContext(ctx, `SELECT hour, count FROM log_bucket WHERE signature_id = ? AND hour >= ? ORDER BY hour`,
			w.ID, ts(from.Add(-time.Hour)))
		if err != nil {
			return nil, fmt.Errorf("cannot read the log counts: %w", err)
		}
		counts := map[time.Time]int64{}
		for buckets.Next() {
			var hour string
			var n int64
			if err := buckets.Scan(&hour, &n); err != nil {
				buckets.Close()
				return nil, fmt.Errorf("cannot read the log counts: %w", err)
			}
			h, err := parseTime(hour)
			if err != nil {
				buckets.Close()
				return nil, err
			}
			counts[h] = n
		}
		err = buckets.Err()
		buckets.Close()
		if err != nil {
			return nil, fmt.Errorf("cannot read the log counts: %w", err)
		}
		for h, n := range counts {
			if !h.Before(from) && spikes(wst, n, counts[h.Add(-time.Hour)]) {
				w.Spiked = true
			}
		}
		out = append(out, w)
	}
	return out, nil
}

// Text returns the cleaned text kept for an error; ok is false when none is.
// It was masked and capped when it was stored; it is checked again here, with the
// masker's own marker allowed (readBackText), so that what the digest says is
// what an alert said.
func (r *Repo) Text(ctx context.Context, id string) (string, bool, error) {
	var enc []byte
	err := r.s.DB().QueryRowContext(ctx, `SELECT text_enc FROM log_signature WHERE id = ?`, id).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cannot read the log text: %w", err)
	}
	if len(enc) == 0 {
		return "", false, nil
	}
	txt, err := OpenText(enc)
	if err != nil {
		return "", false, err
	}
	txt, ok := readBackText(txt)
	return txt, ok, nil
}

// LastLineHour returns the latest hour an error was written in, read from the
// dates of its lines (ok is false when no count is left).
func (r *Repo) LastLineHour(ctx context.Context, signatureID string) (hour time.Time, ok bool, err error) {
	var s sql.NullString
	if err := r.s.DB().QueryRowContext(ctx, `SELECT MAX(hour) FROM log_bucket WHERE signature_id = ?`, signatureID).Scan(&s); err != nil {
		return time.Time{}, false, fmt.Errorf("cannot read the log counts: %w", err)
	}
	if !s.Valid {
		return time.Time{}, false, nil
	}
	hour, err = parseTime(s.String)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("cannot read the log counts: %w", err)
	}
	return hour, true, nil
}
