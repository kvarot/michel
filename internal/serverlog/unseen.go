package serverlog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Causes of an unseen file: a closed list, written by the filter and checked
// again when its answer comes back. Denied: the account cannot open it (or
// search its folder). Link: a symbolic link, never followed. Absent: no such
// file. NotFile: a folder or another thing that is no regular file. Tools: a
// tool the filter needs is missing on the server. Other: it changed while it
// was read, or its name is not a plain one.
const (
	CauseDenied  = "denied"
	CauseLink    = "link"
	CauseAbsent  = "absent"
	CauseNotFile = "not_file"
	CauseTools   = "tools"
	CauseOther   = "other"
)

// ValidCause tells whether c is one of the causes of an unseen file.
func ValidCause(c string) bool {
	switch c {
	case CauseDenied, CauseLink, CauseAbsent, CauseNotFile, CauseTools, CauseOther:
		return true
	}
	return false
}

// UnseenFile is a file of a source that the last read could not open. File is
// a path the source declares (or a match of its wildcard): configuration, never
// log content.
type UnseenFile struct {
	SourceID, File, Cause string
	At                    time.Time
}

// SetUnseen replaces the unseen files of a source by those of the read that
// ran at at: a file that can be read again leaves the list.
func (r *Repo) SetUnseen(ctx context.Context, sourceID string, files map[string]string, at time.Time) error {
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the unseen log files: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM log_unseen WHERE source_id = ?`, sourceID); err != nil {
		return fmt.Errorf("cannot save the unseen log files: %w", err)
	}
	for file, cause := range files {
		if !ValidCause(cause) {
			return fmt.Errorf("%w: unseen cause %q", ErrInvalidRecord, cause)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO log_unseen (source_id, file, cause, at) VALUES (?,?,?,?)`, sourceID, file, cause, ts(at)); err != nil {
			return fmt.Errorf("cannot save the unseen log files: %w", err)
		}
	}
	return tx.Commit()
}

// Unseen lists the unseen files of the sources of a server, by source.
func (r *Repo) Unseen(ctx context.Context, targetID string) (map[string][]UnseenFile, error) {
	rows, err := r.s.DB().QueryContext(ctx, `SELECT u.source_id, u.file, u.cause, u.at FROM log_unseen u
		JOIN log_source s ON s.id = u.source_id WHERE s.target_id = ? ORDER BY u.source_id, u.file`, targetID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the unseen log files: %w", err)
	}
	defer rows.Close()
	out := map[string][]UnseenFile{}
	for rows.Next() {
		var u UnseenFile
		var at string
		if err := rows.Scan(&u.SourceID, &u.File, &u.Cause, &at); err != nil {
			return nil, fmt.Errorf("cannot read the unseen log files: %w", err)
		}
		if u.At, err = parseTime(at); err != nil {
			return nil, err
		}
		out[u.SourceID] = append(out[u.SourceID], u)
	}
	return out, rows.Err()
}

// CountNew counts the errors of a server that are new or came back, in the
// sources that are on: nobody reads the others.
func (r *Repo) CountNew(ctx context.Context, targetID string) (int, error) {
	var n int
	err := r.s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM log_signature g JOIN log_source s ON s.id = g.source_id WHERE g.target_id = ? AND s.active = 1 AND g.status IN (?, ?)`,
		targetID, string(StatusNew), string(StatusReopened)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("cannot count the log errors: %w", err)
	}
	return n, nil
}

// UpdateSourceReset is UpdateSource, and when reset is set it also forgets the
// positions and the unseen files of the source in the same transaction: the
// next read is a first read, from the end of the files. A failure leaves both
// as they were, so a retry changes the same things.
func (r *Repo) UpdateSourceReset(ctx context.Context, s Source, reset bool, at time.Time) error {
	if err := checkSource(s); err != nil {
		return err
	}
	tx, err := r.s.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot save the log source: %w", err)
	}
	defer tx.Rollback()
	var was string
	if err := tx.QueryRowContext(ctx, `SELECT path FROM log_source WHERE id = ?`, s.ID).Scan(&was); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: source %s", ErrNotFound, s.ID)
		}
		return fmt.Errorf("cannot save the log source: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE log_source SET path = ?, format = ?, level_field = ?, channel_field = ?, pattern = ?, active = ? WHERE id = ?`,
		s.Path, string(s.Format), s.LevelField, s.ChannelField, s.Pattern, boolInt(s.Active), s.ID); err != nil {
		return fmt.Errorf("cannot save the log source: %w", err)
	}
	if was != s.Path {
		if _, err := tx.ExecContext(ctx, `UPDATE log_source SET path_at = ? WHERE id = ?`, ts(at), s.ID); err != nil {
			return fmt.Errorf("cannot save the log source: %w", err)
		}
	}
	if reset {
		for _, q := range []string{`DELETE FROM log_cursor WHERE source_id = ?`, `DELETE FROM log_unseen WHERE source_id = ?`} {
			if _, err := tx.ExecContext(ctx, q, s.ID); err != nil {
				return fmt.Errorf("cannot save the log source: %w", err)
			}
		}
	}
	return tx.Commit()
}

// ForgetTarget removes everything Michel holds about the logs of a server:
// its errors (ignored ones too), counts, positions, notes, unseen files,
// sources and settings. It is what removing a server does. Nothing is touched
// on the server.
func (r *Repo) ForgetTarget(ctx context.Context, targetID string) error {
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
		`DELETE FROM log_note WHERE target_id = ?`,
		`DELETE FROM log_source WHERE target_id = ?`,
		`DELETE FROM log_settings WHERE target_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, targetID); err != nil {
			return fmt.Errorf("cannot erase the log data: %w", err)
		}
	}
	return tx.Commit()
}

// TryLock takes the read lock of a server, the one a pass holds: the routes that
// erase or rewrite log data take it, so that a running read cannot write rows
// back behind them. ok is false while a read runs; unlock must be called when
// ok.
func TryLock(targetID string) (unlock func(), ok bool) {
	if _, busy := running.LoadOrStore(targetID, struct{}{}); busy {
		return nil, false
	}
	return func() { running.Delete(targetID) }, true
}

// CleanedText is the text a server error may carry out of the filter, as the
// store and the alerts see it: the check of validText, the masker, the cap. ok
// is false for a text that must be dropped. A try shows the same.
func CleanedText(text string) (string, bool) { return cleanedText(text) }

// Fingerprint is the SHA-256 of the records read, without their text.
func Fingerprint(recs []Record) string { return fingerprint(recs) }

// ReasonOf names why a connection or a read failed (a Reason* key), without
// what the server printed.
func ReasonOf(err error) string { return reasonOf(err) }

// ReadVolume is the number of bytes a first look at the files read: the size
// of what was taken, the cap's skipped part left out.
func ReadVolume(out Output) int64 {
	var n int64
	for _, f := range out.Files {
		if f.First {
			continue
		}
		if d := f.Offset - f.Skipped; d > 0 {
			n += d
		}
	}
	return n
}
