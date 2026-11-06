// Package history writes and reads the history of the findings and of the
// fix attempts: the finding_event and fix_attempt_event tables. It imports
// neither scan, decide nor fix, so that each of them can write its events
// inside its own transaction.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The kinds of a finding event.
const (
	KindSeen     = "seen"     // first stored
	KindGone     = "gone"     // no longer found
	KindBack     = "back"     // found again after it was gone
	KindReopened = "reopened" // its decision stopped being in force
)

// The statuses of a finding that StatusEvents tells apart (the same words as
// the scan package).
const (
	statusPending = "pending"
	statusGone    = "gone"
	statusDecided = "decided"
)

// StatusEvents returns the kinds of the events to write, in order, when a
// finding goes from status from to status to (from is "" when the finding is
// stored for the first time). reason is the reason a decision was superseded
// by the same change, "" if none was. new -> pending and pending -> decided
// are not events: the decision table already dates them.
func StatusEvents(from, to, reason string) []string {
	switch {
	case from == "":
		return []string{KindSeen}
	case from == to:
		return nil
	case to == statusGone:
		return []string{KindGone}
	case from == statusGone:
		if to == statusPending && reason != "" {
			return []string{KindBack, KindReopened}
		}
		return []string{KindBack}
	case from == statusDecided && to == statusPending:
		return []string{KindReopened}
	}
	return nil
}

// errPathInDetail refuses a detail that would put a path in the history.
var errPathInDetail = errors.New("a finding event holds no path")

// AddFindingEvent writes one event of a finding inside tx, numbered after the
// events the finding already has. detail (nil for none) is stored as JSON and
// must hold no path: a string value with a slash or a backslash is refused.
func AddFindingEvent(ctx context.Context, tx *sql.Tx, findingID string, at time.Time, kind string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	for k, v := range detail {
		if s, ok := v.(string); ok && strings.ContainsAny(s, `/\`) {
			return fmt.Errorf("%w (%s)", errPathInDetail, k)
		}
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("cannot write the history of the finding: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_event (finding_id, seq, at, kind, detail)
		SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ? FROM finding_event WHERE finding_id = ?`,
		findingID, at.UTC().Format(time.RFC3339), kind, string(body), findingID); err != nil {
		return fmt.Errorf("cannot write the history of the finding: %w", err)
	}
	return nil
}

// AddStatusEvents writes, inside tx, the events of a finding going from
// status from to status to (StatusEvents), reason being the reason of the
// supersession the change carries ("" if none). A reopened event keeps that
// reason in detail.reason.
func AddStatusEvents(ctx context.Context, tx *sql.Tx, findingID, from, to, reason string, at time.Time) error {
	for _, kind := range StatusEvents(from, to, reason) {
		var detail map[string]any
		if kind == KindReopened && reason != "" {
			detail = map[string]any{"reason": reason}
		}
		if err := AddFindingEvent(ctx, tx, findingID, at, kind, detail); err != nil {
			return err
		}
	}
	return nil
}
