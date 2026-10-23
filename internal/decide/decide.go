// Package decide keeps the user's decisions on findings (fix, defer, ignore)
// with a snapshot of what was known when deciding, so that a re-scan asks
// again only when something changed.
package decide

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/scan"
)

// Action is what the user decided to do about a finding.
type Action string

// Actions.
const (
	Fix    Action = "fix"
	Defer  Action = "defer"
	Ignore Action = "ignore"
)

// Reason says why a decision stopped being in force.
type Reason string

// Reasons, equal to the codes package scan writes.
const (
	Redecided           Reason = scan.ReasonRedecided
	SeverityChanged     Reason = scan.ReasonSeverityChanged
	FixedVersionChanged Reason = scan.ReasonFixedVersionChanged
	DueReached          Reason = scan.ReasonDueReached
	ReappearedChanged   Reason = scan.ReasonReappearedChanged
)

// Decision is one decision on a finding. The last one not superseded is in
// force; older ones are kept as history.
type Decision struct {
	ID, FindingID, ProjectID string
	Action                   Action
	Justification            string
	// DueAt is the deferral date; zero unless Action is Defer.
	DueAt     time.Time
	Author    string
	CreatedAt time.Time
	// SeenSeverity and SeenFixedVersions are the snapshot of the finding
	// when the decision was taken.
	SeenSeverity      string
	SeenFixedVersions []string
	// SupersededAt is zero while the decision is in force.
	SupersededAt     time.Time
	SupersededReason Reason
}

// DefaultDefer is the deferral given when the user names no date.
const DefaultDefer = 30 * 24 * time.Hour

// MaxJustification is the longest justification accepted, in characters.
const MaxJustification = 1000

// Validation and storage errors.
var (
	ErrJustificationRequired = errors.New("ignoring a finding needs a justification")
	ErrInvalidAction         = errors.New("unknown action: use fix, defer or ignore")
	ErrFindingGone           = errors.New("the finding is no longer seen")
	ErrDueInPast             = errors.New("the deferral date is not in the future")
	ErrJustificationTooLong  = errors.New("the justification is too long")
	ErrFindingNotFound       = errors.New("no finding has this id")
	ErrInvalidFilter         = errors.New("unknown filter: use fix, defer, ignore, superseded or all")
)

// Validate checks action/justification/due; it sanitizes and trims the justification.
// A defer without a date gets now + DefaultDefer; other actions lose any date.
func Validate(d *Decision, now time.Time) error {
	switch d.Action {
	case Fix, Ignore:
		d.DueAt = time.Time{}
	case Defer:
		if d.DueAt.IsZero() {
			d.DueAt = now.UTC().Add(DefaultDefer).Truncate(time.Second)
		} else if !d.DueAt.After(now) {
			return ErrDueInPast
		}
		d.DueAt = d.DueAt.UTC()
	default:
		return ErrInvalidAction
	}
	d.Justification = strings.TrimSpace(scan.SanitizeText(d.Justification))
	if utf8.RuneCountInString(d.Justification) > MaxJustification {
		return ErrJustificationTooLong
	}
	if d.Action == Ignore && d.Justification == "" {
		return ErrJustificationRequired
	}
	return nil
}

// Changed tells whether the finding's severity or fixed versions differ from the snapshot (fixed versions compared as sorted sets).
// The severity wins when both differ.
func Changed(d Decision, severity string, fixed []string) (changed bool, reason Reason) {
	changed, r := scan.SnapshotChanged(d.SeenSeverity, d.SeenFixedVersions, severity, fixed)
	return changed, Reason(r)
}

// timeText is t in RFC 3339 UTC, or "" for the zero time.
func timeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// MarshalJSON writes the decision with snake_case keys; zero times are "".
func (d Decision) MarshalJSON() ([]byte, error) {
	fixed := d.SeenFixedVersions
	if fixed == nil {
		fixed = []string{}
	}
	return json.Marshal(struct {
		ID                string   `json:"id"`
		FindingID         string   `json:"finding_id"`
		ProjectID         string   `json:"project_id"`
		Action            Action   `json:"action"`
		Justification     string   `json:"justification"`
		DueAt             string   `json:"due_at"`
		Author            string   `json:"author"`
		CreatedAt         string   `json:"created_at"`
		SeenSeverity      string   `json:"seen_severity"`
		SeenFixedVersions []string `json:"seen_fixed_versions"`
		SupersededAt      string   `json:"superseded_at"`
		SupersededReason  Reason   `json:"superseded_reason"`
	}{d.ID, d.FindingID, d.ProjectID, d.Action, d.Justification, timeText(d.DueAt), d.Author, timeText(d.CreatedAt),
		d.SeenSeverity, fixed, timeText(d.SupersededAt), d.SupersededReason})
}
