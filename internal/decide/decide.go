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
	ReviewDue           Reason = scan.ReasonReviewDue
	ReappearedChanged   Reason = scan.ReasonReappearedChanged
	KEVChanged          Reason = scan.ReasonKEVChanged
)

// Decision is one decision on a finding. The last one not superseded is in
// force; older ones are kept as history.
type Decision struct {
	ID, FindingID, ProjectID string
	Action                   Action
	Justification            string
	// DueAt is the deferral date of a Defer, or the review date of an
	// Ignore (zero = never reviewed); zero for a Fix.
	DueAt     time.Time
	Author    string
	CreatedAt time.Time
	// SeenSeverity, SeenFixedVersions and SeenKEV are the snapshot of the
	// finding when the decision was taken.
	SeenSeverity      string
	SeenFixedVersions []string
	SeenKEV           bool
	// SupersededAt is zero while the decision is in force.
	SupersededAt     time.Time
	SupersededReason Reason
}

// DefaultDefer is the deferral given when the user names no date.
const DefaultDefer = 30 * 24 * time.Hour

// DefaultReview is the review delay of an ignore when the caller asks for the
// default; Validate never applies it (a zero DueAt means "never").
const DefaultReview = 365 * 24 * time.Hour

// ReviewDate turns a review choice ("1y", "6m", "3m" or "never") into the
// DueAt of an ignore at now. "never" gives the zero time. ok is false for any
// other value.
func ReviewDate(choice string, now time.Time) (due time.Time, ok bool) {
	now = now.UTC().Truncate(time.Second)
	switch choice {
	case "1y":
		return now.Add(DefaultReview), true
	case "6m":
		return now.AddDate(0, 6, 0), true
	case "3m":
		return now.AddDate(0, 3, 0), true
	case "never":
		return time.Time{}, true
	}
	return time.Time{}, false
}

// MaxJustification is the longest justification accepted, in characters.
const MaxJustification = 1000

// Validation and storage errors.
var (
	ErrJustificationRequired = errors.New("ignoring a finding needs a justification")
	ErrInvalidAction         = errors.New("unknown action: use fix, defer or ignore")
	ErrFindingGone           = errors.New("the finding is no longer seen")
	ErrDueInPast             = errors.New("the date is not in the future")
	ErrJustificationTooLong  = errors.New("the justification is too long")
	ErrNoFixForExposure      = errors.New("an open service cannot be fixed by Michel")
	ErrFindingNotFound       = errors.New("no finding has this id")
	ErrInvalidFilter         = errors.New("unknown filter: use fix, defer, ignore, superseded or all")
)

// Validate checks action/justification/due; it sanitizes and trims the justification.
// A defer without a date gets now + DefaultDefer; a fix loses any date; an
// ignore keeps its review date (zero = never) and refuses one in the past.
func Validate(d *Decision, now time.Time) error {
	switch d.Action {
	case Fix:
		d.DueAt = time.Time{}
	case Ignore:
		if !d.DueAt.IsZero() {
			if !d.DueAt.After(now) {
				return ErrDueInPast
			}
			d.DueAt = d.DueAt.UTC()
		}
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

// ValidateFor is Validate for a decision on the finding f: it also refuses
// "fix" on an exposure finding (Michel cannot close an open service, "fix"
// would only hide the finding with nobody to fix it). The CLI and the local
// API both decide through it.
func ValidateFor(f scan.Finding, d *Decision, now time.Time) error {
	if d.Action == Fix && f.Kind == scan.KindServerExposure {
		return ErrNoFixForExposure
	}
	return Validate(d, now)
}

// Changed tells whether the finding's severity, fixed versions or KEV mark differ from the snapshot (fixed versions compared as sorted sets).
// The severity wins, then the fixed versions, then the KEV mark.
func Changed(d Decision, severity string, fixed []string, kev bool) (changed bool, reason Reason) {
	changed, r := scan.SnapshotChanged(d.SeenSeverity, d.SeenFixedVersions, d.SeenKEV, severity, fixed, kev)
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
		SeenKEV           bool     `json:"seen_kev"`
		SupersededAt      string   `json:"superseded_at"`
		SupersededReason  Reason   `json:"superseded_reason"`
	}{d.ID, d.FindingID, d.ProjectID, d.Action, d.Justification, timeText(d.DueAt), d.Author, timeText(d.CreatedAt),
		d.SeenSeverity, fixed, d.SeenKEV, timeText(d.SupersededAt), d.SupersededReason})
}
