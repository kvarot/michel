package decide

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/scan"
)

var now = time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)

func TestValidateIgnoreNeedsJustification(t *testing.T) {
	for _, why := range []string{"", "   ", "\x1b\x07 \t"} {
		d := Decision{Action: Ignore, Justification: why}
		if err := Validate(&d, now); !errors.Is(err, ErrJustificationRequired) {
			t.Errorf("ignore with %q: %v", why, err)
		}
	}
	d := Decision{Action: Ignore, Justification: "  \x1b[31mnot reachable from our code\x07  "}
	if err := Validate(&d, now); err != nil {
		t.Fatal(err)
	}
	if d.Justification != "[31mnot reachable from our code" {
		t.Errorf("justification not sanitized and trimmed: %q", d.Justification)
	}
	for _, a := range []Action{Fix, Defer} {
		d := Decision{Action: a}
		if err := Validate(&d, now); err != nil {
			t.Errorf("%s without justification: %v", a, err)
		}
	}
	d = Decision{Action: "later"}
	if err := Validate(&d, now); !errors.Is(err, ErrInvalidAction) {
		t.Errorf("unknown action: %v", err)
	}
}

func TestValidateDeferDefaultsTo30Days(t *testing.T) {
	d := Decision{Action: Defer}
	if err := Validate(&d, now); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(30 * 24 * time.Hour); !d.DueAt.Equal(want) || DefaultDefer != 30*24*time.Hour {
		t.Errorf("due = %v, want %v", d.DueAt, want)
	}
	given := now.Add(72 * time.Hour)
	d = Decision{Action: Defer, DueAt: given}
	if err := Validate(&d, now); err != nil || !d.DueAt.Equal(given) {
		t.Errorf("explicit due changed: %v %v", d.DueAt, err)
	}
	for _, a := range []Action{Fix, Ignore} {
		d := Decision{Action: a, Justification: "x", DueAt: given}
		if err := Validate(&d, now); err != nil || !d.DueAt.IsZero() {
			t.Errorf("%s keeps a due date: %v %v", a, d.DueAt, err)
		}
	}
}

func TestValidateRejectsPastDue(t *testing.T) {
	for _, due := range []time.Time{now, now.Add(-time.Hour), now.Add(-30 * 24 * time.Hour)} {
		d := Decision{Action: Defer, DueAt: due}
		if err := Validate(&d, now); !errors.Is(err, ErrDueInPast) {
			t.Errorf("due %v: %v", due, err)
		}
	}
	d := Decision{Action: Defer, DueAt: now.Add(time.Second)}
	if err := Validate(&d, now); err != nil {
		t.Errorf("due one second ahead: %v", err)
	}
}

func TestValidateCapsJustification(t *testing.T) {
	d := Decision{Action: Ignore, Justification: strings.Repeat("é", MaxJustification)}
	if err := Validate(&d, now); err != nil {
		t.Errorf("1000 characters refused: %v", err)
	}
	d = Decision{Action: Fix, Justification: strings.Repeat("é", MaxJustification+1)}
	if err := Validate(&d, now); !errors.Is(err, ErrJustificationTooLong) {
		t.Errorf("1001 characters: %v", err)
	}
	// Spaces around the text do not count.
	d = Decision{Action: Fix, Justification: "  " + strings.Repeat("a", MaxJustification) + "\n"}
	if err := Validate(&d, now); err != nil {
		t.Errorf("trimmed text of 1000 characters refused: %v", err)
	}
}

func TestChangedDetectsSeverityThenFix(t *testing.T) {
	d := Decision{SeenSeverity: "high", SeenFixedVersions: []string{"1.2.5"}}
	cases := []struct {
		sev     string
		fixed   []string
		changed bool
		reason  Reason
	}{
		{"high", []string{"1.2.5"}, false, ""},
		{"critical", []string{"1.2.5"}, true, SeverityChanged},
		{"high", []string{"1.2.5", "2.0.0"}, true, FixedVersionChanged},
		{"critical", []string{"1.2.5", "2.0.0"}, true, SeverityChanged},
		{"high", nil, true, FixedVersionChanged},
	}
	for _, c := range cases {
		changed, reason := Changed(d, c.sev, c.fixed, false)
		if changed != c.changed || reason != c.reason {
			t.Errorf("Changed(%s, %v) = %v %q, want %v %q", c.sev, c.fixed, changed, reason, c.changed, c.reason)
		}
	}
	two := Decision{SeenSeverity: "high", SeenFixedVersions: []string{"2.0.0", "1.2.5"}}
	if changed, _ := Changed(two, "high", []string{"1.2.5", "2.0.0"}, false); changed {
		t.Error("a different order alone counts as a change")
	}
	none := Decision{SeenSeverity: "low"}
	if changed, _ := Changed(none, "low", []string{}, false); changed {
		t.Error("no fixed version before and after counts as a change")
	}
}

// "fix" on an open service is refused; ignore and defer pass, and so does
// "fix" on a dependency.
func TestValidateForRefusesFixOnExposure(t *testing.T) {
	exposure := scan.Finding{Kind: scan.KindServerExposure}
	dep := scan.Finding{Kind: scan.KindDependency}
	d := Decision{Action: Fix}
	if err := ValidateFor(exposure, &d, now); !errors.Is(err, ErrNoFixForExposure) {
		t.Errorf("fix on exposure: %v", err)
	}
	d = Decision{Action: Fix}
	if err := ValidateFor(dep, &d, now); err != nil {
		t.Errorf("fix on dependency: %v", err)
	}
	d = Decision{Action: Defer}
	if err := ValidateFor(exposure, &d, now); err != nil {
		t.Errorf("defer on exposure: %v", err)
	}
	d = Decision{Action: Ignore, Justification: "closed on purpose"}
	if err := ValidateFor(exposure, &d, now); err != nil {
		t.Errorf("ignore on exposure: %v", err)
	}
}
