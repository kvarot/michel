package serverlog

import (
	"context"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/target"
)

func windowByType(list []WindowError, typ string) (WindowError, bool) {
	for _, w := range list {
		if w.Type == typ {
			return w, true
		}
	}
	return WindowError{}, false
}

func TestWindowCountsWhatHappenedSince(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	apply := func(typ string, count int64, hour, at time.Time) {
		t.Helper()
		r := Record{Level: LevelError, Type: typ, Location: "Demo.php:42", Hour: hour, Count: count}
		if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, at); err != nil {
			t.Fatal(err)
		}
	}
	since := t0.Add(-24 * time.Hour)
	// Old error, quiet in the window: counted 0, so left out.
	apply("OldException", 9, t0.Add(-72*time.Hour), t0.Add(-72*time.Hour))
	// Old error that came again twice in the window.
	apply("BusyException", 4, t0.Add(-72*time.Hour), t0.Add(-72*time.Hour))
	apply("BusyException", 3, t0.Add(-5*time.Hour), t0.Add(-5*time.Hour))
	apply("BusyException", 2, t0.Add(-2*time.Hour), t0.Add(-2*time.Hour))
	// New error in the window.
	apply("FreshException", 37, t0.Add(-3*time.Hour), t0.Add(-3*time.Hour))
	// An error that spikes inside the window: 200 in an hour after 5 the hour before.
	apply("SpikeException", 5, t0.Add(-6*time.Hour), t0.Add(-6*time.Hour))
	apply("SpikeException", 200, t0.Add(-5*time.Hour), t0.Add(-5*time.Hour))
	// An error told by an alert in the window is still there (last_alert_at filters nothing).
	sigs, _ := e.r.Signatures(ctx, e.tgt.ID)
	for _, g := range sigs {
		if g.Type == "FreshException" {
			if err := e.r.MarkAlerted(ctx, []string{g.ID}, t0.Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// An ignored error is left out.
	apply("IgnoredException", 8, t0.Add(-2*time.Hour), t0.Add(-2*time.Hour))
	all, _ := e.r.Signatures(ctx, e.tgt.ID)
	for _, g := range all {
		if g.Type == "IgnoredException" {
			if err := e.r.SetStatus(ctx, g.ID, StatusIgnored); err != nil {
				t.Fatal(err)
			}
		}
	}

	got, err := e.r.Window(ctx, e.tgt.ID, since)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := windowByType(got, "OldException"); ok {
		t.Error("an error with no occurrence in the window is listed")
	}
	if _, ok := windowByType(got, "IgnoredException"); ok {
		t.Error("an ignored error is listed")
	}
	busy, ok := windowByType(got, "BusyException")
	if !ok || busy.Count != 5 || busy.Spiked || !busy.FirstAt.Before(since) {
		t.Errorf("busy = %+v (%v)", busy, ok)
	}
	fresh, ok := windowByType(got, "FreshException")
	if !ok || fresh.Count != 37 || fresh.Spiked || !fresh.FirstAt.After(since) || fresh.Status != StatusNew {
		t.Errorf("fresh = %+v (%v)", fresh, ok)
	}
	spike, ok := windowByType(got, "SpikeException")
	if !ok || spike.Count != 205 || !spike.Spiked {
		t.Errorf("spike = %+v (%v)", spike, ok)
	}
	if len(got) != 3 {
		t.Errorf("window = %d errors, want 3", len(got))
	}
}

func TestWindowSpikeBeforeTheWindowIsNotASpike(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	old := t0.Add(-48 * time.Hour)
	for _, c := range []int64{5, 200} {
		r := Record{Level: LevelError, Type: "PastSpike", Location: "Demo.php:42", Hour: old, Count: c}
		if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, old); err != nil {
			t.Fatal(err)
		}
		old = old.Add(time.Hour)
	}
	r := Record{Level: LevelError, Type: "PastSpike", Location: "Demo.php:42", Hour: t0.Add(-time.Hour), Count: 6}
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := e.r.Window(ctx, e.tgt.ID, t0.Add(-24*time.Hour))
	if err != nil || len(got) != 1 || got[0].Spiked || got[0].Count != 6 {
		t.Errorf("window = %+v, %v", got, err)
	}
}

func TestTextReturnsTheStoredCleanedText(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st := DefaultSettings(target.EnvProd)
	st.TargetID, st.StoreText = e.tgt.ID, true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	r := rec(2, t0)
	r.Text = "Undefined index in array"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0); err != nil {
		t.Fatal(err)
	}
	none := rec(1, t0)
	none.Type = "NoText"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{none}, t0); err != nil {
		t.Fatal(err)
	}
	sigs, _ := e.r.Signatures(ctx, e.tgt.ID)
	for _, g := range sigs {
		txt, ok, err := e.r.Text(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if g.Type == "DemoException" && (!ok || txt != "Undefined index in array") {
			t.Errorf("text = %q, %v", txt, ok)
		}
		if g.Type == "NoText" && (ok || txt != "") {
			t.Errorf("text of an error without one = %q, %v", txt, ok)
		}
	}
}
