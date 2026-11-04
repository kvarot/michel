package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

// gapFixture: a server with two logs, a gap on each over the same hours.
func gapFixture(t *testing.T) (l logFixture, second serverlog.Source) {
	t.Helper()
	localZone(t, time.UTC)
	l = newLogFixture(t, target.EnvPreprod)
	ctx := context.Background()
	second, err := l.repo.AddSource(ctx, serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/second.log", Format: serverlog.FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []serverlog.Source{l.src, second} {
		if err := l.repo.RecordState(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: s.ID, Kind: serverlog.NoteGap, From: now.Add(-8 * time.Hour), To: now.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	return l, second
}

func gapText(t *testing.T, l logFixture, lang i18n.Lang) string {
	t.Helper()
	s, _ := RenderText(l.compute(lang, Options{}))
	return s
}

func keep(t *testing.T, l logFixture, at time.Time, fs ...serverlog.Failure) {
	t.Helper()
	if err := l.repo.SetFailures(context.Background(), l.tgt.ID, fs, at); err != nil {
		t.Fatal(err)
	}
}

// A merged gap does not hand the cause of one log to the logs that did not have it.
func TestDigestGapCauseOfOneLogIsNotTheCauseOfTheOther(t *testing.T) {
	l, second := gapFixture(t)
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{SourceID: second.ID, Reason: serverlog.ReasonTools})
	if got := gapText(t, l, i18n.EN); strings.Contains(got, "awk") || !strings.Contains(got, "Michel does not know why.") {
		t.Errorf("one log's cause covered both:\n%s", got)
	}
	// The server's cause covers every log of the gap.
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{Reason: serverlog.ReasonRefused})
	if got := gapText(t, l, i18n.EN); !strings.Contains(got, "the server refused the connection") {
		t.Errorf("server cause lost:\n%s", got)
	}
	// Each log with its own cause, the same one: covered.
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{SourceID: l.src.ID, Reason: serverlog.ReasonTools}, serverlog.Failure{SourceID: second.ID, Reason: serverlog.ReasonTools})
	if got := gapText(t, l, i18n.EN); !strings.Contains(got, "awk") {
		t.Errorf("same cause on both lost:\n%s", got)
	}
	// Two different causes tell nothing.
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{SourceID: l.src.ID, Reason: serverlog.ReasonTools}, serverlog.Failure{SourceID: second.ID, Reason: serverlog.ReasonDenied})
	if got := gapText(t, l, i18n.EN); strings.Contains(got, "awk") || strings.Contains(got, "refused Michel") || !strings.Contains(got, "does not know why") {
		t.Errorf("two causes gave one:\n%s", got)
	}
}

// A failure of a later pass, or of a log outside the gap, says nothing about it.
func TestDigestGapIgnoresFailuresOutsideIt(t *testing.T) {
	l, _ := gapFixture(t)
	keep(t, l, now.Add(-time.Hour+30*time.Second), serverlog.Failure{Reason: serverlog.ReasonRefused})
	if got := gapText(t, l, i18n.EN); strings.Contains(got, "refused the connection") {
		t.Errorf("a later failure explained a closed gap:\n%s", got)
	}
	keep(t, l, now.Add(-9*time.Hour), serverlog.Failure{Reason: serverlog.ReasonRefused})
	if got := gapText(t, l, i18n.EN); strings.Contains(got, "refused the connection") {
		t.Errorf("an earlier failure explained the gap:\n%s", got)
	}
	// A failure of a log that was not behind.
	third, err := l.repo.AddSource(context.Background(), serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/third.log", Format: serverlog.FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{SourceID: third.ID, Reason: serverlog.ReasonTools})
	if got := gapText(t, l, i18n.EN); strings.Contains(got, "awk") {
		t.Errorf("the cause of a log outside the gap explained it:\n%s", got)
	}
}

// The cause kept is the one of the last try, and the line says so.
func TestDigestGapSaysTheCauseIsOfTheLastTry(t *testing.T) {
	l, _ := gapFixture(t)
	keep(t, l, now.Add(-time.Hour), serverlog.Failure{Reason: serverlog.ReasonNoAgent})
	if got := gapText(t, l, i18n.EN); !strings.Contains(got, "Michel only knows the cause of its last try. Cause: the program that keeps your SSH key") {
		t.Errorf("en:\n%s", got)
	}
	if got := gapText(t, l, i18n.FR); !strings.Contains(got, "Michel ne connaît que la cause de sa dernière tentative. Cause : le programme qui garde ta clé SSH") {
		t.Errorf("fr:\n%s", got)
	}
}
