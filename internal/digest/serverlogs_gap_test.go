package digest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

// localZone makes the computer's time zone z for the test: the digest writes the
// hours of a gap the way the person lives them.
func localZone(t *testing.T, z *time.Location) {
	t.Helper()
	was := time.Local
	time.Local = z
	t.Cleanup(func() { time.Local = was })
}

func TestDigestGapHoursAreLocalAndNeverSayUTC(t *testing.T) {
	l := newLogFixture(t, target.EnvPreprod)
	localZone(t, time.FixedZone("paris", 3600))
	if err := l.repo.RecordState(context.Background(), serverlog.Note{TargetID: l.tgt.ID, SourceID: l.src.ID, Kind: serverlog.NoteGap,
		From: now.Add(-8 * time.Hour), To: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d := l.compute(i18n.EN, Options{})
	text, _ := RenderText(d)
	if !strings.Contains(text, "between 2026-10-22 23:30 and 2026-10-23 05:30") || strings.Contains(text, "UTC") {
		t.Errorf("en:\n%s", text)
	}
	fr, _ := RenderText(l.compute(i18n.FR, Options{}))
	if !strings.Contains(fr, "entre le 22/10/2026 à 23h30 et le 23/10/2026 à 05h30") || strings.Contains(fr, "UTC") {
		t.Errorf("fr:\n%s", fr)
	}
}

// A gap belongs to the log that was behind: with several logs, the line names the
// ones that were, and only a gap that covers every log speaks of "the logs".
func TestDigestGapNamesTheLogsThatWereBehind(t *testing.T) {
	localZone(t, time.UTC)
	l := newLogFixture(t, target.EnvPreprod)
	ctx := context.Background()
	second, err := l.repo.AddSource(ctx, serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/second.log", Format: serverlog.FormatText, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	third, err := l.repo.AddSource(ctx, serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/third.log", Format: serverlog.FormatPostgres, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	gap := func(src serverlog.Source, from, to time.Duration) {
		t.Helper()
		if err := l.repo.RecordState(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: src.ID, Kind: serverlog.NoteGap, From: now.Add(from), To: now.Add(to)}); err != nil {
			t.Fatal(err)
		}
	}
	// One log of three was behind.
	gap(second, -8*time.Hour, -2*time.Hour)
	_, s := l.logSection(i18n.EN)
	if len(s.Gaps) != 1 || len(s.Gaps[0].Sources) != 1 || s.Gaps[0].All || s.Gaps[0].Sources[0] != (serverlog.SourceRef{Rank: 2, Format: serverlog.FormatText}) {
		t.Fatalf("gaps = %+v", s.Gaps)
	}
	text, _ := RenderText(l.compute(i18n.EN, Options{}))
	if !strings.Contains(text, "Michel could not read log no. 2 on the server page between ") || strings.Contains(text, "(text)") {
		t.Errorf("en:\n%s", text)
	}
	fr, _ := RenderText(l.compute(i18n.FR, Options{}))
	if !strings.Contains(fr, "Michel n'a pas pu lire le journal n° 2 de la page du serveur entre le ") {
		t.Errorf("fr:\n%s", fr)
	}
	// Two of three: both are named. Overlapping hours are one period.
	gap(third, -6*time.Hour, -time.Hour)
	_, s = l.logSection(i18n.EN)
	if len(s.Gaps) != 1 || len(s.Gaps[0].Sources) != 2 || s.Gaps[0].All {
		t.Fatalf("gaps = %+v", s.Gaps)
	}
	text, _ = RenderText(l.compute(i18n.EN, Options{}))
	if !strings.Contains(text, "Michel could not read log no. 2 on the server page and log no. 3 on the server page (PostgreSQL) between ") {
		t.Errorf("en:\n%s", text)
	}
	// Every log: the logs, as before.
	gap(l.src, -7*time.Hour, -3*time.Hour)
	_, s = l.logSection(i18n.EN)
	if len(s.Gaps) != 1 || !s.Gaps[0].All {
		t.Fatalf("gaps = %+v", s.Gaps)
	}
	text, _ = RenderText(l.compute(i18n.EN, Options{}))
	if !strings.Contains(text, "Michel could not read the logs between ") {
		t.Errorf("en:\n%s", text)
	}
	raw, _ := json.Marshal(l.compute(i18n.EN, Options{}))
	if strings.Contains(string(raw), second.ID) || strings.Contains(string(raw), "/var/log") {
		t.Errorf("json holds an id or a path: %s", raw)
	}
}

// The reason the pass kept for a failure that is still going on is the reason of
// the gap; a reason it did not keep, or a general one, is "Michel does not know why".
func TestDigestGapUsesTheReasonThePassKept(t *testing.T) {
	localZone(t, time.UTC)
	l := newLogFixture(t, target.EnvPreprod)
	ctx := context.Background()
	if err := l.repo.RecordState(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: l.src.ID, Kind: serverlog.NoteGap, From: now.Add(-8 * time.Hour), To: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	text := func(lang i18n.Lang) string {
		s, _ := RenderText(l.compute(lang, Options{}))
		return s
	}
	if got := text(i18n.EN); !strings.Contains(got, "Michel does not know why.") {
		t.Errorf("no reason kept:\n%s", got)
	}
	// A reason kept at the end of the gap: the connection to the server failed.
	if err := l.repo.SetFailures(ctx, l.tgt.ID, []serverlog.Failure{{Reason: serverlog.ReasonRefused}}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := text(i18n.EN); !strings.Contains(got, "Cause: the server refused the connection.") || strings.Contains(got, "does not know why") {
		t.Errorf("reason kept:\n%s", got)
	}
	if got := text(i18n.FR); !strings.Contains(got, "Cause : le serveur a refusé la connexion.") {
		t.Errorf("reason kept (fr):\n%s", got)
	}
	// The general reason tells nothing more than "unknown".
	if err := l.repo.SetFailures(ctx, l.tgt.ID, []serverlog.Failure{{Reason: serverlog.ReasonError}}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := text(i18n.EN); !strings.Contains(got, "Michel does not know why.") {
		t.Errorf("general reason:\n%s", got)
	}
	// A failure from outside the gap says nothing about it.
	if err := l.repo.SetFailures(ctx, l.tgt.ID, []serverlog.Failure{{Reason: serverlog.ReasonRefused}}, now.Add(-20*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := text(i18n.EN); strings.Contains(got, "refused the connection") {
		t.Errorf("an old failure explained the gap:\n%s", got)
	}
}

// A format a beginner does not know (text, other) is not put in brackets.
func TestSourceLabelHasNoBracketsForTextAndOther(t *testing.T) {
	for _, c := range []struct {
		lang i18n.Lang
		ref  serverlog.SourceRef
		want string
	}{
		{i18n.FR, serverlog.SourceRef{Rank: 3, Format: serverlog.FormatText}, "le journal n° 3 de la page du serveur"},
		{i18n.FR, serverlog.SourceRef{Rank: 3, Format: serverlog.Format("zzz")}, "le journal n° 3 de la page du serveur"},
		{i18n.EN, serverlog.SourceRef{Rank: 3, Format: serverlog.FormatText}, "log no. 3 on the server page"},
		{i18n.FR, serverlog.SourceRef{Rank: 2, Format: serverlog.FormatPHP}, "le journal n° 2 de la page du serveur (PHP)"},
		{i18n.FR, serverlog.SourceRef{Rank: 2, Format: serverlog.FormatPostgres}, "le journal n° 2 de la page du serveur (PostgreSQL)"},
		{i18n.FR, serverlog.SourceRef{Rank: 2, Format: serverlog.FormatMonolog}, "le journal n° 2 de la page du serveur (erreurs de l'application)"},
	} {
		if got := SourceLabel(c.lang, c.ref); got != c.want {
			t.Errorf("%s %+v = %q, want %q", c.lang, c.ref, got, c.want)
		}
	}
	for lang, want := range map[i18n.Lang]string{i18n.FR: "du journal n° 3 de la page du serveur", i18n.EN: "of log no. 3 on the server page"} {
		if got := sourceOf(lang, 3, serverlog.FormatText); got != want {
			t.Errorf("%s: sourceOf = %q, want %q", lang, got, want)
		}
	}
	if got := sourceOf(i18n.FR, 2, serverlog.FormatPHP); got != "du journal n° 2 de la page du serveur (PHP)" {
		t.Errorf("sourceOf with a format = %q", got)
	}
}
