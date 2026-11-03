package serverlog

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

var t0 = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

type env struct {
	r   *Repo
	s   *store.Store
	tgt target.Target
	src Source
}

func setup(t *testing.T, e target.Env) env {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	tgt, err := target.NewRepo(s).Add(ctx, target.Target{Name: "srv-demo", Host: "192.0.2.10", User: "deploy", Kind: target.KindVPS, Env: e})
	if err != nil {
		t.Fatal(err)
	}
	r := NewRepo(s)
	src, err := r.AddSource(ctx, Source{TargetID: tgt.ID, Path: "/var/log/demo/app.log", Format: FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return env{r, s, tgt, src}
}

func rec(count int64, hour time.Time) Record {
	return Record{Level: LevelError, Type: "DemoException", Location: "Demo.php:42", Hour: hour, Count: count}
}

func count(t *testing.T, e env, q string) int {
	t.Helper()
	var n int
	if err := e.s.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDefaultSettingsMatchSpec(t *testing.T) {
	p := DefaultSettings(target.EnvProd)
	want := map[Level]Route{LevelCritical: RouteImmediate, LevelError: RouteDigest, LevelWarning: RouteIgnored, LevelInfo: RouteIgnored}
	for l, r := range want {
		if p.Routes[l] != r {
			t.Errorf("prod %s = %q, want %q", l, p.Routes[l], r)
		}
	}
	for _, e := range []target.Env{target.EnvPreprod, target.EnvDev} {
		d := DefaultSettings(e)
		want := map[Level]Route{LevelCritical: RouteDigest, LevelError: RouteDigest, LevelWarning: RouteIgnored, LevelInfo: RouteIgnored}
		for l, r := range want {
			if d.Routes[l] != r {
				t.Errorf("%s %s = %q, want %q", e, l, d.Routes[l], r)
			}
		}
	}
	if p.Interval != 5*time.Minute || p.RetentionDays != 90 || p.ResolveAfter != 7*24*time.Hour || p.ReadCap != 5<<20 ||
		p.ReadTimeout != 30*time.Second || p.MaxAlertsPerHour != 10 || p.SMS || p.StoreText || p.AlertText {
		t.Fatalf("defaults = %+v", p)
	}
}

func TestSettingsRoundTripAndDefaultFromEnv(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	got, err := e.r.Settings(ctx, e.tgt.ID)
	if err != nil || got.TargetID != e.tgt.ID || got.Routes[LevelCritical] != RouteImmediate {
		t.Fatalf("default settings = %+v, %v", got, err)
	}
	got.RetentionDays, got.SMS, got.Routes[LevelWarning] = 30, true, RouteDigest
	if err := e.r.SaveSettings(ctx, got); err != nil {
		t.Fatal(err)
	}
	back, err := e.r.Settings(ctx, e.tgt.ID)
	if err != nil || back.RetentionDays != 30 || !back.SMS || back.Routes[LevelWarning] != RouteDigest || back.Interval != 5*time.Minute {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

func TestSignatureDoesNotDependOnText(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	a, b := rec(1, t0), rec(2, t0)
	a.Text, b.Text = "first words", "other words"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{a, b}, t0); err != nil {
		t.Fatal(err)
	}
	sigs, err := e.r.Signatures(ctx, e.tgt.ID)
	if err != nil || len(sigs) != 1 || sigs[0].Total != 3 {
		t.Fatalf("signatures = %+v, %v", sigs, err)
	}
	if sigs[0].ID != SignatureID(e.src.ID, LevelError, "DemoException", "Demo.php:42", "") {
		t.Fatal("id is not the documented hash")
	}
}

func TestApplyStoresNoTextUnlessAllowed(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	r := rec(1, t0)
	r.Text = "cleaned text"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Fatalf("text rows = %d", n)
	}
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 1 {
		t.Fatalf("text rows = %d", n)
	}
	if n, err := e.r.EraseText(ctx, e.tgt.ID); err != nil || n != 1 {
		t.Fatalf("EraseText = %d, %v", n, err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Fatalf("text rows after erase = %d", n)
	}
}

func TestApplyLifecycle(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	fresh, reopened, _, err := e.r.Apply(ctx, e.src, []Record{rec(1, t0)}, t0)
	if err != nil || len(fresh) != 1 || len(reopened) != 0 || fresh[0].Status != StatusNew {
		t.Fatalf("first apply = %+v %+v, %v", fresh, reopened, err)
	}
	id := fresh[0].ID
	// Same error again: neither fresh nor reopened.
	fresh, reopened, _, _ = e.r.Apply(ctx, e.src, []Record{rec(1, t0)}, t0.Add(time.Minute))
	if len(fresh) != 0 || len(reopened) != 0 {
		t.Fatalf("second apply = %+v %+v", fresh, reopened)
	}
	// Not resolved before ResolveAfter, resolved after.
	if got, err := e.r.Resolve(ctx, t0.Add(6*24*time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("early resolve = %+v, %v", got, err)
	}
	got, err := e.r.Resolve(ctx, t0.Add(8*24*time.Hour))
	if err != nil || len(got) != 1 || got[0].ID != id || got[0].Status != StatusResolved {
		t.Fatalf("resolve = %+v, %v", got, err)
	}
	back := t0.Add(9 * 24 * time.Hour)
	fresh, reopened, _, err = e.r.Apply(ctx, e.src, []Record{rec(1, back)}, back)
	if err != nil || len(fresh) != 0 || len(reopened) != 1 || reopened[0].Status != StatusReopened {
		t.Fatalf("reopen = %+v %+v, %v", fresh, reopened, err)
	}
	// An ignored signature stays ignored, still counts and never alerts.
	if err := e.r.SetStatus(ctx, id, StatusIgnored); err != nil {
		t.Fatal(err)
	}
	later := back.Add(30 * 24 * time.Hour)
	fresh, reopened, spiked, err := e.r.Apply(ctx, e.src, []Record{rec(500, later)}, later)
	if err != nil || len(fresh)+len(reopened)+len(spiked) != 0 {
		t.Fatalf("ignored apply = %+v %+v %+v, %v", fresh, reopened, spiked, err)
	}
	if got, _ := e.r.Resolve(ctx, later.Add(30*24*time.Hour)); len(got) != 0 {
		t.Fatalf("ignored was resolved: %+v", got)
	}
	sigs, _ := e.r.Signatures(ctx, e.tgt.ID)
	if len(sigs) != 1 || sigs[0].Status != StatusIgnored || sigs[0].Total != 503 {
		t.Fatalf("signatures = %+v", sigs)
	}
}

func TestApplySpike(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur int64
		want      bool
	}{
		{"nine times", 10, 90, false},
		{"ten times under 100", 10, 99, false},
		{"ten times and 100", 10, 100, true},
		{"under ten times of 100", 100, 900, false},
		{"ten times of 100", 100, 1000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t, target.EnvProd)
			ctx := context.Background()
			prev, hour := t0, t0.Add(time.Hour)
			if _, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(c.prev, prev)}, prev); err != nil {
				t.Fatal(err)
			}
			_, _, spiked, err := e.r.Apply(ctx, e.src, []Record{rec(c.cur, hour)}, hour)
			if err != nil || (len(spiked) == 1) != c.want {
				t.Fatalf("spiked = %+v, %v", spiked, err)
			}
			// More occurrences in the same hour do not spike again.
			_, _, again, _ := e.r.Apply(ctx, e.src, []Record{rec(5, hour)}, hour)
			if c.want && len(again) != 0 {
				t.Fatalf("spiked twice: %+v", again)
			}
		})
	}
}

func TestApplyKeepsNoTextForIgnored(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	r := rec(1, t0)
	r.Text = "cleaned text"
	fresh, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0)
	if err != nil || len(fresh) != 1 {
		t.Fatalf("apply = %+v, %v", fresh, err)
	}
	if err := e.r.SetStatus(ctx, fresh[0].ID, StatusIgnored); err != nil {
		t.Fatal(err)
	}
	if _, err := e.r.EraseText(ctx, e.tgt.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Fatalf("ignored signature got text back: %d", n)
	}
}

func TestPurgeKeepsIgnoredRowsOnly(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	keep := Record{Level: LevelError, Type: "KeepException", Location: "Keep.php:1", Hour: t0, Count: 4, Text: "kept words"}
	gone := Record{Level: LevelError, Type: "GoneException", Location: "Gone.php:1", Hour: t0, Count: 3, Text: "gone words"}
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{keep, gone}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetStatus(ctx, SignatureID(e.src.ID, LevelError, "KeepException", "Keep.php:1", ""), StatusIgnored); err != nil {
		t.Fatal(err)
	}
	if err := e.r.AddNote(ctx, Note{TargetID: e.tgt.ID, SourceID: e.src.ID, Kind: NoteGap, From: t0, To: t0.Add(time.Hour), Amount: 1}); err != nil {
		t.Fatal(err)
	}
	// Inside retention: nothing goes.
	if err := e.r.Purge(ctx, t0.Add(89*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if sigs, _ := e.r.Signatures(ctx, e.tgt.ID); len(sigs) != 2 {
		t.Fatalf("early purge left %d signatures", len(sigs))
	}
	if err := e.r.Purge(ctx, t0.Add(91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sigs, _ := e.r.Signatures(ctx, e.tgt.ID)
	if len(sigs) != 1 || sigs[0].Type != "KeepException" || sigs[0].Status != StatusIgnored || sigs[0].Total != 4 {
		t.Fatalf("after purge = %+v", sigs)
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM log_bucket`,
		`SELECT COUNT(*) FROM log_note`,
		`SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`,
	} {
		if n := count(t, e, q); n != 0 {
			t.Fatalf("%s = %d", q, n)
		}
	}
	// The ignored error comes back after the purge and stays ignored; the
	// purged one restarts as new.
	fresh, _, _, _ := e.r.Apply(ctx, e.src, []Record{keep}, t0.Add(92*24*time.Hour))
	if len(fresh) != 0 {
		t.Fatalf("ignored came back fresh: %+v", fresh)
	}
	fresh, _, _, _ = e.r.Apply(ctx, e.src, []Record{gone}, t0.Add(92*24*time.Hour))
	if len(fresh) != 1 {
		t.Fatalf("purged error should restart as new: %+v", fresh)
	}
}

func TestEraseTargetRemovesEverything(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(2, t0)}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetStatus(ctx, SignatureID(e.src.ID, LevelError, "DemoException", "Demo.php:42", ""), StatusIgnored); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SaveCursors(ctx, []Cursor{{SourceID: e.src.ID, File: e.src.Path, FileID: "1:2", Offset: 10, ReadAt: t0}}); err != nil {
		t.Fatal(err)
	}
	if err := e.r.AddNote(ctx, Note{TargetID: e.tgt.ID, Kind: NoteRotated, From: t0, To: t0}); err != nil {
		t.Fatal(err)
	}
	// Another server's data stays.
	other, err := target.NewRepo(e.s).Add(ctx, target.Target{Name: "other", Host: "192.0.2.11", Kind: target.KindVPS})
	if err != nil {
		t.Fatal(err)
	}
	osrc, _ := e.r.AddSource(ctx, Source{TargetID: other.ID, Path: "/var/log/o.log", Format: FormatText, Active: true})
	if _, _, _, err := e.r.Apply(ctx, osrc, []Record{rec(1, t0)}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.EraseTarget(ctx, e.tgt.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM log_signature WHERE target_id = '` + e.tgt.ID + `'`,
		`SELECT COUNT(*) FROM log_bucket WHERE signature_id NOT IN (SELECT id FROM log_signature)`,
		`SELECT COUNT(*) FROM log_cursor WHERE source_id = '` + e.src.ID + `'`,
		`SELECT COUNT(*) FROM log_note WHERE target_id = '` + e.tgt.ID + `'`,
	} {
		if n := count(t, e, q); n != 0 {
			t.Fatalf("%s = %d", q, n)
		}
	}
	if sigs, _ := e.r.Signatures(ctx, other.ID); len(sigs) != 1 {
		t.Fatalf("other server lost data: %+v", sigs)
	}
	if srcs, _ := e.r.Sources(ctx, e.tgt.ID); len(srcs) != 1 {
		t.Fatalf("sources are settings and stay: %+v", srcs)
	}
}

func TestRetentionFloor(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	for _, d := range []int{6, 366} {
		bad := st
		bad.RetentionDays = d
		if err := e.r.SaveSettings(ctx, bad); err == nil {
			t.Errorf("%d days accepted", d)
		}
	}
	for _, d := range []int{7, 365} {
		ok := st
		ok.RetentionDays = d
		if err := e.r.SaveSettings(ctx, ok); err != nil {
			t.Errorf("%d days refused: %v", d, err)
		}
	}
	short := st
	short.RetentionDays, short.ResolveAfter = 10, 20*24*time.Hour
	if err := e.r.SaveSettings(ctx, short); err == nil {
		t.Error("retention under the resolved delay accepted")
	}
}

func TestSourcesAndCursors(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	if _, err := e.r.AddSource(ctx, Source{TargetID: e.tgt.ID, Path: "", Format: FormatPHP}); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := e.r.AddSource(ctx, Source{TargetID: e.tgt.ID, Path: "/x.log", Format: "weird"}); err == nil {
		t.Error("unknown format accepted")
	}
	src := e.src
	src.Active, src.Pattern = false, "^x"
	if err := e.r.UpdateSource(ctx, src); err != nil {
		t.Fatal(err)
	}
	srcs, _ := e.r.Sources(ctx, e.tgt.ID)
	if len(srcs) != 1 || srcs[0].Active || srcs[0].Pattern != "^x" || srcs[0].CreatedAt.IsZero() {
		t.Fatalf("sources = %+v", srcs)
	}
	cs := []Cursor{{SourceID: src.ID, File: "/var/log/demo/a.log", FileID: "1", Offset: 5, ReadAt: t0}, {SourceID: src.ID, File: "/var/log/demo/b.log", FileID: "2", Offset: 7, ReadAt: t0}}
	if err := e.r.SaveCursors(ctx, cs); err != nil {
		t.Fatal(err)
	}
	cs[0].Offset = 9
	if err := e.r.SaveCursors(ctx, cs[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := e.r.Cursors(ctx, src.ID)
	if err != nil || len(got) != 2 || got[0].Offset != 9 || got[1].Offset != 7 || !got[0].ReadAt.Equal(t0) {
		t.Fatalf("cursors = %+v, %v", got, err)
	}
	if _, _, _, err := e.r.Apply(ctx, src, []Record{rec(1, t0)}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.DeleteSource(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	if srcs, _ := e.r.Sources(ctx, e.tgt.ID); len(srcs) != 0 {
		t.Fatalf("source not deleted: %+v", srcs)
	}
	if sigs, _ := e.r.Signatures(ctx, e.tgt.ID); len(sigs) != 0 {
		t.Fatalf("source data kept: %+v", sigs)
	}
	if got, _ := e.r.Cursors(ctx, src.ID); len(got) != 0 {
		t.Fatalf("cursors kept: %+v", got)
	}
}

func TestNotes(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	n := Note{TargetID: e.tgt.ID, SourceID: e.src.ID, Kind: NoteSkipped, From: t0, To: t0.Add(time.Hour), Amount: 12}
	if err := e.r.AddNote(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := e.r.AddNote(ctx, Note{TargetID: e.tgt.ID, Kind: "bogus"}); err == nil {
		t.Error("unknown kind accepted")
	}
	got, err := e.r.Notes(ctx, e.tgt.ID)
	if err != nil || len(got) != 1 || got[0] != n {
		t.Fatalf("notes = %+v, %v", got, err)
	}
}

// The repository takes only what ValidatePath takes: a path Script refuses
// would be stored and then fail every read for good.
func TestSourcePathsGoThroughValidatePath(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	bad := []string{"/var/log/$(id).log", "/var/log/a'b.log", "/var/log/a;b.log", "/var/log/`id`.log", "relative.log", "/var/log/../etc/x", "/var/*/x.log", "/var/log/"}
	for _, p := range bad {
		_, err := e.r.AddSource(ctx, Source{TargetID: e.tgt.ID, Path: p, Format: FormatPHP})
		if !errors.Is(err, ErrInvalidPath) || strings.Contains(err.Error(), p) {
			t.Errorf("AddSource(%q): %v", p, err)
		}
		src := e.src
		src.Path = p
		err = e.r.UpdateSource(ctx, src)
		if !errors.Is(err, ErrInvalidPath) || strings.Contains(err.Error(), p) {
			t.Errorf("UpdateSource(%q): %v", p, err)
		}
	}
	stored, err := e.r.Sources(ctx, e.tgt.ID)
	if err != nil || len(stored) != 1 || stored[0].Path != e.src.Path {
		t.Errorf("a refused path reached the database: %+v %v", stored, err)
	}
	if _, err := e.r.AddSource(ctx, Source{TargetID: e.tgt.ID, Path: "/var/log/app-*.log", Format: FormatPHP}); err != nil {
		t.Errorf("a plain wildcard in the last segment: %v", err)
	}
}

func TestApplyKeepsAnErrorWithoutAType(t *testing.T) {
	e := setup(t, target.EnvProd)
	r := Record{Level: LevelWarning, Location: "Demo.php:3", Hour: t0, Count: 2}
	fresh, _, _, err := e.r.Apply(context.Background(), e.src, []Record{r}, t0)
	if err != nil || len(fresh) != 1 || fresh[0].Type != "" {
		t.Fatalf("fresh = %+v, %v", fresh, err)
	}
	if _, _, _, err := e.r.Apply(context.Background(), e.src, []Record{{Level: "nope", Count: 1}}, t0); !errors.Is(err, ErrInvalidRecord) {
		t.Errorf("an unknown level: %v", err)
	}
}

func TestMarkAlertedAndAlertedSince(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	fresh, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(1, t0), {Level: LevelError, Type: "Other", Hour: t0, Count: 1}}, t0)
	if err != nil || len(fresh) != 2 {
		t.Fatal(fresh, err)
	}
	if n, _ := e.r.AlertedSince(ctx, e.tgt.ID, t0.Add(-time.Hour)); n != 0 {
		t.Fatalf("nothing is told yet: %d", n)
	}
	if err := e.r.MarkAlerted(ctx, []string{fresh[0].ID}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.MarkAlerted(ctx, nil, t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.r.AlertedSince(ctx, e.tgt.ID, t0.Add(-time.Hour)); n != 1 {
		t.Errorf("told in the last hour: %d", n)
	}
	if n, _ := e.r.AlertedSince(ctx, e.tgt.ID, t0); n != 0 {
		t.Errorf("told after t0 itself: %d", n)
	}
	if n, _ := e.r.AlertedSince(ctx, "other-server", t0.Add(-time.Hour)); n != 0 {
		t.Errorf("another server: %d", n)
	}
	got, _ := e.r.Signatures(ctx, e.tgt.ID)
	told := 0
	for _, g := range got {
		if !g.LastAlertAt.IsZero() {
			told++
		}
	}
	if told != 1 {
		t.Errorf("marked: %d", told)
	}
}

func TestCursorHelpers(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	if at, err := e.r.LastRead(ctx, e.tgt.ID); err != nil || !at.IsZero() {
		t.Fatalf("no position yet: %v, %v", at, err)
	}
	cs := []Cursor{
		{SourceID: e.src.ID, File: "/var/log/demo/a.log", FileID: "1", Offset: 5, ReadAt: t0},
		{SourceID: e.src.ID, File: "/var/log/demo/b.log", FileID: "2", Offset: 7, ReadAt: t0.Add(time.Minute)},
		{SourceID: e.src.ID, File: "/var/log/demo/app-*.log/", ReadAt: t0},
	}
	if err := e.r.SaveCursors(ctx, cs); err != nil {
		t.Fatal(err)
	}
	if at, _ := e.r.LastRead(ctx, e.tgt.ID); !at.Equal(t0.Add(time.Minute)) {
		t.Errorf("LastRead = %v", at)
	}
	if err := e.r.PruneCursors(ctx, e.src.ID, []string{"/var/log/demo/a.log"}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.r.Cursors(ctx, e.src.ID)
	if len(got) != 1 || got[0].File != "/var/log/demo/a.log" || got[0].Offset != 5 {
		t.Fatalf("after the prune: %+v", got)
	}
	later := t0.Add(time.Hour)
	if err := e.r.TouchCursors(ctx, e.src.ID, later); err != nil {
		t.Fatal(err)
	}
	got, _ = e.r.Cursors(ctx, e.src.ID)
	if !got[0].ReadAt.Equal(later) || got[0].Offset != 5 || got[0].FileID != "1" {
		t.Errorf("touch changed more than the date: %+v", got[0])
	}
}

func TestRecordStateExtendsWhatLasts(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	n := func(kind string, from, to time.Duration, amount int64) Note {
		return Note{TargetID: e.tgt.ID, SourceID: e.src.ID, Kind: kind, From: t0.Add(from), To: t0.Add(to), Amount: amount}
	}
	// A condition seen on consecutive passes is one note.
	for i := 0; i < 3; i++ {
		d := time.Duration(i) * 5 * time.Minute
		if err := e.r.RecordState(ctx, n(NoteUnseen, d, d+5*time.Minute, int64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	notes, _ := e.r.Notes(ctx, e.tgt.ID)
	if len(notes) != 1 || !notes[0].From.Equal(t0) || !notes[0].To.Equal(t0.Add(15*time.Minute)) || notes[0].Amount != 3 {
		t.Fatalf("notes = %+v", notes)
	}
	// After a pass without it, it comes back as a new note.
	if err := e.r.RecordState(ctx, n(NoteUnseen, time.Hour, time.Hour+5*time.Minute, 1)); err != nil {
		t.Fatal(err)
	}
	if notes, _ = e.r.Notes(ctx, e.tgt.ID); len(notes) != 2 {
		t.Fatalf("notes = %+v", notes)
	}
	// A gap is the same gap when it starts at the same time; one that starts
	// where the last one ended is another.
	if err := e.r.RecordState(ctx, n(NoteGap, 2*time.Hour, 3*time.Hour, 0)); err != nil {
		t.Fatal(err)
	}
	if err := e.r.RecordState(ctx, n(NoteGap, 2*time.Hour, 5*time.Hour, 0)); err != nil {
		t.Fatal(err)
	}
	if err := e.r.RecordState(ctx, n(NoteGap, 5*time.Hour, 6*time.Hour, 0)); err != nil {
		t.Fatal(err)
	}
	gaps := 0
	notes, _ = e.r.Notes(ctx, e.tgt.ID)
	for _, x := range notes {
		if x.Kind == NoteGap {
			gaps++
		}
	}
	if gaps != 2 {
		t.Fatalf("gaps = %d in %+v", gaps, notes)
	}
	if latest, ok, err := e.r.LatestNote(ctx, e.tgt.ID, e.src.ID, NoteGap); err != nil || !ok || !latest.To.Equal(t0.Add(6*time.Hour)) {
		t.Errorf("latest gap = %+v, %v, %v", latest, ok, err)
	}
	if _, ok, _ := e.r.LatestNote(ctx, e.tgt.ID, e.src.ID, NoteRotated); ok {
		t.Error("a note of a kind that never happened")
	}
	if err := e.r.RecordState(ctx, Note{TargetID: e.tgt.ID, Kind: "bogus"}); !errors.Is(err, ErrInvalidNote) {
		t.Errorf("unknown kind: %v", err)
	}
}

func TestHourCount(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	fresh, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(5, t0.Add(10*time.Minute))}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := e.r.HourCount(ctx, fresh[0].ID, t0); n != 5 {
		t.Errorf("count = %d", n)
	}
	if n, _ := e.r.HourCount(ctx, fresh[0].ID, t0.Add(-time.Hour)); n != 0 {
		t.Errorf("another hour = %d", n)
	}
}
