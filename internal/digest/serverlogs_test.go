package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

type logFixture struct {
	*fixture
	repo *serverlog.Repo
	tgt  target.Target
	src  serverlog.Source
}

func newLogFixture(t *testing.T, env target.Env) logFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	tgt, err := target.NewRepo(f.st).Add(ctx, target.Target{Name: "srv-demo", Host: "192.0.2.10", Kind: target.KindVPS, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	repo := serverlog.NewRepo(f.st)
	src, err := repo.AddSource(ctx, serverlog.Source{TargetID: tgt.ID, Path: "/var/log/demo/app.log", Format: serverlog.FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return logFixture{f, repo, tgt, src}
}

func (l logFixture) apply(typ string, level serverlog.Level, count int64, at time.Time, text string) {
	l.t.Helper()
	r := serverlog.Record{Level: level, Type: typ, Location: "Demo.php:42", Hour: at, Count: count, Text: text}
	if _, _, _, err := l.repo.Apply(context.Background(), l.src, []serverlog.Record{r}, at); err != nil {
		l.t.Fatal(err)
	}
}

func (l logFixture) sig(typ string) serverlog.Signature {
	l.t.Helper()
	sigs, err := l.repo.Signatures(context.Background(), l.tgt.ID)
	if err != nil {
		l.t.Fatal(err)
	}
	for _, g := range sigs {
		if g.Type == typ {
			return g
		}
	}
	l.t.Fatalf("no error %s", typ)
	return serverlog.Signature{}
}

func (l logFixture) settings(mut func(*serverlog.Settings)) {
	l.t.Helper()
	st, err := l.repo.Settings(context.Background(), l.tgt.ID)
	if err != nil {
		l.t.Fatal(err)
	}
	mut(&st)
	if err := l.repo.SaveSettings(context.Background(), st); err != nil {
		l.t.Fatal(err)
	}
}

// logSection computes the digest and returns the section of the server.
func (l logFixture) logSection(lang i18n.Lang) (Digest, ServerLogDigest) {
	l.t.Helper()
	d := l.compute(lang, Options{})
	for _, s := range d.ServerLogs {
		if s.Name == "srv-demo" {
			return d, s
		}
	}
	l.t.Fatalf("no section for srv-demo in %+v", d.ServerLogs)
	return d, ServerLogDigest{}
}

func (l logFixture) seedWindow() {
	l.t.Helper()
	ctx := context.Background()
	// Old and quiet: not in the digest.
	l.apply("QuietException", serverlog.LevelError, 9, now.Add(-72*time.Hour), "")
	// New in the window, and told by an alert already: still there (R24).
	l.apply("FreshException", serverlog.LevelError, 37, now.Add(-3*time.Hour), "")
	if err := l.repo.MarkAlerted(ctx, []string{l.sig("FreshException").ID}, now.Add(-2*time.Hour)); err != nil {
		l.t.Fatal(err)
	}
	// Old, back after being resolved.
	l.apply("BackException", serverlog.LevelCritical, 2, now.Add(-10*24*time.Hour), "")
	if err := l.repo.SetStatus(ctx, l.sig("BackException").ID, serverlog.StatusResolved); err != nil {
		l.t.Fatal(err)
	}
	l.apply("BackException", serverlog.LevelCritical, 4, now.Add(-time.Hour), "")
	// Old, much more frequent inside the window.
	l.apply("SpikeException", serverlog.LevelError, 2, now.Add(-10*24*time.Hour), "")
	l.apply("SpikeException", serverlog.LevelError, 5, now.Add(-9*time.Hour), "")
	l.apply("SpikeException", serverlog.LevelError, 300, now.Add(-8*time.Hour), "")
	// Old, seen by the user, a little busier: nothing to tell.
	l.apply("SeenException", serverlog.LevelError, 3, now.Add(-10*24*time.Hour), "")
	l.apply("SeenException", serverlog.LevelError, 3, now.Add(-4*time.Hour), "")
	if err := l.repo.SetStatus(ctx, l.sig("SeenException").ID, serverlog.StatusSeen); err != nil {
		l.t.Fatal(err)
	}
	// A level the settings send nowhere (warning), and an ignored error.
	l.apply("WarnException", serverlog.LevelWarning, 12, now.Add(-3*time.Hour), "")
	l.apply("IgnoredException", serverlog.LevelError, 6, now.Add(-3*time.Hour), "")
	if err := l.repo.SetStatus(ctx, l.sig("IgnoredException").ID, serverlog.StatusIgnored); err != nil {
		l.t.Fatal(err)
	}
}

func TestDigestListsNewAndFrequentErrors(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	l.seedWindow()
	d, s := l.logSection(i18n.EN)
	if s.New != 1 || s.Reopened != 1 {
		t.Errorf("new %d, reopened %d", s.New, s.Reopened)
	}
	var got []string
	for _, it := range s.Top {
		got = append(got, string(it.Kind)+":"+it.Type)
		if it.SourceID != "" || it.Text != "" {
			t.Errorf("item = %+v", it)
		}
	}
	// The most severe first, then the most frequent.
	want := []string{"reopened:BackException", "new:FreshException", "spike:SpikeException", "frequent:SeenException"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("top = %v, want %v", got, want)
	}
	if s.Top[0].Count != 4 || s.Top[1].Count != 37 || s.Top[2].Count != 305 || s.Top[3].Count != 3 {
		t.Errorf("counts = %+v", s.Top)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Server logs:", "srv-demo: 1 new error, 1 error came back", "- FreshException, Demo.php:42, 37 times (new)",
		"- BackException, Demo.php:42, 4 times (back)", "- SpikeException, Demo.php:42, 305 times (far more often than before)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"QuietException", "WarnException", "IgnoredException"} {
		if strings.Contains(text, not) {
			t.Errorf("text lists %s:\n%s", not, text)
		}
	}
	page, err := RenderHTML(d)
	if err != nil || !strings.Contains(page, "<h2>Server logs</h2>") || !strings.Contains(page, "FreshException, Demo.php:42, 37 times (new)") {
		t.Errorf("html: %v\n%s", err, page)
	}
	fr, err := RenderText(l.compute(i18n.FR, Options{}))
	for _, want := range []string{"Journaux des serveurs :", "srv-demo : 1 nouvelle erreur, 1 erreur revenue", "FreshException, Demo.php:42, 37 fois (nouvelle)"} {
		if err != nil || !strings.Contains(fr, want) {
			t.Errorf("fr lacks %q: %v\n%s", want, err, fr)
		}
	}
	// The JSON holds no id of a source or of a server.
	raw, err := json.Marshal(d)
	if err != nil || strings.Contains(string(raw), l.src.ID) || strings.Contains(string(raw), l.tgt.ID) || !strings.Contains(string(raw), `"server_logs"`) {
		t.Errorf("json: %v\n%s", err, raw)
	}
	if d.NewTotal != 2 {
		t.Errorf("new total = %d, want the 2 new or back errors", d.NewTotal)
	}
	if strings.Contains(d.Title, "nothing new") {
		t.Errorf("title = %q", d.Title)
	}
}

func TestDigestOmitsAServerWithNothingToSay(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	l.apply("QuietException", serverlog.LevelError, 9, now.Add(-72*time.Hour), "")
	d := l.compute(i18n.EN, Options{})
	text, _ := RenderText(d)
	if len(d.ServerLogs) != 0 || strings.Contains(text, "Server logs") {
		t.Errorf("sections = %+v\n%s", d.ServerLogs, text)
	}
	if d.Word == "" {
		t.Errorf("a quiet digest lost its word")
	}
}

func TestDigestShowsReadGap(t *testing.T) {
	// A preprod server that was never read: no alert goes out for it, the
	// digest is the only place that says so.
	l := newLogFixture(t, target.EnvPreprod)
	ctx := context.Background()
	gap := serverlog.Note{TargetID: l.tgt.ID, SourceID: l.src.ID, Kind: serverlog.NoteGap, From: now.Add(-8 * time.Hour), To: now.Add(-2 * time.Hour)}
	if err := l.repo.RecordState(ctx, gap); err != nil {
		t.Fatal(err)
	}
	other, err := l.repo.AddSource(ctx, serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/other.log", Format: serverlog.FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	// A gap over before the window is not told again.
	if err := l.repo.RecordState(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: other.ID, Kind: serverlog.NoteGap,
		From: now.Add(-100 * time.Hour), To: now.Add(-90 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Another source behind in the same hours: one line for the server.
	if err := l.repo.RecordState(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: other.ID, Kind: serverlog.NoteGap,
		From: now.Add(-6 * time.Hour), To: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d, s := l.logSection(i18n.EN)
	if len(s.Gaps) != 1 || !s.Gaps[0].From.Equal(gap.From) || !s.Gaps[0].To.Equal(now.Add(-time.Hour)) {
		t.Fatalf("gaps = %+v", s.Gaps)
	}
	text, _ := RenderText(d)
	if !strings.Contains(text, "srv-demo") || !strings.Contains(text, "between 2026-10-22 22:30 UTC and 2026-10-23 05:30 UTC") {
		t.Errorf("text:\n%s", text)
	}
	fr, _ := RenderText(l.compute(i18n.FR, Options{}))
	if !strings.Contains(fr, "entre le 22/10/2026 à 22h30 UTC et le 23/10/2026 à 05h30 UTC") {
		t.Errorf("fr:\n%s", fr)
	}
	if page, _ := RenderHTML(d); !strings.Contains(page, "<li>Michel could not read the logs between 2026-10-22 22:30 UTC") {
		t.Errorf("html:\n%s", page)
	}
	// A gap stores two dates and nothing about why: the line says so, and names
	// no cause it does not know.
	if !strings.Contains(text, "Errors that happened then may be missing. The cause is not known.") {
		t.Errorf("no word on the cause:\n%s", text)
	}
	if !strings.Contains(fr, "peuvent manquer. La cause n'est pas connue.") {
		t.Errorf("no word on the cause (fr):\n%s", fr)
	}
	// Past the window it is gone.
	d2, err := Compute(ctx, l.st, now.Add(30*time.Hour), i18n.EN, Options{Since: now})
	if err != nil || len(d2.ServerLogs) != 0 {
		t.Errorf("later: %v %+v", err, d2.ServerLogs)
	}
}

const sampleText = "Undefined index in array"

func TestDigestNoTextByDefault(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	l.apply("FreshException", serverlog.LevelError, 3, now.Add(-time.Hour), sampleText)
	d, s := l.logSection(i18n.EN)
	text, _ := RenderText(d)
	page, _ := RenderHTML(d)
	raw, _ := json.Marshal(d)
	if s.Top[0].Text != "" || strings.Contains(text+page+string(raw), sampleText) {
		t.Errorf("text in the digest with the default settings:\n%s", text)
	}
}

// A log that grew past the read cap is told in one line per server, with the
// sum of the period, unless errors go nowhere on this server.
func TestDigestTellsTheVolumeLeftUnread(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	other, err := l.repo.AddSource(ctx, serverlog.Source{TargetID: l.tgt.ID, Path: "/var/log/demo/other.log", Format: serverlog.FormatPHP, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	skipped := func(src string, to time.Time, n int64) {
		t.Helper()
		if err := l.repo.AddNote(ctx, serverlog.Note{TargetID: l.tgt.ID, SourceID: src, Kind: serverlog.NoteSkipped, From: to.Add(-5 * time.Minute), To: to, Amount: n}); err != nil {
			t.Fatal(err)
		}
	}
	skipped(l.src.ID, now.Add(-2*time.Hour), 30<<20)
	skipped(other.ID, now.Add(-time.Hour), 10<<20)
	// Before the period, and after it: not counted here.
	skipped(l.src.ID, now.Add(-100*time.Hour), 1<<30)
	skipped(l.src.ID, now.Add(time.Hour), 1<<30)

	d, s := l.logSection(i18n.EN)
	if s.Skipped != 40<<20 {
		t.Fatalf("skipped = %d", s.Skipped)
	}
	text, _ := RenderText(d)
	page, _ := RenderHTML(d)
	for name, out := range map[string]string{"text": text, "html": page} {
		if strings.Count(out, "40 MiB of the logs of this server were not read") != 1 {
			t.Errorf("%s:\n%s", name, out)
		}
		if strings.Contains(out, "/var/log") {
			t.Errorf("%s names a file:\n%s", name, out)
		}
	}
	fr := l.compute(i18n.FR, Options{})
	frText, _ := RenderText(fr)
	frPage, _ := RenderHTML(fr)
	for name, out := range map[string]string{"text": frText, "html": frPage} {
		if strings.Count(out, "40 Mio des journaux de ce serveur") != 1 {
			t.Errorf("fr %s:\n%s", name, out)
		}
	}

	// No error of this level goes anywhere: neither does this line.
	l.settings(func(st *serverlog.Settings) { st.Routes[serverlog.LevelError] = serverlog.RouteIgnored })
	if d := l.compute(i18n.EN, Options{}); len(d.ServerLogs) != 0 {
		t.Errorf("sections with the route ignored: %+v", d.ServerLogs)
	}
}

func TestDigestTextFollowsAlertSetting(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	// The text is kept but not sent in alerts: not in the digest either.
	l.settings(func(s *serverlog.Settings) { s.StoreText = true })
	l.apply("FreshException", serverlog.LevelError, 3, now.Add(-time.Hour), sampleText)
	// An address that got through the filter is dropped before it is stored.
	l.apply("AddressException", serverlog.LevelError, 3, now.Add(-time.Hour), "refused for admin@example.test from 203.0.113.9 at https://example.test/a?b=c")
	d, s := l.logSection(i18n.EN)
	for _, it := range s.Top {
		if it.Text != "" {
			t.Errorf("text without the alert setting: %+v", it)
		}
	}
	if out, _ := RenderText(d); strings.Contains(out, sampleText) {
		t.Errorf("text:\n%s", out)
	}
	l.settings(func(s *serverlog.Settings) { s.AlertText = true })
	d, s = l.logSection(i18n.EN)
	var shown, address int
	for _, it := range s.Top {
		if it.Type == "FreshException" && it.Text == sampleText {
			shown++
		}
		if it.Type == "AddressException" && it.Text != "" {
			address++
		}
	}
	if shown != 1 || address != 0 {
		t.Fatalf("top = %+v", s.Top)
	}
	text, _ := RenderText(d)
	page, _ := RenderHTML(d)
	raw, _ := json.Marshal(d)
	for name, out := range map[string]string{"text": text, "html": page, "json": string(raw)} {
		if !strings.Contains(out, sampleText) {
			t.Errorf("%s lacks the text:\n%s", name, out)
		}
		for _, bad := range []string{"admin@", "203.0.113", "example.test/a"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s holds %q", name, bad)
			}
		}
	}
	// Back to "none": the stored text is erased and the digest has none.
	if _, err := l.repo.EraseText(context.Background(), l.tgt.ID); err != nil {
		t.Fatal(err)
	}
	l.settings(func(s *serverlog.Settings) { s.AlertText, s.StoreText = false, false })
	d, _ = l.logSection(i18n.EN)
	if out, _ := RenderText(d); strings.Contains(out, sampleText) {
		t.Errorf("text after the return to none:\n%s", out)
	}
}

func TestDeviationRemindedWeekly(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	l.settings(func(s *serverlog.Settings) { s.StoreText, s.AlertText = true, true })
	d, s := l.logSection(i18n.EN)
	if len(s.Deviations) != 2 || s.Deviations[0] != serverlog.DeviationStoreText || s.Deviations[1] != serverlog.DeviationAlertText {
		t.Fatalf("deviations = %v", s.Deviations)
	}
	text, _ := RenderText(d)
	for _, want := range []string{"Reminder, once a week", "keeps the text of the errors", "sent in the alerts"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	fr, _ := RenderText(l.compute(i18n.FR, Options{}))
	if !strings.Contains(fr, "Rappel de la semaine") {
		t.Errorf("fr:\n%s", fr)
	}
	if page, _ := RenderHTML(d); !strings.Contains(page, "<li>Reminder, once a week") {
		t.Errorf("html:\n%s", page)
	}
	// The run that carried it is the mark: three days later nothing, a week
	// later it comes back.
	run := RunOf(d, now)
	if run.Summary["deviation_reminded"] != 1 {
		t.Fatalf("summary = %v", run.Summary)
	}
	if err := NewRepo(l.st).Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		after time.Duration
		want  bool
	}{{3 * 24 * time.Hour, false}, {6*24*time.Hour + 23*time.Hour, false}, {7 * 24 * time.Hour, true}, {9 * 24 * time.Hour, true}} {
		got, err := Compute(ctx, l.st, now.Add(c.after), i18n.EN, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if has := len(got.ServerLogs) == 1 && len(got.ServerLogs[0].Deviations) > 0; has != c.want {
			t.Errorf("after %v: reminded = %v, want %v (%+v)", c.after, has, c.want, got.ServerLogs)
		}
	}
	// A run that did not carry it does not reset the week.
	plain := RunOf(Digest{Since: now, Until: now.Add(24 * time.Hour), Lang: i18n.EN}, now.Add(24*time.Hour))
	if plain.Summary["deviation_reminded"] != 0 {
		t.Errorf("summary = %v", plain.Summary)
	}
	if err := NewRepo(l.st).Save(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if got, err := Compute(ctx, l.st, now.Add(7*24*time.Hour), i18n.EN, Options{}); err != nil || len(got.ServerLogs) != 1 {
		t.Errorf("a plain run reset the week: %v %+v", err, got.ServerLogs)
	}
	// Back to the recommended choice: no reminder at all.
	l.settings(func(s *serverlog.Settings) { s.StoreText, s.AlertText = false, false })
	got, err := Compute(ctx, l.st, now.Add(30*24*time.Hour), i18n.EN, Options{})
	if err != nil || len(got.ServerLogs) != 0 {
		t.Errorf("after the return to the recommended choice: %v %+v", err, got.ServerLogs)
	}
}

func TestDigestRespectsScopedChannels(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	l.seedWindow()
	l.settings(func(s *serverlog.Settings) { s.StoreText, s.AlertText = true, true })
	d, _ := l.logSection(i18n.EN)
	// A channel limited to projects gets no server section, nor the errors in its counters.
	scoped := Filter(d, []string{"demo"})
	if len(scoped.ServerLogs) != 0 {
		t.Fatalf("scoped = %+v", scoped.ServerLogs)
	}
	if scoped.NewTotal != 0 {
		t.Errorf("scoped new total = %d", scoped.NewTotal)
	}
	for _, render := range []func(Digest) (string, error){RenderText, RenderHTML} {
		out, err := render(scoped)
		if err != nil || strings.Contains(out, "FreshException") || strings.Contains(out, "srv-demo") {
			t.Errorf("scoped render: %v\n%s", err, out)
		}
	}
	// The other channels get the section as it is, in text and HTML.
	all := ForChannel(d)
	if len(all.ServerLogs) != 1 || len(all.ServerLogs[0].Top) != len(d.ServerLogs[0].Top) {
		t.Fatalf("channel copy = %+v", all.ServerLogs)
	}
	for _, render := range []func(Digest) (string, error){RenderText, RenderHTML} {
		out, err := render(all)
		if err != nil || !strings.Contains(out, "FreshException") {
			t.Errorf("render: %v\n%s", err, out)
		}
	}
	// A project filter naming no project leaves the logs out too.
	if g := Filter(d, []string{"nobody"}); len(g.ServerLogs) != 0 {
		t.Errorf("filter nobody = %+v", g.ServerLogs)
	}
}

func TestInactiveServerIsNotInTheDigest(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	l.apply("FreshException", serverlog.LevelError, 3, now.Add(-time.Hour), "")
	if _, err := l.st.DB().Exec(`UPDATE target SET active = 0`); err != nil {
		t.Fatal(err)
	}
	if d := l.compute(i18n.EN, Options{}); len(d.ServerLogs) != 0 {
		t.Errorf("sections = %+v", d.ServerLogs)
	}
}

// Reproduction of finding C1: an error read after the last digest is told in
// the next one even when the hour written in its log is older than that digest.
func TestDigestCountsErrorsByReadTime(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	if err := NewRepo(l.st).Save(ctx, Run{Since: now.Add(-25 * time.Hour), Until: now.Add(-time.Hour), Lang: i18n.EN, CreatedAt: now.Add(-time.Hour),
		Channels: []ChannelResult{{Name: "hook", Type: "webhook", Result: "ok"}}}); err != nil {
		t.Fatal(err)
	}
	// Written five hours ago, read half an hour ago: after the digest.
	r := serverlog.Record{Level: serverlog.LevelError, Type: "LateException", Location: "Demo.php:42", Hour: now.Add(-5 * time.Hour), Count: 7}
	if _, _, _, err := l.repo.Apply(ctx, l.src, []serverlog.Record{r}, now.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, s := l.logSection(i18n.EN)
	if s.New != 1 || len(s.Top) != 1 || s.Top[0].Type != "LateException" || s.Top[0].Count != 7 {
		t.Fatalf("section = %+v", s)
	}
}

// Each reading falls in exactly one of two digests that follow each other,
// the boundary included.
func TestDigestCountsEachReadingOnce(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	boundary := now.Add(-time.Hour)
	read := func(typ string, at time.Time) {
		r := serverlog.Record{Level: serverlog.LevelError, Type: typ, Location: "Demo.php:42", Hour: boundary.Truncate(time.Hour), Count: 1}
		if _, _, _, err := l.repo.Apply(ctx, l.src, []serverlog.Record{r}, at); err != nil {
			t.Fatal(err)
		}
	}
	read("BeforeException", boundary.Add(-2*time.Second))
	read("OnTheLineException", boundary)
	read("AfterException", boundary.Add(2*time.Second))
	types := func(d Digest) string {
		var out []string
		for _, s := range d.ServerLogs {
			for _, it := range s.Top {
				out = append(out, it.Type)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	first, err := Compute(ctx, l.st, boundary, i18n.EN, Options{Since: boundary.Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compute(ctx, l.st, now, i18n.EN, Options{Since: boundary})
	if err != nil {
		t.Fatal(err)
	}
	a, b := types(first), types(second)
	for _, typ := range []string{"BeforeException", "OnTheLineException", "AfterException"} {
		if strings.Contains(a, typ) == strings.Contains(b, typ) {
			t.Errorf("%s is in %q and %q: it must be in exactly one", typ, a, b)
		}
	}
}

// Finding I2: an error back three days ago and still coming is not told as
// back again in today's digest.
func TestReopenedIsToldOnceInTheWindowItReturned(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	l.apply("BackException", serverlog.LevelError, 2, now.Add(-10*24*time.Hour), "")
	if err := l.repo.SetStatus(ctx, l.sig("BackException").ID, serverlog.StatusResolved); err != nil {
		t.Fatal(err)
	}
	l.apply("BackException", serverlog.LevelError, 4, now.Add(-3*24*time.Hour), "")
	l.apply("BackException", serverlog.LevelError, 4, now.Add(-time.Hour), "")
	d := l.compute(i18n.EN, Options{})
	if len(d.ServerLogs) != 1 || d.ServerLogs[0].Reopened != 0 || d.NewTotal != 0 || strings.Contains(d.Title, "nothing new") {
		t.Fatalf("told again: %+v total %d title %q", d.ServerLogs, d.NewTotal, d.Title)
	}
	// In the window it came back, it is told.
	d, err := Compute(ctx, l.st, now.Add(-2*24*time.Hour), i18n.EN, Options{Since: now.Add(-4 * 24 * time.Hour)})
	if err != nil || len(d.ServerLogs) != 1 || d.ServerLogs[0].Reopened != 1 {
		t.Errorf("window of the return: %v %+v", err, d.ServerLogs)
	}
}

// Ruling R27: the most frequent errors of the window are listed, not only
// the ones that spiked; new and back ones come first; only those count as new.
func TestDigestListsSteadyFrequentErrors(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	ctx := context.Background()
	l.apply("SteadyException", serverlog.LevelError, 1, now.Add(-10*24*time.Hour), "")
	for h := 1; h <= 3; h++ {
		r := serverlog.Record{Level: serverlog.LevelError, Type: "SteadyException", Location: "Demo.php:42", Hour: now.Add(-time.Duration(h) * time.Hour).Truncate(time.Hour), Count: 90}
		if _, _, _, err := l.repo.Apply(ctx, l.src, []serverlog.Record{r}, now.Add(-time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	l.apply("QuietException", serverlog.LevelError, 3, now.Add(-10*24*time.Hour), "")
	l.apply("QuietException", serverlog.LevelError, 3, now.Add(-2*time.Hour), "")
	l.apply("IgnoredBusyException", serverlog.LevelError, 1, now.Add(-10*24*time.Hour), "")
	l.apply("IgnoredBusyException", serverlog.LevelError, 500, now.Add(-2*time.Hour), "")
	if err := l.repo.SetStatus(ctx, l.sig("IgnoredBusyException").ID, serverlog.StatusIgnored); err != nil {
		t.Fatal(err)
	}
	l.apply("FreshException", serverlog.LevelWarning, 1, now.Add(-time.Hour), "")
	l.apply("NewException", serverlog.LevelError, 2, now.Add(-time.Hour), "")
	d, s := l.logSection(i18n.EN)
	var got []string
	for _, it := range s.Top {
		got = append(got, string(it.Kind)+":"+it.Type)
	}
	if strings.Join(got, ",") != "new:NewException,frequent:SteadyException,frequent:QuietException" {
		t.Fatalf("top = %v", got)
	}
	if s.Top[1].Count != 270 || d.NewTotal != 1 || s.New != 1 {
		t.Errorf("count %d, new total %d, new %d", s.Top[1].Count, d.NewTotal, s.New)
	}
	text, _ := RenderText(d)
	if !strings.Contains(text, "- SteadyException, Demo.php:42, 270 times\n") || strings.Contains(text, "(often)") {
		t.Errorf("text:\n%s", text)
	}
	// Only a frequent error: not "nothing new".
	if err := l.repo.SetStatus(ctx, l.sig("NewException").ID, serverlog.StatusIgnored); err != nil {
		t.Fatal(err)
	}
	d, _ = l.logSection(i18n.EN)
	if strings.Contains(d.Title, "nothing new") || d.Word != "" {
		t.Errorf("title %q word %q", d.Title, d.Word)
	}
	page, _ := RenderHTML(d)
	if strings.Contains(page, "<li>- ") {
		t.Errorf("html has a text bullet:\n%s", page)
	}
}

// Ruling R27b: no floor. An error read a few times is listed when a slot is
// free, the cap drops the least frequent, and a frequent item has no label.
func TestDigestFrequentListIsCappedWithoutAFloor(t *testing.T) {
	l := newLogFixture(t, target.EnvProd)
	for i := 1; i <= 7; i++ {
		typ := fmt.Sprintf("Old%dException", i)
		l.apply(typ, serverlog.LevelError, 1, now.Add(-10*24*time.Hour), "")
		l.apply(typ, serverlog.LevelError, int64(i), now.Add(-time.Hour), "")
	}
	d, s := l.logSection(i18n.EN)
	if len(s.Top) != MaxLogTop || s.Top[0].Type != "Old7Exception" || s.Top[4].Type != "Old3Exception" || s.Top[4].Count != 3 {
		t.Fatalf("top = %+v", s.Top)
	}
	text, _ := RenderText(d)
	if !strings.Contains(text, "- Old7Exception, Demo.php:42, 7 times\n") || strings.Contains(text, "Old2Exception") || strings.Contains(text, "(often)") {
		t.Errorf("text:\n%s", text)
	}
}
