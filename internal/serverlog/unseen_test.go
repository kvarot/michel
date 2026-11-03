package serverlog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/target"
)

// The filter says why a file was not read, with a closed code, and nothing
// else: a refused link must not read as a rights problem.
func TestUnseenCauseIsTheTrueOne(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	cause := func(path string, o FilterOptions) string {
		t.Helper()
		out := pass(t, path, earlier, o)
		if len(out.Unseen) != 1 || out.Unseen[0] != path {
			t.Fatalf("%s: unseen = %+v", path, out)
		}
		return out.UnseenCause[path]
	}
	if got := cause(shPath(filepath.Join(dir, "missing.log")), FilterOptions{}); got != CauseAbsent {
		t.Errorf("missing file: %q", got)
	}
	sub := filepath.Join(dir, "sub.log")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := cause(shPath(sub), FilterOptions{}); got != CauseNotFile {
		t.Errorf("a folder: %q", got)
	}
	// A wildcard that matches nothing is an absent file, too.
	wild := shPath(filepath.Join(dir, "none-*.log"))
	if got := cause(wild, FilterOptions{}); got != CauseAbsent {
		t.Errorf("a wildcard without a match: %q", got)
	}
	real := filepath.Join(dir, "real.log")
	if err := os.WriteFile(real, []byte(warnLine), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(real, link); err == nil {
		if got := cause(shPath(link), FilterOptions{}); got != CauseLink {
			t.Errorf("a symbolic link: %q", got)
		}
	} else {
		t.Logf("no symbolic link on this machine: %v", err)
	}
	// The tools are missing: the cause is the tools, not the rights.
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not installed")
	}
	src := Source{Path: shPath(real), Format: FormatPHP}
	script, err := Script(src, earlier, FilterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "PATH="+t.TempDir())
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v", err)
	}
	if out := ParseOutput(raw, src, FilterOptions{}, filterNow); out.UnseenCause[src.Path] != CauseTools {
		t.Errorf("no tools: %+v", out)
	}
}

func TestUnseenCauseDeniedForARightsProblem(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.log")
	if err := os.WriteFile(secret, []byte(warnLine), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := denyRead(t, secret)
	defer allow()
	out := pass(t, shPath(secret), earlier, FilterOptions{})
	if len(out.Unseen) != 1 || out.UnseenCause[shPath(secret)] != CauseDenied {
		t.Errorf("denied file: %+v", out)
	}
	// A file that is absent in a folder nobody can search is a rights problem.
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "app.log"), []byte(warnLine), 0o644); err != nil {
		t.Fatal(err)
	}
	allowDir := denyDir(t, locked)
	defer allowDir()
	if _, err := os.Stat(filepath.Join(locked, "app.log")); err == nil {
		t.Skip("the folder can still be searched on this machine")
	}
	missing := shPath(filepath.Join(locked, "gone.log"))
	out = pass(t, missing, earlier, FilterOptions{})
	if len(out.Unseen) != 1 || out.UnseenCause[missing] != CauseDenied {
		t.Errorf("file in an unsearchable folder: %+v", out)
	}
}

// The cause is revalidated like every field: an unknown code, or none, is a
// refused line, and the file is not listed.
func TestParseRefusesAnUnknownOrMissingUnseenCause(t *testing.T) {
	src := Source{Path: parsePath, Format: FormatMonolog}
	for name, line := range map[string]string{
		"none":    "U\t" + parsePath,
		"unknown": "U\t" + parsePath + "\troot",
		"empty":   "U\t" + parsePath + "\t",
		"extra":   "U\t" + parsePath + "\tdenied\textra",
	} {
		out := ParseOutput([]byte(line+"\n"), src, FilterOptions{}, filterNow)
		if len(out.Unseen) != 0 || out.Rejected != 1 {
			t.Errorf("%s: %+v", name, out)
		}
	}
	for _, c := range []string{CauseDenied, CauseLink, CauseAbsent, CauseNotFile, CauseTools, CauseOther} {
		out := ParseOutput([]byte("U\t"+parsePath+"\t"+c+"\n"), src, FilterOptions{}, filterNow)
		if len(out.Unseen) != 1 || out.UnseenCause[parsePath] != c {
			t.Errorf("%s: %+v", c, out)
		}
	}
}

// A pass keeps the unseen files of each source with their cause, says how many
// to its caller, and forgets them once they can be read.
func TestPassKeepsUnseenFilesUntilTheyCanBeRead(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatPHP)
	ctx := context.Background()
	missing := pe.src
	missing.Path = shPath(filepath.Join(filepath.Dir(pe.file), "later.log"))
	if err := pe.repo.UpdateSource(ctx, missing); err != nil {
		t.Fatal(err)
	}
	res := pe.run()
	if res.Unseen != 1 {
		t.Fatalf("result = %+v", res)
	}
	got, err := pe.repo.Unseen(ctx, pe.tgt.ID)
	if err != nil || len(got[pe.src.ID]) != 1 || got[pe.src.ID][0].File != missing.Path || got[pe.src.ID][0].Cause != CauseAbsent {
		t.Fatalf("unseen = %+v %v", got, err)
	}
	appendTo(t, filepath.Join(filepath.Dir(pe.file), "later.log"), "")
	pe.run()
	if got, _ := pe.repo.Unseen(ctx, pe.tgt.ID); len(got) != 0 {
		t.Errorf("a readable file stays listed: %+v", got)
	}
}

func TestForgetTargetErasesEverythingOfAServer(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	ign := rec(1, t0)
	ign.Type = "IgnoredException"
	text := rec(2, t0)
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	text.Text = "Connection refused for <str>"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{text, ign}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetStatus(ctx, SignatureID(e.src.ID, ign.Level, ign.Type, ign.Location, ign.Channel), StatusIgnored); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SaveCursors(ctx, []Cursor{{SourceID: e.src.ID, File: "/var/log/demo/app.log", FileID: "1:2", Offset: 10, ReadAt: t0}}); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetUnseen(ctx, e.src.ID, map[string]string{"/var/log/demo/app.log": CauseDenied}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.AddNote(ctx, Note{TargetID: e.tgt.ID, SourceID: e.src.ID, Kind: NoteGap, From: t0, To: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if erased, err := ForgetTargetAudited(ctx, e.r, log, "web", e.tgt.ID); err != nil || !erased {
		t.Fatal(err)
	}
	for _, tb := range []string{"log_signature", "log_bucket", "log_read", "log_cursor", "log_note", "log_unseen", "log_source", "log_settings"} {
		if n := count(t, e, `SELECT COUNT(*) FROM `+tb); n != 0 {
			t.Errorf("%s holds %d rows after the server was forgotten", tb, n)
		}
	}
	ev := auditEvidence(t, e, "log.purge")
	if len(ev) != 1 || !strings.Contains(ev[0], `"scope":"server_removed"`) || strings.Contains(ev[0], "Connection") {
		t.Errorf("log.purge = %v", ev)
	}
}

func TestUpdateSourceResetIsOneStep(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	if err := e.r.SaveCursors(ctx, []Cursor{{SourceID: e.src.ID, File: e.src.Path, FileID: "1:2", Offset: 10, ReadAt: t0}}); err != nil {
		t.Fatal(err)
	}
	bad := e.src
	bad.Path = "relative.log"
	if err := e.r.UpdateSourceReset(ctx, bad, true, t0); err == nil {
		t.Fatal("an invalid source was saved")
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_cursor`); n != 1 {
		t.Errorf("a refused update forgot the positions: %d", n)
	}
	moved := e.src
	moved.Path = "/var/log/demo/other.log"
	if err := e.r.UpdateSourceReset(ctx, moved, true, t0); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_cursor`); n != 0 {
		t.Errorf("positions left after a reset: %d", n)
	}
	if got, _ := e.r.Sources(ctx, e.tgt.ID); len(got) != 1 || got[0].Path != moved.Path {
		t.Errorf("sources = %+v", got)
	}
	if got, _ := e.r.Sources(ctx, e.tgt.ID); !got[0].PathAt.Equal(t0) {
		t.Errorf("the date of the path change = %v", got[0].PathAt)
	}
	moved.Active = false
	if err := e.r.UpdateSourceReset(ctx, moved, false, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.r.Sources(ctx, e.tgt.ID); !got[0].PathAt.Equal(t0) {
		t.Errorf("a change of something else moved the date of the path change: %v", got[0].PathAt)
	}
}

func TestRetentionMovedAwayFromTheRecommendedChoiceNeedsConfirmAgain(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.RetentionDays = 100
	if err := ChangeSettings(ctx, e.r, log, e.tgt, st, true); err != nil {
		t.Fatal(err)
	}
	st.RetentionDays = 365
	if err := ChangeSettings(ctx, e.r, log, e.tgt, st, false); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("100 to 365 days without confirmation: %v", err)
	}
	if got := NewDeviations(Settings{RetentionDays: 100}, Settings{RetentionDays: 100}); len(got) != 0 {
		t.Errorf("the same value is no new step: %v", got)
	}
	if got := NewDeviations(Settings{RetentionDays: 100}, Settings{RetentionDays: 90}); len(got) != 0 {
		t.Errorf("going back is no step: %v", got)
	}
}

func TestSettingsHaveUpperBounds(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	for name, mod := range map[string]func(s *Settings){
		"cap":     func(s *Settings) { s.ReadCap = MaxReadCap + 1 },
		"timeout": func(s *Settings) { s.ReadTimeout = MaxReadTimeout + time.Second },
		"factor":  func(s *Settings) { s.SpikeFactor = 1 },
		"min":     func(s *Settings) { s.SpikeMin = 0 },
		"min max": func(s *Settings) { s.SpikeMin = MaxSpikeMin + 1 },
	} {
		st, _ := e.r.Settings(ctx, e.tgt.ID)
		mod(&st)
		if err := e.r.SaveSettings(ctx, st); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.ReadCap, st.ReadTimeout = MaxReadCap, MaxReadTimeout
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Errorf("the bounds themselves: %v", err)
	}
}

func TestSpikeThresholdIsASetting(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	if st.SpikeFactor != 10 || st.SpikeMin != 100 {
		t.Fatalf("defaults = %d, %d", st.SpikeFactor, st.SpikeMin)
	}
	st.SpikeFactor, st.SpikeMin = 3, 20
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.r.Settings(ctx, e.tgt.ID); got.SpikeFactor != 3 || got.SpikeMin != 20 {
		t.Fatalf("saved = %d, %d", got.SpikeFactor, got.SpikeMin)
	}
	first := rec(5, t0)
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{first}, t0); err != nil {
		t.Fatal(err)
	}
	// 30 occurrences the next hour: a spike at 3 times and 20, not at 10 and 100.
	next := rec(30, t0.Add(time.Hour))
	_, _, spiked, err := e.r.Apply(ctx, e.src, []Record{next}, t0.Add(time.Hour))
	if err != nil || len(spiked) != 1 {
		t.Errorf("spiked = %+v %v", spiked, err)
	}
}

// The masked text that is stored comes back: the masker's own marker holds digits,
// which the check of a raw text refuses, so the check must know the marker.
func TestStoredMaskedTextComesBack(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	r := rec(2, t0)
	r.Text = "Login failed password: hunter in [path]"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0); err != nil {
		t.Fatal(err)
	}
	id := SignatureID(e.src.ID, r.Level, r.Type, r.Location, r.Channel)
	txt, ok, err := e.r.Text(ctx, id)
	if err != nil || !ok || strings.Contains(txt, "hunter") || !strings.HasPrefix(txt, "Login failed password: [secret-") {
		t.Errorf("stored text = %q %v %v", txt, ok, err)
	}
	// A forged marker with digits is no way to carry digits in: the rest of the
	// check still applies.
	if _, ok := cleanedText("call [secret-12345678-1] 0612345678"); ok {
		t.Errorf("digits outside a marker passed")
	}
}

// The causes are the same under every shell the servers may have.
func TestUnseenCauseUnderEachShell(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub.log")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sh := range [][]string{{"sh"}, {"dash"}, {"busybox", "sh"}} {
		if _, err := exec.LookPath(sh[0]); err != nil {
			continue
		}
		t.Run(strings.Join(sh, "-"), func(t *testing.T) {
			for path, want := range map[string]string{shPath(filepath.Join(dir, "missing.log")): CauseAbsent, shPath(sub): CauseNotFile,
				shPath(filepath.Join(dir, "none-*.log")): CauseAbsent} {
				src := Source{Path: path, Format: FormatPHP}
				script, err := Script(src, earlier, FilterOptions{})
				if err != nil {
					t.Fatal(err)
				}
				out := ParseOutput(runWith(t, script, sh, ""), src, FilterOptions{}, filterNow)
				if out.UnseenCause[path] != want || out.Rejected != 0 {
					t.Errorf("%s: %+v, want %s", path, out, want)
				}
			}
		})
	}
}

// A pass that read nothing leaves the read dates alone: the date of a file that
// cannot be opened today is the day it was last read, not the day of the pass.
func TestPassDoesNotTouchTheDateOfWhatItDidNotRead(t *testing.T) {
	for _, wildcard := range []bool{false, true} {
		name := "plain file"
		if wildcard {
			name = "wildcard"
		}
		t.Run(name, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatPHP)
			ctx := context.Background()
			if wildcard {
				src := pe.src
				src.Path = shPath(filepath.Dir(pe.file)) + "/app-*.log"
				pe.file = filepath.Join(filepath.Dir(pe.file), "app-1.log")
				appendTo(t, pe.file, "")
				if err := pe.repo.UpdateSource(ctx, src); err != nil {
					t.Fatal(err)
				}
				pe.src = src
			}
			pe.activate()
			pe.write("PHP Warning:  x in /var/www/demo/a.php on line 3")
			readAt := pe.clock.Now()
			pe.run()
			cs, _ := pe.repo.Cursors(ctx, pe.src.ID)
			if len(cs) != 1 || !cs[0].ReadAt.Equal(readAt) {
				t.Fatalf("after the read: %+v", cs)
			}
			pe.clock.Advance(10 * time.Minute)
			if err := os.Remove(pe.file); err != nil {
				t.Fatal(err)
			}
			if res := pe.run(); res.Unseen != 1 {
				t.Fatalf("the pass that follows: %+v", res)
			}
			cs, _ = pe.repo.Cursors(ctx, pe.src.ID)
			for _, c := range cs {
				if !c.ReadAt.Equal(readAt) {
					t.Errorf("the date of %s moved to %v by a pass that read nothing (read at %v)", c.File, c.ReadAt, readAt)
				}
			}
		})
	}
}

// A file that cannot be opened when the source is activated is located by its
// metadata, but it was not read: its position carries no read date.
func TestActivationOfAnUnreadableFileLeavesNoReadDate(t *testing.T) {
	needTools(t)
	pe := newPassEnv(t, target.EnvProd, FormatPHP)
	appendTo(t, pe.file, "PHP Warning:  x in /var/www/demo/a.php on line 3\n")
	allow := denyRead(t, pe.file)
	defer allow()
	pe.run()
	cs, _ := pe.repo.Cursors(context.Background(), pe.src.ID)
	for _, c := range cs {
		if c.File == pe.src.Path && !c.ReadAt.IsZero() {
			t.Errorf("a file never read has the read date %v", c.ReadAt)
		}
	}
	if un, _ := pe.repo.Unseen(context.Background(), pe.tgt.ID); len(un[pe.src.ID]) != 1 {
		t.Skip("the file can still be read on this machine")
	}
}

// A marker of the masker cut by the cap is dropped, so that the text that is
// stored comes back (a half marker is refused by the check).
func TestMarkerCutByTheCapIsDropped(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	st, _ := e.r.Settings(ctx, e.tgt.ID)
	st.StoreText = true
	if err := e.r.SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	half := regexp.MustCompile(`\[secret[^\]]*$`)
	cut := 0
	for n := 160; n <= 183; n++ {
		r := rec(1, t0)
		r.Type = fmt.Sprintf("Cut%d", n)
		r.Text = strings.Repeat("a", n) + " password: hunter"
		if _, _, _, err := e.r.Apply(ctx, e.src, []Record{r}, t0); err != nil {
			t.Fatal(err)
		}
		txt, ok, err := e.r.Text(ctx, SignatureID(e.src.ID, r.Level, r.Type, r.Location, r.Channel))
		if err != nil || !ok || half.MatchString(txt) || strings.Contains(txt, "hunter") {
			t.Fatalf("filler %d: %q %v %v", n, txt, ok, err)
		}
		if !strings.Contains(txt, "[secret-") {
			cut++
		}
	}
	if cut == 0 {
		t.Errorf("no filler length made the cap cut the marker: the test checks nothing")
	}
}

// The check lets the masker's own marker through and nothing else with digits.
func TestMarkerExemptionIsNarrow(t *testing.T) {
	// Read side (a text that was masked and stored): the marker is a word, nothing
	// else with digits passes.
	for text, want := range map[string]bool{
		"x [secret-41111111-1] y":                  true,
		"x [secret-41111111-1111111111111111] y":   false,
		"x [secret-41111111-1] 198.51.100.7":       false,
		"x [secret-41111111-1] jean.dupont@host":   false,
		"x [secret-41111111-1] https://host/a?b=c": false,
		"x [secret-4111111-1] y":                   false,
		"x [secret-41111111-1":                     false,
		"call [secret-12345678-1] 0612345678":      false,
	} {
		if _, ok := readBackText(text); ok != want {
			t.Errorf("readBackText(%q) = %v, want %v", text, ok, want)
		}
	}
	// Write side (a raw text from the filter, the seal, the alerts): strict, a
	// marker is not welcome in it.
	for _, raw := range []string{"x [secret-41111111-1] y", "x [secret-41111111-1111111111111111] y", "ip 198.51.100.7", "jean.dupont@host", "https://host/a"} {
		if _, ok := cleanedText(raw); ok {
			t.Errorf("cleanedText(%q) passed", raw)
		}
		if enc, _ := sealText(raw); enc != nil {
			t.Errorf("sealText(%q) sealed a raw text that is not clean", raw)
		}
	}
}
