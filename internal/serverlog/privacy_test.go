package serverlog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/target"
)

func auditor(e env) *audit.Logger { return audit.NewLogger(e.s, func() time.Time { return t0 }) }

// auditEvidence returns the evidence JSON of every event with this action.
func auditEvidence(t *testing.T, e env, action string) []string {
	t.Helper()
	rows, err := e.s.DB().Query(`SELECT evidence FROM audit_event WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func TestDeviationNeedsConfirmation(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	cur, _ := e.r.Settings(ctx, e.tgt.ID)
	if d := Deviations(cur); len(d) != 0 {
		t.Fatalf("defaults deviate: %v", d)
	}
	next := cur
	next.StoreText = true
	if err := ChangeSettings(ctx, e.r, log, e.tgt, next, false); !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("unconfirmed text = %v, want ErrConfirmationNeeded", err)
	}
	if got, _ := e.r.Settings(ctx, e.tgt.ID); got.StoreText {
		t.Fatal("an unconfirmed deviation was saved")
	}
	if n := len(auditEvidence(t, e, "log.settings")); n != 0 {
		t.Fatalf("a refused change was audited %d times", n)
	}
	if err := ChangeSettings(ctx, e.r, log, e.tgt, next, true); err != nil {
		t.Fatal(err)
	}
	// A shorter retention is a choice away from the recommendation too.
	short := next
	short.RetentionDays = 30
	if err := ChangeSettings(ctx, e.r, log, e.tgt, short, false); !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("unconfirmed retention = %v", err)
	}
	if err := ChangeSettings(ctx, e.r, log, e.tgt, short, true); err != nil {
		t.Fatal(err)
	}
	if d := strings.Join(Deviations(short), ","); d != "store_text,retention" {
		t.Fatalf("Deviations = %q", d)
	}
	// Going back to the recommendation, or staying where one already is,
	// asks nothing.
	back := short
	back.RetentionDays = 90
	if err := ChangeSettings(ctx, e.r, log, e.tgt, back, false); err != nil {
		t.Fatalf("back to the recommended retention = %v", err)
	}
	if err := ChangeSettings(ctx, e.r, log, e.tgt, back, false); err != nil {
		t.Fatalf("a deviation already confirmed asked again: %v", err)
	}
	if n := len(auditEvidence(t, e, "log.settings")); n != 4 {
		t.Fatalf("log.settings events = %d, want 4", n)
	}
}

func TestHDSCanDeviateWithConfirmation(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	hds, err := target.NewRepo(e.s).Add(ctx, target.Target{Name: "srv-health", Host: "192.0.2.20", User: "deploy", Kind: target.KindHDS, Env: target.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	next, _ := e.r.Settings(ctx, hds.ID)
	next.StoreText, next.AlertText, next.RetentionDays = true, true, 365
	if err := ChangeSettings(ctx, e.r, log, hds, next, false); !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("unconfirmed on hds = %v", err)
	}
	if err := ChangeSettings(ctx, e.r, log, hds, next, true); err != nil {
		t.Fatalf("hds must not be blocked (decision 6): %v", err)
	}
	got, _ := e.r.Settings(ctx, hds.ID)
	if !got.StoreText || !got.AlertText || got.RetentionDays != 365 {
		t.Fatalf("saved = %+v", got)
	}
	ev := auditEvidence(t, e, "log.settings")
	if len(ev) != 1 || !strings.Contains(ev[0], `"health":true`) || !strings.Contains(ev[0], `"confirmed":true`) {
		t.Fatalf("audit = %v", ev)
	}
	// A server that is not hds is audited as such.
	n2, _ := e.r.Settings(ctx, e.tgt.ID)
	n2.StoreText = true
	if err := ChangeSettings(ctx, e.r, log, e.tgt, n2, true); err != nil {
		t.Fatal(err)
	}
	if ev := auditEvidence(t, e, "log.settings"); !strings.Contains(ev[1], `"health":false`) {
		t.Fatalf("audit of a non-hds server = %s", ev[1])
	}
}

func TestAlertTextRequiresStoreText(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	next, _ := e.r.Settings(ctx, e.tgt.ID)
	next.AlertText = true
	if err := checkSettings(next); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("checkSettings = %v", err)
	}
	if err := ChangeSettings(ctx, e.r, log, e.tgt, next, true); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("ChangeSettings = %v, want ErrInvalidSettings even when confirmed", err)
	}
	next.StoreText = true
	if err := ChangeSettings(ctx, e.r, log, e.tgt, next, true); err != nil {
		t.Fatal(err)
	}
	// Switching the text off while alerts carry it is refused too.
	off := next
	off.StoreText = false
	if err := ChangeSettings(ctx, e.r, log, e.tgt, off, true); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("text off, alerts on = %v", err)
	}
}

func applyText(t *testing.T, e env, text string) {
	t.Helper()
	r := rec(2, t0)
	r.Text = text
	if _, _, _, err := e.r.Apply(context.Background(), e.src, []Record{r}, t0); err != nil {
		t.Fatal(err)
	}
}

func TestBackToNoneErasesStoredTextNow(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	on, _ := e.r.Settings(ctx, e.tgt.ID)
	on.StoreText = true
	if err := ChangeSettings(ctx, e.r, log, e.tgt, on, true); err != nil {
		t.Fatal(err)
	}
	applyText(t, e, "disk is full")
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 1 {
		t.Fatalf("text rows = %d", n)
	}
	off := on
	off.StoreText = false
	if err := ChangeSettings(ctx, e.r, log, e.tgt, off, false); err != nil {
		t.Fatalf("back to the recommendation asked a confirmation: %v", err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Fatalf("%d texts left after going back to none", n)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature`); n != 1 {
		t.Fatalf("the error itself must stay, rows = %d", n)
	}
	if ev := auditEvidence(t, e, "log.settings"); len(ev) != 2 {
		t.Fatalf("log.settings = %v", ev)
	}
	pv := auditEvidence(t, e, "log.purge")
	if len(pv) != 1 || !strings.Contains(pv[0], `"scope":"text"`) || !strings.Contains(pv[0], `"rows":1`) {
		t.Fatalf("log.purge = %v", pv)
	}
}

// A text left behind (the erasure failed after the settings were saved, or
// anything else) goes at the next save with the text off.
func TestTextOffSaveErasesAStrayText(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	on, _ := e.r.Settings(ctx, e.tgt.ID)
	on.StoreText = true
	if err := e.r.SaveSettings(ctx, on); err != nil {
		t.Fatal(err)
	}
	applyText(t, e, "disk is full")
	off := on
	off.StoreText = false
	if err := e.r.SaveSettings(ctx, off); err != nil { // the erasure never ran
		t.Fatal(err)
	}
	if err := ChangeSettings(ctx, e.r, log, e.tgt, off, false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Fatalf("stray text kept: %d", n)
	}
	if pv := auditEvidence(t, e, "log.purge"); len(pv) != 1 {
		t.Fatalf("log.purge = %v", pv)
	}
}

func TestStoredTextIsEncryptedAndMasked(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	on, _ := e.r.Settings(ctx, e.tgt.ID)
	on.StoreText = true
	if err := e.r.SaveSettings(ctx, on); err != nil {
		t.Fatal(err)
	}
	applyText(t, e, "login failed password=hunter for user")
	var enc []byte
	if err := e.s.DB().QueryRow(`SELECT text_enc FROM log_signature`).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "hunter") {
		t.Fatal("the token is in the database")
	}
	if secret.Protected() && strings.Contains(string(enc), "login failed") {
		t.Fatal("the text is in the database in clear")
	}
	got, err := OpenText(enc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "hunter") || !strings.Contains(got, "login failed password=[secret-") {
		t.Fatalf("stored text = %q", got)
	}
}

func TestStoredTextNeverCarriesIdentifiers(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	on, _ := e.r.Settings(ctx, e.tgt.ID)
	on.StoreText = true
	if err := e.r.SaveSettings(ctx, on); err != nil {
		t.Fatal(err)
	}
	// Shapes the filter replaces: if one reaches Apply, no text is kept.
	for _, bad := range []string{
		"connection from 192.0.2.7 refused", "mail to jean@example.test failed",
		"GET https://example.test/p?token=x failed", "user \"jean\" unknown", strings.Repeat("a", 201),
	} {
		applyText(t, e, bad)
		if n := count(t, e, `SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
			t.Fatalf("text %q was stored", bad)
		}
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature`); n != 1 {
		t.Fatalf("the error must still be counted, rows = %d", n)
	}
}

func TestPurgeAtRetention(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	now := t0.Add(40 * 24 * time.Hour)
	fresh := rec(1, now)
	fresh.Type = "FreshException"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(3, t0)}, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{fresh}, now); err != nil {
		t.Fatal(err)
	}
	// 90 days: nothing expires after 40.
	if err := PurgeAudited(ctx, e.r, log, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature`); n != 2 {
		t.Fatalf("rows at 40 days = %d", n)
	}
	s, _ := e.r.Settings(ctx, e.tgt.ID)
	s.RetentionDays = 30
	if err := ChangeSettings(ctx, e.r, log, e.tgt, s, true); err != nil {
		t.Fatal(err)
	}
	if err := PurgeAudited(ctx, e.r, log, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_signature`); n != 1 {
		t.Fatalf("rows after retention = %d", n)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_bucket`); n != 1 {
		t.Fatalf("hourly counts after retention = %d", n)
	}
	pv := auditEvidence(t, e, "log.purge")
	if len(pv) != 1 || !strings.Contains(pv[0], `"scope":"retention"`) || !strings.Contains(pv[0], `"signatures":1`) { // the run at 40 days removed nothing and is not audited
		t.Fatalf("log.purge = %v", pv)
	}
}

func TestAuditCarriesNoContent(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	on, _ := e.r.Settings(ctx, e.tgt.ID)
	on.StoreText = true
	if err := ChangeSettings(ctx, e.r, log, e.tgt, on, true); err != nil {
		t.Fatal(err)
	}
	applyText(t, e, "quota exceeded password=hunter")
	if _, err := EraseTextAudited(ctx, e.r, log, "web", e.tgt.ID); err != nil {
		t.Fatal(err)
	}
	applyText(t, e, "quota exceeded password=hunter")
	off := on
	off.StoreText = false
	if err := ChangeSettings(ctx, e.r, log, e.tgt, off, false); err != nil {
		t.Fatal(err)
	}
	if err := PurgeAudited(ctx, e.r, log, t0.Add(400*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := e.s.DB().Query(`SELECT action, target, evidence FROM audit_event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var a, tg, ev string
		if err := rows.Scan(&a, &tg, &ev); err != nil {
			t.Fatal(err)
		}
		n++
		for _, w := range []string{"quota", "exceeded", "hunter", "DemoException", "Demo.php", "app.log"} {
			if strings.Contains(a+tg+ev, w) {
				t.Fatalf("audit %s holds %q: %s", a, w, ev)
			}
		}
	}
	if n < 5 {
		t.Fatalf("audit events = %d", n)
	}
}

func TestPurgeAuditedSkipsARunThatRemovesNothing(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{rec(1, t0)}, t0); err != nil {
		t.Fatal(err)
	}
	// Nothing is old enough: no event, whatever the number of ticks.
	for i := 0; i < 3; i++ {
		if err := PurgeAudited(ctx, e.r, log, t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(auditEvidence(t, e, "log.purge")); n != 0 {
		t.Fatalf("%d log.purge events for runs that removed nothing", n)
	}
	// Past the retention it removes, and says so once.
	if err := PurgeAudited(ctx, e.r, log, t0.Add(100*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ev := auditEvidence(t, e, "log.purge")
	if len(ev) != 1 || !strings.Contains(ev[0], `"signatures":1`) {
		t.Fatalf("events = %v", ev)
	}
	if err := PurgeAudited(ctx, e.r, log, t0.Add(101*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(auditEvidence(t, e, "log.purge")); n != 1 {
		t.Fatalf("an empty run after it was audited: %d events", n)
	}
}

func TestEraseTargetAuditedWipesEverythingAndSaysSo(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx, log := context.Background(), auditor(e)
	kept := rec(2, t0)
	ign := rec(1, t0)
	ign.Type = "IgnoredException"
	if _, _, _, err := e.r.Apply(ctx, e.src, []Record{kept, ign}, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SetStatus(ctx, SignatureID(e.src.ID, ign.Level, ign.Type, ign.Location, ign.Channel), StatusIgnored); err != nil {
		t.Fatal(err)
	}
	if err := e.r.SaveCursors(ctx, []Cursor{{SourceID: e.src.ID, File: "/var/log/demo/app.log", FileID: "1:2", Offset: 10, ReadAt: t0}}); err != nil {
		t.Fatal(err)
	}
	if err := e.r.AddNote(ctx, Note{TargetID: e.tgt.ID, SourceID: e.src.ID, Kind: NoteGap, From: t0, To: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := EraseTargetAudited(ctx, e.r, log, "web", e.tgt.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT COUNT(*) FROM log_signature`, `SELECT COUNT(*) FROM log_bucket`, `SELECT COUNT(*) FROM log_cursor`, `SELECT COUNT(*) FROM log_note`} {
		if n := count(t, e, q); n != 0 {
			t.Errorf("%s = %d after the erasure", q, n)
		}
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_source`); n != 1 {
		t.Errorf("the sources stay: %d", n)
	}
	ev := auditEvidence(t, e, "log.purge")
	if len(ev) != 1 || !strings.Contains(ev[0], `"scope":"all"`) || strings.Contains(ev[0], "DemoException") || strings.Contains(ev[0], "app.log") {
		t.Errorf("log.purge = %v", ev)
	}
}
