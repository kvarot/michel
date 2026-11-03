package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

func TestDigestServersSection(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := target.NewRepo(f.st)
	prod, err := repo.Add(ctx, target.Target{Name: "srv-demo", Host: "192.0.2.10", Kind: target.KindVPS, Env: target.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	calm, err := repo.Add(ctx, target.Target{Name: "srv-calm", Host: "192.0.2.11", Kind: target.KindVPS, Env: target.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	_ = calm
	old := now.Add(-10 * 24 * time.Hour)
	recent := now.Add(-2 * time.Hour)
	f.seed(finding{project: prod.ID, pkg: "php", osv: "ACME-1", severity: "critical", firstSeen: recent})
	f.seed(finding{project: prod.ID, pkg: "openssl", osv: "ACME-2", severity: "high", firstSeen: recent})
	f.seed(finding{project: prod.ID, pkg: "curl", osv: "ACME-3", severity: "high", firstSeen: old})
	f.seed(finding{project: prod.ID, pkg: "nginx", osv: "ACME-4", severity: "high", firstSeen: old, status: "gone", changed: recent})
	f.seed(finding{project: prod.ID, pkg: "bash", osv: "ACME-5", severity: "high", firstSeen: old, status: "gone", changed: old})
	// One fix undone in the window, one before it.
	for i, at := range []time.Time{recent, old} {
		if _, err := f.st.DB().Exec(`INSERT INTO fix_attempt (id, finding_id, project_id, origin, state, cause, created_at, updated_at)
			VALUES (?, 'F', ?, 'user', 'failed', 'rolled_back', ?, ?)`, "A"+string(rune('0'+i)), prod.ID, ts(at), ts(at)); err != nil {
			t.Fatal(err)
		}
	}
	d := f.compute(i18n.EN, Options{})
	if len(d.Servers) != 1 || d.Servers[0] != (ServerDigest{Name: "srv-demo", New: 2, Fixed: 1, RolledBack: 1}) {
		t.Fatalf("servers = %+v", d.Servers)
	}
	text, err := RenderText(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Servers:", "srv-demo: 2 new flaws, 1 flaw fixed, 1 fix undone"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "srv-calm") || strings.Contains(text, "openssl") || strings.Contains(text, "ACME-1") {
		t.Errorf("text holds more than counts:\n%s", text)
	}
	fr, err := RenderText(f.compute(i18n.FR, Options{}))
	if err != nil || !strings.Contains(fr, "Serveurs :") || !strings.Contains(fr, "srv-demo : 2 nouvelles failles, 1 faille corrigée, 1 correction annulée") {
		t.Errorf("fr: %v\n%s", err, fr)
	}
	page, err := RenderHTML(d)
	if err != nil || !strings.Contains(page, "<h2>Servers</h2>") || !strings.Contains(page, "srv-demo: 2 new flaws") {
		t.Errorf("html: %v\n%s", err, page)
	}
	// No server touched: no section. A channel limited to projects gets none.
	if g := Filter(d, []string{"demo"}); len(g.Servers) != 0 {
		t.Errorf("filtered servers = %+v", g.Servers)
	}
	if _, err := f.st.DB().Exec(`UPDATE target SET active = 0`); err != nil {
		t.Fatal(err)
	}
	d = f.compute(i18n.EN, Options{})
	text, _ = RenderText(d)
	if len(d.Servers) != 0 || strings.Contains(text, "Servers") {
		t.Errorf("inactive servers listed: %+v", d.Servers)
	}
}

// An exposure counts like any finding of the server, through the very rules
// and the very store: a number in the digest, never a port or an address.
func TestDigestServersCountsExposure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tg, err := target.NewRepo(f.st).Add(ctx, target.Target{Name: "srv-demo", Host: "192.0.2.10", Kind: target.KindVPS, Env: target.EnvProd})
	if err != nil {
		t.Fatal(err)
	}
	set, err := serverrules.Rules()
	if err != nil {
		t.Fatal(err)
	}
	store := func(at time.Time, fs []scan.Finding) {
		t.Helper()
		tx, err := f.st.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, _, _, err := scan.ApplyServerFindings(ctx, tx, tg.ID, "run", at, fs, scan.ServerApply{}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	const address = "203.0.113.7"
	fs := serverrules.Evaluate(tg, target.Inventory{ListenersRead: true, Listeners: []target.Listener{
		{Address: address, Port: 5432, Scope: target.ScopeOpen}, {Address: "0.0.0.0", Port: 6379, Scope: target.ScopeOpen}}}, set)
	if len(fs) != 2 {
		t.Fatalf("findings %+v", fs)
	}
	noDetail := func(d Digest) {
		t.Helper()
		text, err := RenderText(d)
		if err != nil {
			t.Fatal(err)
		}
		page, err := RenderHTML(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, out := range []string{text, page} {
			for _, bad := range []string{"5432", "6379", address, "0.0.0.0", "exposed_", "exposure"} {
				if strings.Contains(out, bad) {
					t.Errorf("the digest names %q:\n%s", bad, out)
				}
			}
		}
	}
	store(now.Add(-2*time.Hour), fs)
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		if len(d.Servers) != 1 || d.Servers[0] != (ServerDigest{Name: "srv-demo", New: 2}) {
			t.Fatalf("new: servers = %+v", d.Servers)
		}
		noDetail(d)
	}
	store(now.Add(-time.Hour), nil)
	for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
		d := f.compute(lang, Options{})
		if len(d.Servers) != 1 || d.Servers[0] != (ServerDigest{Name: "srv-demo", Fixed: 2}) {
			t.Fatalf("gone: servers = %+v", d.Servers)
		}
		noDetail(d)
	}
}

// The fix service stores this very cause on a rolled back server fix.
func TestRolledBackCauseIsTheFixServices(t *testing.T) {
	if CauseRolledBack != fix.CauseRolledBack {
		t.Errorf("digest %q, fix %q", CauseRolledBack, fix.CauseRolledBack)
	}
}
