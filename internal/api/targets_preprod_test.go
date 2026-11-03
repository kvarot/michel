package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// The page must tell a package of the system from PHP's own flaw: only the
// first has a ready-made fix (fix.planFor).
func TestServerFindingSaysItsEcosystem(t *testing.T) {
	f := scan.Finding{Kind: scan.KindServerPackage, OSVID: "PHP-1", Package: "php", Ecosystem: "php-upstream"}
	if got := targetFindingView(i18n.FR, "michel", f).Ecosystem; got != "php-upstream" {
		t.Errorf("ecosystem = %q", got)
	}
}

// seedPlannable is a finding and an inventory StartServer can plan from.
func (tf *targetFixture) seedPlannable(tg TargetView, id string) {
	tf.t.Helper()
	tf.seedServerFinding(tg.ID, id, scan.KindServerConfig, "allow_url_include")
	file := "/etc/php/8.2/fpm/php.ini"
	if _, err := tf.st.DB().Exec(`UPDATE finding SET location = ?, sapi = 'fpm' WHERE id = ?`, file+":7", id); err != nil {
		tf.t.Fatal(err)
	}
	inv := target.Inventory{TargetID: tg.ID, At: now, OS: target.OSInfo{ID: "debian", VersionID: "12"},
		PHP:        []target.PHPRuntime{{SAPI: "fpm", Binary: "/usr/sbin/php-fpm8.2", Version: "8.2.20", LoadedIni: file}},
		Directives: []target.Directive{{SAPI: "fpm", Name: "allow_url_include", Value: "1", File: file, Line: 7}},
		Files:      []target.FileSeen{{Path: file, SHA256: "abc", Size: 12}}}
	if err := target.NewRepo(tf.st).SaveInventory(context.Background(), inv); err != nil {
		tf.t.Fatal(err)
	}
}

// A busy server is refused in words that name where the fix waits: on a
// server with a preprod, that is the preprod (StartServer works there first).
func TestServerBusyNamesWhereItRuns(t *testing.T) {
	tf := newTargetFixture(t)
	alone := tf.addNamed("srv-alone", "192.0.2.80")
	pre := tf.addNamed("srv-busy-pre", "192.0.2.81", "preprod")
	prod := tf.addNamed("srv-busy-prod", "192.0.2.82")
	repo := target.NewRepo(tf.st)
	stored, err := repo.Get(context.Background(), prod.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.PreprodID = pre.ID
	if err := repo.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	tf.seedPlannable(alone, "fsrv000000000020")
	tf.seedPlannable(pre, "fsrv000000000021")
	tf.seedPlannable(prod, "fsrv000000000022")
	tf.seedServerAttempt(alone, "fsrv000000000020", target.ExecUser, false)
	tf.seedServerAttempt(pre, "fsrv000000000021", target.ExecUser, false)
	for name, tc := range map[string]struct{ path, code, en, fr string }{
		"alone":   {"/api/v1/targets/" + alone.ID + "/fix/fsrv000000000020", "fix.server.busy", "on this server", "sur ce serveur"},
		"preprod": {"/api/v1/targets/" + prod.ID + "/fix/fsrv000000000022", "fix.server.busy_preprod", "preprod srv-busy-pre", "préprod srv-busy-pre"},
	} {
		for lang, want := range map[string]string{"en": tc.en, "fr": tc.fr} {
			code, body := tf.send("POST", tc.path+"?lang="+lang, "")
			var eb FixErrorBody
			_ = json.Unmarshal([]byte(body), &eb)
			if code != http.StatusConflict || eb.Code != tc.code || !strings.Contains(eb.Error, want) {
				t.Errorf("%s (%s) = %d %s", name, lang, code, body)
			}
		}
	}
}

// A preprod's attempt says which production flaw it is tried for: the
// production's card finds it by that id.
func TestServerAttemptSaysItsProductionFinding(t *testing.T) {
	tf := newTargetFixture(t)
	pre := tf.addNamed("srv-pre-view", "192.0.2.83", "preprod")
	prod := tf.addNamed("srv-prod-view", "192.0.2.84")
	tf.seedServerFinding(pre.ID, "fsrv000000000030", scan.KindServerConfig, "allow_url_include")
	if _, err := fix.NewRepo(tf.st).CreateAttempt(context.Background(), fix.Attempt{FindingID: "fsrv000000000030", ProjectID: pre.ID, Origin: fix.OriginServer,
		Work: fix.Work{Server: &fix.ServerWork{TargetID: pre.ID, ProdTargetID: prod.ID, ProdFindingID: "fsrv000000000031"}}}); err != nil {
		t.Fatal(err)
	}
	var list []AttemptView
	tf.get("/api/v1/fixes?target="+pre.ID, &list)
	if len(list) != 1 || list[0].Server == nil || list[0].Server.ProdFindingID != "fsrv000000000031" || list[0].Server.ForProduction == nil {
		t.Fatalf("attempts = %+v", list)
	}
}

// What the consent says of secrets is what the code does: it recognises them,
// and may miss one.
func TestServerConsentSaysSecretsAreRecognised(t *testing.T) {
	for _, lang := range []i18n.Lang{i18n.FR, i18n.EN} {
		for _, key := range []string{"fix.consent.server_sensitive", "fix.consent.server_what_leaves"} {
			text := i18n.T(lang, key)
			for _, bad := range []string{"ne sortent jamais", "never leave"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s (%s) still promises: %q", key, lang, text)
				}
			}
		}
	}
}
