package api

import (
	"context"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// Task 13: the page shows the two scripts (to read and to copy) in the
// attempt's full view only, exactly as validated; the list stays light.
func TestServerAttemptShowsScriptsInFullViewOnly(t *testing.T) {
	tf := newTargetFixture(t)
	tg := tf.addNamed("srv-scripts", "192.0.2.80")
	tf.seedServerFinding(tg.ID, "fsrv000000000002", scan.KindServerConfig, "allow_url_include")
	a, _ := tf.seedServerAttempt(tg, "fsrv000000000002", target.ExecUser, false)

	var v AttemptView
	tf.get("/api/v1/fix/"+a.ID, &v)
	if v.Server == nil || v.Server.Scripts == nil || v.Server.Scripts.Apply != "echo apply" || v.Server.Scripts.Undo != "echo undo" {
		t.Fatalf("full view scripts = %+v", v.Server)
	}
	var list []AttemptView
	tf.get("/api/v1/fixes?target="+tg.ID, &list)
	if len(list) != 1 || list[0].Server == nil || list[0].Server.Scripts != nil {
		t.Errorf("list scripts = %+v", list)
	}
	code, body := tf.send("GET", "/api/v1/fixes?target="+tg.ID, "")
	if code != 200 || strings.Contains(body, "echo apply") {
		t.Errorf("list holds a script: %d %s", code, body)
	}
}

// The sheet names the distribution database to turn on when the packages
// seen cannot be judged without it; a project linked to the server shows in
// the list too.
func TestTargetDetailNamesTheSourceToEnable(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-src", "192.0.2.81")
	inv := target.Inventory{TargetID: v.ID, At: now, OS: target.OSInfo{ID: "debian", VersionID: "12"},
		Packages: []target.Package{{Name: "openssl", Source: "openssl", Version: "3.0.15-1~deb12u1"}}}
	if err := target.NewRepo(tf.st).SaveInventory(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	got := tf.view(v.ID)
	if got.SourceToEnable != "osv.debian" {
		t.Errorf("source to enable = %q", got.SourceToEnable)
	}
	var list []TargetView
	tf.get("/api/v1/targets", &list)
	if len(list) != 1 || list[0].SourceToEnable != "" {
		t.Errorf("list = %+v", list)
	}
}

// Task 13 fix round 1 (B1, B9): the list says how many open flaws are
// critical and how many are urgent, so the Today headline and the state
// sentence can say it; each finding of the sheet says whether it is urgent.
func TestTargetListCountsCriticalAndUrgent(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-crit", "192.0.2.82")
	tf.seedServerFinding(v.ID, "fsrv000000000003", scan.KindServerPackage, "PHP2SHELL")
	tf.seedServerFinding(v.ID, "fsrv000000000004", scan.KindServerConfig, "expose_php")
	if _, err := tf.st.DB().Exec(`UPDATE finding SET severity_label = 'critical' WHERE id = 'fsrv000000000003'`); err != nil {
		t.Fatal(err)
	}
	var list []TargetView
	tf.get("/api/v1/targets", &list)
	if len(list) != 1 || list[0].Open != 2 || list[0].CriticalOpen != 1 || list[0].UrgentOpen != 1 {
		t.Fatalf("list = %+v", list)
	}
	got := tf.view(v.ID)
	urgent := map[string]bool{}
	for _, f := range got.Findings {
		urgent[f.ID] = f.Urgent
	}
	if !urgent["fsrv000000000003"] || urgent["fsrv000000000004"] {
		t.Errorf("urgent = %v", urgent)
	}
}
