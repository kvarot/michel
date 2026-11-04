package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/target"
)

func TestInventoryResponseHasNoSecret(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-inv", "192.0.2.50")
	repo := target.NewRepo(tf.st)
	inv := target.Inventory{TargetID: v.ID, At: now, OS: target.OSInfo{ID: "debian", VersionID: "12"},
		PHP: []target.PHPRuntime{{SAPI: "fpm", Binary: "/usr/sbin/php-fpm8.2", Version: "8.2.20", LoadedIni: "/home/deploy/php/php.ini",
			ScannedFiles: []string{"/home/deploy/conf.d/a.ini", "/home/deploy2/conf.d/b.ini"}}},
		Directives: []target.Directive{
			{SAPI: "fpm", Name: "mysqli.default_pw", Value: "hunter2-secret", Secret: true, File: "/home/deploy/site/.user.ini", Line: 3},
			{SAPI: "fpm", Name: "display_errors", Value: "Off", File: "/etc/php/8.2/fpm/php.ini", Line: 10},
			{SAPI: "fpm", Name: "error_log", Value: "/home/deploy/logs/php.log", File: "/etc/php/8.2/fpm/php.ini", Line: 11},
			{SAPI: "fpm", Name: "open_basedir", Value: "/home/deploy2/www:/home/deploy", File: "/etc/php/8.2/fpm/php.ini", Line: 12},
		},
		Files:  []target.FileSeen{{Path: "/home/deploy/site/.user.ini", SHA256: "abc", Size: 12}},
		Unseen: []target.Unseen{{What: "/home/deploy/site/.user.ini", Reason: collect.ReasonProbe}}}
	if err := repo.SaveInventory(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"en", "fr"} {
		code, body := tf.send("GET", "/api/v1/targets/"+v.ID+"/inventory?lang="+lang, "")
		if code != http.StatusOK {
			t.Fatalf("inventory = %d %s", code, body)
		}
		for _, leak := range []string{"hunter2-secret", "/home/deploy/"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s inventory holds %q: %s", lang, leak, body)
			}
		}
		for _, want := range []string{`"~/site/.user.ini"`, `"~/php/php.ini"`, `"~/logs/php.log"`, "/home/deploy2/conf.d/b.ini", "/home/deploy2/www:~"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s inventory lacks %q: %s", lang, want, body)
			}
		}
		var out InventoryView
		_ = json.Unmarshal([]byte(body), &out)
		var secret *InventoryDirective
		for i := range out.Directives {
			if out.Directives[i].Name == "mysqli.default_pw" {
				secret = &out.Directives[i]
			}
		}
		if secret == nil || !secret.Secret || secret.Value != "" || secret.ValueText == "" || secret.Line != 3 {
			t.Errorf("secret directive = %+v", secret)
		}
		if len(out.Unseen) != 1 || out.Unseen[0].Reason == collect.ReasonProbe || out.Unseen[0].Reason == "" {
			t.Errorf("unseen = %+v", out.Unseen)
		}
	}
	if code, body := tf.send("GET", "/api/v1/targets/nope/inventory", ""); code != http.StatusNotFound {
		t.Errorf("unknown server = %d %s", code, body)
	}
	empty := tf.addNamed("srv-none", "192.0.2.51")
	if code, body := tf.send("GET", "/api/v1/targets/"+empty.ID+"/inventory", ""); code != http.StatusNotFound || !strings.Contains(body, "api.target.no_inventory") {
		t.Errorf("never checked = %d %s", code, body)
	}
}

// seedServerFinding stores an open finding of a server.
func (tf *targetFixture) seedServerFinding(targetID, id, kind, osv string) {
	tf.t.Helper()
	_, err := tf.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at, summary, kind, location)
		VALUES (?, ?, 'php.ini', 'Debian', 'allow_url_include', ?, 'high', '1', '[]', 'new', 's1', 's1', ?, ?, ?, 'allow_url_include is risky; advised: 0', ?, '/home/deploy/conf/php.ini:7')`,
		id, targetID, osv, ts(now), ts(now), ts(now), kind)
	if err != nil {
		tf.t.Fatal(err)
	}
}

// seedServerAttempt stores a server fix in state proposed, run by executor,
// that backs up one file of the SSH user's home.
func (tf *targetFixture) seedServerAttempt(tg TargetView, findingID string, executor target.Executor, snapshot bool) (fix.Attempt, fix.Proposal) {
	tf.t.Helper()
	ctx := context.Background()
	repo := fix.NewRepo(tf.st)
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: findingID, ProjectID: tg.ID, Origin: fix.OriginServer,
		Work: fix.Work{Server: &fix.ServerWork{TargetID: tg.ID}}})
	if err != nil {
		tf.t.Fatal(err)
	}
	sf := fix.ServerFix{TargetID: tg.ID, FindingID: findingID, CorrectionID: "01CORRECTION", Executor: executor, NeedsSnapshot: snapshot,
		Actions: []serverfix.Action{{Op: serverfix.OpBackup, Path: "/home/deploy/conf/php.ini"}}}
	p, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "Set allow_url_include to 0.", Hash: "hash-srv",
		Scripts: &serverfix.Bundle{Apply: "echo apply", Undo: "echo undo", Hash: "scripts", RunAsRoot: false}, Server: &sf,
		Steps: []fix.StepResult{{Op: "backup_file", OK: true, Detail: "saved"}}})
	if err != nil {
		tf.t.Fatal(err)
	}
	if err := repo.SetState(ctx, a.ID, []fix.State{fix.StatePreparing}, fix.StateProposed, ""); err != nil {
		tf.t.Fatal(err)
	}
	return a, p
}

func TestSnapshotDoneThenApprove(t *testing.T) {
	tf := newTargetFixture(t)
	tg := tf.addNamed("srv-fix", "192.0.2.60")
	tf.seedServerFinding(tg.ID, "fsrv000000000001", scan.KindServerPackage, "DSA-0000-1001")
	a, p := tf.seedServerAttempt(tg, "fsrv000000000001", target.ExecUser, true)

	var v AttemptView
	tf.get("/api/v1/fix/"+a.ID, &v)
	if v.Server == nil || !v.Server.NeedsSnapshot || v.Server.SnapshotDone || v.Server.Executor != "user" || v.Server.RunAsRoot ||
		v.Project != "srv-fix" || v.Server.Target.ID != tg.ID || v.Finding.OSVID != "DSA-0000-1001" || v.State != "proposed" {
		t.Fatalf("attempt = %+v / %+v", v, v.Server)
	}
	if len(v.Server.Steps) != 1 || v.Server.Steps[0].Op != "backup_file" || !v.Server.Steps[0].OK {
		t.Errorf("steps = %+v", v.Server.Steps)
	}
	if len(v.Server.BackupList) != 1 || v.Server.BackupList[0] != "~/.michel/backups/01CORRECTION/1 -> ~/conf/php.ini" {
		t.Errorf("backup list = %q", v.Server.BackupList)
	}
	approve := `{"hash":"` + p.Hash + `"}`
	// A package upgrade is not approved before the user's snapshot.
	code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/approve", approve)
	var eb FixErrorBody
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "fix.server.snapshot_required" {
		t.Fatalf("approve without snapshot = %d %s", code, body)
	}
	if code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/applied-by-me", ""); code != http.StatusConflict {
		t.Errorf("applied-by-me before approval = %d %s", code, body)
	}
	code, body = tf.send("POST", "/api/v1/fix/"+a.ID+"/snapshot-done", "")
	if code != http.StatusOK {
		t.Fatalf("snapshot-done = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &v)
	if v.Server == nil || !v.Server.SnapshotDone || v.Server.SnapshotDoneAt == "" {
		t.Errorf("after snapshot = %+v", v.Server)
	}
	if rows := tf.auditRows("server_fix.snapshot_done"); len(rows) != 1 || rows[0].evidence["author"] != "web" {
		t.Errorf("audit = %+v", rows)
	}
	// Approved, and left there: the user runs the script themselves.
	code, body = tf.send("POST", "/api/v1/fix/"+a.ID+"/approve", approve)
	if code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &v)
	if v.State != "approved" || v.ApprovedBy != "web" {
		t.Errorf("after approve = %s by %q", v.State, v.ApprovedBy)
	}
	if code, _ := tf.send("POST", "/api/v1/fix/nope/snapshot-done", ""); code != http.StatusNotFound {
		t.Errorf("unknown attempt = %d", code)
	}
	// The list knows the new states and the server filter.
	var list []AttemptView
	tf.get("/api/v1/fixes?target="+tg.ID+"&state=approved,running,unknown", &list)
	if len(list) != 1 || list[0].ID != a.ID || list[0].Server == nil {
		t.Errorf("list = %+v", list)
	}
	if code, _ := tf.send("GET", "/api/v1/fixes?state=bogus", ""); code != http.StatusBadRequest {
		t.Errorf("bad state = %d", code)
	}
	if code, _ := tf.send("GET", "/api/v1/fixes?target=nope-nope", ""); code != http.StatusNotFound {
		t.Errorf("unknown target filter = %d", code)
	}
}

func TestServerRefusalsAreTranslated(t *testing.T) {
	tf := newTargetFixture(t)
	report := tf.addNamed("srv-report", "192.0.2.70")
	if code, _ := tf.send("PATCH", "/api/v1/targets/"+report.ID, `{"fix_level":0}`); code != http.StatusOK {
		t.Fatal("level 0")
	}
	hds := tf.send0("POST", "/api/v1/targets", `{"name":"srv-hds","host":"192.0.2.71","user":"deploy","kind":"hds"}`)
	tf.seedServerFinding(report.ID, "fsrv000000000010", scan.KindServerConfig, "allow_url_include")
	tf.seedServerFinding(hds.ID, "fsrv000000000011", scan.KindServerConfig, "allow_url_include")
	for name, tc := range map[string]struct {
		method, path, body, code string
		status                   int
		en, fr                   string
	}{
		"report only":    {"POST", "/api/v1/targets/" + report.ID + "/fix/fsrv000000000010", "", "fix.server.report_only", 409, "set to report only", "réglé sur"},
		"as a finding":   {"POST", "/api/v1/findings/fsrv000000000010/fix", "", "fix.server.report_only", 409, "report only", "Signaler"},
		"health agent":   {"POST", "/api/v1/targets/" + hds.ID + "/agent-fix/fsrv000000000011", "", "fix.err.health_forbidden", 403, "health", "santé"},
		"health consent": {"POST", "/api/v1/targets/" + hds.ID + "/ai-consent", "", "fix.err.health_forbidden", 403, "health", "santé"},
		"unknown finding": {"POST", "/api/v1/targets/" + report.ID + "/fix/nope", "", "api.target.finding_not_found", 404,
			"no finding", "aucune faille"},
		"other server's finding": {"POST", "/api/v1/targets/" + report.ID + "/fix/fsrv000000000011", "", "api.target.finding_not_found", 404,
			"no finding", "aucune faille"},
		"unknown server": {"POST", "/api/v1/targets/nope/fix/x", "", "api.target.not_found", 404, "No server", "Aucun serveur"},
		"strict local":   {"POST", "/api/v1/targets/" + report.ID + "/ai-consent", "", "fix.err.strict_local", 403, "strict_local", "strict_local"},
	} {
		for lang, want := range map[string]string{"en": tc.en, "fr": tc.fr} {
			code, body := tf.send(tc.method, tc.path+"?lang="+lang, tc.body)
			var eb FixErrorBody
			_ = json.Unmarshal([]byte(body), &eb)
			if code != tc.status || eb.Code != tc.code {
				t.Errorf("%s (%s) = %d %s", name, lang, code, body)
				continue
			}
			if strings.HasPrefix(eb.Error, "!") || !strings.Contains(eb.Error, want) {
				t.Errorf("%s (%s): %q lacks %q", name, lang, eb.Error, want)
			}
		}
	}
	// The consent screen of a server in strict_local says why, and a health one never gets one.
	var cv ServerConsentView
	tf.get("/api/v1/targets/"+report.ID+"/ai-consent", &cv)
	if cv.Ready || cv.Consented || !cv.SwitchMode || cv.RefusalCode != "fix.err.strict_local" || len(cv.Lines) == 0 {
		t.Errorf("consent view = %+v", cv)
	}
	tf.get("/api/v1/targets/"+hds.ID+"/ai-consent", &cv)
	if cv.Ready || cv.RefusalCode != "fix.err.health_forbidden" || len(cv.Lines) != 1 {
		t.Errorf("health consent view = %+v", cv)
	}
	// Giving the consent on the user's click switches the mode and records it; revoking forgets it.
	code, body := tf.send("POST", "/api/v1/targets/"+report.ID+"/ai-consent", `{"switch_to_standard":true}`)
	if code != http.StatusOK {
		t.Fatalf("give consent = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &cv)
	if !cv.Consented || !cv.Ready || cv.GivenAt == "" {
		t.Errorf("after consent = %+v", cv)
	}
	if rows := tf.auditRows("ai.consent"); len(rows) != 1 || rows[0].evidence["kind"] != "server" {
		t.Errorf("audit = %+v", rows)
	}
	code, body = tf.send("DELETE", "/api/v1/targets/"+report.ID+"/ai-consent", "")
	if code != http.StatusOK {
		t.Fatalf("revoke = %d %s", code, body)
	}
	_ = json.Unmarshal([]byte(body), &cv)
	if cv.Consented || cv.Ready {
		t.Errorf("after revoke = %+v", cv)
	}
	if rows := tf.auditRows("ai.consent_revoked"); len(rows) != 1 {
		t.Errorf("revoke audit = %+v", rows)
	}
}

func (tf *targetFixture) send0(method, path, body string) TargetView {
	tf.t.Helper()
	code, out := tf.send(method, path, body)
	if code != http.StatusCreated && code != http.StatusOK {
		tf.t.Fatalf("%s %s = %d %s", method, path, code, out)
	}
	var v TargetView
	_ = json.Unmarshal([]byte(out), &v)
	return v
}

func TestTargetDetailAndDelete(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add(`"links":[{"project":"demo","remote_dir":"/home/deploy/site"}]`)
	tf.pin(v.ID)
	tf.seedServerFinding(v.ID, "fsrv000000000020", scan.KindServerConfig, "allow_url_include")
	var d TargetView
	tf.get("/api/v1/targets/"+v.ID+"?lang=fr", &d)
	if len(d.Findings) != 1 || d.Open != 1 || d.State.Code != "never_checked" || !strings.Contains(d.State.Text, "vérifié") {
		t.Errorf("detail = %+v / %+v", d.State, d.Findings)
	}
	f := d.Findings[0]
	if f.Location != "~/conf/php.ini:7" || f.Title == "" || strings.HasPrefix(f.Title, "!") {
		t.Errorf("finding = %+v", f)
	}
	if len(d.Projects) != 1 || d.Projects[0].RemoteDir != "~/site" {
		t.Errorf("projects = %+v", d.Projects)
	}
	var list []TargetView
	tf.get("/api/v1/targets", &list)
	if len(list) != 1 || list[0].Findings != nil || list[0].Open != 1 {
		t.Errorf("list = %+v", list)
	}
	// The server leaves Michel; nothing else is touched.
	if code, body := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusOK {
		t.Fatalf("delete = %d %s", code, body)
	}
	if code, _ := tf.send("GET", "/api/v1/targets/"+v.ID, ""); code != http.StatusNotFound {
		t.Errorf("after delete = %d", code)
	}
	if rows := tf.auditRows("target.remove"); len(rows) != 1 {
		t.Errorf("audit = %+v", rows)
	}
	if code, _ := tf.send("DELETE", "/api/v1/targets/"+v.ID, ""); code != http.StatusNotFound {
		t.Errorf("second delete = %d", code)
	}
}

func TestTargetTildeKeepsOtherUsers(t *testing.T) {
	for in, want := range map[string]string{
		"/home/deploy/x":                  "~/x",
		"/home/deploy":                    "~",
		"/home/deploy2/x":                 "/home/deploy2/x",
		"/srv/home/deploy/x":              "/srv/home/deploy/x",
		"a=/home/deploy/x:/home/deploy/y": "a=~/x:~/y",
		"/home/other/x":                   "/home/other/x",
	} {
		if got := tilde("deploy", in); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
	if tilde("", "/home//x") != "/home//x" {
		t.Error("an empty user rewrote a path")
	}
}

// No route starts a fix of an exposure, and no attempt comes out of trying:
// closing a service is the person's job.
func TestExposureCannotStartAFix(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	const id = "fexposure0000001"
	tf.seedServerFinding(v.ID, id, scan.KindServerExposure, "exposed_database")
	for path, want := range map[string]struct {
		status int
		code   string
	}{
		"/api/v1/targets/" + v.ID + "/fix/" + id:       {http.StatusConflict, "api.target.exposure_no_fix"},
		"/api/v1/targets/" + v.ID + "/agent-fix/" + id: {http.StatusConflict, "api.target.exposure_no_fix"},
		"/api/v1/findings/" + id + "/fix":              {http.StatusNotFound, ""},
	} {
		code, body := tf.send("POST", path, "")
		var eb FixErrorBody
		_ = json.Unmarshal([]byte(body), &eb)
		if code != want.status || eb.Code != want.code {
			t.Errorf("%s = %d %s", path, code, body)
		}
	}
	var attempts int
	if err := tf.st.DB().QueryRow(`SELECT COUNT(*) FROM fix_attempt`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Errorf("%d attempts", attempts)
	}
}

// B1 (R62): a validated fix the user was to run says whether the server's
// settings now let Michel run it; the hand over route refuses a wrong hash
// and, without the settings, refuses to run anything.
func TestHandOverView(t *testing.T) {
	tf := newTargetFixture(t)
	tg := tf.addNamed("srv-hand", "192.0.2.61")
	tf.seedServerFinding(tg.ID, "fsrv000000000002", scan.KindServerConfig, "expose_php")
	a, p := tf.seedServerAttempt(tg, "fsrv000000000002", target.ExecUser, false)
	var v AttemptView
	if code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/hand-over", `{"hash":"`+p.Hash+`"}`); code != http.StatusConflict {
		t.Fatalf("hand-over before approval = %d %s", code, body)
	}
	if code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/approve", `{"hash":"`+p.Hash+`"}`); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}
	tf.get("/api/v1/fix/"+a.ID, &v)
	if v.Server == nil || v.Server.HandOver != "settings" {
		t.Fatalf("hand over with the settings off = %+v", v.Server)
	}
	var eb FixErrorBody
	if code, _ := tf.send("POST", "/api/v1/fix/"+a.ID+"/hand-over", `{}`); code != http.StatusBadRequest {
		t.Errorf("hand-over without hash = %d", code)
	}
	if code, body := tf.send("PATCH", "/api/v1/targets/"+tg.ID, `{"executor":"michel"}`); code != http.StatusOK {
		t.Fatalf("settings = %d %s", code, body)
	}
	tf.get("/api/v1/fix/"+a.ID, &v)
	if v.Server == nil || v.Server.HandOver != "ready" {
		t.Errorf("hand over with the settings on = %+v", v.Server)
	}
	code, body := tf.send("POST", "/api/v1/fix/"+a.ID+"/hand-over", `{"hash":"nope"}`)
	_ = json.Unmarshal([]byte(body), &eb)
	if code != http.StatusConflict || eb.Code != "fix.err.stale_proposal" {
		t.Errorf("hand-over with a stale hash = %d %s", code, body)
	}
}
