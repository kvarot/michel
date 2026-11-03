package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func (tf *targetFixture) exposure(id string) (ExposureView, string) {
	tf.t.Helper()
	var v ExposureView
	body := tf.get("/api/v1/targets/"+id+"/exposure", &v)
	return v, body
}

// storeListeners stores an inventory that says what listens, or, with read
// false, that ss gave no answer.
func (tf *targetFixture) storeListeners(id string, read bool, ls ...target.Listener) {
	tf.t.Helper()
	inv := target.Inventory{TargetID: id, At: now, Listeners: ls, ListenersRead: read}
	if !read {
		inv.Unseen = []target.Unseen{{What: "listeners", Reason: collect.ReasonListeners}}
	}
	if err := target.NewRepo(tf.st).SaveInventory(context.Background(), inv); err != nil {
		tf.t.Fatal(err)
	}
}

func listener(addr string, port int) target.Listener {
	return target.Listener{Address: addr, Port: port, Scope: target.ClassifyListen(addr)}
}

// seedExposure stores the finding of a service that listens on all addresses.
func (tf *targetFixture) seedExposure(targetID, id, port, rule, status, lastSeen string) {
	tf.t.Helper()
	_, err := tf.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at, summary, kind, location)
		VALUES (?, ?, ?, 'server-exposure', ?, ?, 'medium', '', '[]', ?, 's1', 's1', ?, ?, ?, 'seen from inside the server', ?, '')`,
		id, targetID, "exposure:"+port, port, rule, status, ts(now.Add(-72*time.Hour)), lastSeen, lastSeen, scan.KindServerExposure)
	if err != nil {
		tf.t.Fatal(err)
	}
}

func rowOf(v ExposureView, port int, scope string) (ExposureService, bool) {
	for _, s := range v.Services {
		if s.Port == port && s.Scope == scope {
			return s, true
		}
	}
	return ExposureService{}, false
}

func TestExposureNeverCheckedSaysNotRead(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	got, body := tf.exposure(v.ID)
	if got.Read || got.CheckedAt != "" || len(got.Services) != 0 || len(got.Closed) != 0 {
		t.Errorf("view = %+v", got)
	}
	// Lists, not null: the page walks them.
	for _, k := range []string{`"services":[]`, `"closed":[]`, `"unseen":[`} {
		if !strings.Contains(body, k) {
			t.Errorf("%s missing from %s", k, body)
		}
	}
}

func TestExposureGroupsByPortAndScope(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true,
		listener("0.0.0.0", 5432), listener("::", 5432), listener("10.0.0.5", 5432), listener("127.0.0.1", 5432),
		listener("0.0.0.0", 443), listener("0.0.0.0", 31337), listener("127.0.0.1", 6379))
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	got, _ := tf.exposure(v.ID)
	if !got.Read || got.CheckedAt != ts(now) || got.Kind != "vps" {
		t.Fatalf("view = %+v", got)
	}
	if len(got.Services) != 6 {
		t.Fatalf("services = %+v", got.Services)
	}
	open, ok := rowOf(got, 5432, "open")
	if !ok || strings.Join(open.Addresses, ",") != "0.0.0.0,::" || open.Service != "database" || open.Verdict != "close" || open.FindingID != "fexpo000000000001" {
		t.Errorf("5432 open = %+v", open)
	}
	for _, scope := range []string{"private", "server"} {
		s, ok := rowOf(got, 5432, scope)
		if !ok || len(s.Addresses) != 1 || s.FindingID != "" || s.Verdict != "close" {
			t.Errorf("5432 %s = %+v", scope, s)
		}
	}
	if s, ok := rowOf(got, 443, "open"); !ok || s.Service != "web" || s.Verdict != "normal" {
		t.Errorf("443 = %+v", s)
	}
	if s, ok := rowOf(got, 31337, "open"); !ok || s.Service != "other" || s.Verdict != "unknown" {
		t.Errorf("31337 = %+v", s)
	}
	// By port, then by who it listens for.
	var order []string
	for _, s := range got.Services {
		order = append(order, fmt.Sprintf("%d/%s", s.Port, s.Scope))
	}
	if want := "443/open 5432/open 5432/private 5432/server 6379/server 31337/open"; strings.Join(order, " ") != want {
		t.Errorf("order = %v", order)
	}
}

func TestExposureOldInventoryNotRead(t *testing.T) {
	for name, set := range map[string]func(tf *targetFixture, id string){
		"stored before the reading existed": func(tf *targetFixture, id string) {
			if err := target.NewRepo(tf.st).SaveInventory(context.Background(), target.Inventory{TargetID: id, At: now}); err != nil {
				tf.t.Fatal(err)
			}
		},
		"ss failed":      func(tf *targetFixture, id string) { tf.storeListeners(id, false) },
		"read, no row":   func(tf *targetFixture, id string) { tf.storeListeners(id, true) },
		"rows, not read": func(tf *targetFixture, id string) { tf.storeListeners(id, false, listener("0.0.0.0", 5432)) },
	} {
		t.Run(name, func(t *testing.T) {
			tf := newTargetFixture(t)
			v := tf.addNamed("srv-demo", "192.0.2.60")
			tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
			set(tf, v.ID)
			got, _ := tf.exposure(v.ID)
			if got.Read || len(got.Services) != 0 || got.CheckedAt == "" {
				t.Fatalf("view = %+v", got)
			}
			found := false
			for _, u := range got.Unseen {
				found = found || u.Reason == i18n.T(i18n.EN, collect.ReasonListeners)
			}
			if !found {
				t.Errorf("not read, and no word on it: %+v", got.Unseen)
			}
		})
	}
}

func TestExposureFirewallIsNeverVerified(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true, listener("0.0.0.0", 443))
	got, _ := tf.exposure(v.ID)
	if !got.Read {
		t.Fatal("not read")
	}
	var fw, udp bool
	for _, u := range got.Unseen {
		fw = fw || u.Reason == i18n.T(i18n.EN, "api.exposure.firewall.reason")
		udp = udp || u.Reason == i18n.T(i18n.EN, "api.exposure.udp.reason")
	}
	if !fw || !udp {
		t.Errorf("unseen = %+v", got.Unseen)
	}
}

func TestExposureClosedCarriesTheLastDateSeenOpen(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true, listener("0.0.0.0", 443))
	last := ts(now.Add(-48 * time.Hour))
	tf.seedExposure(v.ID, "fexpo000000000002", "6379", "exposed_cache", "gone", last)
	got, _ := tf.exposure(v.ID)
	if len(got.Closed) != 1 || got.Closed[0] != (ExposureClosed{Port: 6379, Service: "cache", LastSeenOpen: last}) {
		t.Errorf("closed = %+v", got.Closed)
	}
}

func (tf *targetFixture) decideExposure(tid, fid, body string) (int, string) {
	return tf.send("POST", "/api/v1/targets/"+tid+"/exposure/"+fid+"/decision", body)
}

func TestExposureDecisionNeedsWhy(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	for _, body := range []string{`{}`, `{"why":"   "}`} {
		code, b := tf.decideExposure(v.ID, "fexpo000000000001", body)
		var eb ErrorBody
		_ = json.Unmarshal([]byte(b), &eb)
		if code != http.StatusBadRequest || eb.Error != i18n.T(i18n.EN, "api.decision.refused") || eb.Hint != i18n.T(i18n.EN, "api.decision.why_required") {
			t.Errorf("%s = %d %s", body, code, b)
		}
	}
	// The action is not the caller's to choose.
	if code, _ := tf.decideExposure(v.ID, "fexpo000000000001", `{"why":"x","action":"fix"}`); code != http.StatusBadRequest {
		t.Errorf("an action in the body = %d", code)
	}
	if rows := tf.auditRows("decision.set"); len(rows) != 0 {
		t.Errorf("audited: %+v", rows)
	}
}

func TestExposureDecisionOnlyForExposureOfThisServer(t *testing.T) {
	tf := newTargetFixture(t)
	a := tf.addNamed("srv-demo", "192.0.2.60")
	b := tf.addNamed("srv-other", "192.0.2.61")
	tf.seedExposure(b.ID, "fexpo000000000003", "5432", "exposed_database", "new", ts(now))
	tf.seedServerFinding(a.ID, "fconfig000000001", scan.KindServerConfig, "allow_url_include")
	for _, c := range []struct{ tid, fid string }{
		{a.ID, "fexpo000000000003"}, // another server's
		{a.ID, "fconfig000000001"},  // another kind
		{a.ID, "fabsent000000001"},  // nothing
		{"01NOSUCHSERVER", "fexpo000000000003"},
	} {
		if code, body := tf.decideExposure(c.tid, c.fid, `{"why":"blocked by the host"}`); code != http.StatusNotFound {
			t.Errorf("%s/%s = %d %s", c.tid, c.fid, code, body)
		}
	}
	if rows := tf.auditRows("decision.set"); len(rows) != 0 {
		t.Errorf("audited: %+v", rows)
	}
}

func TestExposureDecisionAudited(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	code, body := tf.decideExposure(v.ID, "fexpo000000000001", `{"why":"  the host firewall blocks it\u0007 "}`)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	rows := tf.auditRows("decision.set")
	if len(rows) != 1 {
		t.Fatalf("decision.set = %+v", rows)
	}
	var answer ExposureView
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	var evID string
	_ = tf.st.DB().QueryRow(`SELECT id FROM audit_event WHERE action = 'decision.set'`).Scan(&evID)
	if evID == "" || answer.AuditEventID != evID {
		t.Errorf("audit event id %q, want %q", answer.AuditEventID, evID)
	}
	r := rows[0]
	if r.actor != "web" || r.target != "fexpo000000000001" || r.evidence["action"] != "ignore" || r.evidence["author"] != "web" ||
		r.evidence["justification"] != "the host firewall blocks it" || r.evidence["osv_id"] != "exposed_database" || r.evidence["project_id"] != v.ID {
		t.Errorf("decision.set = %+v", r)
	}
	var st string
	if err := tf.st.DB().QueryRow(`SELECT status FROM finding WHERE id = 'fexpo000000000001'`).Scan(&st); err != nil || st != scan.StatusDecided {
		t.Errorf("status %q %v", st, err)
	}
}

func TestExposureDecisionLeavesTheServiceInItsColumn(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true, listener("0.0.0.0", 5432))
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	code, body := tf.decideExposure(v.ID, "fexpo000000000001", `{"why":"the host firewall blocks it"}`)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var answer ExposureView
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	again, _ := tf.exposure(v.ID)
	for _, got := range []ExposureView{answer, again} {
		s, ok := rowOf(got, 5432, "open")
		if !ok || s.Verdict != "close" || s.Service != "database" || s.DecidedWhy != "the host firewall blocks it" || s.FindingID != "fexpo000000000001" {
			t.Errorf("service = %+v in %+v", s, got.Services)
		}
		if len(got.Closed) != 0 {
			t.Errorf("a decided service is not closed: %+v", got.Closed)
		}
	}
}

func TestExposureRoutesNeedTheToken(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/api/v1/targets/" + v.ID + "/exposure", ""},
		{"POST", "/api/v1/targets/" + v.ID + "/exposure/fexpo000000000001/decision", `{"why":"x"}`},
	} {
		for _, tok := range []string{"", "wrong"} {
			resp, body := tf.do(r.method, r.path, tok, r.body)
			if resp.StatusCode != http.StatusUnauthorized || strings.Contains(body, "srv-demo") {
				t.Errorf("%s %s token %q = %d %s", r.method, r.path, tok, resp.StatusCode, body)
			}
		}
	}
	var st string
	_ = tf.st.DB().QueryRow(`SELECT status FROM finding WHERE id = 'fexpo000000000001'`).Scan(&st)
	if st != scan.StatusNew {
		t.Errorf("status = %s after unauthorized calls", st)
	}
}

func TestExposureClosedJSONNameSaysLastSeenOpen(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true, listener("0.0.0.0", 443))
	tf.seedExposure(v.ID, "fexpo000000000002", "6379", "exposed_cache", "gone", ts(now.Add(-48*time.Hour)))
	_, body := tf.exposure(v.ID)
	if !strings.Contains(body, `"last_seen_open":`) || strings.Contains(body, `"at":`) {
		t.Errorf("body = %s", body)
	}
}

// A closed line next to the same port listening open would be a false
// sentence: the stored inventory is the newer fact.
func TestExposureClosedDropsAPortSeenOpenAgain(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.storeListeners(v.ID, true, listener("0.0.0.0", 5432), listener("127.0.0.1", 6379))
	tf.seedExposure(v.ID, "fexpo000000000002", "5432", "exposed_database", "gone", ts(now.Add(-48*time.Hour)))
	tf.seedExposure(v.ID, "fexpo000000000003", "6379", "exposed_cache", "gone", ts(now.Add(-48*time.Hour)))
	got, _ := tf.exposure(v.ID)
	// 5432 is open again: no closed line. 6379 only listens for the server: still closed to all.
	if len(got.Closed) != 1 || got.Closed[0].Port != 6379 {
		t.Errorf("closed = %+v", got.Closed)
	}
}

func TestExposureUnseenListenersIsTranslated(t *testing.T) {
	for name, set := range map[string]func(tf *targetFixture, id string){
		"stored unseen": func(tf *targetFixture, id string) { tf.storeListeners(id, false) },
		"old inventory": func(tf *targetFixture, id string) {
			if err := target.NewRepo(tf.st).SaveInventory(context.Background(), target.Inventory{TargetID: id, At: now}); err != nil {
				tf.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			tf := newTargetFixture(t)
			v := tf.addNamed("srv-demo", "192.0.2.60")
			set(tf, v.ID)
			for _, lang := range []i18n.Lang{i18n.EN, i18n.FR} {
				var got ExposureView
				tf.get("/api/v1/targets/"+v.ID+"/exposure?lang="+string(lang), &got)
				want := i18n.T(lang, "api.exposure.listeners.what")
				if want == "api.exposure.listeners.what" || want == "listeners" {
					t.Fatalf("%s: catalog key missing: %q", lang, want)
				}
				found := false
				for _, u := range got.Unseen {
					found = found || u.What == want
					if u.What == "listeners" {
						t.Errorf("%s: raw word in %+v", lang, got.Unseen)
					}
				}
				if !found {
					t.Errorf("%s: %q not in %+v", lang, want, got.Unseen)
				}
			}
		})
	}
}

func TestExposureDecisionWhyTooLong(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "new", ts(now))
	code, b := tf.decideExposure(v.ID, "fexpo000000000001", `{"why":"`+strings.Repeat("é", decide.MaxJustification+1)+`"}`)
	var eb ErrorBody
	_ = json.Unmarshal([]byte(b), &eb)
	if code != http.StatusBadRequest || eb.Error != i18n.T(i18n.EN, "api.decision.refused") ||
		!strings.HasPrefix(eb.Hint, strings.SplitN(i18n.T(i18n.EN, "api.decision.why_too_long", decide.MaxJustification), "%", 2)[0]) {
		t.Errorf("%d %s", code, b)
	}
	if rows := tf.auditRows("decision.set"); len(rows) != 0 {
		t.Errorf("audited: %+v", rows)
	}
}

func TestExposureDecisionOnGoneIsConflict(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.addNamed("srv-demo", "192.0.2.60")
	tf.seedExposure(v.ID, "fexpo000000000001", "5432", "exposed_database", "gone", ts(now))
	code, b := tf.decideExposure(v.ID, "fexpo000000000001", `{"why":"blocked by the host"}`)
	var eb ErrorBody
	_ = json.Unmarshal([]byte(b), &eb)
	if code != http.StatusConflict || eb.Error != i18n.T(i18n.EN, "api.decision.gone") || eb.Hint != i18n.T(i18n.EN, "api.decision.gone_hint") {
		t.Errorf("%d %s", code, b)
	}
	if rows := tf.auditRows("decision.set"); len(rows) != 0 {
		t.Errorf("audited: %+v", rows)
	}
}
