package serverrules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func TestJudgeListenerTable(t *testing.T) {
	s := mustRules(t)
	vps := srv(target.EnvProd, target.KindVPS)
	vps.Port = 22
	for port, want := range map[int]Judgement{
		80:    {ServiceWeb, VerdictNormal},
		443:   {ServiceWeb, VerdictNormal},
		22:    {ServiceAdmin, VerdictNormal},
		3306:  {ServiceDatabase, VerdictClose},
		5432:  {ServiceDatabase, VerdictClose},
		27017: {ServiceDatabase, VerdictClose},
		9200:  {ServiceDatabase, VerdictClose},
		6379:  {ServiceCache, VerdictClose},
		11211: {ServiceCache, VerdictClose},
		8080:  {ServiceOther, VerdictUnknown},
		2222:  {ServiceOther, VerdictUnknown},
	} {
		if got := JudgeListener(s, vps, target.Listener{Address: "0.0.0.0", Port: port, Scope: target.ScopeOpen}); got != want {
			t.Errorf("port %d: %+v, want %+v", port, got, want)
		}
	}
	// R10: the port Michel connects to is the administration one, whatever it is.
	for _, port := range []int{2222, 5432} {
		tg := vps
		tg.Port = port
		if got := JudgeListener(s, tg, target.Listener{Address: "0.0.0.0", Port: port, Scope: target.ScopeOpen}); got != (Judgement{ServiceAdmin, VerdictNormal}) {
			t.Errorf("connection port %d: %+v", port, got)
		}
	}
}

func openOn(addr string, port int) target.Listener {
	return target.Listener{Address: addr, Port: port, Scope: target.ClassifyListen(addr)}
}

func listening(ls ...target.Listener) target.Inventory {
	return target.Inventory{ListenersRead: true, Listeners: ls}
}

func TestOpenDatabaseIsAFinding(t *testing.T) {
	tg := srv(target.EnvProd, target.KindVPS)
	fs := Evaluate(tg, listening(openOn("0.0.0.0", 5432), openOn("0.0.0.0", 443), openOn("0.0.0.0", 22), openOn("0.0.0.0", 8080)), mustRules(t))
	if len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	f := fs[0]
	if f.ID != scan.FindingID(tg.ID, "exposure:5432", "server-exposure", "5432", "exposed_database") || f.ProjectID != tg.ID ||
		f.ManifestRelPath != "exposure:5432" || f.Package != "5432" || f.OSVID != "exposed_database" ||
		f.Kind != scan.KindServerExposure || f.Ecosystem != "server-exposure" || f.SeverityLabel != "medium" {
		t.Fatalf("finding %+v", f)
	}
	// What Michel saw, nothing about what can reach it.
	if f.Summary == "" {
		t.Error("no summary")
	}
	for _, bad := range []string{"reachable", "closed", "exposed to"} {
		if strings.Contains(strings.ToLower(f.Summary), bad) {
			t.Errorf("summary %q says %q", f.Summary, bad)
		}
	}
	if fs := Evaluate(tg, listening(openOn("::", 6379)), mustRules(t)); len(fs) != 1 || fs[0].OSVID != "exposed_cache" || fs[0].SeverityLabel != "medium" {
		t.Fatalf("cache %+v", fs)
	}
}

func TestReservedDatabaseIsNot(t *testing.T) {
	tg := srv(target.EnvProd, target.KindVPS)
	if fs := Evaluate(tg, listening(openOn("127.0.0.1", 3306), openOn("::1", 3306), openOn("10.0.0.5", 5432), openOn("fd00::1", 6379)), mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings %+v", fs)
	}
}

func TestNoExposureFindingOnShared(t *testing.T) {
	if fs := Evaluate(srv(target.EnvProd, target.KindShared), listening(openOn("0.0.0.0", 3306)), mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings %+v", fs)
	}
}

func TestHdsGetsTheFinding(t *testing.T) {
	if fs := Evaluate(srv(target.EnvProd, target.KindHDS), listening(openOn("0.0.0.0", 3306)), mustRules(t)); len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
}

func TestOnePerPortAcrossIPv4AndIPv6(t *testing.T) {
	fs := Evaluate(srv(target.EnvProd, target.KindVPS), listening(openOn("::", 5432), openOn("*", 5432), openOn("0.0.0.0", 5432), openOn("127.0.0.1", 5432)), mustRules(t))
	if len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	// Open on one address counts, whatever the others are; the order is stable.
	fs = Evaluate(srv(target.EnvProd, target.KindVPS), listening(openOn("0.0.0.0", 6379), openOn("127.0.0.1", 5432), openOn("::", 5432), openOn("0.0.0.0", 3306)), mustRules(t))
	if len(fs) != 3 || fs[0].Package != "3306" || fs[1].Package != "5432" || fs[2].Package != "6379" {
		t.Fatalf("findings %+v", fs)
	}
}

// The port Michel connects to is never a service to close (R10).
func TestConnectionPortIsNoFinding(t *testing.T) {
	tg := srv(target.EnvProd, target.KindVPS)
	tg.Port = 3306
	if fs := Evaluate(tg, listening(openOn("0.0.0.0", 3306)), mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings %+v", fs)
	}
}

// Only a complete read with at least one row tells what listens.
func TestUnknownListIsNoFinding(t *testing.T) {
	tg := srv(target.EnvProd, target.KindVPS)
	partial := target.Inventory{Listeners: []target.Listener{openOn("0.0.0.0", 3306)}}
	if fs := Evaluate(tg, partial, mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings on an unread list: %+v", fs)
	}
	for name, inv := range map[string]target.Inventory{
		"not read":   partial,
		"zero rows":  {ListenersRead: true},
		"old format": {},
	} {
		if ListenersKnown(inv) {
			t.Errorf("%s: known", name)
		}
	}
	if !ListenersKnown(listening(openOn("127.0.0.1", 3306))) {
		t.Error("a complete read is known")
	}
}

// OpenPortKeys holds what a complete read shows open, each port once, by port:
// the keys of the findings that read cannot close.
func TestOpenPortKeys(t *testing.T) {
	got := OpenPortKeys(listening(openOn("0.0.0.0", 3306), openOn("::", 3306), openOn("127.0.0.1", 6379), openOn("*", 80)))
	if fmt.Sprint(got) != "[exposure:80 exposure:3306]" {
		t.Fatalf("keys %v", got)
	}
}

func TestExposureTextsExist(t *testing.T) {
	closing := 0
	for _, r := range mustRules(t).Listen {
		if r.Verdict != VerdictClose {
			continue
		}
		closing++
		if r.Severity != "medium" {
			t.Errorf("%s: severity %s, R9 says medium", r.Rule, r.Severity)
		}
		for _, suffix := range []string{".title", ".explain"} {
			if !i18n.Has(r.Key + suffix) {
				t.Errorf("no text %s%s", r.Key, suffix)
			}
		}
	}
	if closing != 2 {
		t.Errorf("%d rules to close", closing)
	}
}

func TestUnknownVersionIsRefused(t *testing.T) {
	if Version != 3 {
		t.Fatalf("Version = %d", Version)
	}
	if _, err := parse([]byte("version: 2\n")); err == nil {
		t.Error("an old version is accepted")
	}
	if _, err := parse([]byte("version: 4\n")); err == nil {
		t.Error("a newer version is accepted")
	}
	if _, err := parse([]byte("version: 3\n")); err != nil {
		t.Errorf("the current version is refused: %v", err)
	}
}

func TestParseRejectsBadListenRules(t *testing.T) {
	for name, rule := range map[string]string{
		"no port":          `{ports: [], service: web, verdict: normal}`,
		"port 0":           `{ports: [0], service: web, verdict: normal}`,
		"port 70000":       `{ports: [70000], service: web, verdict: normal}`,
		"service":          `{ports: [80], service: mail, verdict: normal}`,
		"verdict":          `{ports: [80], service: web, verdict: fine}`,
		"close no rule":    `{ports: [80], service: web, verdict: close, severity: medium, key: k}`,
		"close no key":     `{ports: [80], service: web, verdict: close, rule: r, severity: medium}`,
		"close high":       `{ports: [80], service: web, verdict: close, rule: r, severity: high, key: k}`,
		"close unset":      `{ports: [80], service: web, verdict: close, rule: r, key: k}`,
		"normal with rule": `{ports: [80], service: web, verdict: normal, rule: r}`,
		"unknown field":    `{ports: [80], service: web, verdict: normal, nope: 1}`,
	} {
		if _, err := parse([]byte("version: 3\nlisten:\n  - " + rule + "\n")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, rules := range map[string]string{
		"port twice": "  - {ports: [80], service: web, verdict: normal}\n  - {ports: [80], service: admin, verdict: normal}\n",
		"rule twice": "  - {ports: [1], service: cache, verdict: close, rule: r, severity: medium, key: k}\n  - {ports: [2], service: cache, verdict: close, rule: r, severity: medium, key: k}\n",
	} {
		if _, err := parse([]byte("version: 3\nlisten:\n" + rules)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	clash := "version: 3\nconfig:\n  - {id: a, directive: x, risky: \"on\", severity: low, changeable: all, key: k}\nlisten:\n  - {ports: [1], service: cache, verdict: close, rule: a, severity: medium, key: k}\n"
	if _, err := parse([]byte(clash)); err == nil {
		t.Error("a listen rule named like a config rule is accepted")
	}
}
