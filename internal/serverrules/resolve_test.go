package serverrules

import (
	"fmt"
	"slices"
	"testing"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

const fpmBin = "/opt/php/sbin/php-fpm"
const poolFile = "/etc/php/pool.d/demo.conf"

func dir(sapi, bin, name, value, file string) target.Directive {
	return target.Directive{SAPI: sapi, Binary: bin, Name: name, Value: value, File: file, Line: 3}
}

func ids(fs []scan.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.OSVID+"@"+f.ManifestRelPath)
	}
	return out
}

func hasRule(fs []scan.Finding, id string) bool {
	return slices.ContainsFunc(fs, func(f scan.Finding) bool { return f.OSVID == id })
}

func TestUserIniCannotChangeSystemDirective(t *testing.T) {
	inv := target.Inventory{
		PHP: []target.PHPRuntime{fpm("8.4.27", "")},
		Directives: []target.Directive{
			dir("fpm", fpmBin, "allow_url_include", "On", "/etc/php/php.ini"),
			dir("user_ini", fpmBin, "allow_url_include", "0", "/home/demo/www/.user.ini"),
		},
	}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); !hasRule(fs, "allow_url_include") {
		t.Fatalf("a .user.ini cannot change allow_url_include: %v", ids(fs))
	}
}

func TestUserIniEmptyBinaryNeverClears(t *testing.T) {
	other := target.PHPRuntime{SAPI: "fpm", Binary: "/opt/php83/sbin/php-fpm", Version: "8.3.36"}
	inv := target.Inventory{
		PHP: []target.PHPRuntime{fpm("8.4.27", ""), other},
		Directives: []target.Directive{
			dir("user_ini", "", "open_basedir", "/home/demo/www", "/home/demo/www/.user.ini"),
			dir("user_ini", fpmBin, "open_basedir", "/home/demo/www", "/home/demo/www/.user.ini"),
		},
	}
	fs := Evaluate(srv(target.EnvProd, target.KindShared), inv, mustRules(t))
	n := 0
	for _, f := range fs {
		if f.OSVID == "open_basedir_shared" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("a .user.ini folder never clears a runtime, findings: %v", ids(fs))
	}
}

func TestUserIniAddsRisk(t *testing.T) {
	inv := target.Inventory{
		PHP: []target.PHPRuntime{fpm("8.4.27", ""), {SAPI: "fpm", Binary: "/opt/php83/sbin/php-fpm", Version: "8.3.36"}},
		Directives: []target.Directive{
			dir("fpm", fpmBin, "display_errors", "0", "/etc/php/php.ini"),
			dir("user_ini", "", "display_errors", "On", "/home/demo/www/.user.ini"),
		},
	}
	fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	n := 0
	for _, f := range fs {
		if f.OSVID == "display_errors_prod" {
			n++
			if f.Location != "/home/demo/www/.user.ini:3" {
				t.Fatalf("location = %q", f.Location)
			}
		}
	}
	if n != 2 {
		t.Fatalf("an empty-binary .user.ini adds risk on every FPM: %v", ids(fs))
	}
}

func TestPoolAdminValueBeatsUserIni(t *testing.T) {
	rt := fpm("8.4.27", "")
	rt.PoolFiles = []string{poolFile}
	inv := target.Inventory{
		PHP: []target.PHPRuntime{rt},
		Directives: []target.Directive{
			dir("fpm", fpmBin, "display_errors", "0", "/etc/php/php.ini"),
			dir("fpm", fpmBin, "php_admin_value[display_errors]", "0", poolFile),
			dir("user_ini", fpmBin, "display_errors", "On", "/home/demo/www/.user.ini"),
		},
	}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); hasRule(fs, "display_errors_prod") {
		t.Fatalf("php_admin_value is final: %v", ids(fs))
	}
}

func TestPoolOverridesAreMatched(t *testing.T) {
	cases := []struct {
		name, value, rule string
		want              bool
	}{
		{"php_admin_flag[display_errors]", "on", "display_errors_prod", true},
		{"php_admin_value[display_errors]", "1", "display_errors_prod", true},
		{"php_value[display_errors]", "On", "display_errors_prod", true},
		{"php_flag[display_errors]", "on", "display_errors_prod", true},
		{"php_admin_value[allow_url_include]", "1", "allow_url_include", true},
		{"php_value[allow_url_include]", "1", "allow_url_include", false}, // system: php_value cannot set it
	}
	for _, c := range cases {
		rt := fpm("8.4.27", "")
		rt.PoolFiles = []string{poolFile}
		inv := target.Inventory{PHP: []target.PHPRuntime{rt}, Directives: []target.Directive{dir("fpm", fpmBin, c.name, c.value, poolFile)}}
		if got := hasRule(Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)), c.rule); got != c.want {
			t.Errorf("%s=%s: flagged %v, want %v", c.name, c.value, got, c.want)
		}
	}
	// A pool that already sets the safe value: no mitigation advice.
	rt := fpm("8.3.35", "")
	rt.PoolFiles = []string{poolFile}
	inv := target.Inventory{PHP: []target.PHPRuntime{rt}, Directives: []target.Directive{
		dir("fpm", fpmBin, "session.upload_progress.enabled", "1", "/etc/php/php.ini"),
		dir("fpm", fpmBin, "php_admin_value[session.upload_progress.enabled]", "0", poolFile),
	}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); hasRule(fs, "session_upload_progress_off") {
		t.Fatalf("the pool already sets 0: %v", ids(fs))
	}
}

func TestUnknownVersionIsVisible(t *testing.T) {
	for _, v := range []string{"", "weird"} {
		inv := target.Inventory{PHP: []target.PHPRuntime{fpm(v, "")}, Directives: []target.Directive{
			dir("fpm", fpmBin, "session.upload_progress.enabled", "1", "/etc/php/php.ini")}}
		fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
		pk := byKind(fs, scan.KindServerPackage)
		if len(pk) != 1 || pk[0].OSVID != "PHP-VERSION-UNKNOWN" || pk[0].SeverityLabel != "high" || !slices.Contains(pk[0].Aliases, "CVE-2026-109618") {
			t.Fatalf("%q: findings = %v", v, ids(fs))
		}
		if !hasRule(fs, "session_upload_progress_off") {
			t.Fatalf("%q: mitigation advice expected as if vulnerable", v)
		}
	}
	// A distribution runtime with an unreadable version is not judged here.
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("", "php8.3-fpm")}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings = %v", ids(fs))
	}
}

func TestFatalErrorBacktracesMitigationOn85Only(t *testing.T) {
	d := dir("fpm", fpmBin, "fatal_error_backtraces", "1", "/etc/php/php.ini")
	for v, want := range map[string]bool{"8.5.11": true, "8.4.26": false} {
		inv := target.Inventory{PHP: []target.PHPRuntime{fpm(v, "")}, Directives: []target.Directive{d}}
		fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
		var m *scan.Finding
		for i := range fs {
			if fs[i].OSVID == "fatal_error_backtraces_off" {
				m = &fs[i]
			}
		}
		if (m != nil) != want || (m != nil && !m.Mitigation) {
			t.Fatalf("%s: %v", v, ids(fs))
		}
	}
}

func TestOldBranchesAreEOL(t *testing.T) {
	for _, v := range []string{"5.5.38", "4.4.9", "7.4.33", "8.0.30"} {
		inv := target.Inventory{PHP: []target.PHPRuntime{fpm(v, "")}}
		fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
		if !slices.ContainsFunc(fs, func(f scan.Finding) bool { return f.Summary == "branch no longer supported" }) {
			t.Fatalf("%s: %v", v, ids(fs))
		}
	}
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.2.35", "")}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); len(fs) != 0 {
		t.Fatalf("8.2.35: %v", ids(fs))
	}
}

func TestNonZeroIntegerIsOn(t *testing.T) {
	if !isOn("2") || isOn("0") || isOn("") || isOn("off") {
		t.Fatal("isOn")
	}
}

func TestParseRejectsTypos(t *testing.T) {
	base := "version: 2\nconfig:\n  - {id: a, directive: x, risky: \"on\", severity: %s, changeable: %s, context: [%s], key: k}\n"
	for _, c := range [][3]string{{"low", "all", "sapi:fmp"}, {"low", "all", "prodd"}, {"urgent", "all", "prod"}, {"low", "sometimes", "prod"}} {
		if _, err := parse([]byte(fmt.Sprintf(base, c[0], c[1], c[2]))); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if _, err := parse([]byte(fmt.Sprintf(base, "low", "all", "prod"))); err != nil {
		t.Fatal(err)
	}
}
