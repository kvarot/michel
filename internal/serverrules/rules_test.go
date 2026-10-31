package serverrules

import (
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

func mustRules(t *testing.T) Set {
	t.Helper()
	s, err := Rules()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func srv(env target.Env, kind target.Kind) target.Target {
	return target.Target{ID: "01SRVDEMO", Name: "srv-demo", Kind: kind, Env: env, SiteURL: "https://example.test"}
}

func fpm(version, pkg string) target.PHPRuntime {
	return target.PHPRuntime{SAPI: "fpm", Binary: "/opt/php/sbin/php-fpm", Version: version, FromPackage: pkg}
}

func byKind(fs []scan.Finding, kind string) []scan.Finding {
	var out []scan.Finding
	for _, f := range fs {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestPHP2ShellUpstreamVulnerable(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.3.35", "")}}
	fs := byKind(Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)), scan.KindServerPackage)
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	f := fs[0]
	if f.SeverityLabel != "critical" || f.CVSS != 9.2 || f.FixedVersions[0] != "8.3.36" || f.ProjectID != "01SRVDEMO" {
		t.Fatalf("finding = %+v", f)
	}
	for _, c := range []string{"CVE-2026-109618", "CVE-2026-109619"} {
		if !slices.Contains(f.Aliases, c) {
			t.Fatalf("aliases %v miss %s", f.Aliases, c)
		}
	}
}

func TestPHP2ShellFixed(t *testing.T) {
	for _, v := range []string{"8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13", "8.6.0", "9.0.1"} {
		inv := target.Inventory{PHP: []target.PHPRuntime{fpm(v, "")}}
		if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); len(fs) != 0 {
			t.Fatalf("%s: findings = %+v", v, fs)
		}
	}
}

func TestEOLBranchFlagged(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.1.30", "")}}
	fs := byKind(Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)), scan.KindServerPackage)
	if len(fs) != 2 {
		t.Fatalf("findings = %+v", fs)
	}
	var eol, shell *scan.Finding
	for i := range fs {
		if fs[i].OSVID == "EOL-8.1" {
			eol = &fs[i]
		} else {
			shell = &fs[i]
		}
	}
	if eol == nil || eol.SeverityLabel != "high" || eol.Summary != "branch no longer supported" {
		t.Fatalf("eol = %+v", eol)
	}
	if shell == nil || shell.FixedVersions[0] != "8.2.35" {
		t.Fatalf("php2shell = %+v", shell)
	}
}

func TestDistroPHPNotJudgedUpstream(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.1.2", "php8.3-fpm")}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestFPMVersionJudgedNotCLI(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{
		{SAPI: "cli", Binary: "/usr/bin/php", Version: "8.3.36"},
		{SAPI: "fpm", Binary: "/opt/php82/sbin/php-fpm", Version: "8.2.34"},
	}}
	fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	for _, f := range fs {
		if f.SAPI != "fpm" {
			t.Fatalf("a finding names the CLI: %+v", f)
		}
	}
	fs = byKind(fs, scan.KindServerPackage)
	if len(fs) != 1 || fs[0].ManifestRelPath != "fpm:/opt/php82/sbin/php-fpm" || fs[0].SAPI != "fpm" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestDisplayErrorsOnlyInProd(t *testing.T) {
	inv := target.Inventory{
		PHP:        []target.PHPRuntime{fpm("8.4.27", "")},
		Directives: []target.Directive{{SAPI: "fpm", Binary: "/opt/php/sbin/php-fpm", Name: "display_errors", Value: "On", File: "/etc/php/php.ini", Line: 12}},
	}
	has := func(env target.Env) bool {
		for _, f := range Evaluate(srv(env, target.KindVPS), inv, mustRules(t)) {
			if f.OSVID == "display_errors_prod" {
				return true
			}
		}
		return false
	}
	if !has(target.EnvProd) || has(target.EnvDev) || has(target.EnvPreprod) {
		t.Fatal("display_errors must be flagged in prod only")
	}
}

func TestOpenBasedirSharedOnly(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.4.27", "")}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); slices.ContainsFunc(fs, func(f scan.Finding) bool { return f.OSVID == "open_basedir_shared" }) {
		t.Fatal("open_basedir flagged on a vps")
	}
	if fs := Evaluate(srv(target.EnvProd, target.KindShared), inv, mustRules(t)); !slices.ContainsFunc(fs, func(f scan.Finding) bool { return f.OSVID == "open_basedir_shared" }) {
		t.Fatal("open_basedir not flagged on shared hosting")
	}
}

func TestUploadProgressIsMitigationOnly(t *testing.T) {
	up := target.Directive{SAPI: "fpm", Binary: "/opt/php/sbin/php-fpm", Name: "session.upload_progress.enabled", Value: "1"}
	// Vulnerable runtime: upstream finding AND a mitigation finding.
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.3.35", "")}, Directives: []target.Directive{up}}
	fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	cfg := byKind(fs, scan.KindServerConfig)
	if len(cfg) != 1 || !cfg[0].Mitigation || cfg[0].OSVID != "session_upload_progress_off" {
		t.Fatalf("config findings = %+v", cfg)
	}
	if len(byKind(fs, scan.KindServerPackage)) != 1 {
		t.Fatalf("the upstream finding must stay open: %+v", fs)
	}
	// Off: no mitigation finding, the upstream one stays.
	up.Value = "0"
	inv.Directives = []target.Directive{up}
	fs = Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	if len(byKind(fs, scan.KindServerConfig)) != 0 || len(byKind(fs, scan.KindServerPackage)) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	// Fixed runtime: setting alone is not a finding.
	up.Value = "1"
	inv = target.Inventory{PHP: []target.PHPRuntime{fpm("8.3.36", "")}, Directives: []target.Directive{up}}
	if fs = Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestFindingIDsStableAndDistinct(t *testing.T) {
	inv := target.Inventory{PHP: []target.PHPRuntime{fpm("8.1.30", "")}}
	a := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	b := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t))
	seen := map[string]bool{}
	for i := range a {
		if a[i].ID != b[i].ID || seen[a[i].ID] {
			t.Fatalf("ids not stable and distinct: %+v", a)
		}
		seen[a[i].ID] = true
	}
}

func TestNeverAdvisesMemoryLimitMinusOne(t *testing.T) {
	for _, r := range mustRules(t).Config {
		if r.Directive == "memory_limit" && r.Advised == "-1" {
			t.Fatalf("rule %s advises memory_limit=-1", r.ID)
		}
	}
}

func TestRulesYAMLVersionMatches(t *testing.T) {
	m := regexp.MustCompile(`(?m)^version:\s*(\d+)`).FindSubmatch(rulesYAML)
	if m == nil {
		t.Fatal("rules.yaml has no version")
	}
	if n, _ := strconv.Atoi(string(m[1])); n != Version {
		t.Fatalf("rules.yaml version %d, Version %d", n, Version)
	}
	if _, err := parse([]byte("version: 999\n")); err == nil {
		t.Fatal("a wrong version must be refused")
	}
}

func TestEveryRuleHasEnAndFrText(t *testing.T) {
	s := mustRules(t)
	var keys []string
	for _, r := range s.Config {
		keys = append(keys, r.Key)
	}
	for _, a := range s.Upstream {
		keys = append(keys, a.Key)
	}
	keys = append(keys, "serverrules.eol")
	for _, k := range keys {
		for _, part := range []string{".title", ".explain"} {
			if !i18n.Has(k + part) {
				t.Fatalf("missing EN text %s", k+part)
			}
			if i18n.T(i18n.FR, k+part) == i18n.T(i18n.EN, k+part) {
				t.Fatalf("missing FR text %s", k+part)
			}
		}
	}
}

func TestDistroAdvisoryOpensMitigations(t *testing.T) {
	ids := func(fs []scan.Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.OSVID)
		}
		slices.Sort(out)
		return out
	}
	s := mustRules(t)
	tg := srv(target.EnvProd, target.KindVPS)
	for _, c := range []struct {
		version string
		want    []string
	}{
		{"8.3.6-1", []string{"session_upload_progress_off"}},
		{"8.5.1-1", []string{"fatal_error_backtraces_off", "session_upload_progress_off"}},
	} {
		inv := target.Inventory{PHP: []target.PHPRuntime{fpm(c.version, "php-fpm-demo")}}
		if fs := Evaluate(tg, inv, s); len(fs) != 0 {
			t.Fatalf("%s without distro advisories: %+v", c.version, fs)
		}
		other := EvaluateWith(tg, inv, s, Options{DistroOpen: map[string][]string{"php-other": {"CVE-2026-109618"}}})
		if len(other) != 0 {
			t.Fatalf("%s: an advisory on another package opened %+v", c.version, other)
		}
		got := EvaluateWith(tg, inv, s, Options{DistroOpen: map[string][]string{"php-fpm-demo": {"DSA-0000-9", "CVE-2026-109619"}}})
		if !slices.Equal(ids(got), c.want) {
			t.Fatalf("%s: findings %v, want %v", c.version, ids(got), c.want)
		}
		for _, f := range got {
			if !f.Mitigation || f.Kind != scan.KindServerConfig {
				t.Fatalf("%s: %+v", c.version, f)
			}
		}
	}
}
