package serverfix_test

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/target"
)

// FuzzRenderedScriptStaysInGrammar feeds random values, paths, keys,
// services, packages and correction ids, through Validate and straight into
// Render: either an error, or two scripts that pass Lint and hold no
// deleting command.
func FuzzRenderedScriptStaysInGrammar(f *testing.F) {
	f.Add("0", fpmIni, "display_errors", "php8.2-fpm", "libdemo", "1.1-1", cid, 3, false, false)
	f.Add("Off'; rm -rf / #", "/etc/x'; rm -rf /'.ini", "a|b", "x; rm", "a b", "1;rm", "x\"y", 0, true, true)
	f.Add("/var/www:/tmp", userIni, "php_admin_value[open_basedir]", "nginx", "php8.2-fpm", "8.3.0", "id", -1, true, false)
	f.Add("-delete", "/etc/php/8.2/fpm/../../shadow", "x\nrm -rf /", "a\nb", "", "", "", 1, false, true)
	f.Fuzz(func(t *testing.T, value, path, key, service, pkg, version, id string, line int, appendLine, sudo bool) {
		tg := demoTarget()
		if sudo {
			tg.Sudo = target.SudoNopasswd
		}
		check := func(b serverfix.Bundle) {
			for _, s := range []string{b.Apply, b.Undo} {
				if err := serverfix.Lint(s); err != nil {
					t.Fatalf("rendered script outside the grammar: %v\n%s", err, s)
				}
				for _, l := range strings.Split(s, "\n") {
					if deletion.MatchString(l) {
						t.Fatalf("deleting line %q", l)
					}
				}
			}
		}
		// Through Validate.
		for _, sapi := range []string{"fpm", "cli", "user_ini"} {
			for _, d := range []string{"display_errors", "open_basedir", key} {
				p := setDirective(sapi, d, value, path)
				p.Actions = append(p.Actions, serverfix.Action{Op: serverfix.OpReload, Service: service})
				if v, err := serverfix.Validate(p, tg, demoInventory()); err == nil {
					if b, err := serverfix.Render(v, tg, id); err == nil {
						check(b)
					}
				}
			}
		}
		pp := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: pkg, Version: version}}}
		if v, err := serverfix.Validate(pp, tg, demoInventory()); err == nil {
			if b, err := serverfix.Render(v, tg, id); err == nil {
				check(b)
			}
		}
		// Straight into Render, as a forged plan.
		forged := serverfix.Plan{Actions: []serverfix.Action{
			{Op: serverfix.OpBackup, Path: path},
			{Op: serverfix.OpSetDirective, Path: path, Directive: key, Key: key, Value: value, Line: line, Append: appendLine},
			{Op: serverfix.OpTestConfig, SAPI: "cli", Binary: path, Path: path},
			{Op: serverfix.OpReload, Service: service, Manager: "systemctl"},
			{Op: serverfix.OpPackageUpgrade, Package: pkg, Version: version, Manager: "apt"},
			{Op: serverfix.OpCheckSite},
		}}
		if b, err := serverfix.Render(forged, tg, id); err == nil {
			check(b)
		}
		forged.Actions = forged.Actions[:4]
		if b, err := serverfix.Render(forged, tg, id); err == nil {
			check(b)
		}
	})
}
