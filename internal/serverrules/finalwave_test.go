package serverrules

import (
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// Final wave, Task 5 M6 regression: an inline `; comment` after a risky
// value does not hide it, in php.ini, in a pool and in a .user.ini.
func TestInlineCommentAfterRiskyValueIsRisky(t *testing.T) {
	rt := fpm("8.4.27", "")
	rt.PoolFiles = []string{poolFile}
	for name, d := range map[string][]target.Directive{
		"php.ini": {dir("fpm", fpmBin, "display_errors", "On ; dev", "/etc/php/php.ini")},
		"pool": {dir("fpm", fpmBin, "display_errors", "0", "/etc/php/php.ini"),
			dir("fpm", fpmBin, "php_admin_value[display_errors]", "On ; dev", poolFile)},
		".user.ini": {dir("fpm", fpmBin, "display_errors", "0", "/etc/php/php.ini"),
			dir("user_ini", fpmBin, "display_errors", "On ; dev", "/home/demo/www/.user.ini")},
	} {
		inv := target.Inventory{PHP: []target.PHPRuntime{rt}, Directives: d}
		if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); !hasRule(fs, "display_errors_prod") {
			t.Errorf("%s: display_errors = On ; dev is not judged risky: %v", name, ids(fs))
		}
	}
	// And the comment alone does not make a safe value risky.
	inv := target.Inventory{PHP: []target.PHPRuntime{rt}, Directives: []target.Directive{
		dir("fpm", fpmBin, "display_errors", "Off ; On in dev", "/etc/php/php.ini")}}
	if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); hasRule(fs, "display_errors_prod") {
		t.Errorf("Off ; On in dev judged risky: %v", ids(fs))
	}
}
