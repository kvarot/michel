package serverrules

import (
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// PHP reads an ini boolean as on/yes/true, else the number its leading
// digits make (atoi): "1x", "1.0" and "1:" are On, "0x1" is Off.
func TestIsOnReadsLikePHP(t *testing.T) {
	for v, want := range map[string]bool{
		"1": true, "1x": true, "1.0": true, "1:": true, " 1": true, "01": true, "+1": true, "-1": true, "2": true,
		"On": true, "on": true, "YES": true, "True": true, "On ; dev": true,
		"0": false, "0x1": false, "00": false, "off": false, "Off": false, "no": false, "false": false,
		"none": false, "": false, "x1": false, "-0": false, "0 ; 1": false,
	} {
		if got := isOn(v); got != want {
			t.Errorf("isOn(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestAllowURLIncludeOneDotZeroIsFlagged(t *testing.T) {
	for _, v := range []string{"1.0", "1x", "1:"} {
		inv := target.Inventory{
			PHP:        []target.PHPRuntime{fpm("8.4.27", "")},
			Directives: []target.Directive{dir("fpm", fpmBin, "allow_url_include", v, "/etc/php/php.ini")},
		}
		if fs := Evaluate(srv(target.EnvProd, target.KindVPS), inv, mustRules(t)); !hasRule(fs, "allow_url_include") {
			t.Errorf("allow_url_include = %s not flagged: %v", v, ids(fs))
		}
	}
}
