package mask

import (
	"strings"
	"testing"
	"time"
)

// Fix round 4. Every row holds a later literal Zz9#knLm2Qw that must not be seen.
const chainTail = "'Zz9#knLm2Qw'"

var chainCases = []struct {
	name, text string
	strong     bool
}{
	// A PHP expression after a dot does not end the chain.
	{"constant, no blanks", "$c['password'] = '" + secretValue + "'.PHP_EOL." + chainTail + ";\n", true},
	{"variable and constant", "$c['password'] = '" + secretValue + "' . $x.PHP_EOL . " + chainTail + ";\n", true},
	{"class constant", "$c['password'] = '" + secretValue + "'.self::X." + chainTail + ";\n", true},
	{"call, no blanks", "$c['password'] = '" + secretValue + "'.sprintf('%s', $a)." + chainTail + ";\n", true},
	{"integer", "$c['password'] = '" + secretValue + "' . 1 . " + chainTail + ";\n", true},
	{"float", "$c['password'] = '" + secretValue + "' . 1.5 . " + chainTail + ";\n", true},
	{"negative", "$c['password'] = '" + secretValue + "' . -1 . " + chainTail + ";\n", true},
	{"property base", "$this->c['db']['password'] = '" + secretValue + "'.PHP_EOL." + chainTail + ";\n", true},
	{"static base", "self::$c['password'] = '" + secretValue + "'.PHP_EOL." + chainTail + ";\n", true},
	{"fat arrow", "$c = ['password' => '" + secretValue + "'.PHP_EOL." + chainTail + "];\n", true},
	{"fat arrow alone on its line", "    'password' => '" + secretValue + "'.PHP_EOL." + chainTail + ",\n", true},
	{"mysqli", "$db = new mysqli($h, $u, '" + secretValue + "'.PHP_EOL." + chainTail + ", 'd');\n", true},
	{"mysqli_connect", "$db = MySQLi_Connect($h, $u, '" + secretValue + "'.FOO." + chainTail + ", 'd');\n", true},
	{"define", "define('DB_PASSWORD', '" + secretValue + "'.PHP_EOL." + chainTail + ");\n", true},
	{"define plain", "define('DB_PASSWORD', '" + secretValue + "' . " + chainTail + ");\n", true},
	// A rejected first literal does not take the chain with it.
	{"after a rejected value", "$c['password'] = '' . $x . $d['token'] = '" + secretValue + "' . " + chainTail + ";\n", true},
	{"empty first literal", "$c['password'] = '' . " + chainTail + ";\n", true},
	{"null word first", "$c['password'] = 'null' . " + chainTail + ";\n", true},
	{"empty first, fat arrow", "'password' => '' . " + chainTail + ",\n", true},
	{"empty first, mysqli", "$db = new mysqli($h, $u, '' . " + chainTail + ", 'd');\n", true},
	// Past the chain limit: to the end of the statement or the argument, over lines.
	{"long, over lines", "$c['password'] = '" + secretValue + "'" + strings.Repeat("\n    . $x", 700) + "\n    . " + chainTail + "\n    . 'Aa1nBb2n';\n", true},
	{"long, a semicolon in a string", "$c['password'] = '" + secretValue + "'" + strings.Repeat(" . $x", 900) + " . 'a;b' . " + chainTail + ";\n", true},
	{"long, comment with an apostrophe", "$c['password'] = '" + secretValue + "'" + strings.Repeat(" . $x", 900) + " . /* it's */\n " + chainTail + ";\n", true},
	{"long, unclosed quote", "$c['password'] = '" + secretValue + "'" + strings.Repeat(" . $x", 900) + " . 'Zz9#knLm2Qw\n", true},
}

func TestChainsLeakNothing(t *testing.T) {
	for _, c := range chainCases {
		t.Run(c.name, func(t *testing.T) {
			hits := scanOne(t, "a.php", c.text)
			// The row after a rejected value holds two assignments: the first chain and the second.
			if len(hits) == 0 || hits[len(hits)-1].Strong != c.strong || (len(hits) > 1 && c.name != "after a rejected value") {
				t.Errorf("hits = %+v, want one, strong %v", hits, c.strong)
			}
			m := New()
			out := m.Mask(c.text)
			for _, leak := range []string{"Zz9#", "knLm2Qw", "Aa1nBb2n", secretValue} {
				if strings.Contains(out, leak) {
					t.Errorf("%q leaks: %.200q", leak, out)
				}
			}
			if !quotesBalanced(out) {
				t.Errorf("quotes no longer balanced: %.200q", out)
			}
			if m.Unmask(out) != c.text {
				t.Errorf("round trip failed: %.200q", out)
			}
			if again := m.Mask(out); again != out {
				t.Errorf("masking twice changes the text: %.200q then %.200q", out, again)
			}
		})
	}
}

// What follows a chain stays as it is, and a chain that is only code holds nothing.
func TestChainsKeepWhatFollows(t *testing.T) {
	long := strings.Repeat(" . $x", 900)
	for _, c := range []struct{ name, text string }{
		{"python method arguments", "d['password']='abc'.encode('keep me')\n"},
		{"python method, next line", "d['password']='abc'.encode()\nprint('keep me')\n"},
		{"dollar on an earlier line only", "$a = 1;\nd['password']='abc'.encode('keep me')\n"},
		{"php, next statement", "$c['password'] = 'abc'.PHP_EOL; $k = 'keep me';\n"},
		{"php, next line without semicolon", "$c['password'] = 'abc'.PHP_EOL\n$k = 'keep me';\n"},
		{"php, next argument", "$db = new mysqli($h, $u, 'abc'.PHP_EOL, 'keep me');\n"},
		{"php close tag", "<?php $c['password'] = 'abc'.PHP_EOL ?>\n<p class=\"keep me\">\n"},
		{"long, next statement", "$c['password'] = 'abc'" + long + " . 'x';\n$k = 'keep me';\n"},
		{"long, next argument", "$db = new mysqli($h, $u, 'abc'" + long + ", 'keep me');\n"},
		{"long, closing bracket", "f($c['password'] = 'abc'" + long + ") . 'keep me';\n"},
		{"long, php close tag", "$c['password'] = 'abc'" + long + " ?>\n<p class=\"keep me\">\n"},
		{"hard cap, next line", "$c['password'] = 'abc'" + strings.Repeat(" . $x", 14000) + "\n$k = 'keep me';\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if out := New().Mask(c.text); !strings.Contains(out, "keep me") {
				t.Errorf("code after the chain was masked: %.200q", out)
			}
		})
	}
	for _, text := range []string{
		"$c['password'] = '' . $x;\n",
		"$c['password'] = '' . PHP_EOL;\n",
		"$c['password'] = '';\n",
	} {
		if hits := scanOne(t, "a.php", text); len(hits) != 0 {
			t.Errorf("%q: hits = %+v", text, hits)
		}
		if out := New().Mask(text); out != text {
			t.Errorf("%q changed: %q", text, out)
		}
	}
	for _, text := range []string{
		"$c['password'] = '' . getenv('DB_PASSWORD');\n",
		"$c['password'] = 'abc'.PHP_EOL.getenv('DB_PASSWORD');\n",
	} {
		for _, h := range scanOne(t, "a.php", text) {
			if h.Strong {
				t.Errorf("%q holds the agent", text)
			}
		}
	}
}

// One of this Masker's tokens is left alone, the secret joined to it is not.
func TestChainAfterOwnToken(t *testing.T) {
	m := New()
	tok := m.token(1)
	out := m.Mask("$c['password'] = '" + tok + "' . " + chainTail + ";\n")
	if strings.Contains(out, "Zz9#") || !strings.Contains(out, "'"+tok+"'") {
		t.Errorf("got %q", out)
	}
}

// Every byte is read a bounded number of times, whatever the text around it.
func TestChainLookaheadIsBounded(t *testing.T) {
	const size = 1_000_000
	repeat := func(unit string) string { return strings.Repeat(unit, size/len(unit)) }
	for name, text := range map[string]string{
		"blank lines in a chain":     "$a['password']='x' . $x" + repeat("\n") + ".",
		"comment lines in a chain":   "$a['password']='x' . $x" + repeat("// c\n") + ".",
		"blank lines after a dot":    "$a['password']='x' ." + repeat("\n") + "$x",
		"blank lines, python":        "d['password']='x' ." + repeat("\n") + "$x",
		"blanks, many chains":        repeat("$a['password']='x'\n\n\n\n\n\n\n\n"),
		"unclosed comment":           "$a['password']='x' . $x /*" + repeat(" "),
		"unclosed comment, stars":    "$a['password']='x' . $x /*" + repeat("*"),
		"unclosed comments, chained": repeat("$a['password']='x'./*"),
		"unclosed comments":          repeat("$a['password']='x'/*"),
		"unclosed comments, python":  repeat("d['password']='x' . /*"),
		"dots":                       "$a['password']='x'" + repeat("."),
		"dots, python":               "d['password']='x'" + repeat("."),
		"spaced dots":                "$a['password']='x'" + repeat(" ."),
		"rejected, chained":          repeat("$a['password']=''."),
		"rejected, then code":        repeat("$a['password']=''.$y "),
		"rejected, empty literals":   "$a['password']=''" + repeat(".''"),
		"rejected, comments":         repeat("$a['password']=''./**/"),
		"long lines":                 repeat("$a['password']='x'" + strings.Repeat(" . $x", 900) + "\n"),
		"long, no end":               repeat("$a['password']='x'" + strings.Repeat(" . $x", 15000) + " "),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			New().Mask(text)
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("%v for %d bytes", d, len(text))
			}
		})
	}
}
