package mask

import (
	"strings"
	"testing"
	"time"
)

// secretValue is a fictional password with the shape of a real one.
const secretValue = "S3cr3t!Demo-2024"

var phpShapeCases = []struct {
	name, text   string
	hit, strong  bool
	maskedSecret bool // the secret value must be gone from the masked text
}{
	// The array key on a sensitive name, every quote style.
	{"array single quotes", "$config['password'] = '" + secretValue + "';\n", true, true, true},
	{"array double quotes", "$cfg[\"db_password\"] = \"" + secretValue + "\";\n", true, true, true},
	{"array api key", "$settings['api_key'] = '" + secretValue + "';\n", true, true, true},
	{"array no space", "$config['password']='" + secretValue + "';\n", true, true, true},
	{"array token, fat arrow already covered", "'password' => '" + secretValue + "',\n", true, true, true},
	// Database connections: the password argument.
	{"mysqli", "$db = new mysqli('db.example.test', 'demo', '" + secretValue + "', 'app');\n", true, true, true},
	{"mysqli backslash", "$db = new \\mysqli('db.example.test', 'demo', '" + secretValue + "', 'app');\n", true, true, true},
	{"mysqli_connect", "$db = mysqli_connect('db.example.test', 'demo', \"" + secretValue + "\", 'app');\n", true, true, true},
	{"mysqli host and user variables", "$db = new mysqli($host, $user, '" + secretValue + "', $name);\n", true, true, true},
	{"pdo", "$db = new PDO('mysql:host=db.example.test', 'demo', '" + secretValue + "');\n", true, true, true},
	// Code and weak values: never hold the agent.
	{"array variable", "$config['password'] = $input;\n", false, false, false},
	{"array getenv", "$config['password'] = getenv('DB_PASSWORD');\n", false, false, false},
	{"array env superglobal", "$config['password'] = $_ENV['DB_PASSWORD'];\n", false, false, false},
	{"array env helper", "$config['password'] = env('DB_PASSWORD');\n", false, false, false},
	{"array empty", "$config['password'] = '';\n", false, false, false},
	{"array placeholder", "$config['password'] = 'your-password-here';\n", true, false, false},
	{"array default word", "$config['password'] = 'password';\n", true, false, false},
	{"array min length", "$config['password_min_length'] = 8;\n", false, false, false},
	{"array other name", "$config['username'] = '" + secretValue + "';\n", false, false, false},
	{"mysqli variables", "$db = new mysqli($h, $u, $p, $d);\n", false, false, false},
	{"mysqli_connect variables", "$db = mysqli_connect($h, $u, $p, $d);\n", false, false, false},
	{"mysqli empty password", "$db = new mysqli('db.example.test', 'demo', '', 'app');\n", false, false, false},
	{"mysqli getenv", "$db = new mysqli('db.example.test', 'demo', getenv('DB_PASS'), 'app');\n", false, false, false},
	{"mysqli placeholder", "$db = new mysqli('db.example.test', 'demo', 'your-password-here', 'app');\n", true, false, false},
	// Fix round 1: case, commas, lines, concatenation, code that must stay intact.
	{"mysqli mixed case", "$db = new MySQLi('h', 'u', '" + secretValue + "', 'd');\n", true, true, true},
	{"pdo mixed case", "$db = new Pdo('mysql:host=h', 'u', '" + secretValue + "');\n", true, true, true},
	{"mysqli_connect mixed case", "$db = MySQLi_Connect('h', 'u', '" + secretValue + "', 'd');\n", true, true, true},
	{"mysqli space before paren", "$db = new mysqli ('h', 'u', '" + secretValue + "', 'd');\n", true, true, true},
	{"mysqli comma in host", "$db = new mysqli('h,x', 'u', '" + secretValue + "', 'd');\n", true, true, true},
	{"mysqli call in first argument", "$db = new mysqli(trim($a, ' '), 'u', '" + secretValue + "', 'd');\n", true, true, true},
	{"mysqli long user after comma", "$db = new mysqli('h,x', 'a-long-user-name-1', '" + secretValue + "', 'd');\n", true, true, true},
	{"mysqli over lines", "$db = new mysqli(\n    'h',\n    'u',\n    '" + secretValue + "',\n    'd'\n);\n", true, true, true},
	{"mysqli password with comma and paren", "$db = new mysqli('h', 'u', 'S3cr3t,Demo-2024)x', 'd');\n", true, true, false},
	{"array concatenation", "$config['password'] = 'S3cr3t!Demo' . 'Zz9#kLm2Qw';\n", true, true, true},
	{"mysqli concatenation", "$db = new mysqli('h', 'u', 'S3cr3t!Demo' . \"Zz9#kLm2Qw\", 'd');\n", true, true, true},
	{"pdo concatenation", "$db = new PDO($dsn, 'u', 'S3cr3t!Demo' . 'Zz9#kLm2Qw');\n", true, true, true},
	{"concatenation of a weak first part", "$config['password'] = 'pass' . 'S3cr3t!Zz9#kLm2';\n", true, true, true},
	{"concatenation then variable", "$config['password'] = 'S3cr3t!Demo-2024' . $x;\n", true, true, true},
	{"array spaces in bracket", "$config[ 'password' ] = '" + secretValue + "';\n", true, true, true},
	{"array append", "$config['password'] .= '" + secretValue + "';\n", true, true, true},
	{"array null coalesce", "$config['password'] ??= '" + secretValue + "';\n", true, true, true},
	// Code that is not a value is left as it is.
	{"comparison", "if ($data['token'] == $expected) {\n", false, false, false},
	{"strict comparison", "if ($data['token'] === $expected) {\n", false, false, false},
	{"variable index", "$sessions[$token] = $user;\n", false, false, false},
	{"variable index literal", "$map[$token] = '" + secretValue + "';\n", false, false, false},
	{"bare index", "$a[password] = x;\n", false, false, false},
	{"comparison with literal", "if ($data['token'] == '" + secretValue + "') {\n", false, false, false},
	// Fix round 2: tails with an n, a backslash or an escaped quote, broken chains, lines, comments.
	{"array tail with n", "$config['password'] = 'S3cr3t!Demo' . 'Zz9#knLm2Qw';\n", true, true, true},
	{"array tail escaped quote", "$config['password'] = 'S3cr3t!Demo' . 'Zz9#\\'nkLm2Qw';\n", true, true, true},
	{"array tail ends with a backslash", "$config['password'] = 'S3cr3t!Demo' . 'Zz9#knLm2\\\\';\n", true, true, true},
	{"array three parts", "$config['password'] = 'S3cr3t!Demo' . 'Zz9#kLm2Qw' . 'Aa1nBb2n';\n", true, true, true},
	{"mysqli tail with n", "$db = new mysqli($h, $u, 'S3cr3t!Demo' . 'Zz9#nkLm2Qw', 'd');\n", true, true, true},
	{"pdo tail with n", "$db = new PDO($dsn, 'u', 'S3cr3t!Demo' . 'Zz9#knLm2Qw');\n", true, true, true},
	{"mysqli tail escaped quote", "$db = new mysqli($h, $u, \"S3cr3t!Demo\" . \"Zz9#\\\"knLm2Qw\", 'd');\n", true, true, true},
	{"chain broken by a variable", "$config['password'] = 'S3cr3t!Demo' . $x . 'Zz9#knLm2Qw';\n", true, true, true},
	{"mysqli chain broken by a variable", "$db = new mysqli($h, $u, 'S3cr3t!Demo' . $x . 'Zz9#knLm2Qw', 'd');\n", true, true, true},
	{"chain broken by parentheses", "$config['password'] = 'S3cr3t!Demo' . ('Zz9#knLm2Qw');\n", true, true, true},
	{"chain broken by a call", "$config['password'] = 'S3cr3t!Demo' . sprintf('%s', 'Zz9#knLm2Qw');\n", true, true, true},
	{"chain over lines, dot first", "$config['password'] = 'S3cr3t!Demo'\n    . 'Zz9#knLm2Qw';\n", true, true, true},
	{"chain over lines, dot last", "$config['password'] = 'S3cr3t!Demo' .\n    'Zz9#knLm2Qw';\n", true, true, true},
	{"weak head, variable, strong tail", "$config['password'] = 'abc' . $x . 'S3cr3t!Demo-2024';\n", true, true, true},
	{"mixed quotes single then double", "$config['password'] = 'S3cr3t!Demo' . \"Zz9#knLm2Qw\";\n", true, true, true},
	{"mixed quotes double then single", "$config['password'] = \"S3cr3t!Demo\" . 'Zz9#knLm2Qw';\n", true, true, true},
	{"fat arrow concatenation", "'password' => 'S3cr3t!Demo' . 'Zz9#knLm2Qw',\n", true, true, true},
	{"array() fat arrow concatenation", "$c = array('password' => 'S3cr3t!Demo' . 'Zz9#knLm2Qw', 'user' => 'u');\n", true, true, true},
	{"chain stops at the statement", "$config['password'] = 'S3cr3t!Demo-2024' . $x; $y = 'Zz9#knLm2Qw';\n", true, true, false},
	{"chain stops at the argument", "$db = new mysqli($h, $u, 'S3cr3t!Demo-2024' . $x, 'Zz9#knLm2Qw');\n", true, true, false},
	{"mysqli block comment", "$db = new mysqli($h, $u, /* pw */ 'S3cr3t!Demo-2024', 'd');\n", true, true, true},
	{"mysqli comment with an apostrophe", "$db = new mysqli(\n    'h', // it's the host\n    'u', # the user's name\n    'S3cr3t!Demo-2024'\n);\n", true, true, true},
	{"mysqli three levels of parentheses", "$db = new mysqli(f(g(h($a))), 'u', 'S3cr3t!Demo-2024', 'd');\n", true, true, true},
	{"mysqli four levels of parentheses", "$db = new mysqli(f(g(h(i($a)))), 'u', 'S3cr3t!Demo-2024', 'd');\n", false, false, false},
	// Fix round 3: comments in a chain, where a chain ends, hold, long chains.
	{"chain comment block with apostrophe", "$c['password'] = '" + secretValue + "' . /* it's */ 'Zz9#knLm2Qw';\n", true, true, true},
	{"chain comment line with apostrophe", "$c['password'] = '" + secretValue + "' . // it's here\n    'Zz9#knLm2Qw';\n", true, true, true},
	{"chain comment hash before the dot", "$c['password'] = '" + secretValue + "' # it's\n    . 'Zz9#knLm2Qw';\n", true, true, true},
	{"mysqli chain comment", "$db = new mysqli($h, $u, '" + secretValue + "' . /* it's */ 'Zz9#knLm2Qw', 'd');\n", true, true, true},
	{"keeps python method", "d['password'] = 'abc'.encode()\nprint(\"keep me\")\nx = 'keep me too'\n", true, false, false},
	{"keeps js method on next line", "cfg['token'] = 'abc'\n.trim()\nz = \"keep me\"\n", true, false, false},
	{"keeps after a php close tag", "<?php $c['password'] = '" + secretValue + "' . 'x' ?>\n<p class=\"keep me\">\n", true, true, true},
	{"keeps after a statement without semicolon", "$c['password'] = '" + secretValue + "' . $a\n$d['keep me password'] = 'p2' . $b\n$e = \"keep me\";\n", true, true, true},
	{"chain with a harmless literal keeps the hold", "$c['password'] = '" + secretValue + "' . 'http://x//y' . 'Zz9#knLm2Qw';\n", true, true, true},
	{"chain longer than the limit", "$c['password'] = '" + secretValue + "'" + strings.Repeat(" . $x", 900) + " . 'Zz9#knLm2Qw';\n", true, true, true},
}

func TestPHPArraySecretsAndConnectionPasswords(t *testing.T) {
	for _, c := range phpShapeCases {
		t.Run(c.name, func(t *testing.T) {
			hits := scanOne(t, "a.php", c.text)
			if (len(hits) > 0) != c.hit {
				t.Fatalf("hits = %+v, want a hit: %v", hits, c.hit)
			}
			strong := false
			for _, h := range hits {
				strong = strong || h.Strong
			}
			if strong != c.strong {
				t.Errorf("strong = %v, want %v (%+v)", strong, c.strong, hits)
			}
			out := New().Mask(c.text)
			if c.hit && !quotesBalanced(out) {
				t.Errorf("quotes no longer balanced: %q", out)
			}
			if strings.HasPrefix(c.name, "keeps") && !strings.Contains(out, "keep me") {
				t.Errorf("code after the chain was masked: %q", out)
			}
			if strings.HasPrefix(c.name, "chain stops") && !strings.Contains(out, "Zz9#knLm2Qw") {
				t.Errorf("code after the statement was masked: %q", out)
			}
			for _, leak := range []string{"Zz9#", "kLm2Qw", "knLm2Qw", "nkLm2Qw", "Aa1nBb2n", "S3cr3t,Demo", "Demo-2024)x"} {
				if c.hit && !strings.HasPrefix(c.name, "chain stops") && strings.Contains(out, leak) {
					t.Errorf("part of the secret leaks (%q): %q", leak, out)
				}
			}
			if !c.hit && out != c.text {
				t.Errorf("code was changed: %q", out)
			}
			if c.maskedSecret && (strings.Contains(out, secretValue) || !HasToken(out)) {
				t.Errorf("secret still in the masked text: %q", out)
			}
		})
	}
}

// quotesBalanced says every quote of the line that is not escaped, or inside a
// comment, has its pair: the masked line must still close its strings.
func quotesBalanced(s string) bool {
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			break
		}
		k := strings.Index(s[i:], "*/")
		if k < 0 {
			break
		}
		s = s[:i] + s[i+k+2:]
	}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, " # "); i >= 0 {
			line = line[:i]
		}
		line = strings.ReplaceAll(line, `\\`, "")
		line = strings.ReplaceAll(line, `\'`, "")
		line = strings.ReplaceAll(line, `\"`, "")
		if strings.Count(line, "'")%2 != 0 || strings.Count(line, `"`)%2 != 0 {
			return false
		}
	}
	return true
}

// A chain of three literals is one secret: one hit, one count.
func TestAChainIsOneHit(t *testing.T) {
	text := "$c['password'] = '" + secretValue + "' . $x . 'Zz9#knLm2Qw' . 'Aa1nBb2n';\n"
	if hits := scanOne(t, "a.php", text); len(hits) != 1 {
		t.Errorf("hits = %+v, want one", hits)
	}
	m := New()
	m.Mask(text)
	if n := m.Counts()[string(KindAssignment)]; n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
}

// A dense file near the size cap costs a linear time: no position is read twice.
func TestDenseChainsAreLinear(t *testing.T) {
	for _, unit := range []string{"$a['password']='x'.", "$a['password']='x1'.\"", "'x'. "} {
		text := strings.Repeat(unit, 1_000_000/len(unit))
		start := time.Now()
		New().Mask(text)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%q: %v for %d bytes", unit, d, len(text))
		}
	}
}
