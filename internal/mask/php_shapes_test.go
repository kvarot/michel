package mask

import (
	"strings"
	"testing"
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
			for _, leak := range []string{"Zz9#kLm2Qw", "S3cr3t,Demo", "Demo-2024)x"} {
				if c.hit && strings.Contains(out, leak) {
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
