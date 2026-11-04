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
	{"array variable", "$config['password'] = $input;\n", true, false, false},
	{"array getenv", "$config['password'] = getenv('DB_PASSWORD');\n", true, false, false},
	{"array env superglobal", "$config['password'] = $_ENV['DB_PASSWORD'];\n", true, false, false},
	{"array env helper", "$config['password'] = env('DB_PASSWORD');\n", true, false, false},
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
			if c.maskedSecret && (strings.Contains(out, secretValue) || !HasToken(out)) {
				t.Errorf("secret still in the masked text: %q", out)
			}
		})
	}
}
