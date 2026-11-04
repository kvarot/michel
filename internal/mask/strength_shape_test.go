package mask

import (
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Key-shaped values are built here so that no scanner sees a key in this file.
var (
	stripeShape = "sk_live_" + "51Hxabcdefghijklmnop"
	jwtShape    = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0In0" + "." + "dBjftJeZ4CVPmB92K27u"
	slackShape  = "xoxb-" + "1234567890-abcdefghijkl"
	// The hash of the word "password" in Laravel's old UserFactory: public.
	laravelHash = "$2y$10$" + "92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"
)

var shapeCases = []struct {
	name, file, text string
	hit, strong      bool
}{
	// N1: code on a name that looks sensitive.
	{"py cache", "a.py", "key = cache.get(name)\n", true, false},
	{"py header", "a.py", "token = request.headers.get('Authorization')\n", true, false},
	{"py form", "a.py", "password = form.cleaned_data['password']\n", true, false},
	{"py environ", "a.py", "SECRET_KEY = os.environ.get('SECRET_KEY')\n", true, false},
	{"py getenv", "a.py", "API_KEY = os.getenv('API_KEY')\n", true, false},
	{"py config", "a.py", "TOKEN = config('TOKEN')\n", true, false},
	{"py model", "a.py", "primary_key = models.AutoField(primary_key=True)\n", true, false},
	{"js call", "a.js", "key = String(index);\n", true, false},
	{"js storage", "a.js", "token = localStorage.getItem('token');\n", true, false},
	{"go join", "a.go", "key = strings.Join(parts, \",\")\n", true, false},
	{"env unquoted literal", "a.txt", "API_KEY = kP9mW2xQ7vT3\n", true, true},

	// N2: new detectors, known formats always strong.
	{"define", "a.php", "define('DB_PASSWORD', 'S3cr3t!Prod-2024');\n", true, true},
	{"define salt", "a.php", "define( 'AUTH_SALT', 'kP9mW2xQ7vT3nR8s' );\n", true, true},
	{"define sentence", "a.php", "define('AUTH_KEY', 'put your unique phrase here');\n", true, false},
	{"define no name", "a.php", "define('APP_NAME', 'Michel-2024-x');\n", false, false},
	{"define public", "a.php", "define('PUBLIC_KEY', 'kP9mW2xQ7vT3nR8s');\n", false, false},
	{"define code", "a.php", "define('DB_KEY', getenv('X'));\n", false, false},
	{"stripe", "a.php", "new StripeClient('" + stripeShape + "')\n", true, true},
	{"restricted stripe", "a.js", "const k = \"rk_live_" + "51Hxabcdefghijklmnop\";\n", true, true},
	{"stripe too short", "a.js", "const k = \"sk_live_" + "abc\";\n", false, false},
	{"jwt bearer", "a.js", "Authorization: 'Bearer " + jwtShape + "'\n", true, true},
	{"jwt variable", "a.php", "$jwt = '" + jwtShape + "';\n", true, true},
	{"slack", "a.js", "const s = '" + slackShape + "';\n", true, true},
	{"laravel key", "a.php", "'key' => 'base64:" + "c29tZXRoaW5nLXJhbmRvbS0xMjM0NTY3ODkw',\n", true, true},
	{"plain key", "a.php", "'key' => 'value',\n", false, false},
	{"pdo", "a.php", "new PDO($dsn, 'root', 'S3cr3t!Prod-2024');\n", true, true},
	{"pdo variables", "a.php", "new PDO($dsn, $user, $pass);\n", false, false},

	// N3: letters that make no word.
	{"capitals scattered", "a.txt", "DB_PASSWORD=hXqzPtLmWvRbNc\n", true, true},
	{"consonants", "a.txt", "DB_PASSWORD=abcdfghjkae\n", true, true},
	{"a word", "a.txt", "DB_PASSWORD=Tournesol\n", true, false},
	{"french word", "a.txt", "DB_PASSWORD=motdepasse\n", true, false},
	{"an identifier", "a.txt", "DB_PASSWORD=PasswordInputField\n", true, false},

	// N4: a dot or a comma does not make code.
	{"unquoted jwt", "a.yml", "token: " + jwtShape + "\n", true, true},
	{"unquoted dotted", "a.yml", "password: Tr0ub4dor.3xyz\n", true, true},
	{"member", "a.js", "password: process.env.X\n", true, false},
	{"member of a config", "a.js", "password: cfg.Password\n", true, false},

	// N5: a template is the whole value.
	{"dollar then literal", "a.txt", "DB_PASSWORD='$kP9mW2xQ7vT'\n", true, true},
	{"slash then literal", "a.txt", "APP_KEY=/kP9mW2xQ7vT3nR8sL1bY6fH4dG0jZ5c\n", true, true},
	{"xxx inside a literal", "a.txt", "DB_PASSWORD=Fr4nce_xxx_99\n", true, true},
	{"example inside a word", "a.txt", "DB_PASSWORD=Fr4nceExample2\n", true, true},
	{"variable", "a.txt", "DB_PASSWORD=\"$DB_PASSWORD_VALUE\"\n", true, false},
	{"variable and digit", "a.txt", "DB_PASSWORD=\"$DB_PASSWORD2\"\n", true, false},
	{"moustache", "a.yml", "token: '{{ deploy_token }}'\n", true, false},
	{"moustache tight", "a.yml", "token: '{{deploy_token}}'\n", true, false},
	{"brackets", "a.yml", "api_key: '<api-key-value>'\n", true, false},
	{"percents", "a.yml", "password: '%db_password%'\n", true, false},
	{"shell", "a.sh", "TOKEN=\"$(read_the_token)\"\n", true, false},
	{"lowercase path", "a.txt", "KEY_FILE=/etc/ssl/private/server.key\n", true, false},
	{"placeholder part and a number", "a.txt", "API_KEY=xxxx-xxxx-12345678\n", true, false},
	{"placeholder part", "a.txt", "API_KEY=replace_with_real_value\n", true, false},
	{"change me", "a.txt", "API_KEY=please_change_me_now\n", true, false},

	// N6: public or test values.
	{"laravel hash", "a.php", "'password' => '" + laravelHash + "',\n", true, false},
	{"another hash", "a.php", "'password' => '$2y$10$" + "abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234',\n", true, true},
	{"npm alias", "a.json", "\"token\": \"npm:tok3n-lib@1.2.3\"\n", true, false},
	{"workspace", "a.json", "\"token\": \"workspace:packages/t0ken\"\n", true, false},
	{"file", "a.json", "\"token\": \"file:../t0ken-lib\"\n", true, false},
	{"link", "a.json", "\"token\": \"link:../t0ken-lib\"\n", true, false},
	{"caret", "a.json", "\"token\": \"^12.4.1-beta3\"\n", true, false},
	{"tilde", "a.json", "\"token\": \"~12.4.1-beta3\"\n", true, false},
	{"validation required", "a.php", "'password' => 'required|min:8|regex:a1b2',\n", true, false},
	{"validation nullable", "a.php", "'password' => 'nullable|min:8|regex:a1b2',\n", true, false},
	{"validation string", "a.php", "'password' => 'string|min:8|regex:a1b2',\n", true, false},
	{"validation sometimes", "a.php", "'password' => 'sometimes|min:8|regex:a1b2',\n", true, false},
	{"stripe test", "a.js", "api_key: 'sk_test_" + "51Hxabcdefghijklmnop',\n", true, false},
	{"a fake part", "a.js", "api_key: 'fake-kP9mW2xQ7vT',\n", true, false},
	{"a mock part", "a.js", "api_key: 'mock_kP9mW2xQ7vT',\n", true, false},
	{"a stub part", "a.js", "api_key: 'stub.kP9mW2xQ7vT',\n", true, false},
	{"a dummy part", "a.js", "api_key: 'dummy-kP9mW2xQ7vT',\n", true, false},
	{"test inside a word", "a.js", "api_key: 'Att3st4tionKey9',\n", true, true},

	// A default word plus digits is a real password when it is written out.
	{"default and digits", "a.py", "password = 'admin123'\n", true, true},
	{"default and digits, php", "a.php", "$password = 'root1234';\n", true, true},
	{"default and digits, json", "a.json", "\"password\": \"welcome1\"\n", true, true},
	{"default and digits in an address", "a.txt", "mysql://app:admin123@db.internal/app\n", true, true},
	{"default alone", "a.py", "password = 'password'\n", true, false},
	{"default and digits without quotes", "a.txt", "password: admin123\n", true, false},
	{"default and digits, test part", "a.py", "password = 'test_admin123'\n", true, false},

	// What docs/fix.md says passes, or stops, whatever it looks like.
	{"docs: a sign read as code", "a.txt", "DB_PASSWORD=aB3;xY9!qZ\n", true, false},
	{"docs: joined words", "a.yml", "password: cheval-correct-batterie\n", true, false},
	{"docs: a mock part", "a.txt", "API_KEY=mock-kP9mW2xQ7vT\n", true, false},
	{"docs: a word path", "a.txt", "KEY_FILE=/etc/ssl/private/server.key\n", true, false},
	{"docs: an array name", "a.php", "$config['password'] = 'S3cr3t!Prod-2024';\n", true, true},
	{"docs: mysqli", "a.php", "new mysqli('hote', 'root', 'S3cr3t!Prod-2024');\n", true, true},
	{"docs: a plain key", "a.yml", "key: kP9mW2xQ7vT3\n", false, false},
	{"docs: an example in a format", "a.md", "Use xoxb-your-bot-token here\n", true, true},
}

func TestStrengthOfShapes(t *testing.T) {
	for _, c := range shapeCases {
		t.Run(c.name, func(t *testing.T) {
			hits := scanOne(t, c.file, c.text)
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
		})
	}
}

// The one hash that is exempt is the public one: it is the hash of "password".
func TestTheExemptHashIsThePublicOne(t *testing.T) {
	if err := bcrypt.CompareHashAndPassword([]byte(laravelHash), []byte("password")); err != nil {
		t.Fatal(err)
	}
}

// The detectors as they were before the strength rule moved: what they find
// must stay hidden, whatever is added or judged later.
var formerDetectors = []detector{
	{re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*$)`)},
	{re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`)},
	{kind: KindEnvValue, skip: 1, re: regexp.MustCompile(`(?im)^[ 	]*(?:export[ 	]+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|KEY)(?:_[A-Z0-9_]*)?)[ 	]*=[ 	]*` + valueExpr)},
	{kind: KindAssignment, re: regexp.MustCompile(`(?i)` + keywordExpr + `["']?[ 	]*(?:=>|:|=)[ 	]*` + valueExpr)},
	{re: regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@"'<>]*:([^\s/@"'<>]+)@`)},
}

// formerSpans is what formerDetectors hid in s, by the rules of the time.
func formerSpans(s string) [][2]int {
	var spans [][2]int
	for _, d := range formerDetectors {
		for _, loc := range d.re.FindAllStringSubmatchIndex(s, -1) {
			a, b := loc[0], loc[1]
			if len(loc) > 2 {
				a, b = -1, -1
				for g := 1 + d.skip; 2*g+1 < len(loc); g++ {
					if loc[2*g] >= 0 {
						a, b = loc[2*g], loc[2*g+1]
						break
					}
				}
			}
			if a < 0 || b <= a {
				continue
			}
			if d.kind == KindEnvValue && notSecretNames.MatchString(s[loc[2]:loc[3]]) {
				continue
			}
			if (d.kind == KindEnvValue || d.kind == KindAssignment) && isNonValue(s[a:b]) {
				continue
			}
			spans = append(spans, [2]int{a, b})
		}
	}
	return spans
}

// Masking never narrows: every span the former detectors hid is still inside
// a span hidden now, and a hit of the table is really masked.
func TestMaskingNeverNarrows(t *testing.T) {
	check := func(name, text string, hit bool) {
		t.Helper()
		found := find(text, "")
		for _, span := range formerSpans(text) {
			covered := false
			for _, m := range found {
				covered = covered || (m.start <= span[0] && span[1] <= m.end)
			}
			if !covered {
				t.Errorf("%s: %q is no longer hidden in %q", name, text[span[0]:span[1]], text)
			}
		}
		if hit && !HasToken(New().Mask(text)) {
			t.Errorf("%s: %q is no longer masked", name, text)
		}
	}
	for _, c := range strengthCases {
		check(c.name, c.text, c.hit)
	}
	for _, c := range shapeCases {
		check(c.name, c.text, c.hit)
	}
	for _, line := range []string{
		"k=" + awsShape, "tok " + githubShape, pemShape, "password: hunter2", "pwd=ab", "pass: abcd",
		"'token' => 'abcdefgh12345'", `"password": "my long pass phrase"`, "PASSWORD=${X:-defaultpw}",
		"DB_PASSWORD=%env(X)%defaultpw", "redis://:pw@h", "password=[secret-MyRealPw]",
		"token = `abc def", `PASSWORD="abc def ghi`, "SECRET_KEY_BASE=abcd1234", "export dbtoken=abcd1234",
	} {
		check(strings.TrimSpace(line), line, true)
	}
}
