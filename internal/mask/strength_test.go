package mask

import (
	"os"
	"path/filepath"
	"testing"
)

// scanOne is what ScanFiles says of one file holding text.
func scanOne(t *testing.T, name, text string) []Hit {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return ScanFiles(root, []string{name})
}

// Key-shaped values are built here so that no scanner sees a key in this file.
var (
	awsShape    = "AKIA" + "ABCDEFGHIJKLMNOP"
	githubShape = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	pemShape    = "-----BEGIN RSA " + "PRIVATE KEY-----\nabc\n-----END RSA " + "PRIVATE KEY-----\n"
)

var strengthCases = []struct {
	name, file, text string
	// hit says the detectors see it (masking is unchanged), strong that it
	// stops the agent.
	hit, strong bool
}{
	// Known formats.
	{"aws key", "a.php", "$key = '" + awsShape + "';\n", true, true},
	{"aws key on a plain name", "a.js", "const id = \"" + awsShape + "\";\n", true, true},
	{"aws key documented by AWS", "README.md", "id: " + "AKIAIOSFODNN7" + "EXAMPLE\n", true, false},
	{"github token", "a.yml", "image: " + githubShape + "\n", true, true},
	{"pem", "a.txt", pemShape, true, true},

	// The findings' samples: ordinary code.
	{"ts type", "a.ts", "password: string\n", true, false},
	{"js call", "a.js", "const x = { token: getToken() }\n", true, false},
	{"js rule", "a.js", "rules: { password: [required] }\n", true, false},
	{"php variable", "a.php", "$password = $request->input('password');\n", true, false},
	{"php sentence", "a.php", "'password' => 'Mot de passe incorrect',\n", true, false},
	{"php env", "a.php", "'password' => env('DB_PASSWORD', ''),\n", true, false},
	{"python signature", "a.py", "def login(password: str, token=None):\n", true, false},
	{"readme placeholder", "README.md", "Set `API_KEY=your-key-here`\n", true, false},

	// Realistic PHP.
	{"php rule", "a.php", "'password' => 'required|string|min:8|confirmed',\n", true, false},
	{"php word", "a.php", "'password' => 'incorrect',\n", true, false},
	{"php translation key", "a.php", "'password' => 'passwords.reset',\n", true, false},
	{"unicode escape", "a.json", "\"password\": \"Contrase\\u00f1a\",\n", true, false},
	{"php member", "a.php", "$token = $this->tokens->create($user);\n", true, false},
	{"php literal", "a.php", "$password = 'Xy7kL9qZ2m';\n", true, true},
	{"php literal in an array", "a.php", "'secret' => 'a1b2c3d4e5f6a7b8',\n", true, true},
	{"php symbols", "a.php", "$pwd = 'P@ssw0rd!x';\n", true, true},
	{"php word and digits", "a.php", "$password = 'motdepasse123';\n", true, true},

	// Realistic JS.
	{"js member", "a.js", "const c = { secret: process.env.SESSION_SECRET }\n", true, false},
	{"js argument", "a.js", "login({ password: password1, token })\n", true, false},
	{"js placeholder", "a.js", "api_key: 'YOUR_API_KEY',\n", true, false},
	{"js sentence", "a.js", "password: 'Password is required',\n", true, false},
	{"js short", "a.js", "password: 'abc',\n", true, false},
	{"js template", "a.js", "token: `${prefix}-${id}`,\n", true, false},
	{"js literal", "a.js", "api_key: 'k3Jd92LsQp0x',\n", true, true},
	{"js bearer", "a.js", "token: \"eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0\",\n", true, true},

	// Realistic .env.example.
	{"env empty", ".env.example", "APP_KEY=\n", false, false},
	{"env null", ".env.example", "REDIS_PASSWORD=null\n", false, false},
	{"env framework default", ".env.example", "DB_PASSWORD=secret\n", true, false},
	{"env default word", ".env.example", "DB_PASSWORD=password\n", true, false},
	{"env default with digits", ".env.example", "DB_PASSWORD=password123\n", true, false},
	{"env changeme", ".env.example", "JWT_SECRET=changeme\n", true, false},
	{"env your", ".env.example", "JWT_SECRET=your-secret-key\n", true, false},
	{"env brackets", ".env.example", "API_KEY=<your-api-key>\n", true, false},
	{"env xxx", ".env.example", "STRIPE_SECRET_KEY=sk_test_xxxxxxxx\n", true, false},
	{"env stars", ".env.example", "API_KEY=**************\n", true, false},
	{"env number", ".env.example", "TOKEN_TTL=86400000\n", true, false},
	{"env date", ".env.example", "KEY_ROTATED=2026-01-31\n", true, false},
	{"env address", ".env.example", "TOKEN_URL=https://auth.example.org/oauth2/token\n", true, false},
	{"env path", ".env.example", "KEY_FILE=./certs/key1234.pem\n", true, false},
	{"env words", ".env.example", "SESSION_KEY_PREFIX=laravel_session\n", true, false},
	{"env region", ".env.example", "SECRET_REGION=eu-west-1\n", true, false},
	{"env reference with a word", ".env.example", "DB_PASS=${DB_PASS:-secret}\n", true, false},
	{"env reference with a literal", ".env.example", "DB_PASS=${DB_PASS:-Xy7kL9qZ2m}\n", true, true},
	{"env url words", ".env.example", "DATABASE_URL=postgres://user:password@127.0.0.1:5432/app\n", true, false},
	{"env real looking", ".env.example", "APP_KEY=base64:c29tZXRoaW5nLXJhbmRvbS0xMjM0NTY3ODkw\n", true, true},
	{"env live key", ".env.example", "STRIPE_SECRET_KEY=sk_live_51Habcdefghijklm\n", true, true},
	{"env url literal", ".env.example", "DATABASE_URL=postgres://app:Xy7kL9qZ2m@db.internal/app\n", true, true},

	// Other files.
	{"yaml literal", "a.yml", "password: Xy7kL9qZ2m\n", true, true},
	{"yaml workflow", "a.yml", "token: ${{ secrets.DEPLOY_TOKEN }}\n", true, false},
	{"lock file", "package-lock.json", "{\"name\":\"x\",\"integrity\":\"sha512-abc\"}\n", false, false},
}

func TestStrengthOfAHit(t *testing.T) {
	for _, c := range strengthCases {
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

// A line with a weak and a strong match is strong: the judgement looks at each
// detector's match, not at the merged span.
func TestStrengthSurvivesAMergedSpan(t *testing.T) {
	hits := scanOne(t, "a.env", "TOKEN="+awsShape+"\n")
	if len(hits) != 1 || !hits[0].Strong || hits[0].Kind != KindAWSKey {
		t.Errorf("hits = %+v", hits)
	}
}

// The judgement decides what stops the agent, never what is hidden.
func TestWeakHitsAreStillMasked(t *testing.T) {
	m := New()
	for _, line := range []string{"DB_PASSWORD=secret\n", "password: string\n", "JWT_SECRET=changeme\n", "'password' => 'incorrect',\n"} {
		if out := m.Mask(line); !HasToken(out) {
			t.Errorf("%q is no longer masked: %q", line, out)
		}
	}
}
