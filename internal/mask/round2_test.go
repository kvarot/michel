package mask

import (
	"strings"
	"testing"
)

func TestEnvNameSuffixes(t *testing.T) {
	for _, name := range []string{"SECRETKEY", "APPKEY", "DBPASSWORD", "DB_PASS", "SECRET_KEY_BASE", "dbtoken", "export_pass"} {
		in := name + "=abcd1234"
		m := New()
		out := m.Mask(in)
		if out != name+"="+m.token(1) {
			t.Errorf("%s: got %q", name, out)
		}
	}
	for _, in := range []string{"MONKEY=banana", "COMPASS=north", "BYPASS=1", "PUBLIC_KEY=ssh-rsa-abcdef", "SSH_PUBLICKEY=abc", "KEYBOARD=azerty", "TOKENIZER=abc"} {
		if out := New().Mask(in); out != in {
			t.Errorf("non-secret name changed: %q -> %q", in, out)
		}
	}
}

func TestReferenceSkipIsStrict(t *testing.T) {
	for _, in := range []string{
		"PASSWORD=${X:-defaultpw}",
		"PASSWORD=${X:=defaultpw}",
		"PASSWORD=${X-defaultpw}",
		"password: ${X:-defaultpw}",
		"DB_PASSWORD=%env(X)%defaultpw",
	} {
		m := New()
		if out := m.Mask(in); strings.Contains(out, "defaultpw") {
			t.Errorf("%q leaked: %q", in, out)
		}
	}
	for _, in := range []string{"PASSWORD=${DB_PASS}", "password: ${DB_PASS}", "DB_PASSWORD=%env(DB_PASS)%"} {
		if out := New().Mask(in); out != in {
			t.Errorf("reference changed: %q -> %q", in, out)
		}
	}
}

func TestUnclosedAndEscapedQuotes(t *testing.T) {
	tests := []struct{ in, want string }{
		{`PASSWORD="abc def ghi`, `PASSWORD="@`},
		{`PASSWORD='abc def`, `PASSWORD='@`},
		{`PASSWORD="ab\"cd efgh"`, `PASSWORD="@"`},
		{`PASSWORD='it\'s x'`, `PASSWORD='@'`},
		{"token = `abc def`", "token = `@`"},
		{"token = `abc def", "token = `@"},
		{"line1\nPASSWORD=\"abc def\nline3", "line1\nPASSWORD=\"@\nline3"},
	}
	for _, tc := range tests {
		m := New()
		out := m.Mask(tc.in)
		if want := strings.Replace(tc.want, "@", m.token(1), 1); out != want {
			t.Errorf("Mask(%q) = %q, want %q", tc.in, out, want)
		}
		if m.Unmask(out) != tc.in {
			t.Errorf("round trip failed for %q", tc.in)
		}
	}
}

func TestForeignTokenValueIsMasked(t *testing.T) {
	m := New()
	if out := m.Mask("password=[secret-MyRealPw]"); strings.Contains(out, "MyRealPw") {
		t.Fatalf("leaked: %q", out)
	}
	if out := m.Mask("password=" + m.token(7)); out != "password="+m.token(7) {
		t.Fatalf("own token must stay: %q", out)
	}
}

func TestKeywordPassAndKey(t *testing.T) {
	for _, in := range []string{"pass: abcd", "db_pass = 'abcd'", "app_key: abcd", "secret_key = \"abcd\"", "Pass=abcd"} {
		m := New()
		if out := m.Mask(in); strings.Contains(out, "abcd") {
			t.Errorf("%q leaked: %q", in, out)
		}
	}
	for _, in := range []string{"monkey: banana", "compass: north", "bypass: 1", "key: value", "passenger: abcdef"} {
		if out := New().Mask(in); out != in {
			t.Errorf("false positive: %q -> %q", in, out)
		}
	}
}

func TestConnectionURLPasswords(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DATABASE_URL=mysql://u:pw@h/db", "DATABASE_URL=mysql://u:@@h/db"},
		{"redis://:pw@h", "redis://:@@h"},
		{`dsn "postgres://app:s3cr3t%21@db.local:5432/x?sslmode=disable"`, `dsn "postgres://app:@@db.local:5432/x?sslmode=disable"`},
	}
	for _, tc := range tests {
		m := New()
		out := m.Mask(tc.in)
		if want := strings.ReplaceAll(tc.want, "@@", m.token(1)+"@"); out != want {
			t.Errorf("Mask(%q) = %q, want %q", tc.in, out, want)
		}
		if m.Unmask(out) != tc.in {
			t.Errorf("round trip failed for %q", tc.in)
		}
	}
	for _, in := range []string{"https://example.com:8080/a/b", "https://user@example.com/x", "ssh://git@host:22/repo"} {
		if out := New().Mask(in); out != in {
			t.Errorf("URL changed: %q -> %q", in, out)
		}
	}
}
