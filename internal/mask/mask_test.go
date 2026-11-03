package mask

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/kvarot/michel/internal/secret"
)

func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

func TestMaskStableTokens(t *testing.T) {
	m := New()
	got := m.Mask("k=" + fakeAWS() + " x " + fakeAWS())
	if want := "k=" + m.token(1) + " x " + m.token(1); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	other := "AKIA" + "ZZZZZZZZZZZZZZZZ"
	if got, want := m.Mask(other+" "+fakeAWS()), m.token(2)+" "+m.token(1); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if m.Counts()["aws_key"] != 4 {
		t.Fatalf("counts %v", m.Counts())
	}
}

func TestTokensCarryNonce(t *testing.T) {
	a, b := New(), New()
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(a.nonce) {
		t.Fatalf("nonce %q", a.nonce)
	}
	if a.nonce == b.nonce {
		t.Fatal("two maskers share a nonce")
	}
	out := a.Mask(fakeAWS())
	if out != "[secret-"+a.nonce+"-1]" {
		t.Fatalf("token %q", out)
	}
	if b.Unmask(out) != out {
		t.Fatal("another masker resolved a foreign token")
	}
}

func TestUnmaskRestores(t *testing.T) {
	m := New()
	in := "a " + fakeAWS() + " b password: hunter2hunter2 c"
	masked := m.Mask(in)
	if strings.Contains(masked, fakeAWS()) || strings.Contains(masked, "hunter2") {
		t.Fatalf("not masked: %q", masked)
	}
	if got := m.Unmask(masked); got != in {
		t.Fatalf("got %q want %q", got, in)
	}
	if got := m.Unmask(m.token(99) + " stays"); got != m.token(99)+" stays" {
		t.Fatalf("unknown token changed: %q", got)
	}
}

func TestUnmaskIgnoresForeignTokens(t *testing.T) {
	m := New()
	in := "fixture [secret-1] and [secret-deadbeef-1] and key " + fakeAWS()
	masked := m.Mask(in)
	if !strings.HasPrefix(masked, "fixture [secret-1] and [secret-deadbeef-1] and key ") || strings.Contains(masked, fakeAWS()) {
		t.Fatalf("masked %q", masked)
	}
	if got := m.Unmask(masked); got != in {
		t.Fatalf("got %q want %q", got, in)
	}
	if got := m.Unmask("[secret-1] [secret-deadbeef-1]"); got != "[secret-1] [secret-deadbeef-1]" {
		t.Fatalf("foreign tokens resolved: %q", got)
	}
	s := NewStreamUnmasker(m)
	if got := s.Write("[secret-1] [secret-deadbeef-1] x") + s.Flush(); got != "[secret-1] [secret-deadbeef-1] x" {
		t.Fatalf("stream resolved foreign tokens: %q", got)
	}
}

func TestMaskDetectors(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a1", 20)
	pat := "github_pat_" + strings.Repeat("Ab3_", 8)
	tests := []struct {
		name, in, kind string
		secret         string
	}{
		{"github", "tok " + ghp, "github_token", ghp},
		{"github pat", "tok " + pat, "github_token", pat},
		{"env", "DB_PASSWORD=s3cr3tvalue\nOTHER=1", "env_value", "s3cr3tvalue"},
		{"env short", "API_KEY=abc", "env_value", "abc"},
		{"env bare short key", "KEY=short", "env_value", "short"},
		{"env bare short token", "TOKEN=x", "env_value", "x"},
		{"env lowercase", "db_secret=abcdef", "env_value", "abcdef"},
		{"env quoted spaces", `DB_PASSWORD="correct horse battery"`, "env_value", "correct horse battery"},
		{"env single quoted", "API_TOKEN='a b'", "env_value", "a b"},
		{"env export", "export APP_KEY=base64:abcDEF", "env_value", "base64:abcDEF"},
		{"assignment", `{"api_key": "abcdefgh12345"}`, "assignment", "abcdefgh12345"},
		{"assignment arrow", "'token' => 'abcdefgh12345'", "assignment", "abcdefgh12345"},
		{"assignment quoted phrase", `"password": "my long pass phrase"`, "assignment", "my long pass phrase"},
		{"assignment semicolon", "password=abc;defghijklmn", "env_value", "abc;defghijklmn"},
		{"assignment short", "password: hunter2", "assignment", "hunter2"},
		{"assignment pwd", "pwd=ab", "assignment", "ab"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			out := m.Mask(tc.in)
			// The token's random nonce may hold a short secret ("ab"):
			// look outside the tokens.
			if strings.Contains(tokenShape.ReplaceAllString(out, ""), tc.secret) || !HasToken(out) {
				t.Fatalf("not masked: %q", out)
			}
			if m.Counts()[tc.kind] != 1 {
				t.Fatalf("counts %v", m.Counts())
			}
			if m.Unmask(out) != tc.in {
				t.Fatalf("round trip failed: %q", m.Unmask(out))
			}
		})
	}
	m := New()
	for _, in := range []string{"password: null", "token=true", "secret: False", `password=""`, "password=${DB_PASS}", "DB_PASSWORD=%env(DB_PASS)%", "token:", "see https://example.com/a/b/c"} {
		if out := m.Mask(in); out != in {
			t.Errorf("non-value changed: %q -> %q", in, out)
		}
	}
	// masking already masked text does not create nested tokens
	once := m.Mask("password: " + "abcdefgh12345")
	if twice := m.Mask(once); twice != once {
		t.Fatalf("second pass changed %q into %q", once, twice)
	}
}

func TestMaskDoesNotSkipValueStartingWithToken(t *testing.T) {
	for _, in := range []string{
		"password=[secret-1]hunter2hunter2",
		"password=<path>hunter2hunter2",
		"DB_TOKEN=[secret-1]hunter2hunter2",
	} {
		m := New()
		if out := m.Mask(in); strings.Contains(out, "hunter2") {
			t.Fatalf("%q leaked: %q", in, out)
		}
		if m.Unmask(m.Mask(in)) != in {
			t.Fatalf("%q does not round trip", in)
		}
	}
}

func TestMaskMergesOverlappingSpans(t *testing.T) {
	m := New()
	in := "API_TOKEN=xyz" + fakeAWS() + "tail"
	out := m.Mask(in)
	if out != "API_TOKEN="+m.token(1) {
		t.Fatalf("got %q", out)
	}
	if m.Counts()["aws_key"] != 1 || m.Counts()["env_value"] != 0 {
		t.Fatalf("counts %v", m.Counts())
	}
	m = New()
	out = m.Mask("k=" + fakeAWS() + "ghp_" + strings.Repeat("a1", 20) + " end")
	if strings.Contains(out, "AKIA") || strings.Contains(out, "a1a1") {
		t.Fatalf("adjacent spans leaked: %q", out)
	}
}

func TestMaskPEMBlock(t *testing.T) {
	pem := "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END " + "RSA PRIVATE KEY-----"
	m := New()
	out := m.Mask("before\n" + pem + "\nafter")
	if out != "before\n"+m.token(1)+"\nafter" {
		t.Fatalf("got %q", out)
	}
	if m.Counts()["private_key"] != 1 {
		t.Fatalf("counts %v", m.Counts())
	}
	if m.Unmask(out) != "before\n"+pem+"\nafter" {
		t.Fatal("round trip failed")
	}
	trunc := "-----BEGIN " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34Gkx"
	if out := New().Mask("x\n" + trunc); strings.Contains(out, "MIIB") {
		t.Fatalf("truncated block leaked: %q", out)
	}
}

func TestMaskAbsolutePathsNotReversible(t *testing.T) {
	m := New()
	in := `open D:\data\x1\a.php and "/srv/x1/b.go" ok`
	out := m.Mask(in)
	if out != `open <path> and "<path>" ok` {
		t.Fatalf("got %q", out)
	}
	if m.Unmask(out) != out {
		t.Fatalf("path restored: %q", m.Unmask(out))
	}
	if m.Counts()["abs_path"] != 2 {
		t.Fatalf("counts %v", m.Counts())
	}
	if len(m.Table()) != 0 {
		t.Fatalf("path stored in table: %v", m.Table())
	}
}

func TestMaskAbsolutePathVariants(t *testing.T) {
	tests := map[string]string{
		`in D:\data\My Documents\x1\a.php done`:    `in <path> done`,
		`in D:\data\My Documents\x1\a.php`:         `in <path>`,
		`PATH=/srv/a/b:/srv/c/d:/srv/e/f`:          `PATH=<path>:<path>:<path>`,
		`err at D:/data/x1/a.php: boom`:            `err at <path>: boom`,
		`see https://example.com/a/b and /srv/q/r`: `see https://example.com/a/b and <path>`,
	}
	for in, want := range tests {
		if got := New().Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskConcurrent(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				m.Mask(fakeAWS())
				m.Unmask(m.token(1))
			}
		}()
	}
	wg.Wait()
	if len(m.Table()) != 1 {
		t.Fatalf("table %v", m.Table())
	}
}

func TestStreamUnmaskerJoinsSplitTokens(t *testing.T) {
	m := New()
	tok := m.Mask(fakeAWS())
	if tok != m.token(1) {
		t.Fatal("setup")
	}
	cut := len("[secret-") + 3
	s := NewStreamUnmasker(m)
	var all strings.Builder
	for _, c := range []string{"voici " + tok[:cut], tok[cut:] + " fin"} {
		out := s.Write(c)
		if strings.Contains(out, "[sec") {
			t.Fatalf("partial token emitted: %q", out)
		}
		all.WriteString(out)
	}
	all.WriteString(s.Flush())
	if all.String() != "voici "+fakeAWS()+" fin" {
		t.Fatalf("got %q", all.String())
	}
}

func TestStreamUnmaskerCharByChar(t *testing.T) {
	m := New()
	tok := m.Mask(fakeAWS())
	in := "a [x] " + tok + tok + " [ [secret-"
	s := NewStreamUnmasker(m)
	var all strings.Builder
	for _, r := range in {
		out := s.Write(string(r))
		if strings.Contains(out, "[secret") {
			t.Fatalf("partial token emitted: %q", out)
		}
		all.WriteString(out)
	}
	all.WriteString(s.Flush())
	want := "a [x] " + fakeAWS() + fakeAWS() + " [ [secret-"
	if all.String() != want {
		t.Fatalf("got %q want %q", all.String(), want)
	}
}

func TestStreamUnmaskerFlushesPlainBracket(t *testing.T) {
	s := NewStreamUnmasker(New())
	got := s.Write("[note") + s.Flush()
	if got != "[note" {
		t.Fatalf("got %q", got)
	}
	s = NewStreamUnmasker(New())
	if out := s.Write("x [sec"); out != "x " {
		t.Fatalf("held text not held: %q", out)
	}
	if out := s.Flush(); out != "[sec" {
		t.Fatalf("flush %q", out)
	}
	if out := s.Flush(); out != "" {
		t.Fatalf("second flush %q", out)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	st, err := secret.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := New()
	masked := m.Mask(fakeAWS() + " password: hunter2hunter2")
	id := "01HZXYABCDEFGHJKMNPQRSTVWX"
	if err := m.Save(st, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("mask-" + strings.ToLower(id)); err != nil {
		t.Fatalf("stored name: %v", err)
	}
	l, err := Load(st, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Unmask(masked); got != fakeAWS()+" password: hunter2hunter2" {
		t.Fatalf("got %q", got)
	}
	// numbering continues after the loaded table
	if got := l.Mask("AKIA" + "ZZZZZZZZZZZZZZZZ"); got != l.token(3) {
		t.Fatalf("got %q", got)
	}
	if _, err := Load(st, "01HZXYABCDEFGHJKMNPQRSTVWY"); err == nil {
		t.Fatal("missing table must fail")
	}
}

func TestSaveLoadKeepsNonce(t *testing.T) {
	st, _ := secret.Open(t.TempDir())
	m := New()
	m.Mask(fakeAWS())
	if err := m.Save(st, "abc"); err != nil {
		t.Fatal(err)
	}
	l, err := Load(st, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if l.nonce != m.nonce {
		t.Fatalf("nonce %q != %q", l.nonce, m.nonce)
	}
	if l.Mask(fakeAWS()) != m.token(1) {
		t.Fatal("same value must keep its token after Load")
	}
}

func TestLoadRejectsCorruptTables(t *testing.T) {
	st, _ := secret.Open(t.TempDir())
	for name, body := range map[string]string{
		"notjson":     `nope`,
		"badnonce":    `{"nonce":"XYZ","table":{}}`,
		"foreign":     `{"nonce":"0a0b0c0d","table":{"[secret-deadbeef-1]":"v"}}`,
		"badnumber":   `{"nonce":"0a0b0c0d","table":{"[secret-0a0b0c0d-x]":"v"}}`,
		"zero":        `{"nonce":"0a0b0c0d","table":{"[secret-0a0b0c0d-0]":"v"}}`,
		"overflow":    `{"nonce":"0a0b0c0d","table":{"[secret-0a0b0c0d-99999999999999999999]":"v"}}`,
		"legacyshape": `{"nonce":"0a0b0c0d","table":{"[secret-1]":"v"}}`,
	} {
		if err := st.Set("mask-"+name, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(st, name); err == nil {
			t.Errorf("%s: corrupt table accepted", name)
		}
	}
}

func TestScanFilesReportsNoValue(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "A=1\nDB_PASSWORD=s3cr3tvalue\n")
	write("src/a.php", "<?php\n\n$k = '"+fakeAWS()+"';\n")
	write("src/clean.go", "package x\n")
	write("bin.dat", fakeAWS()+"\x00\x01")
	hits := ScanFiles(root, []string{".env", "src/a.php", "src/clean.go", "bin.dat", "missing.txt", "../escape"})
	want := []Hit{{File: ".env", Line: 2, Kind: KindEnvValue, Strong: true}, {File: "src/a.php", Line: 3, Kind: KindAWSKey, Strong: true}}
	if len(hits) != len(want) {
		t.Fatalf("hits %+v", hits)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("hit %d: %+v want %+v", i, hits[i], want[i])
		}
	}
}

func TestScanFilesSkipsSymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "k.txt"), []byte(fakeAWS()), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "k.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	if hits := ScanFiles(root, []string{"link.txt", "dir/k.txt"}); len(hits) != 0 {
		t.Fatalf("followed a symlink: %+v", hits)
	}
}

func TestHasToken(t *testing.T) {
	for in, want := range map[string]bool{
		"a [secret-deadbeef-1] b": true, "[secret-0a1b2c3d-42]": true, "[secret-deadbeef-7]": true,
		// Not Michel's shape: a library may say these literally.
		"[secret-1]": false, "[secret-42]": false, "[secret-key]": false, "[secret-DEADBEEF-7]": false, "[secret-deadbee-7]": false,
		"[secret-]": false, "secret-1": false, "[note]": false, "": false,
	} {
		if HasToken(in) != want {
			t.Errorf("HasToken(%q) = %v", in, !want)
		}
	}
}
