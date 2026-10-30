package mask

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kvarot/michel/internal/secret"
)

func fakeAWS() string { return "AKIA" + "ABCDEFGHIJKLMNOP" }

func TestMaskStableTokens(t *testing.T) {
	m := New()
	got := m.Mask("k=" + fakeAWS() + " x " + fakeAWS())
	if got != "k=[secret-1] x [secret-1]" {
		t.Fatalf("got %q", got)
	}
	other := "AKIA" + "ZZZZZZZZZZZZZZZZ"
	if got := m.Mask(other + " " + fakeAWS()); got != "[secret-2] [secret-1]" {
		t.Fatalf("got %q", got)
	}
	if m.Counts()["aws_key"] != 4 {
		t.Fatalf("counts %v", m.Counts())
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
	if got := m.Unmask("[secret-99] stays"); got != "[secret-99] stays" {
		t.Fatalf("unknown token changed: %q", got)
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
		{"assignment", `{"api_key": "abcdefgh12345"}`, "assignment", "abcdefgh12345"},
		{"assignment arrow", "'token' => 'abcdefgh12345'", "assignment", "abcdefgh12345"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			out := m.Mask(tc.in)
			if strings.Contains(out, tc.secret) || !HasToken(out) {
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
	if out := m.Mask("password: short"); out != "password: short" {
		t.Fatalf("short value masked: %q", out)
	}
	if out := m.Mask("see https://example.com/a/b/c"); strings.Contains(out, "<path>") {
		t.Fatalf("url treated as path: %q", out)
	}
	// masking already masked text does not create nested tokens
	once := m.Mask("password: " + "abcdefgh12345")
	if twice := m.Mask(once); twice != once {
		t.Fatalf("second pass changed %q into %q", once, twice)
	}
}

func TestMaskPEMBlock(t *testing.T) {
	pem := "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END " + "RSA PRIVATE KEY-----"
	m := New()
	out := m.Mask("before\n" + pem + "\nafter")
	if out != "before\n[secret-1]\nafter" {
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

func TestMaskConcurrent(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				m.Mask(fakeAWS())
				m.Unmask("[secret-1]")
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
	if m.Mask(fakeAWS()) != "[secret-1]" {
		t.Fatal("setup")
	}
	s := NewStreamUnmasker(m)
	var all strings.Builder
	for _, c := range []string{"voici [sec", "ret-1] fin"} {
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
	m.Mask(fakeAWS())
	in := "a [x] [secret-1][secret-1] [ [secret-"
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
	if got := l.Mask("AKIA" + "ZZZZZZZZZZZZZZZZ"); got != "[secret-3]" {
		t.Fatalf("got %q", got)
	}
	if _, err := Load(st, "01HZXYABCDEFGHJKMNPQRSTVWY"); err == nil {
		t.Fatal("missing table must fail")
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
	want := []Hit{{File: ".env", Line: 2, Kind: KindEnvValue}, {File: "src/a.php", Line: 3, Kind: KindAWSKey}}
	if len(hits) != len(want) {
		t.Fatalf("hits %+v", hits)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("hit %d: %+v want %+v", i, hits[i], want[i])
		}
	}
}

func TestHasToken(t *testing.T) {
	for in, want := range map[string]bool{
		"a [secret-1] b": true, "[secret-42]": true,
		"[secret-]": false, "[secret-x]": false, "secret-1": false, "[note]": false, "": false,
	} {
		if HasToken(in) != want {
			t.Errorf("HasToken(%q) = %v", in, !want)
		}
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
	m := New()
	once := m.Mask("password=" + "abcdefgh12345")
	if m.Mask(once) != once {
		t.Fatal("exact token must stay")
	}
}
