package sshtest

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// fakeChannel feeds stdin and drops the output.
type fakeChannel struct{ io.Reader }

func (fakeChannel) Write(p []byte) (int, error) { return len(p), nil }
func (fakeChannel) Stderr() io.ReadWriter       { return &bytes.Buffer{} }

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		`'a' 'b c'`:           {"a", "b c"},
		`'a'\''b; rm x' ''`:   {"a'b; rm x", ""},
		`plain  words`:        {"plain", "words"},
		`"dq $x" back\ slash`: {"dq $x", "back slash"},
		`sh -s`:               {"sh", "-s"},
	}
	for in, want := range cases {
		got, err := SplitWords(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Fatalf("%s: got %q want %q", in, got, want)
		}
	}
	if _, err := SplitWords(`'open`); err == nil {
		t.Fatal("unterminated quote accepted")
	}
}

func TestServerBasics(t *testing.T) {
	s := New(t, Options{Files: map[string]string{"/etc/php.ini": "x=1"}})
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Fatalf("addr %s", s.Addr())
	}
	if !strings.HasPrefix(s.HostKeyFingerprint(), "SHA256:") {
		t.Fatalf("fingerprint %s", s.HostKeyFingerprint())
	}
	if v, ok := s.File("/etc/php.ini"); !ok || v != "x=1" {
		t.Fatalf("File = %q %v", v, ok)
	}
	s.SetFile("/etc/php.ini", "x=2")
	if v, _ := s.File("/etc/php.ini"); v != "x=2" {
		t.Fatalf("SetFile not kept: %q", v)
	}
	if len(s.Log()) != 0 || s.Accepted() != 0 || s.AuthAttempts() != 0 {
		t.Fatal("fresh server is not empty")
	}
}

func TestShellHook(t *testing.T) {
	var got string
	s := New(t, Options{Shell: func(_ *Server, script string, stdout, _ io.Writer) int {
		got = script
		io.WriteString(stdout, "ran")
		return 0
	}})
	if code := s.run(context.Background(), "sh -s", fakeChannel{strings.NewReader("echo hi\n")}); code != 0 || got != "echo hi\n" {
		t.Fatalf("code %d script %q", code, got)
	}
	s2 := New(t, Options{})
	if code := s2.run(context.Background(), "sh -s", fakeChannel{strings.NewReader("x")}); code != 127 {
		t.Fatalf("nil Shell: code %d, want 127", code)
	}
}
