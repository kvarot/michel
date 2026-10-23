package secret_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/secret"
)

func open(t *testing.T) (secret.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestSetGetDeleteRoundTrip(t *testing.T) {
	s, _ := open(t)
	if names, err := s.List(); err != nil || len(names) != 0 {
		t.Fatalf("empty store: names=%v err=%v", names, err)
	}
	if _, err := s.Get("smtp-password"); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("Get absent: %v", err)
	}
	if err := s.Set("smtp-password", []byte("hunter2-tok")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("api-token", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("api-token", []byte("second")); err != nil { // overwrite
		t.Fatal(err)
	}
	got, err := s.Get("smtp-password")
	if err != nil || string(got) != "hunter2-tok" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if got, _ := s.Get("api-token"); string(got) != "second" {
		t.Fatalf("overwrite: %q", got)
	}
	names, err := s.List()
	if err != nil || !reflect.DeepEqual(names, []string{"api-token", "smtp-password"}) {
		t.Fatalf("List = %v, %v", names, err)
	}
	if err := s.Delete("smtp-password"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("smtp-password"); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("second Delete: %v", err)
	}
	if _, err := s.Get("smtp-password"); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
	if names, _ := s.List(); !reflect.DeepEqual(names, []string{"api-token"}) {
		t.Fatalf("List after delete = %v", names)
	}
}

func TestListIgnoresTempAndForeignFiles(t *testing.T) {
	s, dir := open(t)
	if err := s.Set("webhook", []byte("v")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{".tmp-webhook-123", "Upper", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, "secrets", n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := s.List(); err != nil || !reflect.DeepEqual(names, []string{"webhook"}) {
		t.Fatalf("List = %v, %v", names, err)
	}
}

func TestNameRules(t *testing.T) {
	s, _ := open(t)
	for _, n := range []string{"Api-Token", "a/b", `a\b`, "..", "", "a b", strings.Repeat("a", 65)} {
		if err := s.Set(n, []byte("v")); !errors.Is(err, secret.ErrInvalidName) {
			t.Errorf("Set(%q) = %v, want ErrInvalidName", n, err)
		}
		if _, err := s.Get(n); !errors.Is(err, secret.ErrInvalidName) {
			t.Errorf("Get(%q) = %v, want ErrInvalidName", n, err)
		}
		if err := s.Delete(n); !errors.Is(err, secret.ErrInvalidName) {
			t.Errorf("Delete(%q) = %v, want ErrInvalidName", n, err)
		}
	}
	if err := s.Set(strings.Repeat("a", 64), []byte("v")); err != nil {
		t.Errorf("64 characters refused: %v", err)
	}
	if err := s.Set("smtp-1", []byte("v")); err != nil {
		t.Errorf("smtp-1 refused: %v", err)
	}
}

func TestErrorsNeverContainValue(t *testing.T) {
	s, _ := open(t)
	if err := s.Set("Bad", []byte("hunter2-tok")); err == nil || strings.Contains(err.Error(), "hunter2-tok") {
		t.Fatalf("err = %v", err)
	}
}

func TestFileIsNotPlainOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI is Windows only")
	}
	if !secret.Protected() {
		t.Fatal("Protected() = false on Windows")
	}
	s, dir := open(t)
	if err := s.Set("smtp-password", []byte("hunter2-tok")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "secrets", "smtp-password"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("hunter2-tok")) || len(raw) == 0 {
		t.Fatalf("file holds the plain value (%d bytes)", len(raw))
	}
	// A tampered file must not decrypt silently.
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, "secrets", "smtp-password"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("smtp-password"); err == nil {
		t.Fatal("tampered file decrypted without error")
	}
}

func TestFileMode0600Elsewhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are best-effort on Windows; DPAPI protects the value")
	}
	if secret.Protected() {
		t.Fatal("Protected() = true outside Windows")
	}
	s, dir := open(t)
	if err := s.Set("smtp-password", []byte("hunter2-tok")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "secrets", "smtp-password"))
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o600 {
		t.Fatalf("file mode %o, want 600", m)
	}
	di, err := os.Stat(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if m := di.Mode().Perm(); m != 0o700 {
		t.Fatalf("dir mode %o, want 700", m)
	}
}
