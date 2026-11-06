package secret_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestCreateIsExclusive(t *testing.T) {
	dir := t.TempDir()
	st, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := st.(secret.Creator)
	if err := c.Create("demo", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := c.Create("demo", []byte("second")); !errors.Is(err, secret.ErrExists) {
		t.Errorf("second create = %v, want ErrExists", err)
	}
	if v, err := st.Get("demo"); err != nil || string(v) != "first" {
		t.Errorf("value = %q %v, want the first one", v, err)
	}
	if files, err := os.ReadDir(filepath.Join(dir, "secrets")); err != nil || len(files) != 1 {
		t.Errorf("files = %v %v (a temporary file left?)", files, err)
	}
	if err := c.Create("Bad Name", []byte("x")); !errors.Is(err, secret.ErrInvalidName) {
		t.Errorf("bad name = %v", err)
	}
}

// On a file system without hard links, Create stays exclusive: of several
// creators at once exactly one wins, and an existing value is never replaced.
func TestCreateWithoutHardLinksIsExclusive(t *testing.T) {
	defer secret.SetLink(func(string, string) error { return errors.New("hard links not supported") })()
	for round := 0; round < 10; round++ {
		dir := t.TempDir()
		st, err := secret.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c := st.(secret.Creator)
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = c.Create("demo", []byte(fmt.Sprintf("value-%d", i)))
			}(i)
		}
		close(start)
		wg.Wait()
		won := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if won >= 0 {
					t.Fatalf("round %d: %d and %d both created the secret", round, won, i)
				}
				won = i
			case !errors.Is(err, secret.ErrExists):
				t.Fatalf("round %d, creator %d: %v", round, i, err)
			}
		}
		if won < 0 {
			t.Fatalf("round %d: nobody created the secret", round)
		}
		if v, err := st.Get("demo"); err != nil || string(v) != fmt.Sprintf("value-%d", won) {
			t.Fatalf("round %d: value %q %v, want the winner's", round, v, err)
		}
	}
}

// Without hard links, a claim left by a process that stopped before its
// rename does not block Create for ever.
func TestCreateWithoutHardLinksTakesOverStaleClaim(t *testing.T) {
	defer secret.SetLink(func(string, string) error { return errors.New("hard links not supported") })()
	dir := t.TempDir()
	st, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	claim := filepath.Join(dir, "secrets", ".claim-demo")
	if err := os.WriteFile(claim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(claim, old, old); err != nil {
		t.Fatal(err)
	}
	if err := st.(secret.Creator).Create("demo", []byte("v")); err != nil {
		t.Fatalf("Create = %v", err)
	}
	if v, err := st.Get("demo"); err != nil || string(v) != "v" {
		t.Fatalf("Get = %q %v", v, err)
	}
	if names, _ := st.List(); !reflect.DeepEqual(names, []string{"demo"}) {
		t.Errorf("List = %v, want only demo", names)
	}
}
