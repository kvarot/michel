package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/watch"
)

// TestMain pins the system language to English: the default policy says
// assistant.lang: auto, and the expected sentences of this package are
// English unless a test asks otherwise.
func TestMain(m *testing.M) {
	restore := i18n.SetSystemLocaleForTest("en")
	// The daily watch of serve checks the projects of a test by itself at the
	// real hour: off unless a test turns it on.
	watchLoop = func(context.Context, watch.Deps, time.Duration) {}
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestLangAutoFollowsSystemLocale(t *testing.T) {
	dir, list := scannedDemo(t, true)
	restore := i18n.SetSystemLocaleForTest("fr")
	defer restore()

	// No policy file: the default assistant.lang is auto.
	deps, out, _, err := run(t, dir, "finding", list[0].ID)
	if err != nil || deps.Lang != i18n.FR || !strings.Contains(out, "Quoi : ") {
		t.Errorf("defaults, system fr: %v lang=%s\n%s", err, deps.Lang, out)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("assistant:\n  lang: auto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deps, _, _, err = run(t, dir, "finding", list[0].ID); err != nil || deps.Lang != i18n.FR {
		t.Errorf("auto, system fr: %v lang=%s", err, deps.Lang)
	}
	// The flag and an explicit policy language still win over the system.
	if deps, out, _, err = run(t, dir, "finding", list[0].ID, "--lang", "en"); err != nil || deps.Lang != i18n.EN || !strings.Contains(out, "What: ") {
		t.Errorf("flag en: %v lang=%s", err, deps.Lang)
	}
	if err := os.WriteFile(cfg, []byte("assistant:\n  lang: en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deps, _, _, err = run(t, dir, "finding", list[0].ID); err != nil || deps.Lang != i18n.EN {
		t.Errorf("policy en, system fr: %v lang=%s", err, deps.Lang)
	}

	restore2 := i18n.SetSystemLocaleForTest("de")
	defer restore2()
	if err := os.WriteFile(cfg, []byte("assistant:\n  lang: auto\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if deps, _, _, err = run(t, dir, "finding", list[0].ID); err != nil || deps.Lang != i18n.EN {
		t.Errorf("auto, system de: %v lang=%s", err, deps.Lang)
	}
}
