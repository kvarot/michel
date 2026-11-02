package serverfix_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

func TestOpenBasedirUncleanRefused(t *testing.T) {
	inv := demoInventory()
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "open_basedir", Value: "", File: fpmIni, Line: 4})
	for _, v := range []string{"//", "/./", "/tmp/..", "/var/www:", "::", "var/www", "/var/www:/var/../", "/var/./www"} {
		if _, err := serverfix.Validate(setDirective("fpm", "open_basedir", v, ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("open_basedir=%q: %v", v, err)
		}
	}
	if _, err := serverfix.Validate(setDirective("fpm", "open_basedir", "/var/www:/tmp", ""), demoTarget(), inv); err != nil {
		t.Errorf("open_basedir=/var/www:/tmp: %v", err)
	}
}

func TestBinaryRealPathNoFurtherSlash(t *testing.T) {
	b := render(t, setDirective("cli", "display_errors", "0", ""), demoTarget())
	if !strings.Contains(b.Apply, `case "$(readlink -f '`+cliBin+`')" in /usr/bin/php*/*) echo "fichier non sur" >&2; exit 7;; /usr/bin/php*) ;;`) {
		t.Errorf("no real path check:\n%s", b.Apply)
	}
	// A real path under a folder named php*: refused.
	sh := &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{cliBin: "/usr/bin/phpfoo/evil"}}
	h := newHarness(t, sh)
	h.srv.SetFile("/usr/bin/phpfoo/evil", "ELF")
	if code, stderr := h.run(b.Apply); code != 7 || h.file(t, cliIni) != iniText {
		t.Errorf("php*/ folder: exit %d %q", code, stderr)
	}
	// Debian alternatives pass: /usr/bin/php -> /etc/alternatives/php -> /usr/bin/php8.2.
	inv := demoInventory()
	inv.PHP[0].Binary = "/usr/bin/php"
	tg := demoTarget()
	v, err := serverfix.Validate(setDirective("cli", "display_errors", "0", ""), tg, inv)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	b2, err := serverfix.Render(v, tg, cid)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(b2.Apply, `case "$(readlink -f '/usr/bin/php')" in /usr/bin/php*/*) echo "fichier non sur" >&2; exit 7;; /usr/bin/php*) ;;`) {
		t.Errorf("no real path check:\n%s", b2.Apply)
	}
	sh2 := &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{"/usr/bin/php": "/etc/alternatives/php", "/etc/alternatives/php": cliBin}}
	h2 := newHarness(t, sh2)
	if code, stderr := h2.run(b2.Apply); code != 0 {
		t.Errorf("alternatives: exit %d %q\n%s", code, stderr, b2.Apply)
	}
}

func TestLintRealPathNeedsSubfolderGuard(t *testing.T) {
	old := `case "$(readlink -f '/usr/bin/php8.2')" in /usr/bin/php*) ;; *) echo "fichier non sur" >&2; exit 7;; esac`
	if err := serverfix.Lint(old + "\n"); !errors.Is(err, serverfix.ErrGrammar) {
		t.Errorf("Lint accepted %q", old)
	}
	good := `case "$(readlink -f '/usr/bin/php8.2')" in /usr/bin/php*/*) echo "fichier non sur" >&2; exit 7;; /usr/bin/php*) ;; *) echo "fichier non sur" >&2; exit 7;; esac`
	if err := serverfix.Lint(good + "\n"); err != nil {
		t.Errorf("Lint refused %q: %v", good, err)
	}
}
