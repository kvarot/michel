package serverfix_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

func TestUserScriptSetsPath(t *testing.T) {
	b := render(t, setDirective("user_ini", "display_errors", "0", ""), demoTarget())
	for _, s := range []string{b.Apply, b.Undo} {
		if !strings.Contains(s, "\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n") {
			t.Errorf("no PATH line:\n%s", s)
		}
	}
}

func TestBinaryRealPathChecked(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	// A link to a root file in a user's folder: refused.
	sh := &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{fpmBin: "/home/deploy/bin/php-fpm8.2"},
		Meta: map[string]sshtest.Meta{"/home/deploy/bin/php-fpm8.2": {UID: 0, Mode: 0o755}}}
	h := newHarness(t, sh)
	h.srv.SetFile("/home/deploy/bin/php-fpm8.2", "ELF")
	if code, stderr := h.run(b.Apply); code != 7 || h.file(t, fpmIni) != iniText {
		t.Errorf("link into a user folder: exit %d %q", code, stderr)
	}
	if !strings.Contains(b.Apply, `case "$(readlink -f '`+fpmBin+`')" in /usr/sbin/php*/*) echo "fichier non sur" >&2; exit 7;; /usr/sbin/php*) ;;`) {
		t.Errorf("no real path check:\n%s", b.Apply)
	}
	// A link in the same system folder passes.
	sh2 := &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{fpmBin: "/usr/sbin/php-fpm8.2.real"}}
	h2 := newHarness(t, sh2)
	h2.srv.SetFile("/usr/sbin/php-fpm8.2.real", "ELF")
	if code, stderr := h2.run(b.Apply); code != 0 {
		t.Errorf("same folder: exit %d %q", code, stderr)
	}
}

func TestRoleTiedToRuntime(t *testing.T) {
	// The CLI claims the FPM pool as its php.ini.
	inv := demoInventory()
	inv.PHP[0].LoadedIni = pool
	if _, err := serverfix.Validate(setDirective("cli", "allow_url_include", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("CLI php.ini = pool: %v", err)
	}
	// The FPM lists its php.ini as a pool too.
	inv = demoInventory()
	inv.PHP[1].PoolFiles = append(inv.PHP[1].PoolFiles, fpmIni)
	if _, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("php.ini also a pool: %v", err)
	}
}

func TestLintRefusesDotSegments(t *testing.T) {
	for _, l := range []string{
		`cat "$B/1" > '/etc/php/../ssh/sshd_config.d/x.conf'`,
		`cat "$B/1" > '/etc/php-fpm.d/../sudoers.d/x.conf'`,
		`cat "$B/1" > '/home/deploy/../../etc/.user.ini'`,
		`cat "$B/1" > '/etc/php/./8.2/php.ini'`,
		`cat "$B/1" > '/etc/php//8.2/php.ini'`,
		`'/usr/bin/php' -c '/etc/php/../../root/x.ini' -r ''`,
	} {
		if err := serverfix.Lint(l + "\n"); !errors.Is(err, serverfix.ErrGrammar) {
			t.Errorf("Lint accepted %q", l)
		}
	}
	for _, l := range []string{
		`cat "$B/1" > '/etc/php/8.2/fpm/php.ini'`,
		`cat "$B/1" > '/home/deploy/www/demo/.user.ini'`,
		`cat "$B/1" > '/etc/php/8.2/fpm/pool.d/..www.conf'`,
	} {
		if err := serverfix.Lint(l + "\n"); err != nil {
			t.Errorf("Lint refused %q: %v", l, err)
		}
	}
}

func TestOpenBasedirRootRefused(t *testing.T) {
	inv := demoInventory()
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "open_basedir", Value: "", File: fpmIni, Line: 4})
	for _, v := range []string{"/", "/var/www:/", "/:/tmp"} {
		if _, err := serverfix.Validate(setDirective("fpm", "open_basedir", v, ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("open_basedir=%q: %v", v, err)
		}
	}
}
