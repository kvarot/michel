package serverfix_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

func TestBooleanValuesCanonical(t *testing.T) {
	for _, v := range []string{"1x", "1.0", "1:", "0x1", "00", "no", "false", "none", "stderr", "-0"} {
		if _, err := serverfix.Validate(setDirective("fpm", "allow_url_include", v, ""), demoTarget(), demoInventory()); !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("allow_url_include=%q: %v", v, err)
		}
	}
	for _, v := range []string{"0", "Off", "off", "OFF"} {
		if _, err := serverfix.Validate(setDirective("fpm", "allow_url_include", v, ""), demoTarget(), demoInventory()); err != nil {
			t.Errorf("allow_url_include=%q: %v", v, err)
		}
	}
	for _, v := range []string{"1", "On", "on"} {
		if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", v, ""), demoTarget(), demoInventory()); err != nil {
			t.Errorf("session.cookie_secure=%q: %v", v, err)
		}
	}
}

// cliInv makes the CLI read its php.ini from p.
func cliInv(p string) target.Inventory {
	inv := demoInventory()
	inv.PHP[0].LoadedIni = p
	inv.Files = append(inv.Files, target.FileSeen{Path: p})
	return inv
}

func TestRootWritesOnlyPHPTrees(t *testing.T) {
	for _, p := range []string{
		"/etc/ssh/sshd_config.d/x.conf", "/etc/apt/apt.conf.d/99michel.conf", "/etc/nginx/php.ini", "/etc/ld.so.conf",
		"/etc/phpmyadmin/config.ini", "/etc/php-fpm.d.ini", "/usr/local/etc/nginx/php.ini",
		"/etc/php/8.2/fpm/pool.d/deploy.conf", // a pool path given as a CLI php.ini
	} {
		if _, err := serverfix.Validate(setDirective("cli", "allow_url_include", "0", ""), demoTarget(), cliInv(p)); !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{
		"/etc/php.ini", "/etc/php.d/10-demo.ini", "/etc/php83/php.ini", "/usr/local/etc/php.ini", "/usr/local/etc/php/php.ini",
		"/opt/remi/php81/root/etc/php.ini", "/etc/opt/remi/php81/php.ini",
	} {
		if _, err := serverfix.Validate(setDirective("cli", "allow_url_include", "0", ""), demoTarget(), cliInv(p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestTargetFileMustBeRootsAndClosed(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for name, m := range map[string]sshtest.Meta{
		"group-writable": {UID: 0, Mode: 0o664},
		"other-writable": {UID: 0, Mode: 0o646},
		"user-owned":     {UID: 1000, Mode: 0o644},
	} {
		h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Meta: map[string]sshtest.Meta{fpmIni: m}})
		code, stderr := h.run(b.Apply)
		if code != 7 || !strings.Contains(stderr, "fichier non sur") {
			t.Errorf("%s: exit %d %q", name, code, stderr)
		}
		if h.file(t, fpmIni) != iniText {
			t.Errorf("%s: changed", name)
		}
		if code, _ := h.run(b.Undo); code != 4 && code != 7 {
			t.Errorf("%s undo: exit %d", name, code)
		}
	}
}

func TestRootScriptSetsItsEnvironment(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for _, s := range []string{b.Apply, b.Undo} {
		for _, l := range []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "export PATH", "unset PHPRC PHP_INI_SCAN_DIR"} {
			if !strings.Contains(s, "\n"+l+"\n") {
				t.Errorf("missing %q:\n%s", l, s)
			}
		}
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	if code, stderr := h.run(b.Apply); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
}

func TestPHPBinaryCheckedInScript(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for name, meta := range map[string]map[string]sshtest.Meta{
		"binary group-writable": {fpmBin: {UID: 0, Mode: 0o775}},
		"binary user-owned":     {fpmBin: {UID: 1000, Mode: 0o755}},
		"folder group-writable": {"/usr/sbin": {UID: 0, Mode: 0o2775, Dir: true}},
	} {
		h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Meta: meta})
		if code, _ := h.run(b.Apply); code != 7 || h.file(t, fpmIni) != iniText {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	// A binary reached through a link (Debian alternatives) is judged on the
	// real file.
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{fpmBin: "/usr/sbin/php-fpm8.2.real"}})
	h.srv.SetFile("/usr/sbin/php-fpm8.2.real", "ELF")
	if code, stderr := h.run(b.Apply); code != 0 {
		t.Errorf("linked binary: exit %d %s", code, stderr)
	}
}

func TestRootUndoWithoutBackupExits4(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	if code, stderr := h.run(b.Undo); code != serverfix.ExitApplied || !strings.Contains(stderr, "sauvegarde absente") {
		t.Errorf("exit %d %q", code, stderr)
	}
}

func TestBackupFoldersCheckedBeforeMkdir(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	sh := &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{"/var/lib/michel": "/home/deploy/m"},
		Meta: map[string]sshtest.Meta{"/home/deploy/m": {UID: 1000, Mode: 0o755, Dir: true}}}
	h := newHarness(t, sh)
	if code, _ := h.run(b.Apply); code != 7 {
		t.Errorf("exit %d", code)
	}
	if _, ok := sh.Meta["/home/deploy/m/backups"]; ok {
		t.Error("root created a folder through the link")
	}
	for _, c := range sh.Ran() {
		if strings.Contains(c, "mkdir") && strings.Contains(c, "backups") {
			t.Errorf("ran %q before refusing", c)
		}
	}
}

func TestDebianConfDLinkRefused(t *testing.T) {
	inv := demoInventory()
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "expose_php", Value: "On", File: opcache, Line: 2})
	if _, err := serverfix.Validate(setDirective("fpm", "expose_php", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrLinkedFile) {
		t.Errorf("conf.d: %v", err)
	}
}

func TestLintKeysAndPathsFollowValidate(t *testing.T) {
	for _, l := range []string{
		`printf '\n%s\n' 'extension = /home/deploy/x.so' >> "$B/1.1"`,
		`sed '1s|^[[:space:]]*extension[[:space:]]*=.*$|extension = /home/x.so|' "$B/1" > "$B/1.1"`,
		`cat "$B/1" > '/etc/ld.so.conf'`,
		`cat "$B/1" > '/etc/ssh/sshd_config.d/x.conf'`,
		`'/usr/bin/php' -c '/home/deploy/x.ini' -r ''`,
	} {
		if err := serverfix.Lint(l + "\n"); !errors.Is(err, serverfix.ErrGrammar) {
			t.Errorf("Lint accepted %q", l)
		}
	}
	for _, l := range []string{
		`printf '\n[PHP]\n%s\n' 'session.cookie_secure = 1' >> "$B/1.1"`,
		`cat "$B/1.1" > '/etc/php/8.2/fpm/php.ini'`,
		`cat "$B/1.1" > '/home/deploy/www/demo/.user.ini'`,
	} {
		if err := serverfix.Lint(l + "\n"); err != nil {
			t.Errorf("Lint refused %q: %v", l, err)
		}
	}
}
