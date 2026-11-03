package serverfix_test

import (
	"crypto/sha256"
	"encoding/hex"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

const (
	cliIni   = "/etc/php/8.2/cli/php.ini"
	fpmIni   = "/etc/php/8.2/fpm/php.ini"
	opcache  = "/etc/php/8.2/fpm/conf.d/10-opcache.ini"
	pool     = "/etc/php/8.2/fpm/pool.d/www.conf"
	pool2    = "/etc/php/8.2/fpm/pool.d/shop.conf"
	userIni  = "/home/deploy/www/demo/.user.ini"
	userIni2 = "/home/deploy/www/demo/public/.user.ini"
	fpmBin   = "/usr/sbin/php-fpm8.2"
	cliBin   = "/usr/bin/php8.2"
	cid      = "01CORRECTIONDEMO"
	rootBak  = "/var/lib/michel/backups/" + cid
	iniText  = "[PHP]\nengine = On\ndisplay_errors = On ; dev\nmemory_limit = 128M\n"
	poolText = "[www]\nuser = www-data\nlisten = /run/php/php8.2-fpm.sock\n\nphp_admin_flag[allow_url_include] = on\n"
	userText = "display_errors = On\n"
	opText   = "opcache.enable = 1\n"
	shadow   = "root:x:1::\n"
)

func demoTarget() target.Target {
	return target.Target{ID: "01TARGETDEMO", Name: "srv-demo", Host: "192.0.2.10", User: "deploy",
		Kind: target.KindVPS, Env: target.EnvProd, Sudo: target.SudoNone, SiteURL: "https://example.test"}
}

func demoInventory() target.Inventory {
	return target.Inventory{
		TargetID: "01TARGETDEMO",
		OS:       target.OSInfo{ID: "debian", VersionID: "12"},
		PHP: []target.PHPRuntime{
			{SAPI: "cli", Binary: cliBin, Version: "8.2.7", FromPackage: "php8.2-cli", LoadedIni: cliIni, ScannedDir: "/etc/php/8.2/cli/conf.d"},
			{SAPI: "fpm", Binary: fpmBin, Version: "8.2.7", FromPackage: "php8.2-fpm", LoadedIni: fpmIni,
				ScannedDir: "/etc/php/8.2/fpm/conf.d", ScannedFiles: []string{opcache}, PoolFiles: []string{pool}},
		},
		Packages: []target.Package{{Name: "php8.2-fpm", Version: "8.2.7-1~deb12u1"}, {Name: "libdemo", Version: "1.0-1"}},
		Directives: []target.Directive{
			{SAPI: "fpm", Binary: fpmBin, Name: "display_errors", Value: "On ; dev", File: fpmIni, Line: 3},
			{SAPI: "fpm", Binary: fpmBin, Name: "opcache.enable", Value: "1", File: opcache, Line: 1},
			{SAPI: "fpm", Binary: fpmBin, Name: "user", Value: "www-data", File: pool, Line: 2},
			{SAPI: "fpm", Binary: fpmBin, Name: "php_admin_flag[allow_url_include]", Value: "on", File: pool, Line: 5},
			{SAPI: "user_ini", Binary: fpmBin, Name: "display_errors", Value: "On", File: userIni, Line: 1},
		},
		Files: []target.FileSeen{{Path: cliIni}, {Path: fpmIni}, {Path: opcache}, {Path: pool}, {Path: userIni}},
	}
}

// advised values, safe for every rule.
var advised = map[string]string{
	"display_errors": "0", "expose_php": "0", "allow_url_include": "0", "open_basedir": "/var/www:/tmp",
	"session.cookie_secure": "1", "session.upload_progress.enabled": "0", "fatal_error_backtraces": "0",
}

func setDirective(sapi, name, value, path string) serverfix.Plan {
	return serverfix.Plan{TargetID: "01TARGETDEMO", FindingID: "f1",
		Actions: []serverfix.Action{{Op: serverfix.OpSetDirective, SAPI: sapi, Directive: name, Value: value, Path: path}}}
}

func validate(t *testing.T, p serverfix.Plan, tg target.Target) serverfix.Plan {
	t.Helper()
	v, err := serverfix.Validate(p, tg, demoInventory())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return v
}

func render(t *testing.T, p serverfix.Plan, tg target.Target) serverfix.Bundle {
	t.Helper()
	b, err := serverfix.Render(validate(t, p, tg), tg, cid)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b
}

func opStrings(p serverfix.Plan) string {
	var s []string
	for _, a := range p.Actions {
		s = append(s, string(a.Op))
	}
	return strings.Join(s, ",")
}

func TestValidateAddsBackupTestReload(t *testing.T) {
	v := validate(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	if got := opStrings(v); got != "backup_file,set_directive,test_config,reload_service,check_site" {
		t.Fatalf("ops %s", got)
	}
	if a := v.Actions[0]; a.Path != fpmIni {
		t.Errorf("backup %q", a.Path)
	}
	if a := v.Actions[1]; a.Path != fpmIni || a.Line != 3 || a.Append || a.Key != "display_errors" {
		t.Errorf("set %+v", a)
	}
	if a := v.Actions[2]; a.Binary != fpmBin || a.SAPI != "fpm" {
		t.Errorf("test %+v", a)
	}
	if a := v.Actions[3]; a.Service != "php8.2-fpm" || a.Manager != "systemctl" {
		t.Errorf("reload %+v", a)
	}
	if v.NeedsSnapshot {
		t.Error("a directive needs no snapshot")
	}
	// The agent's own steps are checked then replaced.
	p := setDirective("fpm", "display_errors", "0", "")
	p.Actions = append([]serverfix.Action{{Op: serverfix.OpBackup, Path: fpmIni}, {Op: serverfix.OpTestConfig}},
		append(p.Actions, serverfix.Action{Op: serverfix.OpReload, Service: "php8.2-fpm"})...)
	if v2 := validate(t, p, demoTarget()); len(v2.Actions) != len(v.Actions) {
		t.Errorf("normalized plan has %d actions, want %d", len(v2.Actions), len(v.Actions))
	}
	// The CLI php.ini is tested with the CLI and reloads nothing.
	v = validate(t, setDirective("cli", "allow_url_include", "0", ""), demoTarget())
	if got := opStrings(v); got != "backup_file,set_directive,test_config,check_site" {
		t.Errorf("cli ops %s", got)
	}
}

func TestRejectPathNotInInventory(t *testing.T) {
	tg := demoTarget()
	for _, p := range []string{
		"/etc/php/8.2/fpm/conf.d/99-michel.ini", // never read: would be a new file
		"/etc/passwd",
		"/etc/nginx/nginx.conf",
		"/home/other/www/.user.ini",
		"/root/.user.ini",
		"/etc/php/8.2/fpm/php.ini.key",
		"relative/php.ini",
	} {
		_, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", p), tg, demoInventory())
		if !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("%s: %v, want ErrPathNotAllowed", p, err)
		}
		bk := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpBackup, Path: p}}}
		if _, err := serverfix.Validate(bk, tg, demoInventory()); !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("backup %s: %v", p, err)
		}
	}
	// A file of the inventory lists that was not actually read is refused.
	inv := demoInventory()
	inv.Files = inv.Files[:1]
	if _, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", ""), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("unread php.ini: %v", err)
	}
	// Root never writes under /home, /srv, /var/www, /opt (outside the
	// listed trees): a php.ini there is refused.
	for _, ini := range []string{"/home/deploy/php/php.ini", "/srv/php/php.ini", "/var/www/php.ini", "/opt/php/etc/php.ini", "/tmp/php.ini"} {
		inv := demoInventory()
		inv.PHP[1].LoadedIni = ini
		inv.Files = append(inv.Files, target.FileSeen{Path: ini})
		if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", "1", ""), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("root write in %s: %v", ini, err)
		}
	}
	// Unknown directive, service, package; another server; unknown op.
	if _, err := serverfix.Validate(setDirective("fpm", "disable_functions", "x", ""), tg, demoInventory()); !errors.Is(err, serverfix.ErrUnknownDirective) {
		t.Errorf("directive: %v", err)
	}
	p := setDirective("fpm", "display_errors", "0", "")
	p.Actions = append(p.Actions, serverfix.Action{Op: serverfix.OpReload, Service: "nginx"})
	if _, err := serverfix.Validate(p, tg, demoInventory()); !errors.Is(err, serverfix.ErrUnknownService) {
		t.Errorf("service: %v", err)
	}
	pk := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "openssh-server", Version: "1:9.2"}}}
	if _, err := serverfix.Validate(pk, tg, demoInventory()); !errors.Is(err, serverfix.ErrUnknownPackage) {
		t.Errorf("package: %v", err)
	}
	other := setDirective("fpm", "display_errors", "0", "")
	other.TargetID = "01OTHER"
	if _, err := serverfix.Validate(other, tg, demoInventory()); !errors.Is(err, serverfix.ErrBadAction) {
		t.Errorf("other server: %v", err)
	}
	if _, err := serverfix.Validate(serverfix.Plan{Actions: []serverfix.Action{{Op: "remove_file", Path: fpmIni}}}, tg, demoInventory()); !errors.Is(err, serverfix.ErrBadAction) {
		t.Errorf("unknown op: %v", err)
	}
}

func TestRejectDotDotPath(t *testing.T) {
	for _, p := range []string{"/etc/php/8.2/fpm/../fpm/php.ini", "/etc/php/8.2/fpm/./php.ini", "/etc/php/8.2/fpm//php.ini", "/etc/php/8.2/fpm/..php.ini"} {
		if _, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", p), demoTarget(), demoInventory()); !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// deletion matches a deleting command at the start of a line or after a
// separator.
var deletion = regexp.MustCompile(`(^|[\s;{(|&])(rm|mv|dd|truncate|shred|unlink|rmdir)(\s|$)|\s-delete(\s|$)`)

func TestRenderEscapesHostileValues(t *testing.T) {
	tg := demoTarget()
	for _, v := range []string{
		"Off'; rm -rf / #", "0\nrm -rf /", "0 ; dev", "$(reboot)", "`reboot`", "0|sh", "a&b", `a\b`, `"0"`,
		"0\x00", "0\r", "${HOME}", "On # x", "x=y", strings.Repeat("a", 600),
	} {
		_, err := serverfix.Validate(setDirective("fpm", "display_errors", v, ""), tg, demoInventory())
		if !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("Validate(%q): %v, want ErrBadValue", v, err)
		}
		// Render never trusts its plan: a hostile value slipped in after
		// Validate is refused too.
		p := validate(t, setDirective("fpm", "display_errors", "0", ""), tg)
		p.Actions[1].Value = v
		if _, err := serverfix.Render(p, tg, cid); !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("Render(%q): %v", v, err)
		}
	}
	if _, err := serverfix.Validate(serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpSetDirective, SAPI: "fpm", Directive: "memory_limit", Value: "-1"}}}, tg, demoInventory()); !errors.Is(err, serverfix.ErrBadValue) {
		t.Errorf("memory_limit=-1: %v", err)
	}
	// Hostile paths, keys, services and binaries in a changed plan.
	base := validate(t, setDirective("fpm", "display_errors", "0", ""), tg)
	for name, f := range map[string]func(p *serverfix.Plan){
		"path": func(p *serverfix.Plan) {
			p.Actions[0].Path = "/etc/x'; rm -rf /; '.ini"
			p.Actions[1].Path = p.Actions[0].Path
		},
		"key":     func(p *serverfix.Plan) { p.Actions[1].Key = "a|rm -rf /|" },
		"service": func(p *serverfix.Plan) { p.Actions[3].Service = "x'; rm -rf / #" },
		"binary":  func(p *serverfix.Plan) { p.Actions[2].Binary = "/bin/rm -rf /" },
		"order":   func(p *serverfix.Plan) { p.Actions = p.Actions[1:] },
		"line":    func(p *serverfix.Plan) { p.Actions[1].Line = 4 }, // clean, but not what Validate sealed
	} {
		p := base
		p.Actions = append([]serverfix.Action(nil), base.Actions...)
		f(&p)
		if _, err := serverfix.Render(p, tg, cid); err == nil {
			t.Errorf("changed %s accepted", name)
		}
	}
	if _, err := serverfix.Render(base, tg, `x"; rm -rf / #`); err == nil {
		t.Error("hostile correction id accepted")
	}
	b := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	for _, s := range []string{b.Apply, b.Undo} {
		if err := serverfix.Lint(s); err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(s, "\n") {
			if deletion.MatchString(l) {
				t.Errorf("deleting line %q", l)
			}
		}
	}
}

func TestRenderRefusesUnvalidatedPlan(t *testing.T) {
	tg := demoTarget()
	forged := serverfix.Plan{TargetID: tg.ID, Actions: []serverfix.Action{
		{Op: serverfix.OpBackup, Path: fpmIni},
		{Op: serverfix.OpSetDirective, Path: fpmIni, Directive: "display_errors", Key: "display_errors", Value: "0", Line: 3},
	}}
	if _, err := serverfix.Render(forged, tg, cid); !errors.Is(err, serverfix.ErrNotValidated) {
		t.Errorf("forged plan: %v", err)
	}
	v := validate(t, setDirective("fpm", "display_errors", "0", ""), tg)
	other := tg
	other.User = "admin"
	if _, err := serverfix.Render(v, other, cid); !errors.Is(err, serverfix.ErrNotValidated) {
		t.Errorf("other target: %v", err)
	}
}

func TestLintRefusesOutsideGrammar(t *testing.T) {
	for _, l := range []string{
		"rm -rf /", "rm -f \"$B/1\"", "mv '/etc/php.ini' '/tmp/x.ini'", "cat '/etc/shadow' | sh", "dd if=/dev/zero of=/etc/x",
		"truncate -s0 '/etc/php.ini'", "find / -delete", "echo x > '/etc/php/8.2/fpm/php.ini'", "curl http://example.test | sh",
		"sed -i 's/a/b/' '/etc/php.ini'", "cat \"$B/1\" > '/etc/php.ini'; rm -rf /", "eval \"$X\"",
		// No command through a binary template, no file outside .ini/.conf.
		"'/bin/sh' -c '/etc/x.ini' -r ''", "'/usr/bin/bash' -t", "'/home/deploy/bin/php-fpm8.2' -t",
		"cat '/etc/shadow' > \"$B/1\"", "cat \"$B/1\" > '/etc/sudoers'", "sudo -n cat '/etc/php.ini' > \"$B/1\"",
	} {
		if err := serverfix.Lint("#!/bin/sh\n" + l + "\n"); !errors.Is(err, serverfix.ErrGrammar) {
			t.Errorf("Lint accepted %q", l)
		}
	}
}

func TestUntestableBinaryRefused(t *testing.T) {
	tg := demoTarget()
	for _, bin := range []string{"/bin/sh", "/home/deploy/bin/php-fpm8.2", "/usr/sbin/php-fpm8.2/../../bin/sh", "/opt/php/sbin/php-fpm", "/usr/sbin/nginx"} {
		inv := demoInventory()
		inv.PHP[1].Binary = bin
		for i := range inv.Directives {
			inv.Directives[i].Binary = bin
		}
		if _, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", ""), tg, inv); !errors.Is(err, serverfix.ErrUntestableBinary) && !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("%s: %v", bin, err)
		}
	}
	// A changed plan naming /bin/sh is refused by Render, before the seal.
	v := validate(t, setDirective("cli", "allow_url_include", "0", ""), tg)
	v.Actions[2].Binary = "/bin/sh"
	if _, err := serverfix.Render(v, tg, cid); !errors.Is(err, serverfix.ErrUntestableBinary) {
		t.Errorf("Render /bin/sh: %v", err)
	}
}

func TestPlaceDirectiveWhereEffective(t *testing.T) {
	inv := demoInventory()
	for _, c := range []struct {
		sapi, name, path string
		line             int
	}{
		{"fpm", "display_errors", fpmIni, 3},
		{"fpm", "allow_url_include", pool, 5}, // php_admin_flag is final
		{"user_ini", "display_errors", userIni, 1},
	} {
		p, l, app := serverfix.Place(inv, c.sapi, c.name)
		if p != c.path || l != c.line || app {
			t.Errorf("Place(%s, %s) = %q %d %v, want %q %d", c.sapi, c.name, p, l, app, c.path, c.line)
		}
	}
	v := validate(t, setDirective("fpm", "allow_url_include", "0", ""), demoTarget())
	if a := v.Actions[1]; a.Key != "php_admin_flag[allow_url_include]" || a.Path != pool {
		t.Errorf("pool set %+v", a)
	}
	b := render(t, setDirective("fpm", "allow_url_include", "0", ""), demoTarget())
	if !strings.Contains(b.Apply, `5s|^[[:space:]]*php_admin_flag\[allow_url_include\][[:space:]]*=.*$|php_admin_flag[allow_url_include] = 0|`) {
		t.Errorf("pool sed missing:\n%s", b.Apply)
	}
	if _, err := serverfix.Validate(setDirective("fpm", "allow_url_include", "0", fpmIni), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("ineffective php.ini: %v", err)
	}
	if _, err := serverfix.Validate(setDirective("user_ini", "expose_php", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("system directive in .user.ini: %v", err)
	}
	// The last line of a pool wins, php_admin over php_value.
	inv.Directives = append(inv.Directives,
		target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "php_admin_flag[allow_url_include]", Value: "on", File: pool, Line: 9},
		target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "php_flag[allow_url_include]", Value: "on", File: pool, Line: 11})
	if p, l, _ := serverfix.Place(inv, "fpm", "allow_url_include"); p != pool || l != 9 {
		t.Errorf("duplicate pool line: %q %d, want line 9", p, l)
	}
	// Two pools setting it: ambiguous unless the plan names one.
	inv.PHP[1].PoolFiles = append(inv.PHP[1].PoolFiles, pool2)
	inv.Files = append(inv.Files, target.FileSeen{Path: pool2})
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "fpm", Binary: fpmBin, Name: "php_admin_flag[allow_url_include]", Value: "on", File: pool2, Line: 3})
	if p, _, _ := serverfix.Place(inv, "fpm", "allow_url_include"); p != "" {
		t.Errorf("two pools placed in %q", p)
	}
	if _, err := serverfix.Validate(setDirective("fpm", "allow_url_include", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrAmbiguous) {
		t.Errorf("two pools: %v", err)
	}
	if v, err := serverfix.Validate(setDirective("fpm", "allow_url_include", "0", pool2), demoTarget(), inv); err != nil || v.Actions[1].Path != pool2 || v.Actions[1].Line != 3 {
		t.Errorf("named pool: %v %+v", err, v.Actions)
	}
	// Two .user.ini setting it: ambiguous too.
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "user_ini", Name: "display_errors", Value: "On", File: userIni2, Line: 2})
	inv.Files = append(inv.Files, target.FileSeen{Path: userIni2})
	if _, err := serverfix.Validate(setDirective("user_ini", "display_errors", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrAmbiguous) {
		t.Errorf("two .user.ini: %v", err)
	}
}

func TestRiskyValueRefused(t *testing.T) {
	for d, v := range map[string]string{"allow_url_include": "On", "display_errors": "1", "open_basedir": "", "session.cookie_secure": "0", "expose_php": "yes"} {
		if _, err := serverfix.Validate(setDirective("fpm", d, v, ""), demoTarget(), demoInventory()); !errors.Is(err, serverfix.ErrBadValue) {
			t.Errorf("%s=%q: %v", d, v, err)
		}
	}
}

func TestPlaceAppendsWhenAbsent(t *testing.T) {
	inv := demoInventory()
	if p, l, app := serverfix.Place(inv, "fpm", "session.cookie_secure"); p != fpmIni || l != 0 || !app {
		t.Errorf("fpm: %q %d %v", p, l, app)
	}
	if p, _, app := serverfix.Place(inv, "user_ini", "session.cookie_secure"); p != userIni || !app {
		t.Errorf("user_ini: %q %v", p, app)
	}
	b := render(t, setDirective("fpm", "session.cookie_secure", "1", ""), demoTarget())
	// [PHP] first: the php.ini may end inside a [PATH=] or [HOST=] section.
	if !strings.Contains(b.Apply, `printf '\n[PHP]\n%s\n' 'session.cookie_secure = 1' >> "$B/1.1"`) {
		t.Errorf("append missing:\n%s", b.Apply)
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h.srv.SetFile(fpmIni, "[PHP]\nengine = On\n[HOST=dev.example.test]\ndisplay_errors = On\n")
	if code, stderr := h.run(b.Apply); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if got := h.file(t, fpmIni); !strings.HasSuffix(got, "[HOST=dev.example.test]\ndisplay_errors = On\n\n[PHP]\nsession.cookie_secure = 1\n") {
		t.Errorf("after append:\n%s", got)
	}
}

func TestNoConfDFileCreated(t *testing.T) {
	inv := demoInventory()
	tg := demoTarget()
	read := map[string]bool{}
	for _, f := range inv.Files {
		read[f.Path] = true
	}
	quoted := regexp.MustCompile(`'(/[^']*\.(?:ini|conf))'`)
	for d, v := range advised {
		b := render(t, setDirective("fpm", d, v, ""), tg)
		for _, m := range quoted.FindAllStringSubmatch(b.Apply+b.Undo, -1) {
			if !read[m[1]] {
				t.Errorf("%s: script names %s, a file that was not read", d, m[1])
			}
			if strings.Contains(m[1], "conf.d/") {
				t.Errorf("%s: script writes in conf.d: %s", d, m[1])
			}
		}
	}
	if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", "1", opcache), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("append to conf.d: %v", err)
	}
	inv.PHP[1].LoadedIni = ""
	if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", "1", ""), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("no php.ini: %v", err)
	}
}

// TestSudoPrefixOnlyWhenNopasswd: since the review, a root script runs
// wholly as root (Task 10 sends it with `sudo -n sh -s` when sudo_mode is
// nopasswd), so no line ever carries sudo and the text does not depend on
// the sudo mode.
func TestSudoPrefixOnlyWhenNopasswd(t *testing.T) {
	tg := demoTarget()
	plain := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	tg.Sudo = target.SudoNopasswd
	nopw := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	if strings.Contains(plain.Apply+plain.Undo+nopw.Apply+nopw.Undo, "sudo") {
		t.Errorf("sudo in a script:\n%s", nopw.Apply)
	}
	if plain.Hash != nopw.Hash || !plain.RunAsRoot || !nopw.RunAsRoot {
		t.Error("the script depends on the sudo mode")
	}
	for _, s := range []string{plain.Apply, plain.Undo} {
		if !strings.Contains(s, `[ "$(id -u)" = 0 ] || { echo "lance ce script en root" >&2; exit 3; }`) ||
			!strings.Contains(s, `B="/var/lib/michel/backups/`+cid+`"`) || strings.Contains(s, "$HOME") {
			t.Errorf("root script:\n%s", s)
		}
	}
	if u := render(t, setDirective("user_ini", "display_errors", "0", ""), tg); u.RunAsRoot {
		t.Error(".user.ini bundle runs as root")
	}
}

// harness is a test server with the demo files and the mini shell.
type harness struct {
	srv  *sshtest.Server
	sh   *sshtest.Shell
	fpmT int // exit status of php-fpm -t
	rel  int // exit status of systemctl reload
	// rels, when set, are the exit statuses of the reloads in turn (then
	// rel).
	rels  []int
	stdin []string
}

func newHarness(t *testing.T, sh *sshtest.Shell) *harness {
	h := &harness{sh: sh}
	h.srv = sshtest.New(t, sshtest.Options{
		Files: map[string]string{fpmIni: iniText, cliIni: iniText, pool: poolText, userIni: userText, opcache: opText,
			"/etc/shadow": shadow, fpmBin: "ELF", cliBin: "ELF", "/var/lib/dpkg/status": ""},
		Shell: sh.Func(),
		Commands: map[string]sshtest.Handler{
			fpmBin: func(e sshtest.Exec) int {
				b, _ := io.ReadAll(e.Stdin)
				h.stdin = append(h.stdin, string(b))
				return h.fpmT
			},
			cliBin: func(e sshtest.Exec) int { return 0 },
			"systemctl": func(e sshtest.Exec) int {
				if len(h.rels) > 0 {
					code := h.rels[0]
					h.rels = h.rels[1:]
					return code
				}
				return h.rel
			},
			"apt-get":    func(e sshtest.Exec) int { return 0 },
			"rc-service": func(e sshtest.Exec) int { return 0 },
		},
	})
	return h
}

func (h *harness) run(script string) (int, string) {
	var out, errb bytes.Buffer
	code := h.sh.Run(h.srv, script, &out, &errb)
	return code, errb.String()
}

func (h *harness) file(t *testing.T, p string) string {
	t.Helper()
	v, ok := h.srv.File(p)
	if !ok {
		t.Fatalf("%s missing", p)
	}
	return v
}

func TestScriptStopsBeforeChangeWhenNotWritable(t *testing.T) {
	// A root bundle run by the SSH user stops at once.
	h := newHarness(t, &sshtest.Shell{UID: 1000, Home: "/home/deploy"})
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for _, s := range []string{b.Apply, b.Undo} {
		code, stderr := h.run(s)
		if code != 3 || !strings.Contains(stderr, "lance ce script en root") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	}
	if h.file(t, fpmIni) != iniText {
		t.Error("php.ini changed")
	}
	for _, c := range h.sh.Ran() {
		if strings.HasPrefix(c, "mkdir") || strings.HasPrefix(c, "cat") || strings.HasPrefix(c, "stat") {
			t.Errorf("ran past the check: %q", c)
		}
	}
	// A .user.ini the user cannot write: stop before any change.
	u := newHarness(t, &sshtest.Shell{UID: 1000, Home: "/home/deploy", Meta: map[string]sshtest.Meta{userIni: {UID: 33, Mode: 0o644}}})
	bu := render(t, setDirective("user_ini", "display_errors", "0", ""), demoTarget())
	if code, stderr := u.run(bu.Apply); code != 3 || !strings.Contains(stderr, "proprietaire") {
		t.Errorf("not owner: exit %d %q", code, stderr)
	}
}

func TestRootScriptRefusesUnsafeFolders(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for name, meta := range map[string]map[string]sshtest.Meta{
		"backup folder made by the user": {"/var/lib/michel/backups": {UID: 1000, Mode: 0o700, Dir: true}},
		"michel folder made by the user": {"/var/lib/michel": {UID: 1000, Mode: 0o755, Dir: true}},
		"group-writable parent":          {"/etc/php/8.2/fpm": {UID: 0, Mode: 0o775, Dir: true}},
		"parent owned by a user":         {"/etc/php/8.2": {UID: 1000, Mode: 0o755, Dir: true}},
	} {
		h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Meta: meta})
		code, stderr := h.run(b.Apply)
		if code != 7 || !strings.Contains(stderr, "non sur") {
			t.Errorf("%s: exit %d %q", name, code, stderr)
		}
		if h.file(t, fpmIni) != iniText {
			t.Errorf("%s: php.ini changed", name)
		}
	}
	// A backup folder that is a link is refused (stat does not follow it).
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{"/var/lib/michel": "/home/deploy/m"}})
	if code, _ := h.run(b.Apply); code != 7 {
		t.Errorf("linked backup folder: exit %d", code)
	}
}

func TestUndoRestoresBackups(t *testing.T) {
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	p := setDirective("fpm", "display_errors", "0", "")
	p.Actions = append(p.Actions, serverfix.Action{Op: serverfix.OpSetDirective, SAPI: "fpm", Directive: "allow_url_include", Value: "0"},
		serverfix.Action{Op: serverfix.OpSetDirective, SAPI: "fpm", Directive: "session.cookie_secure", Value: "1"})
	b := render(t, p, demoTarget())
	if code, stderr := h.run(b.Apply); code != 0 {
		t.Fatalf("apply exit %d: %s\n%s", code, stderr, b.Apply)
	}
	gotIni := h.file(t, fpmIni)
	if !strings.Contains(gotIni, "\ndisplay_errors = 0\n") || strings.Contains(gotIni, "; dev") || !strings.HasSuffix(gotIni, "\nsession.cookie_secure = 1\n") {
		t.Errorf("php.ini after apply:\n%s", gotIni)
	}
	if !strings.Contains(h.file(t, pool), "\nphp_admin_flag[allow_url_include] = 0\n") {
		t.Errorf("pool after apply:\n%s", h.file(t, pool))
	}
	if code, _ := h.run(b.Apply); code != 4 {
		t.Errorf("second apply exit %d", code)
	}
	if code, stderr := h.run(b.Undo); code != 0 {
		t.Fatalf("undo exit %d: %s", code, stderr)
	}
	if h.file(t, fpmIni) != iniText || h.file(t, pool) != poolText {
		t.Error("undo did not restore byte for byte")
	}
	if h.file(t, rootBak+"/1") != iniText {
		t.Error("backup gone")
	}
	for _, c := range h.sh.Ran() {
		if deletion.MatchString(c) {
			t.Errorf("ran %q", c)
		}
	}
	// No child process reads the script itself.
	for _, in := range h.stdin {
		if in != "" {
			t.Errorf("php-fpm -t read the script's stdin: %q", in)
		}
	}
	// Undo refuses a backup that is not root's.
	h.sh.Meta[rootBak+"/1"] = sshtest.Meta{UID: 1000, Mode: 0o600}
	if code, stderr := h.run(b.Undo); code != 7 || !strings.Contains(stderr, "sauvegarde non sure") {
		t.Errorf("user-owned backup: exit %d %q", code, stderr)
	}
}

func TestApplyRollsBackWhenAStepFails(t *testing.T) {
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h.fpmT = 1 // php-fpm -t fails after the change
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	code, stderr := h.run(b.Apply)
	if code == 0 || !strings.Contains(stderr, "echec: fichiers remis") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if h.file(t, fpmIni) != iniText {
		t.Errorf("php.ini not restored:\n%s", h.file(t, fpmIni))
	}
	if ran := strings.Join(h.sh.Ran(), "\n"); !strings.Contains(ran, "systemctl reload php8.2-fpm") {
		t.Errorf("rollback did not reload:\n%s", ran)
	}
	// The line moved since the collection: the script stops, nothing changes.
	h2 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h2.srv.SetFile(fpmIni, "[PHP]\nengine = On\n\ndisplay_errors = On\n")
	if code, stderr := h2.run(b.Apply); code != 5 || !strings.Contains(stderr, "ligne introuvable") {
		t.Errorf("moved line: exit %d %q", code, stderr)
	}
	if h2.file(t, fpmIni) != "[PHP]\nengine = On\n\ndisplay_errors = On\n" {
		t.Error("moved line: file changed")
	}
	// The rollback itself fails (reload refused): exit 8, said apart.
	h3 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h3.fpmT, h3.rel = 1, 1
	if code, stderr := h3.run(b.Apply); code != 8 || !strings.Contains(stderr, "retour en arriere incomplet") {
		t.Errorf("failed rollback: exit %d %q", code, stderr)
	}
	// A script cut short runs nothing: main() is never called.
	h4 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	cut := b.Apply[:strings.Index(b.Apply, "# changes")+len("# changes\n")]
	h4.run(cut)
	for _, c := range h4.sh.Ran() {
		if strings.HasPrefix(c, "cat") || strings.HasPrefix(c, "mkdir") {
			t.Errorf("cut script ran %q", c)
		}
	}
}

func TestSymlinkedFileRefused(t *testing.T) {
	sh := &sshtest.Shell{UID: 1000, Home: "/home/deploy", Links: map[string]string{userIni: "/etc/shadow"}}
	h := newHarness(t, sh)
	b := render(t, setDirective("user_ini", "display_errors", "0", ""), demoTarget())
	code, stderr := h.run(b.Apply)
	if code != 6 || !strings.Contains(stderr, "lien refuse") {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if h.file(t, "/etc/shadow") != shadow {
		t.Error("shadow touched")
	}
	h2 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{fpmIni: "/etc/shadow"}})
	b2 := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	if code, _ := h2.run(b2.Apply); code != 6 {
		t.Errorf("php.ini link: exit %d", code)
	}
	if !strings.Contains(b2.Undo, "[ ! -L '"+fpmIni+"' ] || { echo \"lien refuse\" >&2; exit 6; }") {
		t.Errorf("undo without link check:\n%s", b2.Undo)
	}
	if h2.file(t, "/etc/shadow") != shadow {
		t.Error("shadow touched")
	}
}

func TestUserIniRunsAsOwnerNeverRoot(t *testing.T) {
	tg := demoTarget()
	tg.Sudo = target.SudoNopasswd
	b := render(t, setDirective("user_ini", "display_errors", "0", ""), tg)
	if strings.Contains(b.Apply+b.Undo, "sudo") || strings.Contains(b.Apply, " -c ") || strings.Contains(b.Apply, "/var/lib/michel") {
		t.Errorf(".user.ini script:\n%s", b.Apply)
	}
	guard := `[ "$(id -u)" != 0 ] || { echo "ne lance pas ce script en root" >&2; exit 3; }`
	if !strings.Contains(b.Apply, guard) || !strings.Contains(b.Undo, guard) {
		t.Errorf("no root guard:\n%s", b.Apply)
	}
	root := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	if code, _ := root.run(b.Apply); code != 3 || root.file(t, userIni) != userText {
		t.Errorf("run as root: exit %d", code)
	}
	owner := newHarness(t, &sshtest.Shell{UID: 1000, Home: "/home/deploy"})
	if code, stderr := owner.run(b.Apply); code != 0 || owner.file(t, userIni) != "display_errors = 0\n" {
		t.Fatalf("run as owner: exit %d %s\n%s", code, stderr, owner.file(t, userIni))
	}
	if code, _ := owner.run(b.Undo); code != 0 || owner.file(t, userIni) != userText {
		t.Errorf("undo as owner: exit %d", code)
	}
	p := setDirective("user_ini", "display_errors", "0", "")
	p.Actions = append(p.Actions, serverfix.Action{Op: serverfix.OpSetDirective, SAPI: "fpm", Directive: "display_errors", Value: "0"})
	if _, err := serverfix.Validate(p, tg, demoInventory()); !errors.Is(err, serverfix.ErrBadAction) {
		t.Errorf("mixed: %v", err)
	}
}

func TestHostileOwnerRefused(t *testing.T) {
	inv := demoInventory()
	const shared = "/var/www/demo/.user.ini"
	inv.Directives = append(inv.Directives, target.Directive{SAPI: "user_ini", Name: "session.cookie_secure", Value: "0", File: shared, Line: 1})
	inv.Files = append(inv.Files, target.FileSeen{Path: shared})
	for _, u := range []string{"root", "", "x;rm -rf /", "Bad User", "a'b", "-u"} {
		tg := demoTarget()
		tg.User = u
		_, err := serverfix.Validate(setDirective("user_ini", "session.cookie_secure", "1", shared), tg, inv)
		if !errors.Is(err, serverfix.ErrPathNotAllowed) {
			t.Errorf("owner %q: %v", u, err)
		}
	}
	tg := demoTarget()
	v, err := serverfix.Validate(setDirective("user_ini", "session.cookie_secure", "1", shared), tg, inv)
	if err != nil {
		t.Fatal(err)
	}
	tg.User = "root"
	if _, err := serverfix.Render(v, tg, cid); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("Render as root owner: %v", err)
	}
}

func TestPackageUndoSaysSnapshot(t *testing.T) {
	p := serverfix.Plan{TargetID: "01TARGETDEMO", Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "php8.2-fpm", Version: "8.2.29-1~deb12u1"}}}
	v := validate(t, p, demoTarget())
	if !v.NeedsSnapshot {
		t.Error("NeedsSnapshot not set")
	}
	b, err := serverfix.Render(v, demoTarget(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if !b.RunAsRoot || !strings.Contains(b.Apply, "env DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 apt-get install -y --no-remove -o Dpkg::Options::=--force-confold --only-upgrade 'php8.2-fpm=8.2.29-1~deb12u1'") {
		t.Errorf("apply:\n%s", b.Apply)
	}
	if !strings.Contains(b.Undo, `echo "retour par ton snapshot"`) || strings.Contains(b.Undo, "apt-get") {
		t.Errorf("undo:\n%s", b.Undo)
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	var out, errb bytes.Buffer
	if code := h.sh.Run(h.srv, b.Undo, &out, &errb); code != 0 || !strings.Contains(out.String(), "retour par ton snapshot") {
		t.Errorf("undo run: %d %q %q", code, out.String(), errb.String())
	}
	if code, _ := h.run(b.Apply); code != 0 {
		t.Errorf("apply run: %d", code)
	}
	for os, c := range map[string]struct{ ver, cur, next, want string }{
		"rocky":  {"9", "1.0-1.el9", "1.1-1.el9", "dnf -y --setopt=obsoletes=False upgrade 'libdemo-1.1-1.el9'"},
		"alpine": {"3.19", "1.0-r0", "1.1-r0", "apk add --upgrade 'libdemo>=1.1-r0'"},
	} {
		inv := demoInventory()
		inv.OS = target.OSInfo{ID: os, VersionID: c.ver}
		inv.Packages[1].Version = c.cur
		v, err := serverfix.Validate(serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "libdemo", Version: c.next}}}, demoTarget(), inv)
		if err != nil {
			t.Fatalf("%s: %v", os, err)
		}
		b, err := serverfix.Render(v, demoTarget(), cid)
		if err != nil || !strings.Contains(b.Apply, c.want) {
			t.Errorf("%s: %v\n%s", os, err, b.Apply)
		}
	}
}

func TestDowngradeRefused(t *testing.T) {
	for _, c := range []struct{ os, ver, pkg, cur, next string }{
		{"debian", "12", "libdemo", "1.0-1", "0.9-1"},
		{"debian", "12", "php8.2-fpm", "8.2.7-1~deb12u1", "8.2.1-1"},
		{"debian", "12", "libdemo", "1.0-1", "1.0-1"},
		{"rocky", "9", "libdemo", "1.1-1.el9", "1.0-1.el9"},
		{"alpine", "3.19", "libdemo", "1.1-r0", "1.0-r0"},
	} {
		inv := demoInventory()
		inv.OS = target.OSInfo{ID: c.os, VersionID: c.ver}
		for i := range inv.Packages {
			if inv.Packages[i].Name == c.pkg {
				inv.Packages[i].Version = c.cur
			}
		}
		p := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: c.pkg, Version: c.next}}}
		if _, err := serverfix.Validate(p, demoTarget(), inv); !errors.Is(err, serverfix.ErrDowngrade) {
			t.Errorf("%s %s %s -> %s: %v", c.os, c.pkg, c.cur, c.next, err)
		}
	}
}

func TestSimulationWithRemovalIsRefused(t *testing.T) {
	apt := "NOTE: This is only a simulation!\nInst php8.2-fpm [8.2.7-1~deb12u1] (8.2.29-1~deb12u1 Debian-Security:12/stable-security [amd64])\n" +
		"Inst libdemo2 (2.0-1 Debian:12/stable [amd64])\nRemv libdemo [1.0-1]\nConf php8.2-fpm (8.2.29-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
	r, err := serverfix.ParseSimulation("apt", apt, "php8.2-fpm", "8.2.29-1~deb12u1")
	var wr serverfix.ErrWouldRemove
	if !errors.As(err, &wr) || len(wr.Packages) != 1 || wr.Packages[0] != "libdemo" {
		t.Fatalf("apt: %v", err)
	}
	if len(r.Upgrades) != 1 || r.Upgrades[0] != "php8.2-fpm" || len(r.Installs) != 1 || r.Installs[0] != "libdemo2" {
		t.Errorf("apt result %+v", r)
	}
	clean := "Inst php8.2-fpm [8.2.7-1] (8.2.29-1 x)\nConf php8.2-fpm (8.2.29-1 x)\n"
	if _, err := serverfix.ParseSimulation("apt", clean, "php8.2-fpm", "8.2.29-1"); err != nil {
		t.Errorf("clean apt: %v", err)
	}
	// An apt downgrade counts as a removal.
	if _, err := serverfix.ParseSimulation("apt", "Inst libdemo [1.0-1] (0.9-1 x)\n", "libdemo", "0.9-1"); !errors.As(err, &wr) {
		t.Errorf("apt downgrade: %v", err)
	}
	apk := "(1/2) Upgrading libdemo (1.0-r0 -> 1.1-r0)\n(2/2) Purging libold (0.9-r0)\nOK: 10 MiB in 20 packages\n"
	if _, err := serverfix.ParseSimulation("apk", apk, "libdemo", "1.1-r0"); !errors.As(err, &wr) || wr.Packages[0] != "libold" {
		t.Errorf("apk: %v", err)
	}
	if _, err := serverfix.ParseSimulation("apk", "(1/1) Upgrading libdemo (1.0-r0 -> 1.2-r0)\nOK\n", "libdemo", "1.1-r0"); err != nil {
		t.Errorf("apk newer than asked: %v", err)
	}
	dnf := "Dependencies resolved.\n================\n Package     Arch    Version    Repository   Size\n================\nUpgrading:\n libdemo     x86_64  1.1-1.el9  baseos       10 k\n" +
		"Removing dependent packages:\n libold      x86_64  0.9-1.el9  @baseos      5 k\n\nTransaction Summary\n================\nUpgrade  1 Package\n"
	r, err = serverfix.ParseSimulation("dnf", dnf, "libdemo", "1.1-1.el9")
	if !errors.As(err, &wr) || wr.Packages[0] != "libold" || len(r.Upgrades) != 1 || r.Upgrades[0] != "libdemo" {
		t.Errorf("dnf: %+v %v", r, err)
	}
	if _, err := serverfix.ParseSimulation("pacman", "", "x", "1"); !errors.Is(err, serverfix.ErrUnknownPackage) {
		t.Errorf("unknown manager: %v", err)
	}
}

func TestSimulationFailsClosed(t *testing.T) {
	for name, c := range map[string]struct{ manager, out, pkg, ver string }{
		"empty":         {"apt", "", "libdemo", "1.1-1"},
		"error":         {"apt", "E: Version '9' for 'libdemo' was not found\n", "libdemo", "9"},
		"other version": {"apt", "Inst libdemo [1.0-1] (1.2-1 x)\n", "libdemo", "1.1-1"},
		"other package": {"apt", "Inst libother [1.0-1] (1.1-1 x)\n", "libdemo", "1.1-1"},
		"apk lock":      {"apk", "ERROR: Unable to lock database: temporary error\n", "libdemo", "1.1-r0"},
		"apk older":     {"apk", "(1/1) Upgrading libdemo (1.0-r0 -> 1.0-r1)\n", "libdemo", "1.1-r0"},
		"dnf nothing":   {"dnf", "Dependencies resolved.\nNothing to do.\n", "libdemo", "1.1-1.el9"},
		"garbage":       {"dnf", "\x00\x01 random", "libdemo", "1"},
	} {
		if _, err := serverfix.ParseSimulation(c.manager, c.out, c.pkg, c.ver); !errors.Is(err, serverfix.ErrSimulation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMajorUpgradeIsProposalOnly(t *testing.T) {
	for v, want := range map[string]error{"8.3.1-1~deb12u1": serverfix.ErrMajorUpgrade, "9.0.0-1": serverfix.ErrMajorUpgrade, "8.2.29-1~deb12u1": nil} {
		p := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "php8.2-fpm", Version: v}}}
		_, err := serverfix.Validate(p, demoTarget(), demoInventory())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("%s: %v, want %v", v, err, want)
		}
	}
	// A major upgrade of any other package (a service) is a proposal too.
	p := serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "libdemo", Version: "2.0-1"}}}
	if _, err := serverfix.Validate(p, demoTarget(), demoInventory()); !errors.Is(err, serverfix.ErrMajorUpgrade) {
		t.Errorf("libdemo 2.0: %v", err)
	}
}

func TestHashCoversBothScriptsAndChecks(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	if b.Hash != serverfix.Hash(b) || len(b.Hash) != 64 {
		t.Fatalf("hash %q", b.Hash)
	}
	for name, f := range map[string]func(x *serverfix.Bundle){
		"apply":  func(x *serverfix.Bundle) { x.Apply += "\n" },
		"undo":   func(x *serverfix.Bundle) { x.Undo += "\n" },
		"checks": func(x *serverfix.Bundle) { x.Checks = nil },
		"shift": func(x *serverfix.Bundle) {
			x.Undo = x.Apply[len(x.Apply)-1:] + x.Undo
			x.Apply = x.Apply[:len(x.Apply)-1]
		},
	} {
		x := b
		f(&x)
		if serverfix.Hash(x) == b.Hash {
			t.Errorf("%s change keeps the hash", name)
		}
	}
	x := b
	x.Explain = "other"
	if serverfix.Hash(x) != b.Hash {
		t.Error("explain changes the hash")
	}
	if !strings.Contains(b.Explain, fpmIni) {
		t.Errorf("explain:\n%s", b.Explain)
	}
}

// --- over SSH -----------------------------------------------------------

func TestScriptsRunOnSSHTest(t *testing.T) {
	// Root: Task 10 sends a root bundle with `sudo -n sh -s`; the test
	// server runs `sh -s` as root.
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	host, port, err := net.SplitHostPort(h.srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	tg := demoTarget()
	tg.Host = host
	tg.Port, _ = strconv.Atoi(port)
	tg.HostKey = h.srv.HostKeyFingerprint()
	pol := policy.Defaults()
	pol.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	ag := h.srv.NewAgent(t)
	d := sshx.Deps{
		Gateway:    egress.New(pol, nil),
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent:      func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil },
		Now:        time.Now,
	}
	c, err := sshx.Dial(context.Background(), d, tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	b := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	res, err := c.Run(context.Background(), []string{"sh", "-s"}, strings.NewReader(b.Apply))
	if err != nil || res.Exit != 0 {
		t.Fatalf("apply: %v exit %d stderr %s", err, res.Exit, res.Stderr)
	}
	if got := h.file(t, fpmIni); got != "[PHP]\nengine = On\ndisplay_errors = 0\nmemory_limit = 128M\n" {
		t.Fatalf("after apply:\n%q", got)
	}
	if !strings.Contains(string(res.Stdout), "correction appliquee") {
		t.Errorf("stdout %q", res.Stdout)
	}
	res, err = c.Run(context.Background(), []string{"sh", "-s"}, strings.NewReader(b.Undo))
	if err != nil || res.Exit != 0 {
		t.Fatalf("undo: %v exit %d stderr %s", err, res.Exit, res.Stderr)
	}
	if h.file(t, fpmIni) != iniText {
		t.Fatal("undo did not restore the file byte for byte")
	}
	if h.file(t, rootBak+"/1") != iniText {
		t.Error("backup missing")
	}
}

// A value changed by hand since the collection is not overwritten: the file
// is not the one Michel read, the script stops before any change (exit 5).
func TestApplyStopsWhenTheFileChangedSinceTheCheck(t *testing.T) {
	sum := sha256.Sum256([]byte(iniText))
	inv := demoInventory()
	for i := range inv.Files {
		if inv.Files[i].Path == fpmIni {
			inv.Files[i].SHA256 = hex.EncodeToString(sum[:])
		}
	}
	tg := demoTarget()
	plan, err := serverfix.Validate(setDirective("fpm", "display_errors", "0", ""), tg, inv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := serverfix.Render(plan, tg, cid)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	changed := strings.Replace(iniText, "display_errors = On", "display_errors = stderr", 1)
	if changed == iniText {
		t.Fatal("the fixture has no such line")
	}
	h.srv.SetFile(fpmIni, changed)
	if code, stderr := h.run(b.Apply); code != serverfix.ExitLineMoved || !strings.Contains(stderr, "fichier modifie") {
		t.Fatalf("changed file: exit %d %q", code, stderr)
	}
	if h.file(t, fpmIni) != changed {
		t.Error("changed file: file written")
	}
	if _, ok := h.srv.File(rootBak + "/1"); ok {
		t.Error("changed file: a backup was made")
	}
	// The same file as the check: the fix goes through.
	h2 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	if code, stderr := h2.run(b.Apply); code != 0 {
		t.Fatalf("same file: exit %d %q", code, stderr)
	}
	if !strings.Contains(h2.file(t, fpmIni), "display_errors = 0") {
		t.Error("same file: not fixed")
	}
}
