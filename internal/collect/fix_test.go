package collect_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/target"
)

func TestErrorCauseIndependentOfLocale(t *testing.T) {
	h := debian(t)
	h.french = true
	h.denied["/etc/php/8.2/fpm/php.ini"] = true
	e := start(t, h)
	inv := run(t, e, demoLinks)
	if !hasUnseen(inv, "/etc/php/8.2/fpm/php.ini", "collect.unseen.not_read") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, u := range inv.Unseen {
		if u.Reason == "collect.unseen.unreadable" {
			t.Fatalf("a cause told from a French text: %+v", u)
		}
	}
	n := 0
	for _, l := range e.srv.Log() {
		if strings.HasPrefix(l, "'command' ") {
			continue
		}
		if !strings.HasPrefix(l, envC) {
			t.Fatalf("command without the C locale: %s", l)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d commands", n)
	}
}

func TestDirectivesOfTwoFPMKeepTheirBinary(t *testing.T) {
	h := debian(t)
	h.bins["/usr/sbin/php-fpm8.3"] = "/usr/sbin/php-fpm8.3"
	h.owners["/usr/sbin/php-fpm8.3"] = "php8.3-fpm"
	o := h.fpm["/usr/sbin/php-fpm8.2"]
	h.fpm["/usr/sbin/php-fpm8.3"] = fpmOut{
		v:  strings.ReplaceAll(o.v, "8.2.20", "8.3.35"),
		i:  strings.ReplaceAll(strings.ReplaceAll(o.i, "8.2", "8.3"), "memory_limit => 256M => 256M", "memory_limit => 512M => 512M"),
		tt: strings.ReplaceAll(o.tt, "8.2", "8.3"),
		m:  o.m,
	}
	h.files["/etc/php/8.3/fpm/php.ini"] = "memory_limit = 512M\n"
	e := start(t, h)
	inv := run(t, e, demoLinks)
	if n := len(runtimeOf(inv, "fpm")); n != 2 {
		t.Fatalf("%d fpm runtimes", n)
	}
	got := map[string]target.Directive{}
	for _, d := range inv.Directives {
		if d.SAPI == "fpm" && d.Name == "memory_limit" {
			if _, dup := got[d.Binary]; dup {
				t.Fatalf("memory_limit twice for %s", d.Binary)
			}
			got[d.Binary] = d
		}
	}
	if got["/usr/sbin/php-fpm8.2"].Value != "256M" || got["/usr/sbin/php-fpm8.3"].Value != "512M" ||
		got["/usr/sbin/php-fpm8.3"].File != "/etc/php/8.3/fpm/php.ini" {
		t.Fatalf("memory_limit %+v", got)
	}
	for _, d := range inv.Directives {
		if d.SAPI != "user_ini" && d.Binary == "" {
			t.Fatalf("directive without binary: %+v", d)
		}
		if d.SAPI == "cli" && d.Binary != "/usr/bin/php" {
			t.Fatalf("cli directive binary %+v", d)
		}
		if d.SAPI == "user_ini" && d.Binary != "" {
			t.Fatalf("two FPM: a .user.ini cannot be tied to one: %+v", d)
		}
	}
	// With one FPM, the .user.ini belongs to it.
	inv = run(t, start(t, debian(t)), demoLinks)
	if d, ok := directive(inv, "user_ini", "display_errors"); !ok || d.Binary != "/usr/sbin/php-fpm8.2" {
		t.Fatalf("user_ini %+v", d)
	}
}

func TestCredentialInsideValueMasked(t *testing.T) {
	h := debian(t)
	h.cliJSON = strings.Replace(h.cliJSON, `"session.save_path":"/var/lib/php/sessions"`,
		`"session.save_path":"tcp://redis.example.test:6379?auth=hunter2-demo&database=2"`, 1)
	if !strings.Contains(h.cliJSON, "auth=hunter2-demo") {
		t.Fatal("fixture not changed")
	}
	e := start(t, h)
	inv := run(t, e, nil)
	d, ok := directive(inv, "cli", "session.save_path")
	if !ok || strings.Contains(d.Value, "hunter2") || !strings.Contains(d.Value, "redis.example.test") {
		t.Fatalf("save_path %+v", d)
	}
	body, _ := json.Marshal(inv)
	if strings.Contains(string(body), "hunter2-demo") {
		t.Fatal("credential stored")
	}
	// Names are checked word by word for every directive; only a few
	// harmless names are exempt.
	for name, want := range map[string]bool{
		"session.redis_auth": true, "opcache.license_key": true, "smtp.credentials": true, "mail.pw": true,
		"session.secret_salt": true, "pcre.jit": false, "session.use_only_cookies": false, "xdebug.idekey": false,
		"opcache.enable": false, "auto_prepend_file": false, "highlight.keyword": false,
	} {
		if got := collect.SecretName(name); got != want {
			t.Errorf("%s: secret %v", name, got)
		}
	}
}

func TestPHPInfoEnvironmentNotDirectives(t *testing.T) {
	s := "phpinfo()\nCore\n\nDirective => Local Value => Master Value\nexpose_php => Off => Off\n\nstandard\n\n" +
		"Dynamic Library Support => enabled => yes\n\nEnvironment\n\nVariable => Value\nFOO => bar => baz\n\n" +
		"PHP Variables\n\nVariable => Value\n$_SERVER['X'] => a => b\n\nDirective => Local Value => Master Value\nlate => 1 => 1\n"
	info := collect.ParsePHPInfo(s)
	if len(info.Directives) != 1 || info.Directives["expose_php"] != "Off" {
		t.Fatalf("directives %v", info.Directives)
	}
}

func TestRepeatedAuthParamMasked(t *testing.T) {
	for _, v := range []string{
		"tcp://redis.example.test:6379?auth[]=user&auth[]=hunter2-demo",
		"tcp://redis.example.test:6379?auth%5B%5D=user&auth%5B%5D=hunter2-demo",
	} {
		h := debian(t)
		h.cliJSON = strings.Replace(h.cliJSON, `"session.save_path":"/var/lib/php/sessions"`, `"session.save_path":"`+v+`"`, 1)
		e := start(t, h)
		inv := run(t, e, nil)
		d, ok := directive(inv, "cli", "session.save_path")
		if !ok || !strings.Contains(d.Value, "redis.example.test") {
			t.Fatalf("save_path %+v", d)
		}
		body, _ := json.Marshal(inv)
		all := string(body)
		rows, err := e.st.DB().Query(`SELECT evidence FROM audit_event`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var ev string
			rows.Scan(&ev)
			all += ev
		}
		rows.Close()
		if strings.Contains(all, "hunter2-demo") {
			t.Fatalf("%s: credential stored", v)
		}
	}
}

func TestKeyWordsInNamesAreSecret(t *testing.T) {
	for _, n := range []string{"redis.keys", "app.api_keys", "ssl.keyfile", "java.keystore", "tls.privkey_path", "session.redis_key"} {
		if !collect.SecretName(n) {
			t.Errorf("%s not secret", n)
		}
	}
	for _, n := range []string{"xdebug.idekey", "highlight.keyword", "mysqlnd.sha256_server_public_key", "memory_limit"} {
		if collect.SecretName(n) {
			t.Errorf("%s secret", n)
		}
	}
}

func TestLinkedConfigFileResolvedBeforeRead(t *testing.T) {
	h := debian(t)
	evil := "/etc/php/8.2/fpm/conf.d/evil.ini"
	h.files[evil] = "root:x:0:0\n"
	h.files["/etc/shadow"] = "root:x:0:0\n"
	h.links[evil] = "/etc/shadow"
	h.links["/etc/php/8.2/fpm/conf.d/home.ini"] = "/home/other/app.ini"
	h.files["/home/other/app.ini"] = "x = 1\n"
	o := h.fpm["/usr/sbin/php-fpm8.2"]
	o.i = strings.Replace(o.i, "/etc/php/8.2/fpm/conf.d/10-opcache.ini", "/etc/php/8.2/fpm/conf.d/10-opcache.ini,\n"+evil+",\n/etc/php/8.2/fpm/conf.d/home.ini", 1)
	h.fpm["/usr/sbin/php-fpm8.2"] = o
	e := start(t, h)
	e.deps.ExtraPaths = []string{"/etc/php/8.2/fpm/conf.d/home.ini"}
	inv := run(t, e, demoLinks)
	if !hasUnseen(inv, evil, "collect.unseen.refused") || !hasUnseen(inv, "/etc/php/8.2/fpm/conf.d/home.ini", "collect.unseen.refused") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, l := range e.srv.Log() {
		if strings.Contains(l, "'head'") && (strings.Contains(l, "evil.ini") || strings.Contains(l, "/etc/shadow") || strings.Contains(l, "home.ini") || strings.Contains(l, "/home/other")) {
			t.Fatalf("linked secret file read: %s", l)
		}
	}
	for _, f := range inv.Files {
		if f.Path == evil {
			t.Fatal("evil.ini listed as read")
		}
	}
	// A link to an allowed file is read through its real path.
	h2 := debian(t)
	h2.links["/etc/php/8.2/fpm/php.ini"] = "/etc/php/8.2/fpm/php.ini.d/real.ini"
	h2.files["/etc/php/8.2/fpm/php.ini.d/real.ini"] = "memory_limit = 256M\n"
	e2 := start(t, h2)
	inv = run(t, e2, nil)
	read := false
	for _, l := range e2.srv.Log() {
		if strings.Contains(l, "'head'") && strings.Contains(l, "/etc/php/8.2/fpm/php.ini.d/real.ini") {
			read = true
		}
	}
	if !read {
		t.Fatal("the real file was not read")
	}
}

func TestPathWithSpaceReadAndCollectionContinues(t *testing.T) {
	h := debian(t)
	h.files["/home/deploy/my site/.user.ini"] = "display_errors = Off\n"
	h.noParent = map[string]bool{"/etc/php/8.2/fpm/gone/extra.ini": true}
	e := start(t, h)
	e.deps.ExtraPaths = []string{"/etc/php/8.2/fpm/gone/extra.ini", "/etc/nginx/nginx (old).conf"}
	links := []target.Link{{TargetID: "01TARGETDEMO", RemoteDir: "/home/deploy/my site"}}
	inv, err := collect.Run(context.Background(), e.deps, e.client, e.tgt, links)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	d, ok := directive(inv, "user_ini", "display_errors")
	if !ok || d.File != "/home/deploy/my site/.user.ini" || d.Value != "Off" {
		t.Fatalf("user_ini %+v", d)
	}
	if !hasUnseen(inv, "/etc/php/8.2/fpm/gone/extra.ini", "collect.unseen.missing") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	// The collection went on to the end: the paren path was handled too.
	if !hasUnseen(inv, "/etc/nginx/nginx (old).conf", "collect.unseen.missing") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
}
