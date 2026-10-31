package collect_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// host describes the simulated server: which binaries exist and what they
// print. The handlers below turn it into sshtest commands.
type host struct {
	files    map[string]string
	denied   map[string]bool   // paths the SSH user may not read
	bins     map[string]string // name or absolute path given to command -v → path printed
	links    map[string]string // readlink -f
	owners   map[string]string // dpkg -S path → package
	cliV     string            // php -v output; "" = no php
	cliIni   string
	cliJSON  string
	fpm      map[string]fpmOut // absolute binary path → outputs
	dpkg     string            // dpkg-query output; "" = no dpkg
	rpm      string
	apk      string
	nginx    string
	apache2  string
	kernel   string
	osRel    string
	headsFor []string        // records every head path, to count read attempts
	french   bool            // the server answers in French when the locale is not forced
	noParent map[string]bool // readlink -f fails: a parent folder is missing
}

type fpmOut struct{ v, i, tt, m string }

func notFound(e sshtest.Exec) int {
	fmt.Fprintf(e.Stderr, "sh: %s: not found\n", e.Args[0])
	return 127
}

func (h *host) commands() map[string]sshtest.Handler {
	out := map[string]sshtest.Handler{}
	out["cat"] = func(e sshtest.Exec) int {
		if len(e.Args) == 2 && e.Args[1] == "/etc/os-release" && h.osRel != "" {
			io.WriteString(e.Stdout, h.osRel)
			return 0
		}
		fmt.Fprintf(e.Stderr, "cat: %s: No such file or directory\n", e.Args[len(e.Args)-1])
		return 1
	}
	out["uname"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, h.kernel+"\n"); return 0 }
	out["command"] = func(e sshtest.Exec) int {
		code := 0
		for _, a := range e.Args[2:] {
			if p, ok := h.bins[a]; ok {
				io.WriteString(e.Stdout, p+"\n")
			} else {
				code = 1
			}
		}
		return code
	}
	out["readlink"] = func(e sshtest.Exec) int {
		p := e.Args[len(e.Args)-1]
		if h.noParent[p] {
			fmt.Fprintf(e.Stderr, "readlink: %s: No such file or directory\n", p)
			return 1
		}
		if r, ok := h.links[p]; ok {
			p = r
		}
		io.WriteString(e.Stdout, p+"\n")
		return 0
	}
	out["head"] = func(e sshtest.Exec) int {
		if len(e.Args) != 4 || e.Args[1] != "-c" {
			return 2
		}
		n, _ := strconv.Atoi(e.Args[2])
		p := e.Args[3]
		h.headsFor = append(h.headsFor, p)
		if h.french {
			// A server that ignored LC_ALL=C: a cause Michel cannot tell.
			fmt.Fprintf(e.Stderr, "head: impossible d'ouvrir '%s' en lecture: Permission non accordée\n", p)
			if h.denied[p] {
				return 1
			}
			if _, ok := h.files[p]; !ok {
				return 1
			}
		}
		if h.denied[p] {
			fmt.Fprintf(e.Stderr, "head: cannot open '%s' for reading: Permission denied\n", p)
			return 1
		}
		c, ok := h.files[p]
		if !ok {
			fmt.Fprintf(e.Stderr, "head: cannot open '%s' for reading: No such file or directory\n", p)
			return 1
		}
		if len(c) > n {
			c = c[:n]
		}
		io.WriteString(e.Stdout, c)
		return 0
	}
	if h.cliV != "" {
		out["php"] = func(e sshtest.Exec) int {
			switch e.Args[1] {
			case "-v":
				io.WriteString(e.Stdout, h.cliV)
			case "-m":
				io.WriteString(e.Stdout, fixtureText["php-m"])
			case "--ini":
				io.WriteString(e.Stdout, h.cliIni)
			case "-r":
				io.WriteString(e.Stdout, h.cliJSON)
			default:
				return 1
			}
			return 0
		}
	}
	for bin, o := range h.fpm {
		o := o
		out[bin] = func(e sshtest.Exec) int {
			switch e.Args[1] {
			case "-v":
				io.WriteString(e.Stdout, o.v)
			case "-i":
				io.WriteString(e.Stdout, o.i)
			case "-m":
				io.WriteString(e.Stdout, o.m)
			case "-tt":
				io.WriteString(e.Stderr, o.tt)
			default:
				return 1
			}
			return 0
		}
	}
	if h.dpkg != "" {
		out["dpkg-query"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, h.dpkg); return 0 }
		out["dpkg"] = func(e sshtest.Exec) int {
			p := e.Args[len(e.Args)-1]
			if pkg, ok := h.owners[p]; ok {
				fmt.Fprintf(e.Stdout, "%s: %s\n", pkg, p)
				return 0
			}
			fmt.Fprintf(e.Stderr, "dpkg-query: no path found matching pattern %s\n", p)
			return 1
		}
	}
	if h.rpm != "" {
		out["rpm"] = func(e sshtest.Exec) int {
			if e.Args[1] == "-qa" {
				io.WriteString(e.Stdout, h.rpm)
				return 0
			}
			p := e.Args[len(e.Args)-1]
			if pkg, ok := h.owners[p]; ok {
				fmt.Fprintf(e.Stdout, "%s\n", pkg)
				return 0
			}
			fmt.Fprintf(e.Stdout, "file %s is not owned by any package\n", p)
			return 1
		}
	}
	if h.apk != "" {
		out["apk"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, h.apk); return 0 }
	}
	if h.nginx != "" {
		nginx := func(e sshtest.Exec) int { io.WriteString(e.Stderr, h.nginx); return 0 }
		out["nginx"] = nginx
		out["/usr/sbin/nginx"] = nginx
	}
	if h.apache2 != "" {
		ap := func(e sshtest.Exec) int { io.WriteString(e.Stdout, h.apache2); return 0 }
		out["apache2"] = ap
		out["/usr/sbin/apache2"] = ap
	}
	for _, name := range []string{"php", "dpkg-query", "dpkg", "rpm", "apk", "nginx", "apache2", "httpd"} {
		if _, ok := out[name]; !ok {
			out[name] = notFound
		}
	}
	// env LC_ALL=C LANG=C <argv>: run argv.
	out["env"] = func(e sshtest.Exec) int {
		i := 1
		for i < len(e.Args) && strings.Contains(e.Args[i], "=") {
			i++
		}
		if i >= len(e.Args) {
			return 2
		}
		inner, ok := out[e.Args[i]]
		if !ok {
			return notFound(sshtest.Exec{Args: e.Args[i:], Stderr: e.Stderr})
		}
		e.Args = e.Args[i:]
		return inner(e)
	}
	return out
}

var fixtureText = map[string]string{}

func loadFixtures(t *testing.T) {
	t.Helper()
	for _, n := range []string{"php-m", "php-v", "php-ini", "php-r.json", "php-fpm8.2-v", "php-fpm8.2-i", "php-fpm8.2-tt",
		"dpkg-query", "nginx-v", "apache2-v", "os-release-debian12", "php.ini", "www.conf"} {
		fixtureText[n] = fixture(t, n)
	}
}

// debian is a Debian 12 VPS with PHP 8.2.20 CLI and FPM from the
// distribution packages and nginx.
func debian(t *testing.T) *host {
	t.Helper()
	loadFixtures(t)
	return &host{
		files: map[string]string{
			"/etc/php/8.2/cli/php.ini":               fixtureText["php.ini"],
			"/etc/php/8.2/cli/conf.d/10-mysqlnd.ini": "extension=mysqlnd.so\n",
			"/etc/php/8.2/cli/conf.d/10-opcache.ini": "zend_extension=opcache.so\n",
			"/etc/php/8.2/fpm/php.ini":               fixtureText["php.ini"],
			"/etc/php/8.2/fpm/conf.d/10-mysqlnd.ini": "extension=mysqlnd.so\n",
			"/etc/php/8.2/fpm/conf.d/10-opcache.ini": "zend_extension=opcache.so\n",
			"/etc/php/8.2/fpm/pool.d/www.conf":       fixtureText["www.conf"],
			"/var/www/demo/public/.user.ini":         "display_errors = On\n",
		},
		denied: map[string]bool{},
		bins: map[string]string{
			"php":                  "/usr/bin/php",
			"/usr/sbin/php-fpm8.2": "/usr/sbin/php-fpm8.2",
			"/usr/sbin/nginx":      "/usr/sbin/nginx",
		},
		links:   map[string]string{"/usr/bin/php": "/usr/bin/php8.2"},
		owners:  map[string]string{"/usr/bin/php8.2": "php8.2-cli", "/usr/sbin/php-fpm8.2": "php8.2-fpm"},
		cliV:    fixtureText["php-v"],
		cliIni:  fixtureText["php-ini"],
		cliJSON: fixtureText["php-r.json"],
		fpm: map[string]fpmOut{"/usr/sbin/php-fpm8.2": {
			v: fixtureText["php-fpm8.2-v"], i: fixtureText["php-fpm8.2-i"], tt: fixtureText["php-fpm8.2-tt"], m: fixtureText["php-m"],
		}},
		dpkg:   fixtureText["dpkg-query"],
		nginx:  fixtureText["nginx-v"],
		kernel: "6.1.0-21-amd64",
		osRel:  fixtureText["os-release-debian12"],
	}
}

type env struct {
	srv    *sshtest.Server
	client *sshx.Client
	tgt    target.Target
	deps   collect.Deps
	st     *store.Store
}

func start(t *testing.T, h *host) *env {
	t.Helper()
	srv := sshtest.New(t, sshtest.Options{Commands: h.commands()})
	ag := srv.NewAgent(t)
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	gw := egress.New(p, nil)
	hostname, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	tg := target.Target{ID: "01TARGETDEMO", Name: "srv-demo", Host: hostname, Port: pn, User: "deploy",
		HostKey: srv.HostKeyFingerprint(), Kind: target.KindVPS, Env: target.EnvProd, Classification: policy.ClassInternal}
	c, err := sshx.Dial(context.Background(), sshx.Deps{
		Gateway:    gw,
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent:      func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil },
		Now:        time.Now,
	}, tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := func() time.Time { return time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC) }
	return &env{srv: srv, client: c, tgt: tg, st: st, deps: collect.Deps{Now: now, Audit: audit.NewLogger(st, now), Gateway: gw}}
}

var demoLinks = []target.Link{{TargetID: "01TARGETDEMO", ProjectID: "01PROJECTDEMO", RemoteDir: "/var/www/demo"}}

func run(t *testing.T, e *env, links []target.Link) target.Inventory {
	t.Helper()
	inv, err := collect.Run(context.Background(), e.deps, e.client, e.tgt, links)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return inv
}

func runtimeOf(inv target.Inventory, sapi string) []target.PHPRuntime {
	var out []target.PHPRuntime
	for _, r := range inv.PHP {
		if r.SAPI == sapi {
			out = append(out, r)
		}
	}
	return out
}

func directive(inv target.Inventory, sapi, name string) (target.Directive, bool) {
	for _, d := range inv.Directives {
		if d.SAPI == sapi && d.Name == name {
			return d, true
		}
	}
	return target.Directive{}, false
}

func hasUnseen(inv target.Inventory, what, reason string) bool {
	for _, u := range inv.Unseen {
		if u.What == what && u.Reason == reason {
			return true
		}
	}
	return false
}

func TestCollectDebianPHPFPM(t *testing.T) {
	e := start(t, debian(t))
	inv := run(t, e, demoLinks)

	if inv.TargetID != "01TARGETDEMO" || !inv.At.Equal(e.deps.Now()) {
		t.Fatalf("target %q at %v", inv.TargetID, inv.At)
	}
	if inv.OS != (target.OSInfo{ID: "debian", VersionID: "12", Pretty: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-21-amd64"}) {
		t.Fatalf("os %+v", inv.OS)
	}
	cli, fpm := runtimeOf(inv, "cli"), runtimeOf(inv, "fpm")
	if len(cli) != 1 || len(fpm) != 1 {
		t.Fatalf("runtimes %+v", inv.PHP)
	}
	c := cli[0]
	if c.Version != "8.2.20" || c.Binary != "/usr/bin/php" || c.FromPackage != "php8.2-cli" {
		t.Fatalf("cli %+v", c)
	}
	if c.LoadedIni != "/etc/php/8.2/cli/php.ini" || c.ScannedDir != "/etc/php/8.2/cli/conf.d" ||
		strings.Join(c.ScannedFiles, ",") != "/etc/php/8.2/cli/conf.d/10-mysqlnd.ini,/etc/php/8.2/cli/conf.d/10-opcache.ini" {
		t.Fatalf("cli ini %+v", c)
	}
	if !contains(c.Modules, "mysqli") || !contains(c.Modules, "Zend OPcache") {
		t.Fatalf("modules %v", c.Modules)
	}
	f := fpm[0]
	if f.Version != "8.2.20" || f.Binary != "/usr/sbin/php-fpm8.2" || f.FromPackage != "php8.2-fpm" {
		t.Fatalf("fpm %+v", f)
	}
	if f.LoadedIni != "/etc/php/8.2/fpm/php.ini" || len(f.ScannedFiles) != 2 || strings.Join(f.PoolFiles, ",") != "/etc/php/8.2/fpm/pool.d/www.conf" {
		t.Fatalf("fpm ini %+v", f)
	}

	// Directives: effective values from each SAPI, placed in the files.
	d, ok := directive(inv, "cli", "expose_php")
	if !ok || d.Value != "1" || d.File != "/etc/php/8.2/cli/php.ini" || d.Line != 3 {
		t.Fatalf("cli expose_php %+v", d)
	}
	d, ok = directive(inv, "cli", "display_errors")
	if !ok || d.Line != 7 {
		t.Fatalf("last occurrence wins: %+v", d)
	}
	d, ok = directive(inv, "fpm", "memory_limit")
	if !ok || d.Value != "256M" {
		t.Fatalf("fpm memory_limit %+v", d)
	}
	d, ok = directive(inv, "fpm", "open_basedir")
	if !ok || d.Value != "" {
		t.Fatalf("fpm open_basedir %+v", d)
	}
	d, ok = directive(inv, "fpm", "listen")
	if !ok || d.File != "/etc/php/8.2/fpm/pool.d/www.conf" || d.Line != 4 {
		t.Fatalf("pool listen %+v", d)
	}
	d, ok = directive(inv, "user_ini", "display_errors")
	if !ok || d.Value != "On" || d.File != "/var/www/demo/public/.user.ini" || d.Line != 1 {
		t.Fatalf(".user.ini %+v", d)
	}
	if _, ok := directive(inv, "cli", "session.save_path"); !ok {
		t.Fatal("session.save_path missing")
	}

	if len(inv.Web) != 1 || inv.Web[0] != (target.WebServer{Name: "nginx", Version: "1.22.1"}) {
		t.Fatalf("web %+v", inv.Web)
	}
	if len(inv.Packages) != 4 || inv.Packages[1] != (target.Package{Name: "php8.2-fpm", Source: "php8.2", Version: "8.2.20-1+deb12u1", Arch: "amd64"}) {
		t.Fatalf("packages %+v", inv.Packages)
	}
	seen := map[string]target.FileSeen{}
	for _, fs := range inv.Files {
		seen[fs.Path] = fs
	}
	ini := seen["/etc/php/8.2/cli/php.ini"]
	if len(ini.SHA256) != 64 || ini.Size != len(fixtureText["php.ini"]) {
		t.Fatalf("file seen %+v", ini)
	}
	if _, ok := seen["/var/www/demo/.user.ini"]; ok {
		t.Fatal("a missing .user.ini is listed as read")
	}
	if len(inv.Unseen) != 0 {
		t.Fatalf("unseen %+v", inv.Unseen)
	}

	// The audit holds counts and the inventory hash only.
	var ev string
	if err := e.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'target.collect'`).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"packages":4`, `"files":`, `"directives":`, `"unseen":0`, `"inventory_sha256":"`} {
		if !strings.Contains(ev, want) {
			t.Fatalf("evidence %s lacks %s", ev, want)
		}
	}
	if strings.Contains(ev, "/etc/") || strings.Contains(ev, "nginx") {
		t.Fatalf("evidence leaks details: %s", ev)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestCollectSharedHostingNoPackages(t *testing.T) {
	h := debian(t)
	h.dpkg = ""
	h.owners = nil
	h.fpm = nil
	h.bins = map[string]string{"php": "/opt/php82/bin/php"}
	h.links = nil
	h.nginx = ""
	e := start(t, h)
	inv := run(t, e, nil)
	cli := runtimeOf(inv, "cli")
	if len(cli) != 1 || cli[0].FromPackage != "" || cli[0].Binary != "/opt/php82/bin/php" {
		t.Fatalf("cli %+v", inv.PHP)
	}
	if len(inv.Packages) != 0 || !hasUnseen(inv, "packages", "collect.unseen.packages") {
		t.Fatalf("packages %+v unseen %+v", inv.Packages, inv.Unseen)
	}
	if !hasUnseen(inv, "web", "collect.unseen.web") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, l := range e.srv.Log() {
		if strings.Contains(l, "'dpkg' '-S'") || strings.Contains(l, "'rpm' '-qf'") {
			t.Fatalf("owner asked with no package manager: %s", l)
		}
	}
}

func TestCLIAndFPMReportedSeparately(t *testing.T) {
	h := debian(t)
	h.cliV = strings.ReplaceAll(h.cliV, "8.2.20", "8.3.35")
	e := start(t, h)
	inv := run(t, e, nil)
	cli, fpm := runtimeOf(inv, "cli"), runtimeOf(inv, "fpm")
	if len(inv.PHP) != 2 || len(cli) != 1 || len(fpm) != 1 {
		t.Fatalf("runtimes %+v", inv.PHP)
	}
	if cli[0].Version != "8.3.35" || fpm[0].Version != "8.2.20" {
		t.Fatalf("cli %s fpm %s", cli[0].Version, fpm[0].Version)
	}
}

func TestOnlyCLISeenIsSaid(t *testing.T) {
	h := debian(t)
	h.fpm = nil
	delete(h.bins, "/usr/sbin/php-fpm8.2")
	e := start(t, h)
	inv := run(t, e, nil)
	if len(runtimeOf(inv, "fpm")) != 0 || len(runtimeOf(inv, "cli")) != 1 {
		t.Fatalf("runtimes %+v", inv.PHP)
	}
	if !hasUnseen(inv, "fpm", "collect.unseen.fpm") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
}

func TestUnreadableIniIsUnseen(t *testing.T) {
	h := debian(t)
	h.denied["/etc/php/8.2/fpm/php.ini"] = true
	e := start(t, h)
	inv := run(t, e, nil)
	if !hasUnseen(inv, "/etc/php/8.2/fpm/php.ini", "collect.unseen.unreadable") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, f := range inv.Files {
		if f.Path == "/etc/php/8.2/fpm/php.ini" {
			t.Fatal("an unreadable file is listed as read")
		}
	}
	n := 0
	for _, l := range e.srv.Log() {
		if strings.Contains(l, "sudo") {
			t.Fatalf("sudo used: %s", l)
		}
		if strings.Contains(l, "'head'") && strings.Contains(l, "/etc/php/8.2/fpm/php.ini") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the unreadable file was tried %d times", n)
	}
	// The effective values are still known from the runtime itself.
	if _, ok := directive(inv, "fpm", "memory_limit"); !ok {
		t.Fatal("fpm directives lost")
	}
}

func TestCollectedSecretsNeverStored(t *testing.T) {
	h := debian(t)
	e := start(t, h)
	inv := run(t, e, demoLinks)
	for _, name := range []string{"mysqli.default_pw"} {
		for _, sapi := range []string{"cli", "fpm"} {
			d, ok := directive(inv, sapi, name)
			if !ok || !d.Secret || d.Value != "" {
				t.Fatalf("%s %s: %+v", sapi, name, d)
			}
		}
	}
	d, ok := directive(inv, "fpm", "env[DATABASE_URL]")
	if !ok || !d.Secret || d.Value != "" {
		t.Fatalf("env: %+v", d)
	}
	d, ok = directive(inv, "fpm", "php_admin_value[mysqli.default_pw]")
	if !ok || !d.Secret || d.Value != "" {
		t.Fatalf("pool admin value: %+v", d)
	}
	if d, _ := directive(inv, "fpm", "memory_limit"); d.Secret {
		t.Fatal("memory_limit marked secret")
	}
	if d, _ := directive(inv, "cli", "opcache.enable"); d.Secret {
		t.Fatal("opcache.enable marked secret")
	}
	body, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := e.st.DB().Query(`SELECT evidence FROM audit_event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	all := string(body)
	for rows.Next() {
		var ev string
		rows.Scan(&ev)
		all += ev
	}
	for _, leak := range []string{"hunter2-demo", "u:p", "mysql://"} {
		if strings.Contains(all, leak) {
			t.Fatalf("%q stored", leak)
		}
	}
}

func TestHealthTargetRefusesNonConfigPath(t *testing.T) {
	tg := target.Target{ID: "01TARGETDEMO", Kind: target.KindHDS, Classification: policy.ClassHealth}
	for _, p := range []string{"/var/www/demo/storage/patients.csv", "/home/deploy/notes.txt", "/srv/data/export.json"} {
		if err := collect.CheckPath(tg, demoLinks, p); !errors.Is(err, collect.ErrHealthPath) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/var/www/demo/.htaccess", "/etc/php/8.2/fpm/conf.d/90-demo.ini"} {
		if err := collect.CheckPath(tg, demoLinks, p); err != nil {
			t.Fatalf("%s refused: %v", p, err)
		}
	}
	// Every server: configuration files only; never logs, data bases,
	// relative paths, folders, key or password files, other users' homes.
	vps := target.Target{Kind: target.KindVPS, Classification: policy.ClassInternal, User: "deploy"}
	otherLinks := []target.Link{{RemoteDir: "/home/client1/www"}}
	for _, p := range []string{"/var/log/nginx/access.log", "/var/www/demo/db.sqlite", "/var/lib/mysql/ibdata1", "etc/php.ini",
		"/etc/../root/x.ini", "/etc/php/", "/home/deploy/notes.txt", "/home/other/app.ini", "/root/app.ini", "/etc/shadow",
		"/etc/ssl/private/site.key", "/home/deploy/.ssh/id_ed25519", "/etc/ssl/certs/site.pem", "/home/client2/www/.user.ini"} {
		if err := collect.CheckPath(vps, otherLinks, p); !errors.Is(err, collect.ErrRefusedPath) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"/home/deploy/app.ini", "/home/client1/www/.user.ini", "/etc/nginx/sites-enabled/demo.conf"} {
		if err := collect.CheckPath(vps, otherLinks, p); err != nil {
			t.Fatalf("%s refused on a vps: %v", p, err)
		}
	}

	// Run does not read a refused extra path: it says so.
	h := debian(t)
	h.files["/var/www/demo/storage/patients.csv"] = "name,diagnosis\n"
	e := start(t, h)
	e.tgt.Kind, e.tgt.Classification = target.KindHDS, policy.ClassHealth
	e.deps.ExtraPaths = []string{"/var/www/demo/storage/patients.csv", "/etc/nginx/nginx.conf"}
	inv := run(t, e, demoLinks)
	if !hasUnseen(inv, "/var/www/demo/storage/patients.csv", "collect.unseen.refused") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, l := range e.srv.Log() {
		if strings.Contains(l, "patients.csv") {
			t.Fatalf("refused path read: %s", l)
		}
	}
}

// allowedShapes is the closed list, written independently of the code.
// envC is the locale prefix every command but command -v carries.
const envC = `'env' 'LC_ALL=C' 'LANG=C' `

var allowedShapes = []*regexp.Regexp{
	regexp.MustCompile(`^'command' '-v'( '(/usr/sbin/)?(php|php-fpm(8\.[1-5])?|nginx|apache2|httpd)')+$`),
	regexp.MustCompile(`^` + envC + `'cat' '/etc/os-release'$`),
	regexp.MustCompile(`^` + envC + `'uname' '-r'$`),
	regexp.MustCompile(`^` + envC + `'php' '(-v|-m|--ini)'$`),
	regexp.MustCompile(`^` + envC + `'php' '-r' '[^']+'$`),
	regexp.MustCompile(`^` + envC + `'/[a-z0-9/]+/php-fpm(8\.[1-5])?' '(-v|-i|-m|-tt)'$`),
	regexp.MustCompile(`^` + envC + `'(/usr/sbin/)?(nginx|apache2|httpd)' '-v'$`),
	regexp.MustCompile(`^` + envC + `'dpkg-query' '-W' '-f' '[^']+'$`),
	regexp.MustCompile(`^` + envC + `'rpm' '-qa' '--qf' '[^']+'$`),
	regexp.MustCompile(`^` + envC + `'apk' 'info' '-v'$`),
	regexp.MustCompile(`^` + envC + `'readlink' '-f' '/[^']+'$`),
	regexp.MustCompile(`^` + envC + `'dpkg' '-S' '/[^']+'$`),
	regexp.MustCompile(`^` + envC + `'rpm' '-qf' '--qf' '[^']+' '/[^']+'$`),
	regexp.MustCompile(`^` + envC + `'head' '-c' '262145' '/[^']+\.(ini|conf)'$`),
}

func TestCommandsAreClosedList(t *testing.T) {
	e := start(t, debian(t))
	run(t, e, demoLinks)
	log := e.srv.Log()
	if len(log) < 10 {
		t.Fatalf("only %d commands", len(log))
	}
	for _, l := range log {
		ok := false
		for _, re := range allowedShapes {
			if re.MatchString(l) {
				ok = true
				break
			}
		}
		if !ok || strings.Contains(l, "sudo") {
			t.Errorf("command outside the closed list: %s", l)
		}
	}
	for _, argv := range collect.Commands(e.tgt) {
		for _, a := range argv {
			if a == "sudo" {
				t.Fatalf("sudo in %v", argv)
			}
		}
		if !matchesAny(sshx.Quote(argv)) {
			t.Errorf("Commands entry outside the closed list: %v", argv)
		}
	}
}

func matchesAny(l string) bool {
	for _, re := range allowedShapes {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

func TestFileSizeCap(t *testing.T) {
	h := debian(t)
	h.files["/etc/php/8.2/fpm/php.ini"] = strings.Repeat("; padding line\n", 20000) // ~300 KiB
	e := start(t, h)
	inv := run(t, e, nil)
	if !hasUnseen(inv, "/etc/php/8.2/fpm/php.ini", "collect.unseen.too_big") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
	for _, f := range inv.Files {
		if f.Path == "/etc/php/8.2/fpm/php.ini" {
			t.Fatal("a too big file is listed as read")
		}
	}
	if collect.MaxFileSize != 256<<10 {
		t.Fatalf("MaxFileSize = %d", collect.MaxFileSize)
	}
}

func TestSiteHeadersReadThroughGateway(t *testing.T) {
	e := start(t, debian(t))
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "www.example.test", Purpose: policy.PurposeTargetHTTP}}
	gw := egress.New(p, nil)
	var asked string
	gw.SetTransportForTest(roundTrip(func(r *http.Request) (*http.Response, error) {
		asked = r.Method + " " + r.URL.String()
		h := http.Header{}
		h.Set("Server", "nginx/1.22.1")
		h.Set("X-Powered-By", "PHP/8.2.20")
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("<html></html>")), Request: r}, nil
	}))
	e.deps.Gateway = gw
	e.tgt.SiteURL = "https://www.example.test/"
	inv := run(t, e, nil)
	if asked != "GET https://www.example.test/" {
		t.Fatalf("asked %q", asked)
	}
	if inv.Site != (target.SiteHeaders{Server: "nginx/1.22.1", PoweredBy: "PHP/8.2.20"}) {
		t.Fatalf("site %+v", inv.Site)
	}

	// Refused by the policy: said, not fatal.
	e2 := start(t, debian(t))
	e2.tgt.SiteURL = "https://www.example.test/"
	inv = run(t, e2, nil)
	if !hasUnseen(inv, "site", "collect.unseen.site") {
		t.Fatalf("unseen %+v", inv.Unseen)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseOSRelease(t *testing.T) {
	cases := map[string]target.OSInfo{
		"os-release-debian12":   {ID: "debian", VersionID: "12", Pretty: "Debian GNU/Linux 12 (bookworm)"},
		"os-release-ubuntu2204": {ID: "ubuntu", VersionID: "22.04", Pretty: "Ubuntu 22.04.4 LTS"},
		"os-release-alpine":     {ID: "alpine", VersionID: "3.20.3", Pretty: "Alpine Linux v3.20"},
		"os-release-almalinux9": {ID: "almalinux", VersionID: "9.4", Pretty: "AlmaLinux 9.4 (Seafoam Ocelot)"},
	}
	for f, want := range cases {
		if got := collect.ParseOSRelease(fixture(t, f)); got != want {
			t.Errorf("%s: %+v", f, got)
		}
	}
}

func TestParsePackages(t *testing.T) {
	rpm := collect.ParseRPM(fixture(t, "rpm-qa"))
	if len(rpm) != 3 || rpm[0] != (target.Package{Name: "php-cli", Source: "php", Version: "8.2.20-1.el9", Arch: "x86_64"}) ||
		rpm[1].Version != "2.4.57-11.el9" || rpm[2].Version != "1:3.0.7-27.el9" || rpm[1].Source != "httpd" {
		t.Fatalf("rpm %+v", rpm)
	}
	apk := collect.ParseAPK(fixture(t, "apk-info"))
	if len(apk) != 4 || apk[2] != (target.Package{Name: "php82-fpm", Source: "php82-fpm", Version: "8.2.20-r0"}) {
		t.Fatalf("apk %+v", apk)
	}
	if w, ok := collect.ParseWeb("apache2", fixture(t, "apache2-v")); !ok || w != (target.WebServer{Name: "apache", Version: "2.4.57"}) {
		t.Fatalf("apache %+v", w)
	}
	// php -i of the command line reads like the FPM one.
	info := collect.ParsePHPInfo(fixture(t, "php-i"))
	if info.LoadedIni != "/etc/php/8.2/cli/php.ini" || len(info.ScannedFiles) != 2 || info.Directives["memory_limit"] != "256M" || info.Directives["open_basedir"] != "" {
		t.Fatalf("php -i %+v", info)
	}
	if _, ok := info.Directives["DATABASE_URL"]; ok {
		t.Fatal("an environment variable read as a directive")
	}
}

// slowRunner answers like r, except that the commands for which slow
// returns true run past their time limit.
type slowRunner struct {
	r    collect.Runner
	slow func(argv []string) bool
}

func (s slowRunner) Run(ctx context.Context, argv []string, stdin io.Reader) (sshx.Result, error) {
	if s.slow(argv) {
		return sshx.Result{}, fmt.Errorf("%w (1s): %w", sshx.ErrCommandTimeout, context.DeadlineExceeded)
	}
	return s.r.Run(ctx, argv, stdin)
}

func TestTimedOutFPMProbeIsUnseen(t *testing.T) {
	e := start(t, debian(t))
	r := slowRunner{r: e.client, slow: func(argv []string) bool {
		return argv[len(argv)-2] == "/usr/sbin/php-fpm8.2" && argv[len(argv)-1] == "-v"
	}}
	inv, err := collect.Run(context.Background(), e.deps, r, e.tgt, demoLinks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(runtimeOf(inv, "fpm")) != 0 || !hasUnseen(inv, "/usr/sbin/php-fpm8.2", collect.ReasonProbe) {
		t.Fatalf("a timed-out php-fpm -v must be said: %+v", inv.Unseen)
	}
}

func TestFailedDiscoveryIsUnseen(t *testing.T) {
	for name, slow := range map[string]bool{"timed out": true, "shell error": false} {
		h := debian(t)
		e := start(t, h)
		var r collect.Runner = e.client
		if slow {
			r = slowRunner{r: e.client, slow: func(argv []string) bool { return argv[0] == "command" }}
		} else {
			cmds := h.commands()
			cmds["command"] = func(e sshtest.Exec) int { io.WriteString(e.Stderr, "sh: broken\n"); return 2 }
			srv := sshtest.New(t, sshtest.Options{Commands: cmds})
			e = restart(t, e, srv)
			r = e.client
		}
		inv, err := collect.Run(context.Background(), e.deps, r, e.tgt, demoLinks)
		if err != nil {
			t.Fatalf("%s: Run: %v", name, err)
		}
		if len(inv.PHP) != 0 || !hasUnseen(inv, "discovery", collect.ReasonProbe) {
			t.Fatalf("%s: unseen %+v", name, inv.Unseen)
		}
	}
	// Nothing found is not a failure.
	h := debian(t)
	h.bins = map[string]string{}
	inv := run(t, start(t, h), demoLinks)
	if hasUnseen(inv, "discovery", collect.ReasonProbe) {
		t.Fatalf("no PHP installed is not a failed lookup: %+v", inv.Unseen)
	}
}

// restart dials srv instead of e's server, with e's settings.
func restart(t *testing.T, e *env, srv *sshtest.Server) *env {
	t.Helper()
	ag := srv.NewAgent(t)
	hostname, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(port)
	tg := e.tgt
	tg.Host, tg.Port, tg.HostKey = hostname, pn, srv.HostKeyFingerprint()
	p := policy.Defaults()
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: policy.PurposeTargetSSH}}
	c, err := sshx.Dial(context.Background(), sshx.Deps{Gateway: egress.New(p, nil), KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		Agent: func() (agent.ExtendedAgent, io.Closer, error) { return ag, nil, nil }, Now: time.Now}, tg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &env{srv: srv, client: c, tgt: tg, st: e.st, deps: e.deps}
}

func TestDashCommandV127IsNotAFailure(t *testing.T) {
	// dash and busybox ash answer 127 as soon as one name is missing.
	h := debian(t)
	cmds := h.commands()
	inner := cmds["command"]
	cmds["command"] = func(e sshtest.Exec) int {
		inner(e)
		return 127
	}
	e := restart(t, start(t, h), sshtest.New(t, sshtest.Options{Commands: cmds}))
	inv, err := collect.Run(context.Background(), e.deps, e.client, e.tgt, demoLinks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasUnseen(inv, "discovery", collect.ReasonProbe) || len(runtimeOf(inv, "cli")) != 1 || len(runtimeOf(inv, "fpm")) != 1 {
		t.Fatalf("exit 127 with names found is a normal answer: unseen %+v, php %+v", inv.Unseen, inv.PHP)
	}
}
