package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/kvarot/michel/internal/sshx/sshtest"
)

// The simulated server: Debian 12 with PHP 8.3.35 built from source in
// /usr/local (command line and PHP-FPM, one php.ini), nginx from the Debian
// packages, and expose_php = On. What PHP prints is read from the php.ini of
// the in-memory file system, so a fix the scripts write shows in the next
// check of Michel.
const (
	phpVersion = "8.3.35"
	phpCLI     = "/usr/local/bin/php"
	phpFPM     = "/usr/local/sbin/php-fpm"
	phpIni     = "/usr/local/etc/php/php.ini"
	fpmConf    = "/usr/local/etc/php-fpm.conf"
	poolFile   = "/usr/local/etc/php-fpm.d/www.conf"
	nginxBin   = "/usr/sbin/nginx"
	sshUser    = "deploy"
	userHome   = "/home/deploy"
)

const osRelease = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`

const startIni = `[PHP]
; demo php.ini (PHP built from source)
engine = On
expose_php = On
display_errors = Off
allow_url_include = Off
memory_limit = 128M
session.upload_progress.enabled = On
`

const pool = `[www]
user = www-data
group = www-data
listen = 127.0.0.1:9000
`

// The packages dpkg knows: PHP is not one of them (built from source).
const dpkgOut = "nginx\tnginx\t1.22.1-9+deb12u1\tamd64\n" +
	"openssl\topenssl\t3.0.15-1~deb12u1\tamd64\n" +
	"libc6\tglibc\t2.36-9+deb12u9\tamd64\n"

// shown are the directives the simulated PHP prints, in that order.
var shown = []string{"allow_url_fopen", "allow_url_include", "display_errors", "expose_php", "memory_limit",
	"open_basedir", "session.upload_progress.enabled"}

// defaults are PHP's values when the php.ini does not set a directive.
var defaults = map[string]string{"allow_url_fopen": "1", "allow_url_include": "0", "display_errors": "1", "expose_php": "1",
	"memory_limit": "128M", "open_basedir": "", "session.upload_progress.enabled": "1"}

// boolean directives print On/Off in phpinfo and "1"/"" in ini_get_all.
var boolean = map[string]bool{"allow_url_fopen": true, "allow_url_include": true, "display_errors": true, "expose_php": true,
	"session.upload_progress.enabled": true}

// host is the state of the demo server shared by its command handlers.
type host struct {
	srv *sshtest.Server
	log io.Writer

	mu      sync.Mutex
	reloads int
}

func files() map[string]string {
	return map[string]string{
		"/etc/os-release":         osRelease,
		phpIni:                    startIni,
		fpmConf:                   "[global]\ninclude=/usr/local/etc/php-fpm.d/*.conf\n",
		poolFile:                  pool,
		phpCLI:                    "ELF",
		phpFPM:                    "ELF",
		nginxBin:                  "ELF",
		"/var/lib/dpkg/status":    "",
		"/var/www/demo/index.php": "<?php echo 'demo';\n",
	}
}

// ini reads the effective values of the php.ini as it is now: the last line
// of a directive wins, PHP's default otherwise.
func (h *host) ini() map[string]string {
	text, _ := h.srv.File(phpIni)
	out := map[string]string{}
	for k, v := range defaults {
		out[k] = v
	}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		if boolean[k] {
			switch strings.ToLower(v) {
			case "on", "1", "yes", "true":
				v = "1"
			default:
				v = ""
			}
		}
		out[k] = v
	}
	return out
}

// ExposePHP tells whether the site sends its PHP version (expose_php).
func (h *host) ExposePHP() bool { return h.ini()["expose_php"] == "1" }

func onOff(name, v string) string {
	if boolean[name] {
		if v == "1" {
			return "On"
		}
		return "Off"
	}
	if v == "" {
		return "no value"
	}
	return v
}

func (h *host) phpInfo() string {
	vals := h.ini()
	var b strings.Builder
	fmt.Fprintf(&b, "phpinfo()\nPHP Version => %s\n\nSystem => Linux srv-demo 6.1.0-28-amd64 #1 SMP x86_64\nServer API => FPM/FastCGI\n", phpVersion)
	b.WriteString("Configuration File (php.ini) Path => /usr/local/etc/php\nLoaded Configuration File => " + phpIni + "\n")
	b.WriteString("Scan this dir for additional .ini files => (none)\nAdditional .ini files parsed => (none)\n\nCore\n\n")
	fmt.Fprintf(&b, "PHP Version => %s\n\nDirective => Local Value => Master Value\n", phpVersion)
	for _, n := range shown {
		v := onOff(n, vals[n])
		fmt.Fprintf(&b, "%s => %s => %s\n", n, v, v)
	}
	b.WriteString("\nEnvironment\n\nVariable => Value\n")
	return b.String()
}

func (h *host) iniJSON() string {
	vals := h.ini()
	keys := append([]string(nil), shown...)
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q:%q", k, vals[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func notFound(e sshtest.Exec) int {
	fmt.Fprintf(e.Stderr, "sh: %s: not found\n", e.Args[0])
	return 127
}

func (h *host) cat(e sshtest.Exec, p string) int {
	v, ok := h.srv.File(p)
	if !ok {
		fmt.Fprintf(e.Stderr, "cat: %s: No such file or directory\n", p)
		return 1
	}
	io.WriteString(e.Stdout, v)
	return 0
}

// commands are the programs of the simulated server. The scripts of a fix
// run in the sshtest shell, which calls these for what it does not know
// itself (php-fpm -t, systemctl reload).
func (h *host) commands() map[string]sshtest.Handler {
	out := map[string]sshtest.Handler{}
	out["cat"] = func(e sshtest.Exec) int {
		if len(e.Args) != 2 {
			return 2
		}
		p := e.Args[1]
		if strings.HasPrefix(p, "/var/lib/michel") {
			// Michel's root backups: not readable by the SSH user.
			io.WriteString(e.Stderr, "cat: permission denied\n")
			return 1
		}
		if !strings.HasPrefix(p, "/") {
			p = userHome + "/" + p
		}
		return h.cat(e, p)
	}
	out["sudo"] = func(e sshtest.Exec) int {
		if len(e.Args) == 4 && e.Args[1] == "-n" && e.Args[2] == "cat" {
			return h.cat(e, e.Args[3])
		}
		io.WriteString(e.Stderr, "sudo: this demo only runs sudo -n cat and sudo -n sh -s\n")
		return 1
	}
	out["uname"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, "6.1.0-28-amd64\n"); return 0 }
	// ss -tln: 22 and 80 are open, 9000 and 5432 stay on the server.
	out["ss"] = func(e sshtest.Exec) int {
		io.WriteString(e.Stdout, "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"+
			"LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n"+
			"LISTEN 0      511          0.0.0.0:80        0.0.0.0:*\n"+
			"LISTEN 0      128        127.0.0.1:9000      0.0.0.0:*\n"+
			"LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*\n"+
			"LISTEN 0      128             [::]:22           [::]:*\n")
		return 0
	}
	out["command"] = func(e sshtest.Exec) int {
		code := 0
		for _, a := range e.Args[2:] {
			switch a {
			case "sh":
				io.WriteString(e.Stdout, "/bin/sh\n")
			case "php":
				io.WriteString(e.Stdout, phpCLI+"\n")
			case "php-fpm":
				io.WriteString(e.Stdout, phpFPM+"\n")
			case "nginx", nginxBin:
				io.WriteString(e.Stdout, nginxBin+"\n")
			default:
				code = 1
			}
		}
		return code
	}
	out["readlink"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, e.Args[len(e.Args)-1]+"\n"); return 0 }
	out["head"] = func(e sshtest.Exec) int {
		if len(e.Args) != 4 || e.Args[1] != "-c" {
			return 2
		}
		p := e.Args[3]
		v, ok := h.srv.File(p)
		if !ok {
			fmt.Fprintf(e.Stderr, "head: cannot open '%s' for reading: No such file or directory\n", p)
			return 1
		}
		io.WriteString(e.Stdout, v)
		return 0
	}
	php := func(e sshtest.Exec) int {
		if len(e.Args) < 2 {
			return 1
		}
		switch e.Args[1] {
		case "-v":
			fmt.Fprintf(e.Stdout, "PHP %s (cli) (built: Oct  1 2026 10:00:00) (NTS)\nCopyright (c) The PHP Group\n", phpVersion)
		case "-m":
			io.WriteString(e.Stdout, "[PHP Modules]\nCore\ndate\njson\nopenssl\nsession\n")
		case "--ini":
			io.WriteString(e.Stdout, "Configuration File (php.ini) Path: /usr/local/etc/php\nLoaded Configuration File:         "+phpIni+
				"\nScan for additional .ini files in: (none)\nAdditional .ini files parsed:      (none)\n")
		case "-r":
			io.WriteString(e.Stdout, h.iniJSON())
		case "-n":
			// php -n -c <file> -r '': the file reads well.
			return 0
		default:
			return 1
		}
		return 0
	}
	out["php"] = php
	out[phpCLI] = php
	out[phpFPM] = func(e sshtest.Exec) int {
		if len(e.Args) < 2 {
			return 1
		}
		switch e.Args[1] {
		case "-v":
			fmt.Fprintf(e.Stdout, "PHP %s (fpm-fcgi) (built: Oct  1 2026 10:00:00)\nCopyright (c) The PHP Group\n", phpVersion)
		case "-m":
			io.WriteString(e.Stdout, "[PHP Modules]\nCore\ndate\njson\nopenssl\nsession\n")
		case "-i":
			io.WriteString(e.Stdout, h.phpInfo())
		case "-tt":
			io.WriteString(e.Stderr, "[31-Oct-2026 10:00:00] NOTICE: [global]\n[31-Oct-2026 10:00:00] NOTICE: [www]\n"+
				"[31-Oct-2026 10:00:00] NOTICE: configuration file "+fpmConf+" test is successful\n")
		case "-t":
			io.WriteString(e.Stderr, "[31-Oct-2026 10:00:00] NOTICE: configuration file "+fpmConf+" test is successful\n")
		default:
			return 1
		}
		return 0
	}
	out["systemctl"] = func(e sshtest.Exec) int {
		h.mu.Lock()
		h.reloads++
		h.mu.Unlock()
		fmt.Fprintf(h.log, "demo: %s\n", strings.Join(e.Args, " "))
		return 0
	}
	out["dpkg-query"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, dpkgOut); return 0 }
	out["dpkg"] = func(e sshtest.Exec) int {
		fmt.Fprintf(e.Stderr, "dpkg-query: no path found matching pattern %s\n", e.Args[len(e.Args)-1])
		return 1
	}
	nginx := func(e sshtest.Exec) int { io.WriteString(e.Stderr, "nginx version: nginx/1.22.1\n"); return 0 }
	out["nginx"] = nginx
	out[nginxBin] = nginx
	for _, name := range []string{"rpm", "apk", "apache2", "httpd"} {
		out[name] = notFound
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
