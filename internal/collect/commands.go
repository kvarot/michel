package collect

import (
	"path"
	"regexp"
	"strconv"

	"github.com/kvarot/michel/internal/target"
)

// The closed list of commands. Every command Michel runs on a server during
// a collection is one of these, built here: there is no other way to build
// one, and runner.run refuses any argv that allowed does not accept. None
// writes anything, none uses sudo.

// iniScript is the fixed PHP code given to `php -r`: it prints the effective
// value of every directive as JSON. It is a constant; nothing is ever added
// to it.
const iniScript = `echo json_encode(ini_get_all(null, false));`

const (
	dpkgFormat = `${Package}\t${source:Package}\t${Version}\t${Architecture}\n`
	rpmFormat  = `%{NAME}\t%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n`
	rpmName    = `%{NAME}\n`
)

// fpmNames are the PHP-FPM binary names Michel looks for.
var fpmNames = []string{"php-fpm", "php-fpm8.1", "php-fpm8.2", "php-fpm8.3", "php-fpm8.4", "php-fpm8.5"}

// webNames are the web server binaries Michel looks for.
var webNames = []string{"nginx", "apache2", "httpd"}

// sbin is where Debian and Red Hat put FPM and the web servers; it is often
// not in the PATH of an SSH user who is not root.
const sbin = "/usr/sbin/"

var (
	cmdOSRelease = []string{"cat", "/etc/os-release"}
	cmdKernel    = []string{"uname", "-r"}
	cmdPHPV      = []string{"php", "-v"}
	cmdPHPM      = []string{"php", "-m"}
	cmdPHPIni    = []string{"php", "--ini"}
	cmdPHPR      = []string{"php", "-r", iniScript}
	cmdDpkg      = []string{"dpkg-query", "-W", "-f", dpkgFormat}
	cmdRPM       = []string{"rpm", "-qa", "--qf", rpmFormat}
	cmdAPK       = []string{"apk", "info", "-v"}
)

// cmdFind is `command -v` on the PHP names (as the plan lists them).
func cmdFind() []string {
	return append([]string{"command", "-v", "php"}, fpmNames...)
}

// cmdFindSbin is `command -v` on the web servers and on the FPM and web
// binaries of /usr/sbin.
func cmdFindSbin() []string {
	argv := append([]string{"command", "-v"}, webNames...)
	for _, n := range fpmNames {
		argv = append(argv, sbin+n)
	}
	for _, n := range webNames {
		argv = append(argv, sbin+n)
	}
	return argv
}

// Commands returns the fixed part of the closed list for t, in the order a
// collection runs them, as they are sent (with the env LC_ALL=C prefix). The rest is built from what these print, through
// the same closed shapes: `<fpm> -v|-m|-i|-tt` for each FPM binary found,
// `<web> -v` for each web server found, `readlink -f`, `dpkg -S` or
// `rpm -qf` on a PHP binary, and `head -c 262145 <file>` for each allowed
// file (CheckPath). No entry depends on t today; the parameter keeps the
// door open for a per-kind list without changing callers.
func Commands(t target.Target) [][]string {
	_ = t
	var out [][]string
	for _, argv := range fixedCommands() {
		out = append(out, withLocale(argv))
	}
	return out
}

func fixedCommands() [][]string {
	return [][]string{
		cmdOSRelease, cmdKernel, cmdFind(), cmdFindSbin(),
		cmdDpkg, cmdRPM, cmdAPK,
		cmdPHPV, cmdPHPM, cmdPHPIni, cmdPHPR,
		{"nginx", "-v"}, {"apache2", "-v"}, {"httpd", "-v"},
	}
}

// localeC is put before every command but `command -v` (a shell builtin
// that env cannot run, whose output is paths only): error texts are then
// the English ones Michel reads, whatever the server's language. It works
// without AcceptEnv in sshd.
var localeC = []string{"env", "LC_ALL=C", "LANG=C"}

// withLocale returns argv as it is sent to the server.
func withLocale(argv []string) []string {
	if len(argv) > 0 && argv[0] == "command" {
		return argv
	}
	return append(append([]string(nil), localeC...), argv...)
}

func cmdRead(p string) []string { return []string{"head", "-c", strconv.Itoa(MaxFileSize + 1), p} }

// binaryRe is an absolute path made of plain characters only.
var binaryRe = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)

func isFPMBinary(p string) bool {
	return binaryRe.MatchString(p) && in(path.Base(p), fpmNames) && path.Clean(p) == p
}

func isWebBinary(p string) bool {
	if in(p, webNames) {
		return true
	}
	return binaryRe.MatchString(p) && in(path.Base(p), webNames) && path.Clean(p) == p
}

func isPHPBinary(p string) bool {
	return binaryRe.MatchString(p) && path.Clean(p) == p
}

// allowed reports whether argv (before withLocale) is one of the closed
// shapes.
func allowed(argv []string) bool {
	for _, fixed := range fixedCommands() {
		if equal(argv, fixed) {
			return true
		}
	}
	switch {
	case len(argv) == 2 && isFPMBinary(argv[0]):
		return in(argv[1], []string{"-v", "-m", "-i", "-tt"})
	case len(argv) == 2 && isWebBinary(argv[0]):
		return argv[1] == "-v"
	case len(argv) == 3 && argv[0] == "readlink" && argv[1] == "-f":
		return isPHPBinary(argv[2])
	case len(argv) == 3 && argv[0] == "dpkg" && argv[1] == "-S":
		return isPHPBinary(argv[2])
	case len(argv) == 5 && argv[0] == "rpm" && argv[1] == "-qf" && argv[2] == "--qf" && argv[3] == rpmName:
		return isPHPBinary(argv[4])
	case len(argv) == 4 && argv[0] == "head" && argv[1] == "-c" && argv[2] == strconv.Itoa(MaxFileSize+1):
		return baseRefusal(argv[3]) == ""
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func in(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
