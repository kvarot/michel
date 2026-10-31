package collect

import (
	"path"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// Parsers of the outputs of the closed list. Remote output is untrusted:
// every kept string goes through text (control characters removed, secrets
// masked) or cleanPath.

func lines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// text is free text from the server as it is stored: no control character,
// and masked if a detector of internal/mask sees a secret in it. Paths are
// left as they are (they are server paths, kept on purpose).
func text(s string) string {
	s = strings.TrimSpace(scan.SanitizeText(s))
	m := mask.New()
	if out := m.Mask(s); m.Len() > 0 {
		return out
	}
	return s
}

// cleanPath is a server path as it is stored, or "" if it is not a clean
// absolute path.
func cleanPath(p string) string {
	p = strings.TrimSpace(scan.SanitizeText(p))
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, "\n\t") {
		return ""
	}
	return p
}

// ParseOSRelease reads /etc/os-release.
func ParseOSRelease(s string) target.OSInfo {
	var o target.OSInfo
	for _, l := range lines(s) {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			o.ID = text(v)
		case "VERSION_ID":
			o.VersionID = text(v)
		case "PRETTY_NAME":
			o.Pretty = text(v)
		}
	}
	return o
}

func splitTabs(l string, n int) ([]string, bool) {
	f := strings.Split(strings.TrimRight(l, "\r"), "\t")
	if len(f) != n || f[0] == "" {
		return nil, false
	}
	return f, true
}

// parseDpkg reads the dpkg-query output of cmdDpkg.
func parseDpkg(s string) []target.Package {
	var out []target.Package
	for _, l := range lines(s) {
		f, ok := splitTabs(l, 4)
		if !ok {
			continue
		}
		p := target.Package{Name: text(f[0]), Source: text(f[1]), Version: text(f[2]), Arch: text(f[3])}
		if p.Source == "" {
			p.Source = p.Name
		}
		out = append(out, p)
	}
	return out
}

// ParseRPM reads the rpm -qa output of cmdRPM. The source package name is
// taken from the source RPM file name; an epoch of 0 or none is dropped.
func ParseRPM(s string) []target.Package {
	var out []target.Package
	for _, l := range lines(s) {
		f, ok := splitTabs(l, 4)
		if !ok {
			continue
		}
		src := strings.TrimSuffix(f[1], ".src.rpm")
		for i := 0; i < 2; i++ {
			if j := strings.LastIndexByte(src, '-'); j > 0 {
				src = src[:j]
			}
		}
		if src == "" || src == "(none)" {
			src = f[0]
		}
		v := f[2]
		v = strings.TrimPrefix(v, "(none):")
		v = strings.TrimPrefix(v, "0:")
		out = append(out, target.Package{Name: text(f[0]), Source: text(src), Version: text(v), Arch: text(f[3])})
	}
	return out
}

var apkRe = regexp.MustCompile(`^(.+)-([0-9][^-]*-r[0-9]+)$`)

// ParseAPK reads apk info -v ("name-version-rN" per line). apk gives no
// source package nor architecture here: Source is the name.
func ParseAPK(s string) []target.Package {
	var out []target.Package
	for _, l := range lines(s) {
		m := apkRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		out = append(out, target.Package{Name: text(m[1]), Source: text(m[1]), Version: text(m[2])})
	}
	return out
}

var (
	nginxRe  = regexp.MustCompile(`nginx/([0-9][0-9A-Za-z.\-]*)`)
	apacheRe = regexp.MustCompile(`Apache/([0-9][0-9A-Za-z.\-]*)`)
)

// ParseWeb reads `<web> -v` of the binary named name.
func ParseWeb(name, out string) (target.WebServer, bool) {
	switch path.Base(name) {
	case "nginx":
		if m := nginxRe.FindStringSubmatch(out); m != nil {
			return target.WebServer{Name: "nginx", Version: text(m[1])}, true
		}
	case "apache2", "httpd":
		if m := apacheRe.FindStringSubmatch(out); m != nil {
			return target.WebServer{Name: "apache", Version: text(m[1])}, true
		}
	}
	return target.WebServer{}, false
}

var phpVersionRe = regexp.MustCompile(`(?m)^PHP ([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)`)

// parsePHPVersion reads `php -v`.
func parsePHPVersion(s string) string {
	if m := phpVersionRe.FindStringSubmatch(s); m != nil {
		return text(m[1])
	}
	return ""
}

// parseModules reads `php -m`: the names, once each, in order.
func parseModules(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lines(s) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "[") {
			continue
		}
		if l = text(l); !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// parseFound reads `command -v`: one absolute path per line.
func parseFound(s string) []string {
	var out []string
	for _, l := range lines(s) {
		if p := cleanPath(l); p != "" && isPHPBinary(p) {
			out = append(out, p)
		}
	}
	return out
}

// iniFiles are the configuration files PHP reports.
type iniFiles struct {
	LoadedIni    string
	ScannedDir   string
	ScannedFiles []string
}

// fileList splits "a,\nb,\nc" (php --ini and php -i continue the list on
// the next lines).
func fileList(first string, rest []string) []string {
	all := first
	for _, r := range rest {
		all += r
	}
	var out []string
	for _, f := range strings.Split(all, ",") {
		if p := cleanPath(f); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func noneToEmpty(v string) string {
	v = strings.TrimSpace(v)
	if v == "(none)" || v == "no value" {
		return ""
	}
	return cleanPath(v)
}

// parseIniFiles reads `php --ini`.
func parseIniFiles(s string) iniFiles {
	var f iniFiles
	ls := lines(s)
	for i, l := range ls {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Loaded Configuration File":
			f.LoadedIni = noneToEmpty(v)
		case "Scan for additional .ini files in":
			f.ScannedDir = noneToEmpty(v)
		case "Additional .ini files parsed":
			if strings.TrimSpace(v) != "(none)" {
				f.ScannedFiles = fileList(v, continuation(ls[i+1:]))
			}
		}
	}
	return f
}

// continuation returns the lines that continue a file list: they start
// with "/" and do not hold a key.
func continuation(ls []string) []string {
	var out []string
	for _, l := range ls {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "/") || strings.Contains(t, "=>") {
			break
		}
		out = append(out, t)
	}
	return out
}

// PHPInfo is what Michel keeps of `php -i` (or `<fpm> -i`).
type PHPInfo struct {
	iniFiles
	// Directives are the local values, by name; "no value" is "".
	Directives map[string]string
}

var directiveNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]*$`)

// ParsePHPInfo reads the text output of phpinfo(): the configuration file
// lines of its header and the "name => local => master" lines of the
// directive tables. A directive line is taken only after a
// "Directive => Local Value => Master Value" header and up to the next
// blank line; nothing is read after the Environment or PHP Variables
// headers (their values are the server's, and may hold " => ").
func ParsePHPInfo(s string) PHPInfo {
	info := PHPInfo{Directives: map[string]string{}}
	ls := lines(s)
	inTable := false
	for i, l := range ls {
		t := strings.TrimSpace(l)
		switch t {
		case "Environment", "PHP Variables":
			return info
		case "Directive => Local Value => Master Value":
			inTable = true
			continue
		case "":
			inTable = false
			continue
		}
		parts := strings.Split(l, " => ")
		switch {
		case inTable:
			if len(parts) != 3 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			if !directiveNameRe.MatchString(name) {
				continue
			}
			v := strings.TrimSpace(parts[1])
			if v == "no value" {
				v = ""
			}
			info.Directives[name] = v
		case len(parts) == 2:
			k, v := strings.TrimSpace(parts[0]), parts[1]
			switch k {
			case "Loaded Configuration File":
				info.LoadedIni = noneToEmpty(v)
			case "Scan this dir for additional .ini files":
				info.ScannedDir = noneToEmpty(v)
			case "Additional .ini files parsed":
				if strings.TrimSpace(v) != "(none)" {
					info.ScannedFiles = fileList(v, continuation(ls[i+1:]))
				}
			}
		}
	}
	return info
}

var (
	poolRe    = regexp.MustCompile(`NOTICE:\s*\[([A-Za-z0-9_.\-]+)\]\s*$`)
	fpmConfRe = regexp.MustCompile(`configuration file (/\S+) test is successful`)
)

// parseFPMTest reads `<fpm> -tt` (on stderr): the pool names and the main
// configuration file. Values are not kept: pools are read from their files.
func parseFPMTest(s string) (pools []string, conf string) {
	for _, l := range lines(s) {
		if m := poolRe.FindStringSubmatch(l); m != nil && m[1] != "global" {
			pools = append(pools, m[1])
		}
		if m := fpmConfRe.FindStringSubmatch(l); m != nil {
			conf = cleanPath(m[1])
		}
	}
	return pools, conf
}

// poolDir guesses the pool folder from the FPM main file, or else from the
// php.ini FPM loads: /etc/php/8.2/fpm/pool.d/ (Debian), /etc/php-fpm.d/
// (Red Hat), /etc/php82/php-fpm.d/ (Alpine).
func poolDir(fpmConf, loadedIni string) string {
	dir := ""
	switch {
	case fpmConf != "":
		dir = path.Dir(fpmConf)
	case loadedIni != "":
		dir = path.Dir(loadedIni)
	default:
		return ""
	}
	switch {
	case path.Base(dir) == "fpm":
		return dir + "/pool.d/"
	case dir == "/etc":
		return "/etc/php-fpm.d/"
	default:
		return dir + "/php-fpm.d/"
	}
}

// harmlessNames are directive names whose words look secret but whose
// value never is.
var harmlessNames = map[string]bool{
	"xdebug.idekey":                    true,
	"mysqlnd.sha256_server_public_key": true,
	"highlight.keyword":                true,
}

var (
	poolWrapperRe = regexp.MustCompile(`^php_(?:admin_)?(?:value|flag)\[(.*)\]$`)
	segmentSep    = regexp.MustCompile(`[._\-\[\]]+`)
	// secretParam is a credential passed as a parameter inside a value
	// (session.save_path = "tcp://redis:6379?auth=..."); its value is
	// replaced by maskedPart before anything else.
	// The name may carry a [] (phpredis ACL: auth[]=user&auth[]=pass), raw
	// or URL-encoded; every value of a repeated parameter is masked.
	secretParam = regexp.MustCompile(`(?i)([?&;,\s](?:auth|password|passwd|pass|pwd|secret|token|key)(?:\[[^\]=&;,\s]*\]|%5B[^=&;,\s]*?%5D)?=)([^&;,\s"']*)`)
)

// maskedPart stands for a credential removed from inside a value.
const maskedPart = "[masked]"

// secretSegment reports whether one word of a directive name says it holds
// a secret: it contains password, passwd, secret, credential, token,
// license, dsn or key (keys, keyfile, privkey_path...), starts with auth,
// or is pw, pwd, pass or passphrase. Short words are compared whole, so
// pcre.jit or session.use_only_cookies are not caught; the few harmless
// names holding "key" are listed in harmlessNames.
func secretSegment(w string) bool {
	for _, sub := range []string{"password", "passwd", "secret", "credential", "token", "license", "dsn", "key"} {
		if strings.Contains(w, sub) {
			return true
		}
	}
	switch w {
	case "pw", "pwd", "pass", "passphrase":
		return true
	}
	return strings.HasPrefix(w, "auth")
}

// SecretName is secretName, for tests and for callers that show a name.
func SecretName(name string) bool { return secretName(name) }

// secretName reports whether a directive name says it holds a secret: one
// of its words (secretSegment), or an env[...] of a FPM pool. The check runs
// for every name; only harmlessNames are exempt.
func secretName(name string) bool {
	inner := name
	if m := poolWrapperRe.FindStringSubmatch(name); m != nil {
		inner = m[1]
	}
	lower := strings.ToLower(inner)
	if strings.HasPrefix(lower, "env[") {
		return true
	}
	if harmlessNames[lower] {
		return false
	}
	for _, w := range segmentSep.Split(lower, -1) {
		if w != "" && secretSegment(w) {
			return true
		}
	}
	return false
}

// maskParams replaces the credentials passed as parameters inside v.
func maskParams(v string) string {
	return secretParam.ReplaceAllString(" "+v, "${1}"+maskedPart)[1:]
}

// isSecret reports whether a directive holds a secret: its name says so
// (secretName), or a detector of internal/mask still sees a secret in its
// value once maskParams ran (DSN with a password, private key...).
func isSecret(name, value string) bool {
	if secretName(name) {
		return true
	}
	m := mask.New()
	m.Mask(maskParams(value))
	return m.Len() > 0
}

// directive builds a stored directive: a secret value is never kept, and
// a credential inside a value is replaced by maskedPart.
func directive(sapi, binary, name, value, file string, line int) target.Directive {
	name = scan.SanitizeText(name)
	d := target.Directive{SAPI: sapi, Binary: binary, Name: name, File: file, Line: line}
	if isSecret(name, value) {
		d.Secret = true
		return d
	}
	d.Value = text(maskParams(value))
	return d
}
