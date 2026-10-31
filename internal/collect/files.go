package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// MaxFileSize caps a configuration file Michel reads: a larger file is not
// kept (Unseen too_big), and at most one byte more than this is transferred.
const MaxFileSize = 256 << 10

var (
	// ErrRefusedPath means a path is never read on any server: not an
	// absolute clean file path, or a log, a data base or a system folder.
	ErrRefusedPath = errors.New("Michel never reads this path on a server: only configuration files, never logs, data bases or folders")
	// ErrHealthPath means a server holding health data refuses a path that
	// is not a configuration file.
	ErrHealthPath = errors.New("on a server holding health data, Michel reads configuration files only")
)

// refusedDirs are never read, whatever the file.
var refusedDirs = []string{
	"/proc/", "/sys/", "/dev/", "/run/", "/var/log/", "/var/backups/",
	"/var/lib/mysql/", "/var/lib/postgresql/", "/var/lib/pgsql/", "/var/lib/mongodb/", "/var/lib/redis/",
}

// refusedName matches logs, data bases, dumps and archives.
var refusedName = regexp.MustCompile(`(?i)(\.log(\.[0-9]+)?|\.sqlite3?|\.db|\.sql|\.ibd|\.frm|\.dump|\.gz|\.bz2|\.xz|\.zip|\.tar)$`)

// configName matches what Michel recognizes as a configuration file.
var configName = regexp.MustCompile(`(?i)(\.ini|\.conf|\.cnf|^\.htaccess|^\.user\.ini)$`)

// baseRefusal returns why p is refused on every server, or "".
func baseRefusal(p string) string {
	switch {
	case !strings.HasPrefix(p, "/"):
		return "not absolute"
	case strings.HasSuffix(p, "/"):
		return "folder"
	case path.Clean(p) != p:
		return "not clean"
	case strings.ContainsAny(p, "\x00\n\r\t*?[]{}$`\\\"'"):
		return "odd characters"
	case refusedName.MatchString(p):
		return "log or data base"
	}
	for _, d := range refusedDirs {
		if strings.HasPrefix(p, d) {
			return "system or data folder"
		}
	}
	return ""
}

// isConfig reports whether p looks like a configuration file.
func isConfig(p string) bool { return configName.MatchString(path.Base(p)) }

// isHealth reports whether t holds health data.
func isHealth(t target.Target) bool {
	return t.Kind == target.KindHDS || t.Classification == policy.ClassHealth
}

// CheckPath says whether Michel may read p on t as a path the user added:
// ErrRefusedPath for a path no server allows, ErrHealthPath for a path that
// is not a configuration file on a server holding health data. The links
// are the deployment folders of the projects on t; they are not a reason
// to allow a non-configuration file on a health server.
func CheckPath(t target.Target, links []target.Link, p string) error {
	_ = links
	if baseRefusal(p) != "" {
		return ErrRefusedPath
	}
	if isHealth(t) && !isConfig(p) {
		return ErrHealthPath
	}
	return nil
}

// iniLine is one "name = value" line of a configuration file.
type iniLine struct {
	name, value string
	line        int
}

var iniRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*=\s*(.*?)\s*$`)

// parseIni returns the "name = value" lines of an ini file (php.ini,
// .user.ini, FPM pool), skipping comments and sections. Quotes around a
// value are removed.
func parseIni(content string) []iniLine {
	var out []iniLine
	for i, l := range strings.Split(content, "\n") {
		l = strings.TrimRight(l, "\r")
		t := strings.TrimSpace(l)
		if t == "" || t[0] == ';' || t[0] == '#' || t[0] == '[' {
			continue
		}
		m := iniRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v := m[2]
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out = append(out, iniLine{name: m[1], value: v, line: i + 1})
	}
	return out
}

// readFile is a file read during the collection: its path and its parsed
// lines, kept in memory for the time of the collection only.
type readFile struct {
	path  string
	lines []iniLine
}

// locate finds where name is set among files, in PHP's load order: the
// last occurrence wins, as PHP does. It returns "" and 0 when no file sets
// it (default value, or set elsewhere).
func locate(files []readFile, name string) (string, int) {
	p, n := "", 0
	for _, f := range files {
		for _, l := range f.lines {
			if l.name == name {
				p, n = f.path, l.line
			}
		}
	}
	return p, n
}

// fileReader reads each allowed file once per collection and remembers it.
type fileReader struct {
	c    *collector
	read map[string]*readFile
	done map[string]bool
}

// iniChain reads php.ini then the scanned files, in PHP's load order, and
// returns those it could read.
func (f *fileReader) iniChain(loaded string, scanned []string) []readFile {
	var out []readFile
	for _, p := range append([]string{loaded}, scanned...) {
		if p == "" {
			continue
		}
		if r := f.get(p, true); r != nil {
			out = append(out, *r)
		}
	}
	return out
}

// get reads p once. A file PHP or FPM reports must be a configuration file
// and pass the base rules; otherwise it is refused. A missing file is said
// only when say is true.
func (f *fileReader) get(p string, say bool) *readFile {
	if r, ok := f.read[p]; ok {
		return r
	}
	if f.done == nil {
		f.done = map[string]bool{}
	}
	if f.done[p] {
		return nil
	}
	f.done[p] = true
	if baseRefusal(p) != "" || (isHealth(f.c.t) && !isConfig(p)) {
		f.c.unseen(cleanPath(p), ReasonRefused)
		return nil
	}
	res, ok := f.c.run(cmdRead(p))
	if !ok {
		if f.c.err != nil {
			return nil
		}
		msg := strings.ToLower(scan.SanitizeText(string(res.Stderr)))
		switch {
		case strings.Contains(msg, "no such file"):
			if say {
				f.c.unseen(p, ReasonMissing)
			}
		default:
			f.c.unseen(p, ReasonUnreadable)
		}
		return nil
	}
	if len(res.Stdout) > MaxFileSize {
		f.c.unseen(p, ReasonTooBig)
		return nil
	}
	sum := sha256.Sum256(res.Stdout)
	f.c.inv.Files = append(f.c.inv.Files, target.FileSeen{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: len(res.Stdout)})
	r := &readFile{path: p, lines: parseIni(string(res.Stdout))}
	f.read[p] = r
	return r
}
