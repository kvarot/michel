package serverfix

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

// SAPIs a set_directive may target.
const (
	SAPICLI     = "cli"
	SAPIFPM     = "fpm"
	SAPIUserIni = "user_ini"
)

// maxValue bounds a directive value.
const maxValue = 512

// valueRe is the whole set of characters a value may hold: enough for
// booleans, numbers, sizes and path lists, and nothing a shell, sed or the
// ini parser reads as special (no quote, space, ;, #, $, &, |, \, =, ~,
// braces or parentheses).
var valueRe = regexp.MustCompile(`^[A-Za-z0-9_./:,@+%-]*$`)

// nameRe is a plain directive name.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`)

// poolKeyRe is a pool line naming a directive.
var poolKeyRe = regexp.MustCompile(`^php_(admin_)?(value|flag)\[([A-Za-z0-9_.]+)\]$`)

// checkValue refuses a value that could leave its place in an ini line or
// a script, and the values Michel never proposes.
func checkValue(directive, v string) error {
	if len(v) > maxValue || !valueRe.MatchString(v) {
		return fmt.Errorf("%w: %q", ErrBadValue, v)
	}
	if directive == "memory_limit" && strings.HasPrefix(v, "-") {
		return fmt.Errorf("%w: memory_limit is never unlimited", ErrBadValue)
	}
	return nil
}

// checkAdvised refuses a value the rule itself judges risky (an empty
// open_basedir included): a fix never makes things worse.
func checkAdvised(r serverrules.ConfigRule, v string) error {
	if serverrules.RiskyValue(r, v) {
		return fmt.Errorf("%w: %s = %q is the risky value", ErrBadValue, r.Directive, v)
	}
	return nil
}

// checkKey accepts a plain directive name or a pool php_*[name] form.
func checkKey(k string) bool {
	if nameRe.MatchString(k) {
		return true
	}
	m := poolKeyRe.FindStringSubmatch(k)
	return m != nil && nameRe.MatchString(m[3])
}

// rule returns the embedded rule of a directive.
func rule(directive string) (serverrules.ConfigRule, error) {
	set, err := serverrules.Rules()
	if err != nil {
		return serverrules.ConfigRule{}, err
	}
	for _, r := range set.Config {
		if r.Directive == directive {
			return r, nil
		}
	}
	return serverrules.ConfigRule{}, fmt.Errorf("%w: %q", ErrUnknownDirective, directive)
}

// location is where a directive is written.
type location struct {
	rt     *target.PHPRuntime // nil for a .user.ini
	path   string
	key    string
	line   int
	append bool
}

// Place returns the file where PHP reads directive for the runtime of sapi
// ("cli", "fpm" or "user_ini"), and its line; or, when no file sets it, the
// loaded php.ini (the .user.ini for user_ini) with appendLine set. A new
// file is never proposed, in conf.d or anywhere. It returns "" when the
// place cannot be told (no runtime, several runtimes of that SAPI, several
// .user.ini, or a directive the file could not set).
func Place(inv target.Inventory, sapi, directive string) (path string, line int, appendLine bool) {
	loc, err := locate(inv, sapi, directive, "")
	if err != nil {
		return "", 0, false
	}
	return loc.path, loc.line, loc.append
}

// locate finds where to write directive. want, when not empty, is the file
// the proposal names: it must be one of the runtime's files.
func locate(inv target.Inventory, sapi, directive, want string) (location, error) {
	r, err := rule(directive)
	if err != nil {
		return location{}, err
	}
	if sapi == SAPIUserIni {
		return locateUserIni(inv, r, want)
	}
	if sapi != SAPICLI && sapi != SAPIFPM {
		return location{}, fmt.Errorf("%w: unknown SAPI %q", ErrBadAction, sapi)
	}
	var rts []*target.PHPRuntime
	for i := range inv.PHP {
		rt := &inv.PHP[i]
		if rt.SAPI != sapi {
			continue
		}
		if want == "" || want == rt.LoadedIni || contains(rt.ScannedFiles, want) || (sapi == SAPIFPM && contains(rt.PoolFiles, want)) {
			rts = append(rts, rt)
		}
	}
	if len(rts) != 1 {
		return location{}, fmt.Errorf("%w: %d %s runtimes hold this file", ErrPathNotAllowed, len(rts), sapi)
	}
	rt := rts[0]
	system := r.Changeable == "system"

	// A pool line is read after the ini files: php_admin_* is final, a
	// php_value/php_flag counts only for a directive a pool may change.
	// Within a pool file the last line wins; several pool files setting it
	// is ambiguous unless the proposal names one.
	if sapi == SAPIFPM {
		perFile := map[string]*target.Directive{}
		var order []string
		for i := range inv.Directives {
			d := &inv.Directives[i]
			if d.SAPI != SAPIFPM || d.Binary != rt.Binary || d.Line <= 0 || !contains(rt.PoolFiles, d.File) {
				continue
			}
			m := poolKeyRe.FindStringSubmatch(d.Name)
			if m == nil || m[3] != directive || (m[1] == "" && system) {
				continue
			}
			cur, seen := perFile[d.File]
			if !seen {
				order = append(order, d.File)
			}
			curAdmin := seen && strings.HasPrefix(cur.Name, "php_admin_")
			if !seen || m[1] != "" || !curAdmin {
				perFile[d.File] = d
			}
		}
		var found *target.Directive
		switch {
		case want != "" && perFile[want] != nil:
			found = perFile[want]
		case want != "" && len(order) > 0:
			return location{}, fmt.Errorf("%w: PHP reads %s from a pool line", ErrPathNotAllowed, directive)
		case len(order) > 1:
			return location{}, fmt.Errorf("%w: %d pools set %s, name one", ErrAmbiguous, len(order), directive)
		case len(order) == 1:
			found = perFile[order[0]]
		case want != "" && contains(rt.PoolFiles, want):
			return location{}, fmt.Errorf("%w: the pool does not set %s, Michel adds lines to php.ini only", ErrPathNotAllowed, directive)
		}
		if found != nil {
			return location{rt: rt, path: found.File, key: found.Name, line: found.Line}, nil
		}
	}
	// The ini files, in PHP's load order: the last one setting it wins.
	var last *target.Directive
	for i := range inv.Directives {
		d := &inv.Directives[i]
		if d.SAPI != sapi || d.Binary != rt.Binary || d.Name != directive || d.Line <= 0 {
			continue
		}
		if d.File != rt.LoadedIni && !contains(rt.ScannedFiles, d.File) {
			continue
		}
		last = d
	}
	if last != nil {
		if want != "" && want != last.File {
			return location{}, fmt.Errorf("%w: PHP reads %s from another file", ErrPathNotAllowed, directive)
		}
		return location{rt: rt, path: last.File, key: directive, line: last.Line}, nil
	}
	if want != "" && want != rt.LoadedIni {
		return location{}, fmt.Errorf("%w: Michel adds lines to the loaded php.ini only, never to conf.d", ErrPathNotAllowed)
	}
	if rt.LoadedIni == "" {
		return location{}, fmt.Errorf("%w: no loaded php.ini", ErrPathNotAllowed)
	}
	return location{rt: rt, path: rt.LoadedIni, key: directive, append: true}, nil
}

// locateUserIni places a directive in a .user.ini: the line that sets it,
// else the end of the only .user.ini read. A directive only php.ini or a
// pool may set has no effect there and is refused.
func locateUserIni(inv target.Inventory, r serverrules.ConfigRule, want string) (location, error) {
	if r.Changeable == "system" {
		return location{}, fmt.Errorf("%w: %s has no effect in a .user.ini", ErrPathNotAllowed, r.Directive)
	}
	perFile := map[string]*target.Directive{}
	var order []string
	for i := range inv.Directives {
		d := &inv.Directives[i]
		if d.SAPI != SAPIUserIni || d.Name != r.Directive || d.Line <= 0 || path.Base(d.File) != ".user.ini" {
			continue
		}
		if want != "" && d.File != want {
			continue
		}
		if perFile[d.File] == nil {
			order = append(order, d.File)
		}
		perFile[d.File] = d // the last line of a file wins
	}
	if len(order) > 1 {
		return location{}, fmt.Errorf("%w: %d .user.ini set %s, name one", ErrAmbiguous, len(order), r.Directive)
	}
	if len(order) == 1 {
		last := perFile[order[0]]
		return location{path: last.File, key: r.Directive, line: last.Line}, nil
	}
	inis := userInis(inv)
	if want != "" {
		if !contains(inis, want) {
			return location{}, fmt.Errorf("%w: this .user.ini was not read", ErrPathNotAllowed)
		}
		return location{path: want, key: r.Directive, append: true}, nil
	}
	if len(inis) > 1 {
		return location{}, fmt.Errorf("%w: %d .user.ini read, name one", ErrAmbiguous, len(inis))
	}
	if len(inis) == 0 {
		return location{}, fmt.Errorf("%w: no .user.ini read", ErrPathNotAllowed)
	}
	return location{path: inis[0], key: r.Directive, append: true}, nil
}

// userInis lists the .user.ini files the collection read.
func userInis(inv target.Inventory) []string {
	var out []string
	add := func(p string) {
		if path.Base(p) == ".user.ini" && !contains(out, p) {
			out = append(out, p)
		}
	}
	for _, d := range inv.Directives {
		if d.SAPI == SAPIUserIni {
			add(d.File)
		}
	}
	for _, f := range inv.Files {
		add(f.Path)
	}
	return out
}

func contains(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// sedPattern is the BRE matching the line that sets key, whatever its
// value and trailing comment: `^[[:space:]]*key[[:space:]]*=.*$`.
func sedPattern(key string) string {
	var b strings.Builder
	b.WriteString(`^[[:space:]]*`)
	for _, c := range key {
		if c == '.' || c == '[' || c == ']' {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteString(`[[:space:]]*=.*$`)
	return b.String()
}

// iniLine is the line Michel writes.
func iniLine(key, value string) string { return key + " = " + value }
