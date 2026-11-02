package serverlog

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// FilterOptions are the settings of one read. Text asks for the cleaned message
// (spec § 7.3); RemoteDirs are the folders of the linked projects, which
// locations are made relative to; ReadCap and MaxFiles bound one pass.
type FilterOptions struct {
	Text       bool
	RemoteDirs []string
	ReadCap    int64
	MaxFiles   int
}

// Defaults of a pass, when the options give none.
const (
	defaultReadCap  = 5 << 20
	defaultMaxFiles = 50
	maxGroups       = 1000
)

var (
	// plainPathRe is every path the filter may name. The class is shared with
	// the file name filter of the shell script: anything else, in a declared
	// path or in a file name a wildcard finds, never reaches a command or the
	// output.
	plainPathRe    = regexp.MustCompile(`^/[A-Za-z0-9._/+=,:~ -]*$`)
	wildcardNameRe = regexp.MustCompile(`^[A-Za-z0-9._+=,:~ *?-]*$`)
	fieldNameRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	patternRe      = regexp.MustCompile(`^[A-Za-z0-9 _.:|()*+?^$\[\]-]{1,128}$`)
	cursorIDRe     = regexp.MustCompile(`^[A-Za-z0-9:_-]{0,64}$`)
)

// checkPlainPath refuses a path that is not absolute or holds anything but the
// plain class. The errors never repeat the value.
func checkPlainPath(p string) error {
	if !plainPathRe.MatchString(p) || strings.Contains(p, "..") {
		return errors.New("serverlog: path refused: absolute, without .. and with plain characters only")
	}
	return nil
}

// checkSourcePath is checkPlainPath, with a wildcard allowed in the last segment.
func checkSourcePath(p string) error {
	i := strings.LastIndex(p, "/")
	if i < 0 || !wildcardNameRe.MatchString(p[i+1:]) || strings.Contains(p, "..") {
		return errors.New("serverlog: path refused: absolute, without .. and with plain characters only")
	}
	return checkPlainPath(p[:i+1])
}

// shellQuote quotes s for sh. Everything that reaches it was checked already;
// the quoting stands on its own anyway.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellGlob quotes a source path, leaving its wildcards to the shell.
func shellGlob(p string) string {
	var b strings.Builder
	start := 0
	for i, c := range p {
		if c == '*' || c == '?' {
			if start < i {
				b.WriteString(shellQuote(p[start:i]))
			}
			b.WriteRune(c)
			start = i + 1
		}
	}
	if start < len(p) {
		b.WriteString(shellQuote(p[start:]))
	}
	return b.String()
}

// textAllowed tells whether a read of this source gives a cleaned text. A JSON
// line has no message Michel knows of: only its declared fields are read.
func textAllowed(src Source, o FilterOptions) bool {
	return o.Text && src.Format != FormatJSON
}

// Script builds the filter for one source, to run with `sh -s`. It holds no
// redirection, no temporary file and no write of any kind. Unless o.Text is on,
// it holds no instruction able to emit anything of a line beyond the extracted
// fields: the guarantee can be read in the script.
//
// No cursor at all means the first read of the source: the files present are
// located at their end and nothing is read. With cursors, a file without one
// appeared since, and is read from its start.
func Script(src Source, cursors []Cursor, o FilterOptions) (string, error) {
	if err := checkSourcePath(src.Path); err != nil {
		return "", err
	}
	parser, vars, err := parserFor(src)
	if err != nil {
		return "", err
	}
	dirs, err := remoteDirs(o.RemoteDirs)
	if err != nil {
		return "", err
	}
	cases, err := cursorCases(cursors)
	if err != nil {
		return "", err
	}
	readCap := o.ReadCap
	if readCap <= 0 {
		readCap = defaultReadCap
	}
	maxFiles := o.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	first := "0"
	if len(cursors) == 0 {
		first = "1"
	}
	noMatch := ""
	if strings.ContainsAny(src.Path, "*?") {
		noMatch = "\tif [ \"$f\" = " + shellQuote(src.Path) + " ]; then\n\t\tprintf 'U\\t%s\\n' \"$f\"\n\t\tcontinue\n\tfi\n"
	}

	// The message lines go before any value enters the program: a folder or a
	// field may well hold the same letters.
	prog := strings.Replace(awkProgram, "@PARSER@", parser, 1)
	if textAllowed(src, o) {
		prog = strings.NewReplacer("@CLEAN@", cleanBlock, "@PRINT@", printWithText).Replace(prog)
	} else {
		prog = strings.NewReplacer("@CLEAN@", "", "@PRINT@", printDefault).Replace(prog)
		prog = withoutMessage(prog)
	}
	prog = strings.NewReplacer(append(vars, "@DIRS@", dirs, "@GROUPS@", strconv.Itoa(maxGroups))...).Replace(prog)
	if strings.Contains(prog, "'") {
		return "", errors.New("serverlog: internal error: a quote in the filter")
	}
	return strings.NewReplacer(
		"@DECL@", shellQuote(src.Path),
		"@GLOB@", shellGlob(src.Path),
		"@NOMATCH@", noMatch,
		"@CURSORS@", cases,
		"@FIRST@", first,
		"@CAP@", strconv.FormatInt(readCap, 10),
		"@MAX@", strconv.Itoa(maxFiles),
		"@PROG@", prog,
	).Replace(shellProgram), nil
}

// withoutMessage takes out every line that handles the message, so that the
// default script does not even hold it.
func withoutMessage(prog string) string {
	lines := strings.Split(prog, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if !strings.Contains(l, "msg") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
}

// remoteDirs writes the linked folders as awk assignments, longest first so
// that a nested project wins.
func remoteDirs(in []string) (string, error) {
	dirs := make([]string, 0, len(in))
	for _, d := range in {
		if err := checkPlainPath(d); err != nil {
			return "", err
		}
		d = strings.TrimRight(d, "/")
		if d == "" {
			return "", errors.New("serverlog: path refused: a linked folder cannot be the root")
		}
		dirs = append(dirs, d)
	}
	sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	var b strings.Builder
	fmt.Fprintf(&b, "\tndirs = %d\n", len(dirs))
	for i, d := range dirs {
		fmt.Fprintf(&b, "\tdirs[%d] = \"%s\"\n", i+1, d)
	}
	return b.String(), nil
}

// cursorCases writes the known positions as the arms of a shell case.
func cursorCases(cursors []Cursor) (string, error) {
	var b strings.Builder
	for _, c := range cursors {
		if err := checkPlainPath(c.File); err != nil {
			return "", err
		}
		if !cursorIDRe.MatchString(c.FileID) || c.Offset < 0 {
			return "", errors.New("serverlog: read position refused")
		}
		fmt.Fprintf(&b, "\t%s) c_id=%s; c_off=%d ;;\n", shellQuote(c.File), shellQuote(c.FileID), c.Offset)
	}
	return b.String(), nil
}

// parserFor returns the awk code of the source's format, and the checked values
// to put in it.
func parserFor(src Source) (string, []string, error) {
	switch src.Format {
	case FormatPHP:
		return phpParser, nil, nil
	case FormatPostgres:
		return postgresParser, nil, nil
	case FormatMonolog:
		return commonLevels + monologParser, nil, nil
	case FormatJSON:
		if !fieldNameRe.MatchString(src.LevelField) {
			return "", nil, errors.New("serverlog: a JSON source needs a plain level field")
		}
		if src.ChannelField != "" && !fieldNameRe.MatchString(src.ChannelField) {
			return "", nil, errors.New("serverlog: the channel field of a JSON source must be plain")
		}
		return commonLevels + jsonParser, []string{"@LF@", src.LevelField, "@CF@", src.ChannelField}, nil
	case FormatText:
		if src.Pattern == "" {
			return textParser, []string{"@MATCH@", textKeywords}, nil
		}
		if !patternRe.MatchString(src.Pattern) {
			return "", nil, errors.New("serverlog: pattern refused: letters, digits and simple operators only")
		}
		if _, err := regexp.CompilePOSIX(src.Pattern); err != nil {
			return "", nil, errors.New("serverlog: pattern refused: it is not a valid expression")
		}
		return textParser, []string{"@MATCH@", "\tif (h ~ \"" + src.Pattern + "\") level = \"error\"\n"}, nil
	}
	return "", nil, errors.New("serverlog: unknown log format")
}

// shellProgram is the frame of the filter. Its output, one fact per line:
//
//	F file id offset skipped rotated first
//	R level type location channel hour count [text]
//	U file
//	M
//
// The file class of plain_name below is plainPathRe's. A file name out of it, or
// one holding "..", is never named: the source as a whole is reported unseen.
// Past MaxFiles, the first names in glob order are left out: dated names sort
// oldest first, and the errors of today are the ones that matter.
const shellProgram = `LC_ALL=C
export LC_ALL
found=$(for tool in awk tail head tr ls wc; do command -v "$tool" || echo '!'; done)
case "$found" in
*!*)
	printf 'U\t%s\n' @DECL@
	exit 0
	;;
esac
prog='@PROG@'
lookup() {
	c_id=''
	c_off=''
	case "$1" in
@CURSORS@	esac
}
digits() {
	case "$1" in
	''|*[!0-9]*) return 1 ;;
	esac
	return 0
}
read_one() {
	if [ ! -f "$f" ] || [ -L "$f" ] || [ ! -r "$f" ]; then
		printf 'U\t%s\n' "$f"
		return
	fi
	set -- $(ls -di "$f")
	id=$1
	size=$(wc -c < "$f" | tr -d ' ')
	if ! digits "$id" || ! digits "$size"; then
		printf 'U\t%s\n' "$f"
		return
	fi
	if [ @FIRST@ = 1 ]; then
		printf 'F\t%s\t%s\t%s\t0\t0\t1\n' "$f" "$id" "$size"
		return
	fi
	off=0
	rot=0
	lookup "$f"
	if [ -n "$c_off" ]; then
		off=$c_off
		if [ "$id" != "$c_id" ] || [ "$size" -lt "$c_off" ]; then
			off=0
			rot=1
		fi
	fi
	start=$off
	win=$((size - off))
	skip=0
	if [ "$win" -gt @CAP@ ]; then
		start=$((size - @CAP@))
		skip=$((start - off))
		win=@CAP@
	fi
	if [ "$win" -eq 0 ]; then
		printf 'F\t%s\t%s\t%s\t0\t%s\t0\n' "$f" "$id" "$off" "$rot"
		return
	fi
	{
		tail -c +$((start + 1)) "$f" | head -c "$win" | tr '\000\015' '  '
		printf '\n'
	} | awk -v f="$f" -v id="$id" -v base="$start" -v skip="$skip" -v rot="$rot" -v win="$win" -v full=@CAP@ "$prog"
	if [ "$?" -ne 0 ]; then
		printf 'U\t%s\n' "$f"
	fi
}
plain_name() {
	case "$1" in
	*[!A-Za-z0-9._/+=,:~\ -]*|*..*) return 1 ;;
	esac
	return 0
}
total=0
for f in @GLOB@; do
	if plain_name "$f"; then
		total=$((total + 1))
	fi
done
drop=$((total - @MAX@))
if [ "$drop" -gt 0 ]; then
	printf 'M\n'
fi
count=0
bad=0
for f in @GLOB@; do
@NOMATCH@	if ! plain_name "$f"; then
		bad=1
		continue
	fi
	count=$((count + 1))
	if [ "$count" -le "$drop" ]; then
		continue
	fi
	read_one
done
if [ "$bad" = 1 ]; then
	printf 'U\t%s\n' @DECL@
fi
exit 0
`

// awkProgram is the common part of the filter. Its input always ends with one
// added newline, so the last record is what follows the last newline of the
// read (often nothing): it is held back and not consumed, and a line cut at the
// end of the read waits for the next one. Everything is written at the end, so
// a crash of awk writes nothing and the shell reports the file unseen. Fewer
// bytes than asked for means a tool failed or the file shrank under the read:
// that is unseen too, never a quiet "no error". The groups are capped, so that
// forged lines cannot fill the output: past the cap, a line counts by level.
//
// NUL and carriage return arrive as spaces, byte for byte: awk implementations
// differ on both, and the position counts bytes.
//
// Only POSIX awk: no gawk extension, no interval expression and no named class,
// since servers may have mawk or busybox.
const awkProgram = `
BEGIN {
@DIRS@	mon["Jan"] = "01"; mon["Feb"] = "02"; mon["Mar"] = "03"; mon["Apr"] = "04"
	mon["May"] = "05"; mon["Jun"] = "06"; mon["Jul"] = "07"; mon["Aug"] = "08"
	mon["Sep"] = "09"; mon["Oct"] = "10"; mon["Nov"] = "11"; mon["Dec"] = "12"
	init_levels()
}
function safe_word(w) {
	if (w ~ /[0-9][0-9][0-9][0-9][0-9][0-9][0-9]/) return 0
	if (w ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) return 0
	return 1
}
function safe_channel(w) {
	return length(w) <= 64 && w ~ /^[A-Za-z0-9_-]+$/ && safe_word(w)
}
function safe_path(r,   n, i, parts, s) {
	n = split(r, parts, "/")
	for (i = 1; i < n; i++) {
		s = parts[i]
		sub(/^\./, "", s)
		if (!safe_word(s) || s ~ /^[0-9]+(\.[0-9]+)+$/ || s ~ /\.[A-Za-z][A-Za-z]+$/) return 0
	}
	s = parts[n]
	sub(/\.[A-Za-z]+$/, "", s)
	sub(/^\./, "", s)
	if (!safe_word(s)) return 0
	if (index(s, ".") && s !~ /^[^.]+\.(blade|html|class|inc|tpl|config|module|interface|trait)$/) return 0
	return 1
}
function place(p, ln,   i, d, r) {
	if (index(p, "..") || 6 < length(ln)) return ""
	r = ""
	for (i = 1; i <= ndirs; i++) {
		d = dirs[i] "/"
		if (index(p, d) == 1) {
			r = substr(p, length(d) + 1)
			break
		}
	}
	if (r == "" || substr(r, 1, 1) == "/" || !safe_path(r)) {
		r = p
		sub(/^.*\//, "", r)
	}
	if (r == "" || 200 < length(r) || r !~ /\.(php|phtml|inc|module|twig|tpl)$/ || !safe_path(r)) return ""
	return r ":" ln
}
function hourof(s,   z, d) {
	if (substr(s, 1, 1) == "[") s = substr(s, 2)
	if (match(s, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][ T][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
		z = substr(s, RLENGTH + 1)
		s = substr(s, 1, 10) "T" substr(s, 12, 2)
		sub(/^\.[0-9]+/, "", z)
		if (substr(z, 1, 1) == "Z") return s "Z"
		if (z ~ /^[-+][0-9][0-9]:[0-9][0-9]/) return s substr(z, 1, 6)
		if (z ~ /^[-+][0-9][0-9][0-9][0-9]/) return s substr(z, 1, 3) ":" substr(z, 4, 2)
		return s
	}
	if (s ~ /^[0-9][0-9]-[A-Z][a-z][a-z]-[0-9][0-9][0-9][0-9] [0-9][0-9]:/) {
		d = substr(s, 4, 3)
		if (d in mon) return substr(s, 8, 4) "-" mon[d] "-" substr(s, 1, 2) "T" substr(s, 13, 2)
	}
	return ""
}
@PARSER@
@CLEAN@
function scan(l,   k) {
	if (substr(l, length(l), 1) == " ") l = substr(l, 1, length(l) - 1)
	level = ""; typ = ""; loc = ""; chan = ""; hour = ""
	msg = ""
	parse(l)
	if (level == "") return
	k = level SUBSEP typ SUBSEP loc SUBSEP chan SUBSEP hour
	if (!(k in c)) {
		if (@GROUPS@ <= groups) k = level SUBSEP SUBSEP SUBSEP SUBSEP
		if (!(k in c)) groups++
	}
	c[k]++
	if (!(k in tx)) tx[k] = clean(msg)
}
{
	if (held) {
		used += length(prev) + 1
		if (skip + 0 == 0 || NR != 2) scan(prev)
	}
	prev = $0
	held = 1
}
END {
	if (used + length(prev) != win + 0) {
		printf "U\t%s\n", f
		exit 0
	}
	pos = base + used
	lost = skip + 0
	if (used == 0 && length(prev) == full + 0) {
		pos = base + full
		lost = lost + full
	}
	for (k in c) {
		split(k, a, SUBSEP)
@PRINT@
	}
	printf "F\t%s\t%s\t%.0f\t%.0f\t%s\t0\n", f, id, pos, lost, rot
}
`

const (
	printDefault  = `		printf "R\t%s\t%s\t%s\t%s\t%s\t%.0f\n", a[1], a[2], a[3], a[4], a[5], c[k]`
	printWithText = `		printf "R\t%s\t%s\t%s\t%s\t%s\t%.0f\t%s\n", a[1], a[2], a[3], a[4], a[5], c[k], tx[k]`
)

// phpParser reads the PHP error log: optional [..] prefixes written by PHP or
// the web server, then a known label at the very start of what is left. The
// type follows the label, the location ends the line: a message cannot move
// either of them.
const phpParser = `
function init_levels() {
	lv["Fatal error"] = "critical"; lv["Parse error"] = "critical"
	lv["Compile error"] = "critical"; lv["Core error"] = "critical"
	lv["Catchable fatal error"] = "critical"; lv["Recoverable fatal error"] = "critical"
	lv["Warning"] = "warning"; lv["Compile warning"] = "warning"; lv["Core warning"] = "warning"
	lv["Notice"] = "info"; lv["Deprecated"] = "info"; lv["Strict Standards"] = "info"
}
function parse(l,   h, p, lab, rest, v, t, ln) {
	h = substr(l, 1, 1024)
	p = h
	while (match(p, /^\[[^]]*\] */)) p = substr(p, RLENGTH + 1)
	if (!match(p, /^(PHP +)?[A-Z][A-Za-z ]*: /)) return
	lab = substr(p, 1, RLENGTH - 2)
	rest = substr(p, RLENGTH + 1)
	sub(/^PHP +/, "", lab)
	if (!(lab in lv)) return
	level = lv[lab]
	hour = hourof(h)
	msg = rest
	if (match(rest, /^ *Uncaught +[A-Za-z_\\][A-Za-z0-9_\\]*(: | in \/)/)) {
		v = substr(rest, RSTART, RLENGTH)
		sub(/^ *Uncaught +/, "", v)
		sub(/(: | in \/)$/, "", v)
		if (length(v) <= 128 && safe_word(v)) typ = v
	}
	t = l
	if (1024 < length(t)) t = substr(t, length(t) - 1023)
	if (match(t, " in /[A-Za-z0-9_./-]+:[0-9]+$")) {
		v = substr(t, RSTART + 4)
		ln = v
		sub(/:[0-9]+$/, "", v)
		sub(/^.*:/, "", ln)
		loc = place(v, ln)
	} else if (match(t, " in /[A-Za-z0-9_./-]+ on line [0-9]+$")) {
		v = substr(t, RSTART + 4)
		ln = v
		sub(/ on line [0-9]+$/, "", v)
		sub(/^.* /, "", ln)
		loc = place(v, ln)
	}
}
`

// postgresParser takes the leftmost severity of a line: the prefix of
// log_line_prefix comes first, and whatever a message holds comes after. With
// %e written right before the severity, the word there is the SQLSTATE when it
// starts with a known class and holds a digit: a pid or a user must not pass. A line
// starting with a tab continues a statement: it holds values, never a severity.
const postgresParser = `
function init_levels() {
	lv["PANIC"] = "critical"; lv["FATAL"] = "critical"
	lv["ERROR"] = "error"; lv["ERREUR"] = "error"
	lv["WARNING"] = "warning"; lv["ATTENTION"] = "warning"
	lv["LOG"] = "info"; lv["NOTICE"] = "info"; lv["INFO"] = "info"
}
function parse(l,   h, s, before, at, n, v) {
	if (substr(l, 1, 1) == "\t") return
	h = substr(l, 1, 1024)
	if (!match(h, /(^| )(PANIC|FATAL|ERROR|ERREUR|WARNING|ATTENTION|LOG|NOTICE|INFO|DEBUG[1-5]?|DETAIL|HINT|CONTEXT|STATEMENT|QUERY|LOCATION):  /)) return
	at = RSTART
	n = RLENGTH
	s = substr(h, at, n)
	sub(/^ /, "", s)
	sub(/:  $/, "", s)
	if (!(s in lv)) return
	level = lv[s]
	hour = hourof(h)
	msg = substr(h, at + n)
	before = substr(h, 1, at - 1)
	if (match(before, /(^| )[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]:?$/)) {
		v = substr(before, RSTART, RLENGTH)
		sub(/^ /, "", v)
		sub(/:$/, "", v)
		if (v ~ /^(00|01|02|03|08|09|0A|0B|0F|0L|0P|0Z|20|21|22|23|24|25|26|27|28|2B|2D|2F|34|38|39|3B|3D|3F|40|42|44|53|54|55|57|58|72|F0|HV|P0|XX)/ && v ~ /[0-9]/) typ = v
	}
}
`

// commonLevels names the levels Monolog and most JSON logs use.
const commonLevels = `
function init_levels() {
	lv["emergency"] = "critical"; lv["emerg"] = "critical"; lv["alert"] = "critical"
	lv["critical"] = "critical"; lv["crit"] = "critical"; lv["fatal"] = "critical"; lv["panic"] = "critical"
	lv["error"] = "error"; lv["err"] = "error"; lv["severe"] = "error"
	lv["warning"] = "warning"; lv["warn"] = "warning"
	lv["notice"] = "info"; lv["info"] = "info"; lv["debug"] = "info"
}
`

// monologParser anchors date, channel and level at the start of the line. The
// context comes as [object] (Class(code: N): message at path:line), after the
// message: only the class and the location are read, by anchored patterns, from
// its last occurrence. A very long line keeps its level and channel only.
const monologParser = `
function parse(l,   h, head, lab, n, rest, v, m, ln) {
	h = substr(l, 1, 1024)
	if (!match(h, /^\[[^]]*\] [A-Za-z0-9_.-]+\.[A-Z]+: /)) return
	n = RLENGTH
	head = substr(h, 1, n - 2)
	sub(/^\[[^]]*\] /, "", head)
	lab = head
	sub(/^.*\./, "", lab)
	lab = tolower(lab)
	if (!(lab in lv)) return
	level = lv[lab]
	v = head
	sub(/\.[A-Z]+$/, "", v)
	if (safe_channel(v)) chan = v
	hour = hourof(h)
	msg = before_context(substr(h, n + 1))
	if (65536 < length(l) || !match(l, /.*\[object\] \(/)) return
	rest = substr(l, RSTART + RLENGTH)
	if (!match(rest, /^[A-Za-z_\\][A-Za-z0-9_\\]*\(code: [-A-Za-z0-9]*\): /)) return
	v = substr(rest, 1, RLENGTH)
	sub(/\(code: .*$/, "", v)
	if (length(v) <= 128 && safe_word(v)) typ = v
	if (!match(rest, ".* at /[A-Za-z0-9_./-]+:[0-9]+[)]")) return
	m = substr(rest, 1, RLENGTH)
	if (!match(m, " at /[A-Za-z0-9_./-]+:[0-9]+[)]$")) return
	v = substr(m, RSTART + 4, RLENGTH - 5)
	ln = v
	sub(/:[0-9]+$/, "", v)
	sub(/^.*:/, "", ln)
	loc = place(v, ln)
}
`

// jsonParser walks the first 16 KiB of an object, keeping only string values of
// the declared fields at its top level: a value or a nested object cannot pose
// as one. Numeric levels are not read.
const jsonParser = `
function parse(l,   s, n, i, ch, d, ins, esc, b, str, val, k, lf, cf, lvl, chn) {
	if (substr(l, 1, 1) != "{") return
	lf = "@LF@"
	cf = "@CF@"
	s = substr(l, 1, 16384)
	n = length(s)
	d = 0; ins = 0; esc = 0; val = 0; k = ""; lvl = ""; chn = ""
	for (i = 1; i <= n; i++) {
		ch = substr(s, i, 1)
		if (ins) {
			if (esc) esc = 0
			else if (ch == "\\") esc = 1
			else if (ch == "\"") {
				ins = 0
				str = substr(s, b, i - b)
				if (d == 1) {
					if (val) {
						if (k == lf) lvl = str
						if (cf != "" && k == cf) chn = str
						val = 0
					} else k = str
				}
			}
			continue
		}
		if (ch == "\"") { ins = 1; b = i + 1 }
		else if (ch == "{" || ch == "[") d++
		else if (ch == "}" || ch == "]") d--
		else if (ch == ":" && d == 1) val = 1
		else if (ch == "," && d == 1) val = 0
	}
	lvl = tolower(lvl)
	if (!(lvl in lv)) return
	level = lv[lvl]
	if (safe_channel(chn)) chan = chn
}
`

// textParser gives a level and nothing else, by keyword or by the given pattern.
const textParser = `
function init_levels() {
}
function parse(l,   h) {
	h = substr(l, 1, 4096)
@MATCH@	if (level == "") return
	hour = hourof(h)
	msg = h
}
`

// textKeywords are whole words in capitals, or a lowercase level in brackets as
// nginx and Apache write it. Plain lowercase words are too often just prose.
const textKeywords = `	if (h ~ /(^|[^A-Za-z0-9_])(EMERGENCY|ALERT|CRITICAL|CRIT|FATAL|PANIC)($|[^A-Za-z0-9_])/ || h ~ /\[(emerg|emergency|alert|crit|critical|fatal)\]/) level = "critical"
	else if (h ~ /(^|[^A-Za-z0-9_])(ERROR|ERR|SEVERE)($|[^A-Za-z0-9_])/ || h ~ /\[(error|err)\]/) level = "error"
	else if (h ~ /(^|[^A-Za-z0-9_])(WARNING|WARN)($|[^A-Za-z0-9_])/ || h ~ /\[(warning|warn)\]/) level = "warning"
`

// cleanBlock is only in the script when the text is on (spec § 7.3). Values go
// in this order because each step would break the next: quotes first, as they
// can hold anything, then what contains dots and slashes, then numbers. From
// the first apostrophe to the last is one quote, so that "it's" cannot shift
// the pairs and let a quoted value out; a quote left open runs to the end.
var cleanBlock = `
function before_context(s,   i) {
	i = index(s, " {")
	if (i) s = substr(s, 1, i - 1)
	i = index(s, "[object]")
	if (i) s = substr(s, 1, i - 1)
	return s
}
function clean(s,   q1, q3) {
	q1 = "\047"
	q3 = "\140"
	gsub(/[^ -~]/, " ", s)
	gsub(/"([^"\\]|\\.)*"/, "[str]", s)
	gsub(q1 ".*" q1, "[str]", s)
	gsub(q3 "[^" q3 "]*" q3, "[str]", s)
	gsub("[\"" q1 q3 "].*$", "[str]", s)
	gsub(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^ ]*/, "[url]", s)
	gsub(/[^ ]*@[^ ]*/, "[email]", s)
	gsub(/\/[^ ]*/, "[path]", s)
	gsub(/[A-Za-z0-9_.-]+=[^ ]*/, "[val]", s)
	gsub(/[A-Za-z0-9_.%-]*::[A-Za-z0-9_.%:-]*/, "[addr]", s)
	gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "[ip]", s)
	gsub(/[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:]*/, "[ip]", s)
	gsub(/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+/, "[host]", s)
	gsub(/` + strings.Repeat("[A-Za-z0-9_+=-]", 20) + `[A-Za-z0-9_+=-]*/, "[token]", s)
	gsub(/[A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*/, "[n]", s)
	gsub(/  +/, " ", s)
	sub(/^ /, "", s)
	sub(/ $/, "", s)
	return substr(s, 1, 200)
}
`
