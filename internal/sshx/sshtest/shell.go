package sshtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Shell is a tiny POSIX sh for the scripts internal/serverfix renders, run
// on the server's in-memory file system. It knows exactly the constructs
// that grammar uses and fails on anything else (exit 2): simple commands
// with single and double quotes, "$VAR", "${VAR}" and "$(simple command)"
// inside double quotes, ;, ||, { ...; }, if ...; then ...; [else ...;] fi
// on one line, the one-line `case "WORD" in PATTERN) ;; *) LIST;; esac`
// (an unquoted pattern with ? and *), redirections >, >>, >&2 and </dev/null,
// NAME="..." assignments, name() { ... } functions over several lines,
// set -eu, umask, trap (EXIT runs on exit) and exit. Built-in commands:
// echo, printf (%s and \n), true, test and [ (-L -w -r -e -f ! = !=),
// mkdir [-p] [-m MODE], cat, cp, cmp -s, sed 'Ns|re|text|' (one
// substitution on one line, basic regular expressions without groups),
// stat -c (%u %a %A, a link is not followed), id -u, env VAR=x... CMD, and
// sudo -n (allowed when Options.Sudo). Any other command runs the server's
// Options.Commands handler, with the script's own text as stdin unless
// redirected from /dev/null. Nothing is ever deleted: the shell has no rm.
//
// Ownership: Meta gives the owner and mode of a file or folder; a path
// not in Meta belongs to the user under Home (0644, folders 0755) and to
// root elsewhere. Root (UID 0, or a command run with sudo -n) writes every
// file; the user writes a file it owns with u+w, the paths of
// Options.Writable, and creates files in folders it owns with u+w. Files
// and folders the script creates belong to whoever creates them, with the
// umask applied. The state (folders, Meta) stays across runs of one Shell,
// which is not safe for concurrent runs.
type Shell struct {
	// UID is the user's id; 0 is root.
	UID int
	// Home is $HOME; "" means /home/demo.
	Home string
	// Links are symbolic links (path → target): test -L sees them, cat and
	// cp follow them, as a real system would.
	Links map[string]string
	// Meta is the owner and mode of files and folders.
	Meta map[string]Meta

	dirs map[string]bool
	mu   sync.Mutex
	ran  []string
}

// Meta is the owner and permission bits of a file or folder.
type Meta struct {
	UID  int
	Mode uint32
	Dir  bool
}

// Ran lists the commands the shell ran, words joined by spaces, sudo -n
// included.
func (sh *Shell) Ran() []string {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return append([]string(nil), sh.ran...)
}

// Func returns the shell as an Options.Shell.
func (sh *Shell) Func() ShellFunc { return sh.Run }

type exitSignal struct{ code int }

type interp struct {
	sh      *Shell
	s       *Server
	home    string
	vars    map[string]string
	funcs   map[string][]string
	traps   map[string]string
	errexit bool
	nounset bool
	dirs    map[string]bool
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	status  int
	depth   int
	umask   uint32
}

// Run runs script and returns its exit status.
func (sh *Shell) Run(s *Server, script string, stdout, stderr io.Writer) int {
	home := sh.Home
	if home == "" {
		home = "/home/demo"
	}
	if sh.dirs == nil {
		sh.dirs = map[string]bool{}
	}
	if sh.Meta == nil {
		sh.Meta = map[string]Meta{}
	}
	x := &interp{sh: sh, s: s, home: home, vars: map[string]string{"HOME": home}, funcs: map[string][]string{},
		traps: map[string]string{}, dirs: sh.dirs, stdin: strings.NewReader(script), stdout: stdout, stderr: stderr, umask: 022}
	code, exited := x.protect(func() { x.runLines(strings.Split(script, "\n")) })
	if !exited {
		code = x.status
	}
	if act := x.traps["EXIT"]; act != "" {
		delete(x.traps, "EXIT")
		x.status = code
		if c, ex := x.protect(func() { x.runLines([]string{act}) }); ex {
			code = c
		}
	}
	return code
}

func (x *interp) protect(f func()) (code int, exited bool) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(exitSignal)
			if !ok {
				panic(r)
			}
			code, exited = e.code, true
		}
	}()
	f()
	return 0, false
}

func (x *interp) fail(format string, a ...any) {
	fmt.Fprintf(x.stderr, "sh: "+format+"\n", a...)
	panic(exitSignal{2})
}

var (
	funcDef = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\(\) \{$`)
	caseRe  = regexp.MustCompile(`^case "(.*)" in ([A-Za-z0-9?*-]+)\) ;; \*\) (.*);; esac$`)
)

func (x *interp) runLines(lines []string) {
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if m := funcDef.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			var body []string
			j := i + 1
			for ; j < len(lines) && strings.TrimSpace(lines[j]) != "}"; j++ {
				body = append(body, lines[j])
			}
			if j == len(lines) {
				x.fail("unterminated function %s", m[1])
			}
			x.funcs[m[1]] = body
			i = j
			continue
		}
		if m := caseRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			word := x.expandDouble(m[1])
			if !globMatch(m[2], word) {
				x.status = x.runList(x.parseLine(m[3]), false)
			} else {
				x.status = 0
			}
			continue
		}
		list := x.parseLine(line)
		if list == nil {
			continue
		}
		x.status = x.runList(list, false)
	}
}

// parseLine parses one line; nil for an empty or comment line.
func (x *interp) parseLine(line string) [][]node {
	toks, err := tokenize(line)
	if err != nil {
		x.fail("%v: %q", err, line)
	}
	if len(toks) == 0 {
		return nil
	}
	p := &parser{toks: toks}
	list, err := p.list(nil)
	if err == nil && p.i != len(p.toks) {
		err = fmt.Errorf("unexpected %q", p.toks[p.i].text)
	}
	if err != nil {
		x.fail("%v: %q", err, line)
	}
	return list
}

// globMatch matches a case pattern with ? and * and literal characters.
func globMatch(pat, s string) bool {
	if pat == "" {
		return s == ""
	}
	switch pat[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(pat[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && globMatch(pat[1:], s[1:])
	case '[', '\\':
		return false // not supported: never matches, the default branch runs
	}
	return s != "" && s[0] == pat[0] && globMatch(pat[1:], s[1:])
}

// --- tokens -------------------------------------------------------------

type segKind int

const (
	segLit    segKind = iota // unquoted literal text
	segSingle                // '...'
	segDouble                // "..." (expanded)
)

type seg struct {
	kind segKind
	text string
}

type token struct {
	op   string // ";", "||", ">", ">>", ">&2"; "" for a word
	text string // raw text, for messages and keywords
	segs []seg
}

func (t token) bare() string {
	if t.op != "" || len(t.segs) != 1 || t.segs[0].kind != segLit {
		return ""
	}
	return t.segs[0].text
}

func tokenize(line string) ([]token, error) {
	var toks []token
	var cur *token
	flush := func() {
		if cur != nil {
			toks = append(toks, *cur)
			cur = nil
		}
	}
	word := func() *token {
		if cur == nil {
			cur = &token{}
		}
		return cur
	}
	lit := func(c byte) {
		w := word()
		w.text += string(c)
		if n := len(w.segs); n > 0 && w.segs[n-1].kind == segLit {
			w.segs[n-1].text += string(c)
		} else {
			w.segs = append(w.segs, seg{segLit, string(c)})
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && cur == nil:
			flush()
			return toks, nil
		case c == '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			w := word()
			w.text += line[i : i+j+2]
			w.segs = append(w.segs, seg{segSingle, line[i+1 : i+1+j]})
			i += j + 1
		case c == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' && j+1 < len(line) && strings.IndexByte(`"\$`, line[j+1]) >= 0 {
					b.WriteByte('\\')
					j++
				}
				if line[j] == '`' {
					return nil, errors.New("backquote")
				}
				b.WriteByte(line[j])
			}
			if j >= len(line) {
				return nil, errors.New("unterminated double quote")
			}
			w := word()
			w.text += line[i : j+1]
			w.segs = append(w.segs, seg{segDouble, b.String()})
			i = j
		case c == ';':
			flush()
			toks = append(toks, token{op: ";", text: ";"})
		case c == '|':
			if i+1 < len(line) && line[i+1] == '|' {
				flush()
				toks = append(toks, token{op: "||", text: "||"})
				i++
				continue
			}
			return nil, errors.New("pipes are not supported")
		case c == '>':
			flush()
			switch {
			case strings.HasPrefix(line[i:], ">>"):
				toks = append(toks, token{op: ">>", text: ">>"})
				i++
			case strings.HasPrefix(line[i:], ">&2"):
				toks = append(toks, token{op: ">&2", text: ">&2"})
				i += 2
			case strings.HasPrefix(line[i:], ">&"):
				return nil, errors.New("unsupported redirection")
			default:
				toks = append(toks, token{op: ">", text: ">"})
			}
		case c == '<':
			flush()
			toks = append(toks, token{op: "<", text: "<"})
		case c == '&' || c == '(' || c == ')' || c == '`' || c == '*' || c == '?':
			return nil, fmt.Errorf("unsupported %q", c)
		case c == '$':
			return nil, errors.New("unquoted expansion")
		case c == '\\':
			if i+1 >= len(line) {
				return nil, errors.New("trailing backslash")
			}
			i++
			lit(line[i])
		default:
			lit(c)
		}
	}
	flush()
	return toks, nil
}

// --- parse --------------------------------------------------------------

type node interface{}

type simple struct {
	words  []token
	redirs []token // op then target word, in pairs (">&2" alone)
}

type group struct{ list [][]node }

type ifNode struct{ cond, body, alt [][]node }

type parser struct {
	toks []token
	i    int
}

func (p *parser) peekWord() string {
	if p.i < len(p.toks) {
		return p.toks[p.i].bare()
	}
	return ""
}

// list parses and-or lists separated by ";" until a stop keyword at the
// start of a command, or the end.
func (p *parser) list(stop []string) ([][]node, error) {
	var out [][]node
	for p.i < len(p.toks) {
		if w := p.peekWord(); w != "" && contains(stop, w) {
			return out, nil
		}
		ao, err := p.andOr(stop)
		if err != nil {
			return nil, err
		}
		out = append(out, ao)
		if p.i < len(p.toks) && p.toks[p.i].op == ";" {
			p.i++
			continue
		}
		break
	}
	return out, nil
}

func (p *parser) andOr(stop []string) ([]node, error) {
	var out []node
	for {
		c, err := p.command(stop)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		if p.i < len(p.toks) && p.toks[p.i].op == "||" {
			p.i++
			continue
		}
		return out, nil
	}
}

func (p *parser) expect(w string) error {
	if p.peekWord() != w {
		return fmt.Errorf("expected %q", w)
	}
	p.i++
	return nil
}

func (p *parser) command(stop []string) (node, error) {
	switch p.peekWord() {
	case "{":
		p.i++
		l, err := p.list([]string{"}"})
		if err != nil {
			return nil, err
		}
		return group{l}, p.expect("}")
	case "if":
		p.i++
		cond, err := p.list([]string{"then"})
		if err != nil {
			return nil, err
		}
		if err := p.expect("then"); err != nil {
			return nil, err
		}
		body, err := p.list([]string{"else", "fi"})
		if err != nil {
			return nil, err
		}
		var alt [][]node
		if p.peekWord() == "else" {
			p.i++
			if alt, err = p.list([]string{"fi"}); err != nil {
				return nil, err
			}
		}
		return ifNode{cond, body, alt}, p.expect("fi")
	case "then", "else", "fi", "}":
		return nil, fmt.Errorf("unexpected %q", p.peekWord())
	}
	var c simple
	for p.i < len(p.toks) {
		t := p.toks[p.i]
		switch t.op {
		case ";", "||":
			if len(c.words) == 0 {
				return nil, fmt.Errorf("empty command before %q", t.op)
			}
			return c, nil
		case ">&2":
			c.redirs = append(c.redirs, t)
			p.i++
		case ">", ">>", "<":
			if p.i+1 >= len(p.toks) || p.toks[p.i+1].op != "" {
				return nil, errors.New("redirection without a file")
			}
			c.redirs = append(c.redirs, t, p.toks[p.i+1])
			p.i += 2
		default:
			if len(c.words) > 0 && contains(stop, t.bare()) && t.bare() == "}" {
				return c, nil
			}
			c.words = append(c.words, t)
			p.i++
		}
	}
	if len(c.words) == 0 {
		return nil, errors.New("empty command")
	}
	return c, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- run ----------------------------------------------------------------

func (x *interp) runList(l [][]node, noErr bool) int {
	st := 0
	for _, ao := range l {
		st = x.runAndOr(ao, noErr)
	}
	x.status = st
	return st
}

func (x *interp) runAndOr(ao []node, noErr bool) int {
	st := 0
	for i, c := range ao {
		st = x.runNode(c, noErr || i < len(ao)-1)
		if st == 0 {
			return 0
		}
	}
	return st
}

func (x *interp) runNode(n node, noErr bool) int {
	switch n := n.(type) {
	case group:
		return x.runList(n.list, noErr)
	case ifNode:
		if x.runList(n.cond, true) == 0 {
			return x.runList(n.body, noErr)
		}
		if n.alt != nil {
			return x.runList(n.alt, noErr)
		}
		return 0
	case simple:
		st := x.runSimple(n)
		x.status = st
		if st != 0 && x.errexit && !noErr {
			panic(exitSignal{st})
		}
		return st
	}
	x.fail("unknown node")
	return 2
}

var varRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

func (x *interp) lookup(name string) string {
	v, ok := x.vars[name]
	if !ok && x.nounset {
		fmt.Fprintf(x.stderr, "sh: %s: parameter not set\n", name)
		panic(exitSignal{2})
	}
	return v
}

// expandDouble expands $NAME, ${NAME} and $(id -u) in a double-quoted text.
func (x *interp) expandDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '$':
			rest := s[i+1:]
			switch {
			case strings.HasPrefix(rest, "("):
				j := strings.IndexByte(rest, ')')
				if j < 0 || strings.ContainsAny(rest[1:j], "(`") {
					x.fail("unsupported command substitution")
				}
				b.WriteString(x.capture(rest[1:j]))
				i += j + 1
			case strings.HasPrefix(rest, "{"):
				j := strings.IndexByte(rest, '}')
				if j < 0 || !varRe.MatchString(rest[1:j]) || varRe.FindString(rest[1:j]) != rest[1:j] {
					x.fail("bad substitution")
				}
				b.WriteString(x.lookup(rest[1:j]))
				i += j + 1
			default:
				name := varRe.FindString(rest)
				if name == "" {
					x.fail("unsupported expansion $%s", rest)
				}
				b.WriteString(x.lookup(name))
				i += len(name)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// capture runs `id` or `stat` (the only command substitutions the grammar
// uses) and returns its output without the
// trailing new lines; its failure does not stop the script.
func (x *interp) capture(cmd string) string {
	list := x.parseLine(cmd)
	if len(list) != 1 || len(list[0]) != 1 {
		x.fail("unsupported command substitution %q", cmd)
	}
	c, ok := list[0][0].(simple)
	if !ok || len(c.redirs) > 0 || (c.words[0].bare() != "id" && c.words[0].bare() != "stat") {
		x.fail("unsupported command substitution %q", cmd)
	}
	var buf bytes.Buffer
	out := x.stdout
	x.stdout = &buf
	st := x.status
	x.runSimple(c)
	x.stdout, x.status = out, st
	return strings.TrimRight(buf.String(), "\n")
}

func (x *interp) expand(t token) string {
	var b strings.Builder
	for _, s := range t.segs {
		switch s.kind {
		case segLit:
			if strings.ContainsAny(s.text, "[") && t.bare() != "[" {
				x.fail("unquoted pattern %q", t.text)
			}
			b.WriteString(s.text)
		case segSingle:
			b.WriteString(s.text)
		case segDouble:
			b.WriteString(x.expandDouble(s.text))
		}
	}
	return b.String()
}

var assignRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=`)

func (x *interp) runSimple(c simple) int {
	// NAME="..." alone.
	if first := c.words[0]; len(first.segs) > 0 && first.segs[0].kind == segLit {
		if m := assignRe.FindStringSubmatch(first.segs[0].text); m != nil {
			if len(c.words) != 1 || len(c.redirs) != 0 {
				x.fail("assignment before a command is not supported")
			}
			rest := token{segs: append([]seg{{segLit, first.segs[0].text[len(m[0]):]}}, first.segs[1:]...)}
			x.vars[m[1]] = x.expand(rest)
			return 0
		}
	}
	argv := make([]string, len(c.words))
	for i, w := range c.words {
		argv[i] = x.expand(w)
	}
	out, errw := x.stdout, x.stderr
	var buf *bytes.Buffer
	var file string
	appendTo := false
	for i := 0; i < len(c.redirs); i++ {
		switch c.redirs[i].op {
		case "<":
			if x.expand(c.redirs[i+1]) != "/dev/null" {
				x.fail("only </dev/null is supported")
			}
			i++
			in := x.stdin
			x.stdin = strings.NewReader("")
			defer func() { x.stdin = in }()
		case ">&2":
			out = x.stderr
		case ">", ">>":
			file = x.expand(c.redirs[i+1])
			appendTo = c.redirs[i].op == ">>"
			i++
			buf = &bytes.Buffer{}
			out = buf
		}
	}
	if file != "" {
		if !x.canCreate(file, x.sh.UID == 0) {
			fmt.Fprintf(errw, "sh: cannot create %s: Permission denied\n", file)
			return 2
		}
	}
	saved := x.stdout
	x.stdout = out
	st := x.command(argv, out, errw)
	x.stdout = saved
	if file != "" {
		x.writeFile(file, buf.String(), appendTo, x.sh.UID == 0)
	}
	return st
}

func (x *interp) record(argv []string) {
	x.sh.mu.Lock()
	x.sh.ran = append(x.sh.ran, strings.Join(argv, " "))
	x.sh.mu.Unlock()
}

func (x *interp) command(argv []string, out, errw io.Writer) int {
	x.record(argv)
	root := x.sh.UID == 0
	if argv[0] == "sudo" {
		if len(argv) < 3 || argv[1] != "-n" {
			x.fail("only sudo -n is supported")
		}
		if !x.s.opts.Sudo {
			io.WriteString(errw, "sudo: a password is required\n")
			return 1
		}
		root, argv = true, argv[2:]
	}
	switch argv[0] {
	case "echo":
		io.WriteString(out, strings.Join(argv[1:], " ")+"\n")
		return 0
	case "printf":
		return x.printf(argv[1:], out)
	case "true":
		return 0
	case "exit":
		code := x.status
		if len(argv) > 1 {
			n, err := strconv.Atoi(argv[1])
			if err != nil {
				x.fail("exit: bad number")
			}
			code = n
		}
		panic(exitSignal{code})
	case "set":
		for _, a := range argv[1:] {
			if !strings.HasPrefix(a, "-") || strings.Trim(a[1:], "eu") != "" {
				x.fail("set %s is not supported", a)
			}
			x.errexit = x.errexit || strings.Contains(a, "e")
			x.nounset = x.nounset || strings.Contains(a, "u")
		}
		return 0
	case "umask":
		n, err := strconv.ParseUint(argv[len(argv)-1], 8, 32)
		if len(argv) != 2 || err != nil || n > 0777 {
			x.fail("bad umask")
		}
		x.umask = uint32(n)
		return 0
	case "trap":
		if len(argv) < 3 {
			x.fail("bad trap")
		}
		for _, sig := range argv[2:] {
			if argv[1] == "-" {
				delete(x.traps, sig)
			} else {
				x.traps[sig] = argv[1]
			}
		}
		return 0
	case "test":
		return x.test(argv[1:], root)
	case "[":
		if argv[len(argv)-1] != "]" {
			x.fail("[: missing ]")
		}
		return x.test(argv[1:len(argv)-1], root)
	case "id":
		if len(argv) != 2 || argv[1] != "-u" {
			x.fail("only id -u is supported")
		}
		uid := x.sh.UID
		if root {
			uid = 0
		}
		fmt.Fprintln(out, uid)
		return 0
	case "mkdir":
		return x.mkdir(argv[1:], root, errw)
	case "stat":
		return x.stat(argv[1:], out, errw)
	case "env":
		i := 1
		for i < len(argv) && assignRe.MatchString(argv[i]) {
			i++
		}
		if i == len(argv) {
			x.fail("env without a command")
		}
		return x.command(argv[i:], out, errw)
	case "cat":
		if len(argv) != 2 {
			x.fail("only cat FILE is supported")
		}
		v, ok := x.s.File(x.resolve(argv[1]))
		if !ok {
			fmt.Fprintf(errw, "cat: %s: No such file or directory\n", argv[1])
			return 1
		}
		io.WriteString(out, v)
		return 0
	case "cp":
		if len(argv) != 3 {
			x.fail("only cp SRC DST is supported")
		}
		v, ok := x.s.File(x.resolve(argv[1]))
		if !ok {
			fmt.Fprintf(errw, "cp: cannot stat %s\n", argv[1])
			return 1
		}
		dst := x.resolve(argv[2])
		if !x.canCreate(dst, root) {
			fmt.Fprintf(errw, "cp: cannot create regular file %s: Permission denied\n", argv[2])
			return 1
		}
		x.writeFile(dst, v, false, root)
		return 0
	case "cmp":
		if len(argv) != 4 || argv[1] != "-s" {
			x.fail("only cmp -s A B is supported")
		}
		a, okA := x.s.File(argv[2])
		b, okB := x.s.File(argv[3])
		switch {
		case !okA || !okB:
			return 2
		case a == b:
			return 0
		}
		return 1
	case "sed":
		return x.sed(argv[1:], out, errw)
	}
	if body, ok := x.funcs[argv[0]]; ok {
		if len(argv) != 1 {
			x.fail("function arguments are not supported")
		}
		if x.depth > 8 {
			x.fail("too deep")
		}
		x.depth++
		x.runLines(body)
		x.depth--
		return x.status
	}
	if strings.ContainsAny(argv[0], " \t") {
		x.fail("bad command %q", argv[0])
	}
	cmd := strings.Join(argv, " ")
	h, ok := x.s.opts.Commands[cmd]
	if !ok {
		h, ok = x.s.opts.Commands[argv[0]]
	}
	if !ok {
		fmt.Fprintf(errw, "sh: %s: not found\n", argv[0])
		return 127
	}
	return h(Exec{Ctx: context.Background(), Args: argv, Stdin: x.stdin, Stdout: out, Stderr: errw})
}

func parent(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (x *interp) underHome(p string) bool {
	return p == x.home || strings.HasPrefix(p, x.home+"/")
}

func (x *interp) dirExists(d string) bool {
	if d == "/" || d == x.home || x.dirs[d] || x.sh.Meta[d].Dir {
		return true
	}
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	for f := range x.s.files {
		if strings.HasPrefix(f, d+"/") {
			return true
		}
	}
	return false
}

func (x *interp) fileExists(p string) bool {
	_, ok := x.s.File(x.resolve(p))
	return ok
}

// resolve follows the shell's symbolic links.
func (x *interp) resolve(p string) string {
	for i := 0; i < 8; i++ {
		t, ok := x.sh.Links[p]
		if !ok {
			return p
		}
		p = t
	}
	return p
}

// meta returns the owner and mode of p (not following a link).
func (x *interp) meta(p string) Meta {
	if m, ok := x.sh.Meta[p]; ok {
		return m
	}
	dir := !x.fileExists(p) && x.dirExists(p)
	m := Meta{Mode: 0o644, Dir: dir}
	if dir {
		m.Mode = 0o755
	}
	if x.underHome(p) {
		m.UID = x.sh.UID
	}
	return m
}

// owns tells whether the user may write p, which it owns with u+w.
func (x *interp) owns(p string) bool {
	m := x.meta(p)
	return m.UID == x.sh.UID && m.Mode&0o200 != 0
}

func (x *interp) writable(p string, root bool) bool {
	p = x.resolve(p)
	return root || x.s.opts.Writable[p] || x.owns(p)
}

// canCreate tells whether p may be written: an existing writable file, or
// a new one in an existing folder the user may write.
func (x *interp) canCreate(p string, root bool) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	p = x.resolve(p)
	if x.fileExists(p) {
		return x.writable(p, root)
	}
	return x.dirExists(parent(p)) && (root || x.owns(parent(p)))
}

// writeFile writes p (a link followed); a new file belongs to its writer.
func (x *interp) writeFile(p, content string, appendTo, root bool) {
	p = x.resolve(p)
	prev, existed := x.s.File(p)
	if !appendTo {
		prev = ""
	}
	if !existed {
		uid := x.sh.UID
		if root {
			uid = 0
		}
		x.sh.Meta[p] = Meta{UID: uid, Mode: 0o666 &^ x.umask}
	}
	x.s.SetFile(p, prev+content)
}

// mkdir runs mkdir [-p] [-m MODE] DIR.
func (x *interp) mkdir(args []string, root bool, errw io.Writer) int {
	parents, mode := false, uint32(0o777)&^x.umask
	for len(args) > 1 {
		switch args[0] {
		case "-p":
			parents, args = true, args[1:]
		case "-m":
			n, err := strconv.ParseUint(args[1], 8, 32)
			if err != nil || n > 0o777 {
				x.fail("mkdir: bad mode")
			}
			mode, args = uint32(n), args[2:]
		default:
			x.fail("mkdir: unsupported %q", args[0])
		}
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "/") {
		x.fail("mkdir: one absolute folder")
	}
	d := strings.TrimRight(args[0], "/")
	uid := x.sh.UID
	if root {
		uid = 0
	}
	make1 := func(p string, m uint32) bool {
		if !x.dirExists(parent(p)) || !(root || x.owns(parent(p))) {
			fmt.Fprintf(errw, "mkdir: cannot create directory %s: Permission denied\n", p)
			return false
		}
		x.dirs[p] = true
		x.sh.Meta[p] = Meta{UID: uid, Mode: m, Dir: true}
		return true
	}
	if !parents {
		if x.dirExists(d) || x.fileExists(d) || x.sh.Links[d] != "" {
			fmt.Fprintf(errw, "mkdir: cannot create directory %s: File exists\n", d)
			return 1
		}
		if !make1(d, mode) {
			return 1
		}
		return 0
	}
	var todo []string
	for p := d; p != "/" && !x.dirExists(p); p = parent(p) {
		todo = append([]string{p}, todo...)
	}
	for _, p := range todo {
		m := uint32(0o777) &^ x.umask
		if p == d {
			m = mode
		}
		if !make1(p, m) {
			return 1
		}
	}
	return 0
}

// stat runs stat -c FORMAT PATH with %u, %a and %A; a link is described
// itself, never followed.
func (x *interp) stat(args []string, out, errw io.Writer) int {
	if len(args) != 3 || args[0] != "-c" {
		x.fail("only stat -c FORMAT PATH is supported")
	}
	p := args[2]
	var m Meta
	typ := byte('-')
	switch {
	case x.sh.Links[p] != "":
		m, typ = Meta{UID: x.meta(p).UID, Mode: 0o777}, 'l'
	case x.fileExists(p) || x.dirExists(p):
		m = x.meta(p)
		if m.Dir {
			typ = 'd'
		}
	default:
		fmt.Fprintf(errw, "stat: cannot statx '%s': No such file or directory\n", p)
		return 1
	}
	sym := []byte{typ}
	for i := 8; i >= 0; i-- {
		c := "rwx"[(8-i)%3]
		if m.Mode&(1<<uint(i)) == 0 {
			c = '-'
		}
		sym = append(sym, c)
	}
	f := args[1]
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		if f[i] != '%' || i+1 >= len(f) {
			b.WriteByte(f[i])
			continue
		}
		i++
		switch f[i] {
		case 'u':
			b.WriteString(strconv.Itoa(m.UID))
		case 'a':
			b.WriteString(strconv.FormatUint(uint64(m.Mode), 8))
		case 'A':
			b.Write(sym)
		default:
			x.fail("stat: unsupported %%%c", f[i])
		}
	}
	fmt.Fprintln(out, b.String())
	return 0
}

func (x *interp) test(args []string, root bool) int {
	b := func(v bool) int {
		if v {
			return 0
		}
		return 1
	}
	if len(args) > 0 && args[0] == "!" {
		return 1 - x.test(args[1:], root)
	}
	switch {
	case len(args) == 2 && args[0] == "-L":
		_, ok := x.sh.Links[args[1]]
		return b(ok)
	case len(args) == 2 && args[0] == "-w":
		return b(x.fileExists(args[1]) && x.writable(args[1], root))
	case len(args) == 2 && args[0] == "-r":
		return b(x.fileExists(args[1]))
	case len(args) == 2 && args[0] == "-f":
		return b(x.fileExists(args[1]))
	case len(args) == 2 && args[0] == "-e":
		return b(x.fileExists(args[1]) || x.dirExists(args[1]))
	case len(args) == 3 && args[1] == "=":
		return b(args[0] == args[2])
	case len(args) == 3 && args[1] == "!=":
		return b(args[0] != args[2])
	}
	x.fail("test: unsupported %q", args)
	return 2
}

func (x *interp) printf(args []string, out io.Writer) int {
	if len(args) == 0 {
		x.fail("printf: no format")
	}
	format, rest := args[0], args[1:]
	for {
		var b strings.Builder
		used := 0
		for i := 0; i < len(format); i++ {
			c := format[i]
			switch {
			case c == '\\' && i+1 < len(format) && format[i+1] == 'n':
				b.WriteByte('\n')
				i++
			case c == '\\' && i+1 < len(format) && format[i+1] == '\\':
				b.WriteByte('\\')
				i++
			case c == '%' && i+1 < len(format) && format[i+1] == 's':
				if used < len(rest) {
					b.WriteString(rest[used])
				}
				used++
				i++
			case c == '%' && i+1 < len(format) && format[i+1] == '%':
				b.WriteByte('%')
				i++
			case c == '\\' || c == '%':
				x.fail("printf: unsupported format %q", format)
			default:
				b.WriteByte(c)
			}
		}
		io.WriteString(out, b.String())
		if used == 0 || used >= len(rest) {
			return 0
		}
		rest = rest[used:]
	}
}

var sedScript = regexp.MustCompile(`^([1-9][0-9]*)s\|([^|]*)\|([^|]*)\|$`)

// sed runs `sed 'Ns|re|text|' FILE`: one substitution on line N.
func (x *interp) sed(args []string, out, errw io.Writer) int {
	if len(args) != 2 {
		x.fail("only sed 'Ns|re|text|' FILE is supported")
	}
	m := sedScript.FindStringSubmatch(args[0])
	if m == nil {
		x.fail("sed: unsupported script %q", args[0])
	}
	if strings.ContainsAny(m[3], "&\\\n") {
		x.fail("sed: unsupported replacement %q", m[3])
	}
	re, err := breToGo(m[2])
	if err != nil {
		x.fail("sed: %v", err)
	}
	n, _ := strconv.Atoi(m[1])
	content, ok := x.s.File(args[1])
	if !ok {
		fmt.Fprintf(errw, "sed: can't read %s: No such file or directory\n", args[1])
		return 2
	}
	lines := strings.Split(content, "\n")
	count := len(lines)
	if strings.HasSuffix(content, "\n") {
		count--
	}
	if n <= count {
		l := lines[n-1]
		if loc := re.FindStringIndex(l); loc != nil {
			lines[n-1] = l[:loc[0]] + m[3] + l[loc[1]:]
		}
	}
	io.WriteString(out, strings.Join(lines, "\n"))
	return 0
}

// breToGo converts the basic regular expressions serverfix writes (literal
// characters, escaped . [ ] * ^ $ / |, bracket expressions with POSIX
// classes, . * and the ^ $ anchors) to Go; groups, intervals and back
// references are refused.
func breToGo(p string) (*regexp.Regexp, error) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '\\':
			if i+1 >= len(p) || strings.IndexByte(`.[]*^$/|`, p[i+1]) < 0 {
				return nil, fmt.Errorf("unsupported escape in %q", p)
			}
			b.WriteByte('\\')
			b.WriteByte(p[i+1])
			i++
		case '[':
			j := i + 1
			if j < len(p) && p[j] == '^' {
				j++
			}
			if j < len(p) && p[j] == ']' {
				j++
			}
			for ; j < len(p) && p[j] != ']'; j++ {
				if p[j] == '\\' {
					return nil, fmt.Errorf("backslash in a bracket in %q", p)
				}
				if strings.HasPrefix(p[j:], "[:") {
					k := strings.Index(p[j:], ":]")
					if k < 0 {
						return nil, fmt.Errorf("bad class in %q", p)
					}
					j += k + 1
				}
			}
			if j >= len(p) {
				return nil, fmt.Errorf("unterminated bracket in %q", p)
			}
			b.WriteString(p[i : j+1])
			i = j
		case '^':
			if i == 0 {
				b.WriteByte('^')
			} else {
				b.WriteString(`\^`)
			}
		case '$':
			if i == len(p)-1 {
				b.WriteByte('$')
			} else {
				b.WriteString(`\$`)
			}
		case '.', '*':
			b.WriteByte(c)
		default:
			if c < 0x20 {
				return nil, fmt.Errorf("control character in %q", p)
			}
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return regexp.Compile(b.String())
}
