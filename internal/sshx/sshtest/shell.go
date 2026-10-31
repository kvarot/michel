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
// with single and double quotes, "$VAR", "${VAR}" and "$(id -u)" inside
// double quotes, ;, ||, { ...; }, if ...; then ...; fi on one line,
// redirections >, >> and >&2, NAME="..." assignments, name() { ... }
// functions over several lines, set -eu, umask, trap (EXIT runs on exit)
// and exit. Built-in commands: echo, printf (%s and \n), true, test and [
// (-L -w -r -e -f ! = !=), mkdir -p, cat, cp, cmp -s, sed 'Ns|re|text|' (one
// substitution on one line, basic regular expressions without groups),
// id -u, and sudo -n (allowed when Options.Sudo). Any other command runs
// the server's Options.Commands handler. Nothing is ever deleted: the
// shell has no rm.
//
// Permissions: root (UID 0, or a command run with sudo -n) writes every
// file; the user writes under Home and the paths of Options.Writable.
type Shell struct {
	// UID is the user's id; 0 is root.
	UID int
	// Home is $HOME; "" means /home/demo.
	Home string
	// Links are symbolic links (path → target): test -L sees them, cat and
	// cp follow them, as a real system would.
	Links map[string]string

	mu  sync.Mutex
	ran []string
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
	stdout  io.Writer
	stderr  io.Writer
	status  int
	depth   int
}

// Run runs script and returns its exit status.
func (sh *Shell) Run(s *Server, script string, stdout, stderr io.Writer) int {
	home := sh.Home
	if home == "" {
		home = "/home/demo"
	}
	x := &interp{sh: sh, s: s, home: home, vars: map[string]string{"HOME": home}, funcs: map[string][]string{},
		traps: map[string]string{}, dirs: map[string]bool{}, stdout: stdout, stderr: stderr}
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

var funcDef = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\(\) \{$`)

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
		toks, err := tokenize(line)
		if err != nil {
			x.fail("%v: %q", err, line)
		}
		if len(toks) == 0 {
			continue
		}
		p := &parser{toks: toks}
		list, err := p.list(nil)
		if err == nil && p.i != len(p.toks) {
			err = fmt.Errorf("unexpected %q", p.toks[p.i].text)
		}
		if err != nil {
			x.fail("%v: %q", err, line)
		}
		x.status = x.runList(list, false)
	}
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
		case c == '&' || c == '<' || c == '(' || c == ')' || c == '`' || c == '*' || c == '?':
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

type ifNode struct{ cond, body [][]node }

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
		body, err := p.list([]string{"fi"})
		if err != nil {
			return nil, err
		}
		return ifNode{cond, body}, p.expect("fi")
	case "then", "fi", "}":
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
		case ">", ">>":
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
			case strings.HasPrefix(rest, "(id -u)"):
				b.WriteString(strconv.Itoa(x.sh.UID))
				i += len("(id -u)")
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
		if !x.canCreate(file, false) {
			fmt.Fprintf(errw, "sh: cannot create %s: Permission denied\n", file)
			return 2
		}
	}
	st := x.command(argv, out, errw)
	if file != "" {
		prev, _ := x.s.File(file)
		if !appendTo {
			prev = ""
		}
		x.s.SetFile(file, prev+buf.String())
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
		if len(argv) != 2 || strings.Trim(argv[1], "01234567") != "" {
			x.fail("bad umask")
		}
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
		if len(argv) != 3 || argv[1] != "-p" {
			x.fail("only mkdir -p DIR is supported")
		}
		d := strings.TrimRight(argv[2], "/")
		if !root && !x.underHome(d) {
			fmt.Fprintf(errw, "mkdir: cannot create directory %s: Permission denied\n", d)
			return 1
		}
		for p := d; p != "" && p != "/"; p = parent(p) {
			x.dirs[p] = true
		}
		return 0
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
		x.s.SetFile(dst, v)
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
	return h(Exec{Ctx: context.Background(), Args: argv, Stdin: strings.NewReader(""), Stdout: out, Stderr: errw})
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
	if d == "/" || d == x.home || x.dirs[d] {
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

func (x *interp) writable(p string, root bool) bool {
	p = x.resolve(p)
	return root || x.underHome(p) || x.s.opts.Writable[p]
}

// canCreate tells whether p may be written: an existing writable file, or
// a new one in an existing folder the user may write.
func (x *interp) canCreate(p string, root bool) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if x.fileExists(p) {
		return x.writable(p, root)
	}
	return x.dirExists(parent(p)) && (root || x.underHome(p))
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
