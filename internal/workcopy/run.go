package workcopy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/scan"
)

// Test statuses.
const (
	TestsPassed = "passed"
	TestsFailed = "failed"
	TestsNotRun = "not_run"
)

var (
	// ErrNoLockfile: the lockfile to install from is not in the copy.
	ErrNoLockfile = errors.New("no lockfile to install from")
	// ErrUnsupportedLockfile: not a lockfile, or a lockfile of another
	// ecosystem.
	ErrUnsupportedLockfile = errors.New("not a lockfile Michel installs from")
	// ErrShellSyntax: a test command that needs a shell.
	ErrShellSyntax = errors.New("the command needs a shell (pipes, redirections, variables or several commands); Michel runs one program")
)

// CmdError is a subprocess that failed. Output is what it wrote, sanitized
// and capped; it is not part of Error(), so that it reaches a message only
// where the caller chooses.
type CmdError struct {
	Cmd    string
	Err    error
	Output string
}

func (e *CmdError) Error() string { return e.Cmd + " failed: " + noPath(e.Err).Error() }
func (e *CmdError) Unwrap() error { return e.Err }

// combined is what a command wrote, stdout then stderr, each capped at
// maxStream bytes and sanitized (scan.SanitizeText).
func combined(stdout, stderr []byte) string {
	part := func(b []byte) string {
		if len(b) > maxStream {
			b = b[:maxStream]
		}
		return scan.SanitizeText(strings.ToValidUTF8(string(b), "�"))
	}
	var b strings.Builder
	if len(stdout) > 0 {
		b.WriteString(part(stdout))
		if !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
	}
	if len(stderr) > 0 {
		b.WriteString(part(stderr))
	}
	return b.String()
}

// RunTests runs the project's test command, already split into argv
// (SplitCommand of project.TestCmd, never a shell), in the copy with the
// fix environment. No command: not_run. Exit 0: passed; another exit code:
// failed, err nil. A program that cannot start: not_run with the error. A
// command cut by ctx: failed with ctx's error. output is stdout then
// stderr, each capped at 64 KiB, sanitized.
func RunTests(ctx context.Context, d Deps, c Copy, testCmd []string) (status, output string, err error) {
	if len(testCmd) == 0 || testCmd[0] == "" {
		return TestsNotRun, "", nil
	}
	if err := copyDir(d, c); err != nil {
		return TestsNotRun, "", err
	}
	h, err := ensureHome(d)
	if err != nil {
		return TestsNotRun, "", err
	}
	stdout, stderr, err := d.exec()(ctx, testCmd[0], testCmd[1:], h.env(d.ProxyAddr), c.Dir)
	out := combined(stdout, stderr)
	switch {
	case err == nil:
		return TestsPassed, out, nil
	case ctx.Err() != nil:
		return TestsFailed, out, ctx.Err()
	case errors.As(err, new(*exec.ExitError)):
		return TestsFailed, out, nil
	default:
		return TestsNotRun, out, fmt.Errorf("Michel cannot start the tests: %w", noPath(err))
	}
}

// assignment is a leading NAME=value word, which only a shell understands.
var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// SplitCommand splits a declared command (project.TestCmd) into argv the
// way a POSIX shell splits words, without running one: blanks separate
// words, '...' is literal, "..." allows \" \\ \$ and \` escapes, a
// backslash outside quotes escapes the next character. Anything only a
// shell would do (| & ; < > ( ) $ ` unquoted, $ or ` in double quotes, a
// leading NAME=value) is ErrShellSyntax. A blank command is nil.
func SplitCommand(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inWord := false
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		case r == '\'':
			inWord = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unclosed single quote in the command")
			}
			cur.WriteString(string(rs[i+1 : j]))
			i = j
		case r == '"':
			inWord = true
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				switch rs[j] {
				case '\\':
					if j+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[j+1]) {
						j++
					}
				case '$', '`':
					return nil, ErrShellSyntax
				}
				cur.WriteRune(rs[j])
			}
			if j == len(rs) {
				return nil, errors.New("unclosed double quote in the command")
			}
			i = j
		case r == '\\':
			if i+1 == len(rs) {
				return nil, errors.New("the command ends with a backslash")
			}
			inWord = true
			i++
			cur.WriteRune(rs[i])
		case strings.ContainsRune("|&;<>()$`", r):
			return nil, ErrShellSyntax
		default:
			inWord = true
			cur.WriteRune(r)
		}
	}
	if inWord {
		args = append(args, cur.String())
	}
	if len(args) > 0 && assignment.MatchString(args[0]) {
		return nil, ErrShellSyntax
	}
	return args, nil
}
