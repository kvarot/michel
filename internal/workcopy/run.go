package workcopy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/scan"
	"gopkg.in/yaml.v3"
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
	// ErrUnsupportedLockfile: a file Michel does not install from, or a
	// lockfile of another ecosystem.
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

// lockfileEcosystem is the OSV ecosystem of each lockfile Michel installs from.
var lockfileEcosystem = map[string]string{
	"composer.lock":     "Packagist",
	"package-lock.json": "npm",
	"pnpm-lock.yaml":    "npm",
	"yarn.lock":         "npm",
}

// installArgv is the closed install command of a lockfile: never a script
// of the project (v1 design § 4.5), never an interactive prompt, never the
// user's npm configuration (npmrc is Michel's empty file).
func installArgv(name string, content []byte, npmrc string) (string, []string) {
	switch name {
	case "composer.lock":
		return "composer", []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}
	case "package-lock.json":
		return "npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund", "--userconfig", npmrc}
	case "pnpm-lock.yaml":
		return "pnpm", []string{"install", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"}
	default: // yarn.lock: berry (YAML with __metadata) or v1
		if strings.Contains(string(content), "__metadata:") {
			return "yarn", []string{"install", "--immutable", "--mode=skip-build"}
		}
		return "yarn", []string{"install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive"}
	}
}

// ErrUnsafeInstall: the project would make the package manager run its own
// code (a yarn release or plugin of the repository, another package manager
// than the one of the lockfile).
var ErrUnsafeInstall = errors.New("the project's settings would make the install run code from the repository")

// insideCopy resolves the symbolic links of dir and checks that it stays
// inside the copy (whose own links are resolved too).
func insideCopy(c Copy, dir string) error {
	root, err := filepath.EvalSymlinks(c.Dir)
	if err != nil {
		return ErrNotACopy
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoLockfile, filepath.Base(dir))
	}
	if rel, err := filepath.Rel(root, real); err != nil || (rel != "." && !filepath.IsLocal(rel)) {
		return fmt.Errorf("%w: the folder of the lockfile leads outside the copy", ErrOutsideCopy)
	}
	return nil
}

// checkYarn refuses a yarn install that would run code of the repository:
// a .yarnrc.yml setting yarnPath or plugins, or a .yarnrc setting
// yarn-path, in the folder of the lockfile or any folder above it in the
// copy (yarn reads them all).
func checkYarn(root, dir string) error {
	for d := dir; ; d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, ".yarnrc.yml")); err == nil {
			var cfg map[string]any
			if yaml.Unmarshal(b, &cfg) != nil {
				return fmt.Errorf("%w: .yarnrc.yml cannot be read", ErrUnsafeInstall)
			}
			for _, k := range []string{"yarnPath", "plugins"} {
				if _, ok := cfg[k]; ok {
					return fmt.Errorf("%w: .yarnrc.yml sets %s", ErrUnsafeInstall, k)
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(d, ".yarnrc")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if k := strings.TrimSpace(line); strings.HasPrefix(k, "yarn-path") || strings.HasPrefix(k, `"yarn-path"`) {
					return fmt.Errorf("%w: .yarnrc sets yarn-path", ErrUnsafeInstall)
				}
			}
		}
		if d == root || filepath.Dir(d) == d {
			return nil
		}
	}
}

// checkPackageManager refuses an install when package.json (next to the
// lockfile) names another package manager than prog in packageManager:
// corepack would fetch and run that one instead.
func checkPackageManager(dir, prog string) error {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if json.Unmarshal(b, &pkg) != nil {
		return fmt.Errorf("%w: package.json cannot be read", ErrUnsafeInstall)
	}
	if pkg.PackageManager == "" {
		return nil
	}
	name, _, _ := strings.Cut(pkg.PackageManager, "@")
	if strings.TrimSpace(name) != prog {
		return fmt.Errorf("%w: package.json asks for %s, the lockfile is %s's", ErrUnsafeInstall, scan.SanitizeText(name), prog)
	}
	return nil
}

// Install installs the dependencies of the lockfile manifestRel (a slash
// path relative to the copy, the finding's manifest) of ecosystem, in its
// folder of the copy, without scripts: composer install --no-scripts
// --no-interaction --no-plugins, npm ci --ignore-scripts (Michel's empty
// npmrc), pnpm install --ignore-scripts --ignore-pnpmfile, or yarn install
// without builds. A project that would make the install run its own code
// is ErrUnsafeInstall. The registries are reached through the egress proxy
// only. A failed install is a *CmdError.
func Install(ctx context.Context, d Deps, c Copy, ecosystem, manifestRel string) error {
	if err := copyDir(d, c); err != nil {
		return err
	}
	rel := filepath.FromSlash(manifestRel)
	if !filepath.IsLocal(rel) || strings.Contains(manifestRel, `\`) {
		return fmt.Errorf("%w: %s", ErrUnsupportedLockfile, manifestRel)
	}
	name := filepath.Base(rel)
	eco, ok := lockfileEcosystem[name]
	if !ok || eco != ecosystem {
		return fmt.Errorf("%w: %s (%s)", ErrUnsupportedLockfile, manifestRel, ecosystem)
	}
	full := filepath.Join(c.Dir, rel)
	dir := filepath.Dir(full)
	if err := insideCopy(c, dir); err != nil {
		return err
	}
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNoLockfile, manifestRel)
	}
	content, err := os.ReadFile(full)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoLockfile, manifestRel)
	}
	h, err := ensureHome(d)
	if err != nil {
		return err
	}
	prog, args := installArgv(name, content, h.npmrc())
	if prog == "yarn" {
		if err := checkYarn(c.Dir, dir); err != nil {
			return err
		}
	}
	if eco == "npm" {
		if err := checkPackageManager(dir, prog); err != nil {
			return err
		}
	}
	stdout, stderr, err := d.exec()(ctx, prog, args, h.env(d.ProxyAddr), dir)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return &CmdError{Cmd: prog + " " + args[0], Err: err, Output: combined(stdout, stderr)}
	}
	return nil
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
