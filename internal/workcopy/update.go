package workcopy

import (
	"context"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
)

// ErrInvalidUpdate: an update argv that is not one of the closed forms.
var ErrInvalidUpdate = errors.New("the update command is not one Michel runs")

// Shapes of the arguments of an update command (the package names and
// versions of the plan, re-validated here, at the sink).
var (
	composerPkgArg = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*(:\^[0-9A-Za-z.+_-]{1,64})?$`)
	npmPkgArg      = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(@[0-9A-Za-z.+_-]{1,64})?$`)
)

// updateForms are the closed update commands (controller rulings 33 and
// 36): the subcommand, the flags that must be present, the flags that may
// be, and the shape of the one package argument.
var updateForms = map[string]struct {
	subs     []string
	required []string
	optional []string
	pkg      *regexp.Regexp
}{
	"composer": {[]string{"update", "require"}, []string{"--no-scripts", "--no-plugins", "--no-interaction"},
		[]string{"--with-all-dependencies", "--with-dependencies", "--update-with-all-dependencies"}, composerPkgArg},
	"npm": {[]string{"install", "update"}, []string{"--ignore-scripts", "--no-audit", "--no-fund"}, []string{"--save-exact"}, npmPkgArg},
}

// checkUpdateArgv validates argv against the closed forms for the program
// of the lockfile name: exactly one package argument, the required flags
// all present, nothing else.
func checkUpdateArgv(name string, argv []string) error {
	prog := "npm"
	if name == "composer.lock" {
		prog = "composer"
	}
	form := updateForms[prog]
	if len(argv) < 3 || argv[0] != prog || !slices.Contains(form.subs, argv[1]) {
		return ErrInvalidUpdate
	}
	pkgs, flags := 0, map[string]bool{}
	for _, a := range argv[2:] {
		switch {
		case strings.HasPrefix(a, "-"):
			if !slices.Contains(form.required, a) && !slices.Contains(form.optional, a) || flags[a] {
				return ErrInvalidUpdate
			}
			flags[a] = true
		case form.pkg.MatchString(a) && !strings.Contains(a, ".."):
			pkgs++
		default:
			return ErrInvalidUpdate
		}
	}
	if pkgs != 1 {
		return ErrInvalidUpdate
	}
	for _, r := range form.required {
		if !flags[r] {
			return ErrInvalidUpdate
		}
	}
	return nil
}

// Update runs the planned update command argv (one of the closed forms:
// composer update|require <pkg[:^ver]> --no-scripts --no-plugins
// --no-interaction [--with-all-dependencies|--with-dependencies|
// --update-with-all-dependencies], npm install|update <pkg[@ver]>
// --ignore-scripts --no-audit --no-fund [--save-exact]) in the folder of
// the lockfile manifestRel, with every check Install makes before it runs
// (settings allowlists, strict lockfile reads, link refusals, fresh output
// folders) and the same environment (fix home, Michel's empty npmrc,
// proxy). yarn.lock and pnpm-lock.yaml are ErrInstallUnsupported; an argv
// outside the forms is ErrInvalidUpdate; a failed command is a *CmdError.
func Update(ctx context.Context, d Deps, c Copy, ecosystem, manifestRel string, argv []string) error {
	p, err := prepareInstall(ctx, d, c, ecosystem, manifestRel)
	if err != nil {
		return err
	}
	defer p.root.Close()
	if err := checkUpdateArgv(p.name, argv); err != nil {
		return err
	}
	args := append([]string{}, argv[1:]...)
	if argv[0] == "npm" {
		args = append(args, "--userconfig", p.h.npmrc())
	}
	err = p.run(ctx, d, argv[0], args)
	// What the update installed (vendor, node_modules) is Michel's output,
	// not part of the change: it goes, whether the command succeeded or
	// failed. Michel installs again in the scratch worktree at Propose. A
	// folder that cannot be removed stays out of the change anyway (the
	// pathspecs of c leave it out).
	_ = removeInstallOutput(p.root, c.InstallDirs)
	return err
}

// TreeHash is the tree id of the copy's content as a change would commit
// it: the index restarted from Root, every file added (excluded files
// left out), git write-tree. Two equal hashes mean the same files with the
// same content.
func TreeHash(ctx context.Context, d Deps, c Copy) (string, error) {
	if err := checkCopy(d, c); err != nil {
		return "", err
	}
	if !shaShape.MatchString(c.Root) {
		return "", ErrInvalidCommit
	}
	h, err := ensureHome(d)
	if err != nil {
		return "", err
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "read-tree", c.Root); err != nil {
		return "", gitErr("read-tree", err, stderr)
	}
	if _, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "add", append([]string{"-A", "--"}, c.pathspecs()...)...); err != nil {
		return "", gitErr("add", err, stderr)
	}
	out, stderr, err := h.git(ctx, d, c.Dir, c.Dir, nil, nil, "write-tree")
	if err != nil {
		return "", gitErr("write-tree", err, stderr)
	}
	tree := strings.TrimSpace(string(out))
	if !shaShape.MatchString(tree) {
		return "", errors.New("git write-tree returned an unexpected tree id")
	}
	return tree, nil
}

// CommitFile returns the content of the file rel (slash path) in the fix
// commit sha of the mirror, never from the working tree; ok is false when
// the commit has no such file.
func CommitFile(ctx context.Context, d Deps, c Copy, sha, rel string) (content []byte, ok bool, err error) {
	if err := checkCopy(d, c); err != nil {
		return nil, false, err
	}
	if !shaShape.MatchString(sha) {
		return nil, false, ErrInvalidCommit
	}
	if err := checkEntry(rawEntry{path: rel, mode: "100644"}); err != nil {
		return nil, false, err
	}
	h, err := ensureHome(d)
	if err != nil {
		return nil, false, err
	}
	out, stderr, err := h.git(ctx, d, c.Mirror, c.Mirror, nil, nil, "show", sha+":"+rel)
	if err != nil {
		if exitCode(err) == 128 {
			return nil, false, nil
		}
		return nil, false, gitErr("show", err, stderr)
	}
	if len(out) >= maxGitOutput {
		return nil, false, ErrDiffTooLarge
	}
	return out, true, nil
}

// ManifestOf is the manifest next to a lockfile (slash path), "" for a
// lockfile Michel does not update.
func ManifestOf(lockRel string) string {
	dir, base := path.Dir(lockRel), path.Base(lockRel)
	var m string
	switch base {
	case "composer.lock":
		m = "composer.json"
	case "package-lock.json":
		m = "package.json"
	default:
		return ""
	}
	if dir == "." {
		return m
	}
	return dir + "/" + m
}
