package workcopy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// lockfileEcosystem is the OSV ecosystem of each lockfile Michel knows.
var lockfileEcosystem = map[string]string{
	"composer.lock":     "Packagist",
	"package-lock.json": "npm",
	"pnpm-lock.yaml":    "npm",
	"yarn.lock":         "npm",
}

var (
	// ErrInstallUnsupported: a yarn.lock or a pnpm-lock.yaml. Michel installs
	// with composer and npm only (their settings can be checked); the caller
	// reports the tests as not run.
	ErrInstallUnsupported = errors.New("Michel installs with composer and npm only; this lockfile's dependencies are not installed and the tests are not run")
	// ErrUnsafeInstall: the project's settings would make the install run
	// code, read files or write outside what Michel allows.
	ErrUnsafeInstall = errors.New("the project's settings would make the install run code from the repository or leave the copy")
)

// Caps on what Michel reads of a project's settings and lockfiles.
const (
	maxSettingsFile int64 = 4 << 20
	maxLockfile     int64 = 64 << 20
)

// install is the closed install command of a lockfile and the folder it
// fills next to it: never a script of the project (v1 design § 4.5), never a
// plugin, never an interactive prompt, never the user's npm configuration
// (npmrc is Michel's empty file).
type install struct {
	prog   string
	args   []string
	folder string
}

func installFor(name, npmrc string) install {
	if name == "composer.lock" {
		return install{"composer", []string{"install", "--no-scripts", "--no-interaction", "--no-plugins"}, "vendor"}
	}
	return install{"npm", []string{"ci", "--ignore-scripts", "--no-audit", "--no-fund", "--userconfig", npmrc}, "node_modules"}
}

// ---- files of the copy, through its root

// Every path below is a slash path relative to the copy ("." is the copy
// itself), opened through an os.Root of the copy: a symbolic link, a
// junction or a ".." that would leave the copy makes the operation fail,
// whatever the agent planted. filepath.EvalSymlinks is never used for
// containment (it does not resolve junctions).

// readIn reads the regular file rel of the copy, at most max bytes. A
// missing file is fs.ErrNotExist; a link, a folder, a path through a link
// that leaves the copy or a larger file is another error.
func readIn(root *os.Root, rel string, max int64) ([]byte, error) {
	info, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path.Base(rel))
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is too large", path.Base(rel))
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is too large", path.Base(rel))
	}
	return b, nil
}

// settings reads the settings file rel of the copy: nil, nil when there is
// none; ErrUnsafeInstall when it is there but cannot be read as a plain file.
func settings(root *os.Root, rel string) ([]byte, error) {
	b, err := readIn(root, rel, maxSettingsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be read", ErrUnsafeInstall, path.Base(rel))
	}
	return b, nil
}

// realFolder checks that dir is a folder of the copy: the root refuses a
// link that leaves the copy on the way, and the folder itself must not be
// a link of any kind (symbolic link, junction).
func realFolder(root *os.Root, dir string) error {
	info, err := root.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNoLockfile, path.Base(dir))
	}
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: the folder of the lockfile leads outside the copy", ErrOutsideCopy)
	}
	return nil
}

// upTo calls f on dir and every folder above it up to the copy itself
// ("."), both included.
func upTo(dir string, f func(string) error) error {
	for d := dir; ; d = path.Dir(d) {
		if err := f(d); err != nil {
			return err
		}
		if d == "." || d == "/" || d == "" {
			return nil
		}
	}
}

// lines splits a settings file the way npm's ini reader does: on \r\n, \r
// and \n alike (a lone \r must not hide a second setting on one line).
func lines(b []byte) []string {
	return strings.FieldsFunc(string(b), func(r rune) bool { return r == '\n' || r == '\r' })
}

// ---- npm

// npmPackageManager is the only packageManager value accepted for an npm
// install: an exact npm version, optionally with its hash. A URL, a path,
// a tag (latest) or another manager would make corepack fetch and run code
// chosen by the repository.
var npmPackageManager = regexp.MustCompile(`^npm@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?(?:\+sha(?:1|224|256|512)\.[0-9a-f]+)?$`)

// semver is an exact version of a locked npm package: never a URL, a path,
// a file: or git spec.
var semver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// npmKey is the only shape of .npmrc key Michel accepts: the registry, a
// scope's registry, the credentials of a registry host, always-auth. Any
// other setting (proxy, store, scripts, git, shell, TLS...) refuses the
// install: the allowlist is the list, not the dangerous keys.
var npmKey = regexp.MustCompile(`^(?:registry|always-auth|@[a-z0-9][a-z0-9._-]*:registry|//[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._~%@/-]*)?:(?:_authToken|_auth|username|_password))$`)

// plainKey reports whether k is written plainly: no quote, no variable,
// no backslash, no space, no section.
func plainKey(k string) bool {
	return k != "" && !strings.ContainsAny(k, "\"'`\\ \t$[]{}")
}

// checkNpmrc refuses an install when a .npmrc from the folder of the
// lockfile up to the copy root holds a key outside npmKey.
func checkNpmrc(root *os.Root, dir string) error {
	return upTo(dir, func(d string) error {
		b, err := settings(root, path.Join(d, ".npmrc"))
		if err != nil || b == nil {
			return err
		}
		for _, line := range lines(b) {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			k, _, _ := strings.Cut(line, "=")
			k = strings.TrimSpace(k)
			if !plainKey(k) || !npmKey.MatchString(k) {
				return fmt.Errorf("%w: .npmrc holds a setting Michel does not allow", ErrUnsafeInstall)
			}
		}
		return nil
	})
}

// localSpec reports whether an npm dependency spec points at the file
// system: file:, link:, portal:, a relative or absolute path, a drive.
func localSpec(spec string) bool {
	s := strings.ToLower(strings.TrimSpace(spec))
	for _, p := range []string{"file:", "link:", "portal:", "git+file:", "./", "../", "/", "~/", "\\", "."} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return len(s) >= 2 && s[1] == ':' && s[0] >= 'a' && s[0] <= 'z'
}

// escapes reports whether a slash or backslash path is absolute or climbs
// out of its folder.
func escapes(p string) bool {
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') {
		return true
	}
	return slices.Contains(strings.Split(p, "/"), "..")
}

// checkSpecs refuses a local spec in a dependency map (overrides may nest).
func checkSpecs(v any) error {
	switch t := v.(type) {
	case string:
		if localSpec(t) {
			return errors.New("a dependency points at a local path")
		}
	case map[string]any:
		for _, x := range t {
			if err := checkSpecs(x); err != nil {
				return err
			}
		}
	case nil, bool, json.Number:
	default:
		return errors.New("unexpected dependencies")
	}
	return nil
}

// checkPackageJSON refuses an npm install when a package.json from the
// folder of the lockfile up to the copy root sets packageManager to anything
// but an exact npm version, depends on a local path (file:, link:, a
// relative or absolute path) or lists workspaces outside its folder.
func checkPackageJSON(root *os.Root, dir string) error {
	return upTo(dir, func(d string) error {
		b, err := settings(root, path.Join(d, "package.json"))
		if err != nil || b == nil {
			return err
		}
		pkg, err := strictObject(b)
		if err == nil {
			err = exactKeys(pkg, "packageManager", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "workspaces")
		}
		if err != nil {
			return fmt.Errorf("%w: package.json cannot be read: %v", ErrUnsafeInstall, err)
		}
		if v, ok := pkg["packageManager"]; ok {
			if pm, ok := asString(v); !ok || !npmPackageManager.MatchString(pm) {
				return fmt.Errorf("%w: packageManager is not an exact npm version", ErrUnsafeInstall)
			}
		}
		for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"} {
			if v, ok := pkg[k]; ok {
				if err := checkSpecs(v); err != nil {
					return fmt.Errorf("%w: package.json %s: %v", ErrUnsafeInstall, k, err)
				}
			}
		}
		if v, ok := pkg["workspaces"]; ok {
			list, ok := v.([]any)
			if !ok {
				obj, isObj := asObject(v)
				if !isObj {
					return fmt.Errorf("%w: package.json workspaces cannot be read", ErrUnsafeInstall)
				}
				if list, ok = obj["packages"].([]any); !ok && obj["packages"] != nil {
					return fmt.Errorf("%w: package.json workspaces cannot be read", ErrUnsafeInstall)
				}
			}
			for _, w := range list {
				s, ok := asString(w)
				if !ok || escapes(s) {
					return fmt.Errorf("%w: a workspace is outside the project", ErrUnsafeInstall)
				}
			}
		}
		return nil
	})
}

// validLockKey reports whether a package-lock.json packages key names a
// folder of the project: relative, without "..", a drive, a backslash or
// an unsafe segment.
func validLockKey(k string) bool {
	if k == "" || escapes(k) || strings.Contains(k, `\`) {
		return false
	}
	for _, seg := range strings.Split(k, "/") {
		if !safeSegment(seg) {
			return false
		}
	}
	return true
}

// checkPackageLock refuses a package-lock.json that npm ci would not read
// exactly as Michel does, or that installs anything but https registry
// tarballs and the project's own workspaces: lockfileVersion 2 or 3 with a
// packages object; every key a folder of the project; a linked package
// resolved to a folder of the project; an installed package resolved from
// https with an integrity and an exact version (a bundled one needs only
// the version); a workspace folder entry without a resolved.
func checkPackageLock(lock []byte) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: package-lock.json %s", ErrUnsafeInstall, fmt.Sprintf(format, a...))
	}
	doc, err := strictObject(lock)
	if err == nil {
		err = exactKeys(doc, "lockfileVersion", "packages")
	}
	if err != nil {
		return fail("cannot be read: %v", err)
	}
	version, ok := doc["lockfileVersion"].(json.Number)
	if n, err := version.Int64(); !ok || err != nil || n < 2 {
		return fail("must be a version 2 or 3 lockfile")
	}
	packages, ok := asObject(doc["packages"])
	if !ok {
		return fail("has no packages object")
	}
	for key, v := range packages {
		if key == "" {
			continue // the project itself: its package.json is checked
		}
		if !validLockKey(key) {
			return fail("names a package outside the project")
		}
		entry, ok := asObject(v)
		if !ok {
			return fail("has a package that is not an object")
		}
		if err := exactKeys(entry, "link", "inBundle", "resolved", "version", "integrity"); err != nil {
			return fail("%s: %v", key, err)
		}
		link, err := optBool(entry, "link")
		if err != nil {
			return fail("%s: %v", key, err)
		}
		bundled, err := optBool(entry, "inBundle")
		if err != nil {
			return fail("%s: %v", key, err)
		}
		resolved, err := optString(entry, "resolved")
		if err != nil {
			return fail("%s: %v", key, err)
		}
		pkgVersion, err := optString(entry, "version")
		if err != nil {
			return fail("%s: %v", key, err)
		}
		integrity, err := optString(entry, "integrity")
		if err != nil {
			return fail("%s: %v", key, err)
		}
		if pkgVersion != "" && !semver.MatchString(pkgVersion) {
			return fail("locks a package at something other than an exact version")
		}
		installed := slices.Contains(strings.Split(key, "/"), "node_modules")
		switch {
		case link:
			if resolved == "" || escapes(resolved) || strings.Contains(resolved, ":") || strings.Contains(resolved, `\`) {
				return fail("links a package outside the project")
			}
		case !installed:
			// A workspace folder of the project: nothing is fetched for it.
			if resolved != "" {
				return fail("resolves a folder of the project from elsewhere")
			}
		case bundled:
			if pkgVersion == "" {
				return fail("has a bundled package without a version")
			}
		default:
			if !strings.HasPrefix(resolved, "https://") {
				return fail("resolves a package from elsewhere than an https registry")
			}
			if integrity == "" || pkgVersion == "" {
				return fail("has a package without an integrity or a version")
			}
		}
	}
	return nil
}

// ---- composer

// composerConfigKeys are the only composer.json config settings accepted:
// none of them moves a folder, turns off TLS or runs a program.
// preferred-install is accepted with the value "dist" only: a source
// install would run git, hg or svn against the lockfile's source URLs.
var composerConfigKeys = []string{"platform", "optimize-autoloader", "sort-packages", "allow-plugins", "preferred-install", "platform-check", "audit"}

// composerDistTypes are the dist types composer downloads over https.
var composerDistTypes = []string{"zip", "tar", "phar", "rar", "gzip", "xz", "file"}

// composerSourceTypes are the version control sources composer knows.
var composerSourceTypes = []string{"git", "hg", "svn", "fossil"}

// checkComposerJSON refuses a composer.json whose config holds a setting
// outside composerConfigKeys, or whose repositories are anything but
// composer repositories over https (false, which turns packagist off, is
// accepted). Keys are read exactly: a duplicate or a case variant is
// refused.
func checkComposerJSON(root *os.Root, dir string) error {
	b, err := settings(root, path.Join(dir, "composer.json"))
	if err != nil || b == nil {
		return err
	}
	doc, err := strictObject(b)
	if err == nil {
		err = exactKeys(doc, "config", "repositories")
	}
	if err != nil {
		return fmt.Errorf("%w: composer.json cannot be read: %v", ErrUnsafeInstall, err)
	}
	if v, ok := doc["config"]; ok {
		cfg, ok := asObject(v)
		if !ok {
			return fmt.Errorf("%w: composer.json config is not an object", ErrUnsafeInstall)
		}
		for k := range cfg {
			if !slices.Contains(composerConfigKeys, k) {
				return fmt.Errorf("%w: composer.json config sets %s", ErrUnsafeInstall, k)
			}
		}
		if v, ok := cfg["preferred-install"]; ok {
			if s, ok := asString(v); !ok || s != "dist" {
				return fmt.Errorf("%w: composer.json config sets preferred-install to something other than dist", ErrUnsafeInstall)
			}
		}
	}
	v, ok := doc["repositories"]
	if !ok {
		return nil
	}
	entries, ok := v.([]any)
	if !ok {
		obj, isObj := asObject(v)
		if !isObj {
			return fmt.Errorf("%w: composer.json repositories cannot be read", ErrUnsafeInstall)
		}
		for _, e := range obj {
			entries = append(entries, e)
		}
	}
	for _, e := range entries {
		if off, ok := e.(bool); ok && !off {
			continue
		}
		repo, ok := asObject(e)
		if !ok {
			return fmt.Errorf("%w: composer.json repositories cannot be read", ErrUnsafeInstall)
		}
		if disablesOnly(repo) {
			continue
		}
		for k := range repo {
			if k != "type" && k != "url" && k != "canonical" && k != "only" && k != "exclude" {
				return fmt.Errorf("%w: composer.json repository sets %s", ErrUnsafeInstall, k)
			}
		}
		typ, _ := asString(repo["type"])
		url, _ := asString(repo["url"])
		if typ != "composer" || !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("%w: composer.json has a repository other than a composer repository over https", ErrUnsafeInstall)
		}
	}
	return nil
}

// disablesOnly reports whether a repositories entry only turns a
// repository off ({"packagist.org": false}).
func disablesOnly(repo map[string]any) bool {
	if len(repo) != 1 {
		return false
	}
	for _, v := range repo {
		off, ok := v.(bool)
		return ok && !off
	}
	return false
}

// checkComposerLock refuses a composer.lock with a package installed from
// anything but an https dist of a known type (zip, tar...) or a version
// control source at a remote URL: no path, artifact or file dist, no
// local source. Keys are read exactly (strictObject): a duplicate or a
// case variant, which PHP and Go would read differently, is refused.
func checkComposerLock(lock []byte) error {
	doc, err := strictObject(lock)
	if err == nil {
		err = exactKeys(doc, "packages", "packages-dev")
	}
	if err != nil {
		return fmt.Errorf("%w: composer.lock cannot be read: %v", ErrUnsafeInstall, err)
	}
	for _, key := range []string{"packages", "packages-dev"} {
		v, ok := doc[key]
		if !ok {
			continue
		}
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%w: composer.lock %s is not a list", ErrUnsafeInstall, key)
		}
		for _, p := range list {
			pkg, ok := asObject(p)
			if !ok {
				return fmt.Errorf("%w: composer.lock has a package that is not an object", ErrUnsafeInstall)
			}
			if err := exactKeys(pkg, "dist", "source"); err != nil {
				return fmt.Errorf("%w: composer.lock cannot be read: %v", ErrUnsafeInstall, err)
			}
			if v, ok := pkg["dist"]; ok {
				typ, url, err := origin(v)
				if err != nil || !slices.Contains(composerDistTypes, typ) || !strings.HasPrefix(url, "https://") {
					return fmt.Errorf("%w: composer.lock installs a package from a local path or without https", ErrUnsafeInstall)
				}
			}
			if v, ok := pkg["source"]; ok {
				typ, url, err := origin(v)
				u := strings.ToLower(url)
				remote := strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "git@") || strings.HasPrefix(u, "ssh://")
				if err != nil || !slices.Contains(composerSourceTypes, typ) || !remote {
					return fmt.Errorf("%w: composer.lock installs a package from a local path", ErrUnsafeInstall)
				}
			}
		}
	}
	return nil
}

// origin reads the type and url strings of a dist or source object.
func origin(v any) (typ, url string, err error) {
	obj, ok := asObject(v)
	if !ok {
		return "", "", errors.New("not an object")
	}
	if err := exactKeys(obj, "type", "url"); err != nil {
		return "", "", err
	}
	if typ, err = optString(obj, "type"); err != nil {
		return "", "", err
	}
	if url, err = optString(obj, "url"); err != nil {
		return "", "", err
	}
	return typ, url, nil
}

// ---- install folders

// linkedFolders are other folders next to the lockfile an install may
// write into: a link there is refused.
var linkedFolders = []string{"bin", ".npm"}

// freshFolder deletes the folder an install fills (vendor, node_modules)
// in dir, whatever it holds, so that no link or hard link planted in it
// survives: a link (or junction) is removed itself, never followed, and
// the root never leaves the copy. The other output folders must not be
// links.
func freshFolder(root *os.Root, dir, folder string) error {
	p := path.Join(dir, folder)
	if info, err := root.Lstat(p); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			if err := root.Remove(p); err != nil {
				return fmt.Errorf("Michel cannot reset %s in the copy: %w", folder, noPath(err))
			}
		} else if err := root.RemoveAll(p); err != nil {
			return fmt.Errorf("Michel cannot reset %s in the copy: %w", folder, noPath(err))
		}
	}
	if _, err := root.Lstat(p); err == nil {
		return fmt.Errorf("Michel cannot reset %s in the copy", folder)
	}
	for _, n := range linkedFolders {
		info, err := root.Lstat(path.Join(dir, n))
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("%w: %s is a link", ErrOutsideCopy, n)
		}
	}
	return nil
}

// Install installs the dependencies of the lockfile manifestRel (a slash
// path relative to the copy, the finding's manifest) of ecosystem, in its
// folder of the copy, without scripts nor plugins:
// composer install --no-scripts --no-interaction --no-plugins, or
// npm ci --ignore-scripts with Michel's empty npmrc. yarn.lock and
// pnpm-lock.yaml are ErrInstallUnsupported. Every file is reached through
// an os.Root of the copy: a lockfile folder behind a symbolic link or a
// junction is ErrOutsideCopy. The project's settings are checked first
// (composer.json, composer.lock, package.json from the lockfile up,
// package-lock.json, .npmrc from the lockfile up): a setting that would
// run code or leave the copy is ErrUnsafeInstall. vendor or node_modules
// is deleted first. The registries are reached through the egress proxy
// only. A failed install is a *CmdError.
func Install(ctx context.Context, d Deps, c Copy, ecosystem, manifestRel string) error {
	if err := copyDir(d, c); err != nil {
		return err
	}
	if manifestRel == "" || strings.Contains(manifestRel, `\`) || path.Clean(manifestRel) != manifestRel || !filepath.IsLocal(filepath.FromSlash(manifestRel)) {
		return fmt.Errorf("%w: %s", ErrUnsupportedLockfile, manifestRel)
	}
	for _, seg := range strings.Split(manifestRel, "/") {
		if !safeSegment(seg) {
			return fmt.Errorf("%w: %s", ErrUnsupportedLockfile, manifestRel)
		}
	}
	name, dir := path.Base(manifestRel), path.Dir(manifestRel)
	eco, ok := lockfileEcosystem[name]
	if !ok || eco != ecosystem {
		return fmt.Errorf("%w: %s (%s)", ErrUnsupportedLockfile, manifestRel, ecosystem)
	}
	if name == "yarn.lock" || name == "pnpm-lock.yaml" {
		return ErrInstallUnsupported
	}
	root, err := os.OpenRoot(c.Dir)
	if err != nil {
		return ErrNotACopy
	}
	defer root.Close()
	if err := realFolder(root, dir); err != nil {
		return err
	}
	lock, err := readIn(root, manifestRel, maxLockfile)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoLockfile, manifestRel)
	}
	h, err := ensureHome(d)
	if err != nil {
		return err
	}
	in := installFor(name, h.npmrc())
	if in.prog == "composer" {
		if err := checkComposerJSON(root, dir); err != nil {
			return err
		}
		if err := checkComposerLock(lock); err != nil {
			return err
		}
	} else {
		if err := checkPackageJSON(root, dir); err != nil {
			return err
		}
		if err := checkPackageLock(lock); err != nil {
			return err
		}
		if err := checkNpmrc(root, dir); err != nil {
			return err
		}
	}
	if err := freshFolder(root, dir, in.folder); err != nil {
		return err
	}
	cwd := filepath.Join(c.Dir, filepath.FromSlash(dir))
	stdout, stderr, err := d.exec()(ctx, in.prog, in.args, h.env(d.ProxyAddr), cwd)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return &CmdError{Cmd: in.prog + " " + in.args[0], Err: err, Output: combined(stdout, stderr)}
	}
	return nil
}
