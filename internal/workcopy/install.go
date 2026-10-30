package workcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

// upTo calls f on dir and every folder above it up to root (both included).
func upTo(root, dir string, f func(string) error) error {
	for d := dir; ; d = filepath.Dir(d) {
		if err := f(d); err != nil {
			return err
		}
		if d == root || filepath.Dir(d) == d {
			return nil
		}
	}
}

// lines splits a settings file the way npm's ini reader does: on \r\n, \r
// and \n alike (a lone \r must not hide a second setting on one line).
func lines(b []byte) []string {
	return strings.FieldsFunc(string(b), func(r rune) bool { return r == '\n' || r == '\r' })
}

// objectKeys decodes a JSON object into its members, refusing a duplicate
// key (a parser could keep either value) and anything that is not an
// object.
func objectKeys(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON object")
	}
	return out, nil
}

// member returns the member named exactly key, refusing a member whose
// name differs from key only by case (Go and PHP do not agree on those).
func member(obj map[string]json.RawMessage, key string) (json.RawMessage, bool, error) {
	for k := range obj {
		if k != key && strings.EqualFold(k, key) {
			return nil, false, fmt.Errorf("%q and %q", key, k)
		}
	}
	v, ok := obj[key]
	return v, ok, nil
}

// ---- npm

// npmPackageManager is the only packageManager value accepted for an npm
// install: an exact npm version, optionally with its hash. A URL, a path,
// a tag (latest) or another manager would make corepack fetch and run code
// chosen by the repository.
var npmPackageManager = regexp.MustCompile(`^npm@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?(?:\+sha(?:1|224|256|512)\.[0-9a-f]+)?$`)

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
func checkNpmrc(root, dir string) error {
	return upTo(root, dir, func(d string) error {
		b, err := os.ReadFile(filepath.Join(d, ".npmrc"))
		if err != nil {
			return nil
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
func checkSpecs(raw json.RawMessage) error {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return errors.New("unreadable dependencies")
	}
	var walk func(any) error
	walk = func(v any) error {
		switch t := v.(type) {
		case string:
			if localSpec(t) {
				return errors.New("a dependency points at a local path")
			}
		case map[string]any:
			for _, x := range t {
				if err := walk(x); err != nil {
					return err
				}
			}
		case nil, bool, float64:
		default:
			return errors.New("unexpected dependencies")
		}
		return nil
	}
	return walk(v)
}

// checkPackageJSON refuses an npm install when a package.json from the
// folder of the lockfile up to the copy root sets packageManager to anything
// but an exact npm version, depends on a local path (file:, link:, a
// relative or absolute path) or lists workspaces outside its folder.
func checkPackageJSON(root, dir string) error {
	return upTo(root, dir, func(d string) error {
		b, err := os.ReadFile(filepath.Join(d, "package.json"))
		if err != nil {
			return nil
		}
		pkg, err := objectKeys(b)
		if err != nil {
			return fmt.Errorf("%w: package.json cannot be read", ErrUnsafeInstall)
		}
		if raw, ok, err := member(pkg, "packageManager"); err != nil {
			return fmt.Errorf("%w: package.json: %v", ErrUnsafeInstall, err)
		} else if ok {
			var pm string
			if json.Unmarshal(raw, &pm) != nil || !npmPackageManager.MatchString(pm) {
				return fmt.Errorf("%w: packageManager is not an exact npm version", ErrUnsafeInstall)
			}
		}
		for _, k := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"} {
			raw, ok, err := member(pkg, k)
			if err != nil {
				return fmt.Errorf("%w: package.json: %v", ErrUnsafeInstall, err)
			}
			if ok {
				if err := checkSpecs(raw); err != nil {
					return fmt.Errorf("%w: package.json %s: %v", ErrUnsafeInstall, k, err)
				}
			}
		}
		raw, ok, err := member(pkg, "workspaces")
		if err != nil {
			return fmt.Errorf("%w: package.json: %v", ErrUnsafeInstall, err)
		}
		if ok {
			var list []string
			if json.Unmarshal(raw, &list) != nil {
				var obj struct {
					Packages []string `json:"packages"`
				}
				if json.Unmarshal(raw, &obj) != nil {
					return fmt.Errorf("%w: package.json workspaces cannot be read", ErrUnsafeInstall)
				}
				list = obj.Packages
			}
			for _, w := range list {
				if escapes(w) {
					return fmt.Errorf("%w: a workspace is outside the project", ErrUnsafeInstall)
				}
			}
		}
		return nil
	})
}

// checkPackageLock refuses a package-lock.json whose packages are linked
// outside the project or resolved from anything but https.
func checkPackageLock(lock []byte) error {
	var doc struct {
		Packages map[string]struct {
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
		} `json:"packages"`
	}
	if json.Unmarshal(lock, &doc) != nil {
		return fmt.Errorf("%w: package-lock.json cannot be read", ErrUnsafeInstall)
	}
	for _, p := range doc.Packages {
		switch {
		case p.Link:
			if p.Resolved == "" || escapes(p.Resolved) || strings.Contains(p.Resolved, ":") {
				return fmt.Errorf("%w: package-lock.json links a package outside the project", ErrUnsafeInstall)
			}
		case p.Resolved != "" && !strings.HasPrefix(p.Resolved, "https://"):
			return fmt.Errorf("%w: package-lock.json resolves a package from elsewhere than an https registry", ErrUnsafeInstall)
		}
	}
	return nil
}

// ---- composer

// composerConfigKeys are the only composer.json config settings accepted:
// none of them moves a folder, turns off TLS or runs a program.
var composerConfigKeys = []string{"platform", "optimize-autoloader", "sort-packages", "allow-plugins", "preferred-install", "platform-check", "audit"}

// checkComposerJSON refuses a composer.json whose config holds a setting
// outside composerConfigKeys, or whose repositories are anything but
// composer repositories over https (false, which turns packagist off, is
// accepted). Keys are read exactly: a duplicate or a case variant is
// refused.
func checkComposerJSON(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return nil
	}
	doc, err := objectKeys(b)
	if err != nil {
		return fmt.Errorf("%w: composer.json cannot be read: %v", ErrUnsafeInstall, err)
	}
	if raw, ok, err := member(doc, "config"); err != nil {
		return fmt.Errorf("%w: composer.json: %v", ErrUnsafeInstall, err)
	} else if ok {
		cfg, err := objectKeys(raw)
		if err != nil {
			return fmt.Errorf("%w: composer.json config is not an object", ErrUnsafeInstall)
		}
		for k := range cfg {
			if !slices.Contains(composerConfigKeys, k) {
				return fmt.Errorf("%w: composer.json config sets %s", ErrUnsafeInstall, k)
			}
		}
	}
	raw, ok, err := member(doc, "repositories")
	if err != nil {
		return fmt.Errorf("%w: composer.json: %v", ErrUnsafeInstall, err)
	}
	if !ok {
		return nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		obj, err := objectKeys(raw)
		if err != nil {
			return fmt.Errorf("%w: composer.json repositories cannot be read", ErrUnsafeInstall)
		}
		for _, v := range obj {
			entries = append(entries, v)
		}
	}
	for _, e := range entries {
		if string(bytes.TrimSpace(e)) == "false" {
			continue
		}
		repo, err := objectKeys(e)
		if err != nil {
			return fmt.Errorf("%w: composer.json repositories cannot be read", ErrUnsafeInstall)
		}
		if disablesOnly(repo) {
			continue
		}
		var typ, url string
		if t, ok := repo["type"]; ok {
			_ = json.Unmarshal(t, &typ)
		}
		if u, ok := repo["url"]; ok {
			_ = json.Unmarshal(u, &url)
		}
		for k := range repo {
			if k != "type" && k != "url" && k != "canonical" && k != "only" && k != "exclude" {
				return fmt.Errorf("%w: composer.json repository sets %s", ErrUnsafeInstall, k)
			}
		}
		if typ != "composer" || !strings.HasPrefix(url, "https://") {
			return fmt.Errorf("%w: composer.json has a repository other than a composer repository over https", ErrUnsafeInstall)
		}
	}
	return nil
}

// disablesOnly reports whether a repositories entry only turns a
// repository off ({"packagist.org": false}).
func disablesOnly(repo map[string]json.RawMessage) bool {
	if len(repo) != 1 {
		return false
	}
	for _, v := range repo {
		return string(bytes.TrimSpace(v)) == "false"
	}
	return false
}

// checkComposerLock refuses a composer.lock with a package installed from
// a local path or from anything but https (dist) or a remote (source).
func checkComposerLock(lock []byte) error {
	type origin struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	var doc struct {
		Packages    []struct{ Dist, Source *origin } `json:"packages"`
		PackagesDev []struct{ Dist, Source *origin } `json:"packages-dev"`
	}
	if json.Unmarshal(lock, &doc) != nil {
		return fmt.Errorf("%w: composer.lock cannot be read", ErrUnsafeInstall)
	}
	for _, p := range append(doc.Packages, doc.PackagesDev...) {
		if p.Dist != nil && (p.Dist.Type == "path" || p.Dist.URL != "" && !strings.HasPrefix(p.Dist.URL, "https://")) {
			return fmt.Errorf("%w: composer.lock installs a package from a local path or without https", ErrUnsafeInstall)
		}
		if p.Source != nil {
			u := strings.ToLower(p.Source.URL)
			remote := strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "git@") || strings.HasPrefix(u, "ssh://")
			if p.Source.Type == "path" || p.Source.URL != "" && !remote {
				return fmt.Errorf("%w: composer.lock installs a package from a local path", ErrUnsafeInstall)
			}
		}
	}
	return nil
}

// ---- install folders

// linkedFolders are other folders next to the lockfile an install may
// write into: a link there is refused.
var linkedFolders = []string{"bin", ".npm"}

// freshFolder deletes the folder an install fills (vendor, node_modules)
// in dir, whatever it holds, so that no link or hard link planted in it
// survives: a link (or junction) is removed itself, never followed. The
// other output folders must not be links.
func freshFolder(c Copy, dir, folder string) error {
	p := filepath.Join(dir, folder)
	if info, err := os.Lstat(p); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("Michel cannot reset %s in the copy: %w", folder, noPath(err))
			}
		} else if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("Michel cannot reset %s in the copy: %w", folder, noPath(err))
		}
	}
	if _, err := os.Lstat(p); err == nil {
		return fmt.Errorf("Michel cannot reset %s in the copy", folder)
	}
	for _, n := range linkedFolders {
		q := filepath.Join(dir, n)
		info, err := os.Lstat(q)
		if err != nil {
			continue
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%w: %s is a link", ErrOutsideCopy, n)
		}
		if err := insideCopy(c, q); err != nil {
			return fmt.Errorf("%w: %s leads outside the copy", ErrOutsideCopy, n)
		}
	}
	return nil
}

// Install installs the dependencies of the lockfile manifestRel (a slash
// path relative to the copy, the finding's manifest) of ecosystem, in its
// folder of the copy, without scripts nor plugins:
// composer install --no-scripts --no-interaction --no-plugins, or
// npm ci --ignore-scripts with Michel's empty npmrc. yarn.lock and
// pnpm-lock.yaml are ErrInstallUnsupported. The project's settings are
// checked first (composer.json, composer.lock, package.json from the
// lockfile up, package-lock.json, .npmrc from the lockfile up): a setting
// that would run code or leave the copy is ErrUnsafeInstall. vendor or
// node_modules is deleted first. The registries are reached through the
// egress proxy only. A failed install is a *CmdError.
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
	if name == "yarn.lock" || name == "pnpm-lock.yaml" {
		return ErrInstallUnsupported
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
	lock, err := os.ReadFile(full)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNoLockfile, manifestRel)
	}
	h, err := ensureHome(d)
	if err != nil {
		return err
	}
	in := installFor(name, h.npmrc())
	if in.prog == "composer" {
		if err := checkComposerJSON(dir); err != nil {
			return err
		}
		if err := checkComposerLock(lock); err != nil {
			return err
		}
	} else {
		if err := checkPackageJSON(c.Dir, dir); err != nil {
			return err
		}
		if err := checkPackageLock(lock); err != nil {
			return err
		}
		if err := checkNpmrc(c.Dir, dir); err != nil {
			return err
		}
	}
	if err := freshFolder(c, dir, in.folder); err != nil {
		return err
	}
	stdout, stderr, err := d.exec()(ctx, in.prog, in.args, h.env(d.ProxyAddr), dir)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return &CmdError{Cmd: in.prog + " " + in.args[0], Err: err, Output: combined(stdout, stderr)}
	}
	return nil
}
