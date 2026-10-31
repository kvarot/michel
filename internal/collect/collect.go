// Package collect reads what runs on a server, read only, through a closed
// list of commands (commands.go): operating system, PHP runtimes (command
// line and FPM, reported apart), web servers, packages and PHP directives.
// Nothing is installed or written on the server and sudo is never used. A
// read that fails becomes an Unseen line, never a second try by another
// means.
//
// Secrets are masked at the source: a secret directive keeps its name and
// place but no value (Secret is true; the page shows the i18n text
// collect.secret_value), the content of a file is never kept (path, SHA-256
// and size only), and every free text goes through internal/mask.
package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

const (
	// MaxDuration bounds a whole collection.
	MaxDuration = 5 * time.Minute
	// siteTimeout bounds the GET of the site.
	siteTimeout = 20 * time.Second

	auditActor  = "michel"
	auditAction = "target.collect"
)

// Unseen reasons: i18n keys of the catalog.
const (
	ReasonOS         = "collect.unseen.os"
	ReasonKernel     = "collect.unseen.kernel"
	ReasonPHP        = "collect.unseen.php"
	ReasonFPM        = "collect.unseen.fpm"
	ReasonDirectives = "collect.unseen.directives"
	ReasonPackages   = "collect.unseen.packages"
	ReasonWeb        = "collect.unseen.web"
	ReasonUnreadable = "collect.unseen.unreadable"
	ReasonNotRead    = "collect.unseen.not_read"
	ReasonMissing    = "collect.unseen.missing"
	ReasonTooBig     = "collect.unseen.too_big"
	ReasonRefused    = "collect.unseen.refused"
	ReasonTruncated  = "collect.unseen.truncated"
	ReasonTimeout    = "collect.unseen.timeout"
	ReasonSite       = "collect.unseen.site"
	// ReasonProbe: a command that asks what is installed failed or ran past its
	// time limit. Unlike ReasonPHP or ReasonFPM (nothing found), what it asks
	// about may be there: its absence proves nothing.
	ReasonProbe = "collect.unseen.probe"
)

// SecretValueKey is the i18n key of the text shown instead of a secret
// value ("[masqué]" / "[masked]").
const SecretValueKey = "collect.secret_value"

// Runner runs one command on the server; *sshx.Client is one.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin io.Reader) (sshx.Result, error)
}

// Deps are the services a collection needs.
type Deps struct {
	Now func() time.Time
	// Audit records target.collect; nil records nothing (tests).
	Audit *audit.Logger
	// Gateway reads the HTTP headers of the site (purpose target.http) when
	// the target has a SiteURL; nil skips that read.
	Gateway *egress.Gateway
	// ExtraPaths are the files the user added for this server; each one is
	// checked by CheckPath before it is read.
	ExtraPaths []string
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// errStop ends a collection early: the connection is gone or the time is up.
type errStop struct{ err error }

func (e errStop) Error() string { return e.err.Error() }
func (e errStop) Unwrap() error { return e.err }

// collector holds one collection.
type collector struct {
	ctx   context.Context
	r     Runner
	t     target.Target
	links []target.Link
	inv   *target.Inventory
	pm    string // package manager that answered: dpkg, rpm, apk or ""
	err   error  // first stop

	resolved map[string]string // readlink -f, by binary
}

// resolve is readlink -f of bin, asked once; bin itself when it fails.
func (c *collector) resolve(bin string) string {
	if r, ok := c.resolved[bin]; ok {
		return r
	}
	r := bin
	if res, ok := c.run([]string{"readlink", "-f", bin}); ok {
		if p := cleanPath(strings.TrimSpace(string(res.Stdout))); p != "" && isPHPBinary(p) {
			r = p
		}
	}
	if c.resolved == nil {
		c.resolved = map[string]string{}
	}
	c.resolved[bin] = r
	return r
}

// run runs argv if it is in the closed list. ok is false when the command
// could not run (not found, failure); res is then still filled when it ran.
// runFile runs a command on a file path: a path whose shape the closed
// list refuses is an Unseen line for that file (refused is true), never a
// stop of the collection.
func (c *collector) runFile(argv []string) (res sshx.Result, ok, refused bool) {
	if c.err == nil && !allowed(argv) {
		return sshx.Result{}, false, true
	}
	res, ok = c.run(argv)
	return res, ok, false
}

func (c *collector) run(argv []string) (sshx.Result, bool) {
	res, ok, _ := c.probe(argv)
	return res, ok
}

// probe is run that also tells when the command could not answer: it ran
// past its time limit (the collection goes on) or did not complete.
func (c *collector) probe(argv []string) (res sshx.Result, ok, broken bool) {
	if c.err != nil {
		return sshx.Result{}, false, false
	}
	if !allowed(argv) {
		// A programming error: the closed list is built in this package.
		c.err = fmt.Errorf("collect: command outside the closed list refused: %s", argv[0])
		return sshx.Result{}, false, false
	}
	var err error
	res, err = c.r.Run(c.ctx, withLocale(argv), nil)
	if err != nil {
		if errors.Is(err, sshx.ErrCommandTimeout) && c.ctx.Err() == nil {
			return res, false, true
		}
		c.err = err
		return res, false, true
	}
	return res, res.Exit == 0, false
}

func (c *collector) unseen(what, reason string) {
	c.inv.Unseen = append(c.inv.Unseen, target.Unseen{What: what, Reason: reason})
}

// Run collects the inventory of t through c. links are the projects
// deployed on t (their .user.ini are read). A read that fails is an
// Unseen line; Run returns an error only when the connection is lost or
// ctx ends, with what it collected so far.
func Run(ctx context.Context, d Deps, r Runner, t target.Target, links []target.Link) (target.Inventory, error) {
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	inv := target.Inventory{TargetID: t.ID, At: d.now()}
	c := &collector{ctx: ctx, r: r, t: t, links: links, inv: &inv}

	c.system()
	found := c.find()
	c.packages()
	files := &fileReader{c: c, read: map[string]*readFile{}}
	c.cli(found, files)
	c.fpm(found, files)
	c.web(found)
	c.userInis(links, files)
	c.extras(d.ExtraPaths, links, files)
	if c.err == nil {
		c.site(d)
	}

	if c.err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		c.unseen("collection", ReasonTimeout)
	}
	aerr := record(d, t, inv, c.err)
	if c.err != nil {
		return inv, errors.Join(fmt.Errorf("the collection stopped: %w", c.err), aerr)
	}
	return inv, aerr
}

func (c *collector) system() {
	if res, ok := c.run(cmdOSRelease); ok {
		c.inv.OS = ParseOSRelease(string(res.Stdout))
	}
	if c.inv.OS.ID == "" {
		c.unseen("os", ReasonOS)
	}
	if res, ok := c.run(cmdKernel); ok {
		c.inv.OS.Kernel = text(lines(string(res.Stdout))[0])
	}
	if c.inv.OS.Kernel == "" {
		c.unseen("kernel", ReasonKernel)
	}
}

// find returns the binaries `command -v` printed, by name or path asked.
func (c *collector) find() map[string]string {
	found := map[string]string{}
	failed := false
	for _, argv := range [][]string{cmdFind(), cmdFindSbin()} {
		// A missing name gives exit 1 (bash, zsh) or 127 (dash, busybox ash);
		// any other status, or no answer in time, means the shell could not
		// look at all.
		res, _, broken := c.probe(argv)
		if (broken || (res.Exit != 0 && res.Exit != 1 && res.Exit != 127)) && c.err == nil {
			failed = true
		}
		for _, p := range parseFound(string(res.Stdout)) {
			for _, asked := range argv[2:] {
				if asked == p || (!strings.HasPrefix(asked, "/") && strings.HasSuffix(p, "/"+asked)) {
					if _, dup := found[asked]; !dup {
						found[asked] = p
					}
				}
			}
		}
	}
	if failed {
		// What was not found may still be installed.
		c.unseen("discovery", ReasonProbe)
	}
	return found
}

func (c *collector) packages() {
	for _, try := range []struct {
		pm    string
		argv  []string
		parse func(string) []target.Package
	}{{"dpkg", cmdDpkg, parseDpkg}, {"rpm", cmdRPM, ParseRPM}, {"apk", cmdAPK, ParseAPK}} {
		res, ok := c.run(try.argv)
		if !ok {
			continue
		}
		c.pm = try.pm
		c.inv.Packages = try.parse(string(res.Stdout))
		if res.Truncated {
			c.unseen("packages", ReasonTruncated)
		}
		return
	}
	c.unseen("packages", ReasonPackages)
}

// owner is the distribution package that owns the binary, or "".
func (c *collector) owner(bin string) string {
	if c.pm != "dpkg" && c.pm != "rpm" {
		return ""
	}
	resolved := c.resolve(bin)
	if c.pm == "dpkg" {
		res, ok := c.run([]string{"dpkg", "-S", resolved})
		if !ok {
			return ""
		}
		first := lines(string(res.Stdout))[0]
		if pkg, _, ok := strings.Cut(first, ":"); ok {
			// "pkg: /path" or "pkg:arch: /path"
			return text(strings.TrimSpace(pkg))
		}
		return ""
	}
	res, ok := c.run([]string{"rpm", "-qf", "--qf", rpmName, resolved})
	if !ok {
		return ""
	}
	return text(lines(string(res.Stdout))[0])
}

func (c *collector) cli(found map[string]string, files *fileReader) {
	bin, ok := found["php"]
	if !ok {
		c.unseen("php", ReasonPHP)
		return
	}
	rt := target.PHPRuntime{SAPI: "cli", Binary: bin}
	if res, ok := c.run(cmdPHPV); ok {
		rt.Version = parsePHPVersion(string(res.Stdout))
	} else if c.err == nil {
		c.unseen(bin, ReasonProbe)
	}
	if res, ok := c.run(cmdPHPM); ok {
		rt.Modules = parseModules(string(res.Stdout))
	}
	if res, ok := c.run(cmdPHPIni); ok {
		f := parseIniFiles(string(res.Stdout))
		rt.LoadedIni, rt.ScannedDir, rt.ScannedFiles = f.LoadedIni, f.ScannedDir, f.ScannedFiles
	}
	rt.FromPackage = c.owner(bin)
	if rt.Version == "" {
		c.unseen("php", ReasonPHP)
	}
	read := files.iniChain(rt.LoadedIni, rt.ScannedFiles)
	values := map[string]string{}
	if res, ok := c.run(cmdPHPR); ok {
		var raw map[string]any
		if json.Unmarshal(res.Stdout, &raw) == nil {
			for k, v := range raw {
				switch v := v.(type) {
				case string:
					values[k] = v
				case nil:
					values[k] = ""
				default:
					values[k] = fmt.Sprint(v)
				}
			}
		}
	}
	if len(values) == 0 {
		c.unseen(bin, ReasonDirectives)
	}
	c.addDirectives("cli", bin, values, read)
	c.inv.PHP = append(c.inv.PHP, rt)
}

func (c *collector) fpm(found map[string]string, files *fileReader) {
	seen := map[string]bool{}
	var bins []string
	for _, n := range fpmNames {
		for _, asked := range []string{sbin + n, n} {
			if p, ok := found[asked]; ok && isFPMBinary(p) && !seen[p] {
				seen[p] = true
				bins = append(bins, p)
			}
		}
	}
	resolved := map[string]bool{}
	for _, bin := range bins {
		if c.err != nil {
			return
		}
		rt := target.PHPRuntime{SAPI: "fpm", Binary: bin}
		res, ok := c.run([]string{bin, "-v"})
		if !ok {
			if c.err == nil {
				c.unseen(bin, ReasonProbe)
			}
			continue
		}
		rt.Version = parsePHPVersion(string(res.Stdout))
		// php-fpm and php-fpm8.2 are often the same program: report it once.
		key := c.resolve(bin)
		if resolved[key] {
			continue
		}
		resolved[key] = true
		if res, ok := c.run([]string{bin, "-m"}); ok {
			rt.Modules = parseModules(string(res.Stdout))
		}
		info := PHPInfo{Directives: map[string]string{}}
		if res, ok := c.run([]string{bin, "-i"}); ok {
			info = ParsePHPInfo(string(res.Stdout))
		}
		rt.LoadedIni, rt.ScannedDir, rt.ScannedFiles = info.LoadedIni, info.ScannedDir, info.ScannedFiles
		res, _ = c.run([]string{bin, "-tt"}) // may fail for a user who is not root; the pools it printed still count
		pools, conf := parseFPMTest(string(res.Stdout) + "\n" + string(res.Stderr))
		guessed := len(pools) == 0
		if guessed {
			pools = []string{"www"} // the pool every distribution ships
		}
		rt.FromPackage = c.owner(bin)
		read := files.iniChain(rt.LoadedIni, rt.ScannedFiles)
		if len(info.Directives) == 0 {
			c.unseen(bin, ReasonDirectives)
		}
		c.addDirectives("fpm", bin, info.Directives, read)
		if dir := poolDir(conf, rt.LoadedIni); dir != "" {
			for _, name := range pools {
				p := dir + name + ".conf"
				f := files.get(p, !guessed)
				if f == nil {
					continue
				}
				rt.PoolFiles = append(rt.PoolFiles, p)
				for _, l := range f.lines {
					c.inv.Directives = append(c.inv.Directives, directive("fpm", bin, l.name, l.value, p, l.line))
				}
			}
		}
		c.inv.PHP = append(c.inv.PHP, rt)
	}
	if len(bins) == 0 || len(resolved) == 0 {
		if c.err == nil {
			c.unseen("fpm", ReasonFPM)
		}
	}
}

// addDirectives stores the effective values of one SAPI, sorted by name,
// each placed in the file that sets it when one of read does.
func (c *collector) addDirectives(sapi, binary string, values map[string]string, read []readFile) {
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		file, line := locate(read, n)
		c.inv.Directives = append(c.inv.Directives, directive(sapi, binary, n, values[n], file, line))
	}
}

func (c *collector) web(found map[string]string) {
	for _, n := range webNames {
		bin, ok := found[sbin+n]
		if !ok {
			bin, ok = found[n]
		}
		if !ok || !isWebBinary(bin) {
			continue
		}
		if n == "httpd" && hasWeb(c.inv.Web, "apache") {
			continue
		}
		res, _ := c.run([]string{bin, "-v"})
		if w, ok := ParseWeb(n, string(res.Stdout)+"\n"+string(res.Stderr)); ok {
			c.inv.Web = append(c.inv.Web, w)
		}
	}
	if len(c.inv.Web) == 0 && c.err == nil {
		c.unseen("web", ReasonWeb)
	}
}

func (c *collector) runtimes(sapi string) []target.PHPRuntime {
	var out []target.PHPRuntime
	for _, r := range c.inv.PHP {
		if r.SAPI == sapi {
			out = append(out, r)
		}
	}
	return out
}

func hasWeb(ws []target.WebServer, name string) bool {
	for _, w := range ws {
		if w.Name == name {
			return true
		}
	}
	return false
}

func (c *collector) userInis(links []target.Link, files *fileReader) {
	// A .user.ini applies to the FPM that serves the folder: known only when
	// one FPM was seen.
	fpmBin := ""
	if fpms := c.runtimes("fpm"); len(fpms) == 1 {
		fpmBin = fpms[0].Binary
	}
	for _, l := range links {
		dir := cleanPath(l.RemoteDir)
		if dir == "" || dir == "/" {
			continue
		}
		for _, p := range []string{dir + "/.user.ini", dir + "/public/.user.ini"} {
			f := files.get(p, false)
			if f == nil {
				continue
			}
			for _, il := range f.lines {
				c.inv.Directives = append(c.inv.Directives, directive("user_ini", fpmBin, il.name, il.value, p, il.line))
			}
		}
	}
}

func (c *collector) extras(paths []string, links []target.Link, files *fileReader) {
	for _, p := range paths {
		if err := CheckPath(c.t, links, p); err != nil {
			c.unseen(cleanPath(p), ReasonRefused)
			continue
		}
		files.get(p, true)
	}
}

// site reads the Server and X-Powered-By headers of the site, as a browser
// would, through the gateway. A failure is said, not fatal.
func (c *collector) site(d Deps) {
	if c.t.SiteURL == "" || d.Gateway == nil {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, siteTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.t.SiteURL, nil)
	if err != nil {
		c.unseen("site", ReasonSite)
		return
	}
	resp, err := d.Gateway.Client(policy.PurposeTargetHTTP).Do(req)
	if err != nil {
		c.unseen("site", ReasonSite)
		return
	}
	resp.Body.Close() // the body is not read
	c.inv.Site = target.SiteHeaders{
		Server:    text(resp.Header.Get("Server")),
		PoweredBy: text(resp.Header.Get("X-Powered-By")),
	}
}

// record writes target.collect: counts and the hash of the inventory only.
func record(d Deps, t target.Target, inv target.Inventory, stop error) error {
	if d.Audit == nil {
		return nil
	}
	body, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	result := "ok"
	if stop != nil {
		result = "stopped"
	}
	_, err = d.Audit.Record(context.Background(), audit.Event{
		Actor: auditActor, Action: auditAction, Target: t.ID, Result: result,
		Evidence: map[string]any{
			"packages":         len(inv.Packages),
			"directives":       len(inv.Directives),
			"files":            len(inv.Files),
			"unseen":           len(inv.Unseen),
			"inventory_sha256": hex.EncodeToString(sum[:]),
		},
	})
	return err
}
