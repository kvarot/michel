package analyze

import (
	"encoding/json"
	"sort"
	"strings"
)

// vendorState tells what Michel found about the installed copy of a package.
type vendorState int

const (
	// vendorMissing: no readable vendor/<pkg>/composer.json (not installed,
	// refused link, unreadable or invalid file).
	vendorMissing vendorState = iota
	// vendorNoAutoload: installed, but declares no PSR-4 / PSR-0 namespace.
	vendorNoAutoload
	// vendorNamespaced: installed with at least one namespace.
	vendorNamespaced
)

// vendorNamespaces reads the autoload.psr-4 / psr-0 namespaces of the
// installed package, without the trailing backslash. Links and paths leaving
// the manifest directory are refused, and composer.json is read up to 1 MiB.
func vendorNamespaces(manifestDir, pkg string) (nss, underscored []string, state vendorState) {
	dir, err := installedPackageDir(manifestDir, "vendor", pkg)
	if err != nil {
		return nil, nil, vendorMissing
	}
	f, _, err := openRegular(manifestDir, dir, "composer.json")
	if err != nil {
		return nil, nil, vendorMissing
	}
	data, err := readLimited(f, maxComposerJSON)
	if err != nil {
		return nil, nil, vendorMissing
	}
	var c struct {
		Autoload struct {
			PSR4 map[string]json.RawMessage `json:"psr-4"`
			PSR0 map[string]json.RawMessage `json:"psr-0"`
		} `json:"autoload"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil, nil, vendorMissing
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]json.RawMessage{c.Autoload.PSR4, c.Autoload.PSR0} {
		for k := range m {
			k = strings.TrimSpace(k)
			us := strings.HasSuffix(k, "_")
			ns := strings.TrimRight(k, `\_`)
			if ns == "" {
				continue
			}
			if us {
				underscored = append(underscored, ns+"_")
			}
			if !seen[ns] {
				seen[ns] = true
				out = append(out, ns)
			}
		}
	}
	if len(out) == 0 {
		return nil, nil, vendorNoAutoload
	}
	sort.Strings(out)
	sort.Strings(underscored)
	return out, underscored, vendorNamespaced
}

// probableNamespace derives `Acme\HttpClient` from "acme/http-client".
func probableNamespace(pkg string) string {
	var segs []string
	for _, part := range strings.Split(pkg, "/") {
		var b strings.Builder
		for _, w := range strings.FieldsFunc(part, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			b.WriteString(strings.ToUpper(w[:1]) + w[1:])
		}
		if b.Len() > 0 {
			segs = append(segs, b.String())
		}
	}
	return strings.Join(segs, `\`)
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// boundaryBefore: start of line, or a non-identifier byte that is not a
// backslash; after a backslash, the byte before it must be a non-identifier
// too (so `App\Twig\Ext` does not match `Twig`, `\Acme\Vuln` matches `Acme\Vuln`).
func boundaryBefore(s string, i int) bool {
	if i == 0 {
		return true
	}
	c := s[i-1]
	if isIdentByte(c) {
		return false
	}
	if c == '\\' {
		return i-1 == 0 || !isIdentByte(s[i-2])
	}
	return true
}

// codeContextBefore lists what may stand right before a one-word namespace for
// the line to be PHP code using it (lowercase).
var codeContextBefore = []string{"use ", "new ", "extends ", "implements ", `\`}

// singleSegmentInCode tells whether the one-word namespace found at [i, end)
// is used as code: followed by `\` or `::`, or preceded by `use `, `new `,
// `extends `, `implements ` or `\`. A bare word (`Twig` in a comment or in
// 'x.html.twig') is not a use.
func singleSegmentInCode(lower string, i, end int) bool {
	if end < len(lower) && (lower[end] == '\\' || strings.HasPrefix(lower[end:], "::")) {
		return true
	}
	for _, c := range codeContextBefore {
		if strings.HasSuffix(lower[:i], c) {
			return true
		}
	}
	return false
}

// lineHasNamespace reports whether the lowercased line references one of the
// lowercased namespaces: a boundary before and no identifier character right
// after (covers `use NS`, `new NS`, `\NS\` and `NS\`). A one-word namespace
// (`Twig`, `Monolog`) also needs a code context, see singleSegmentInCode.
func lineHasNamespace(lower string, nss []string) bool {
	for _, ns := range nss {
		single := !strings.Contains(ns, `\`) && !strings.HasSuffix(ns, "_")
		from := 0
		for {
			i := strings.Index(lower[from:], ns)
			if i < 0 {
				break
			}
			i += from
			from = i + 1
			if !boundaryBefore(lower, i) {
				continue
			}
			end := i + len(ns)
			// A namespace ending in "_" (psr-0 style) is a prefix of the class name.
			if !strings.HasSuffix(ns, "_") && end < len(lower) && isIdentByte(lower[end]) {
				continue
			}
			if single && !singleSegmentInCode(lower, i, end) {
				continue
			}
			return true
		}
	}
	return false
}

// phpExtensions are the files searched for PHP namespaces. Templates (.twig)
// are not PHP: a namespace word there is text, not a use.
var phpExtensions = []string{".php", ".phtml"}

func findPHP(projectRoot, manifestDir string, others []string, pkg string, exclude []string) (CallSites, error) {
	nss, us, state := vendorNamespaces(manifestDir, pkg)
	if state == vendorNoAutoload {
		// Installed, but there is no namespace to look for: searching by a
		// guessed name would only find noise.
		return CallSites{Quality: "noautoload"}, nil
	}
	files, err := userFiles(projectRoot, manifestDir, others, exclude, phpExtensions)
	if err != nil {
		return CallSites{}, err
	}
	search := func(nss []string) (CallSites, error) {
		low := make([]string, len(nss))
		for i, n := range nss {
			low[i] = strings.ToLower(n)
		}
		return scanFiles(projectRoot, files, func(line string) bool {
			return lineHasNamespace(strings.ToLower(line), low)
		})
	}
	if state == vendorNamespaced {
		res, err := search(append(append([]string{}, nss...), us...))
		res.Quality, res.Namespaces = "psr4", nss
		return res, err
	}
	var guess []string
	if ns := probableNamespace(pkg); ns != "" {
		guess = []string{ns}
	}
	res, err := search(guess)
	res.Namespaces = guess
	if res.Count > 0 {
		res.Quality = "name"
	} else {
		res.Quality = "low"
	}
	return res, err
}
