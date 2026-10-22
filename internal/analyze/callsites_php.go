package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// vendorNamespaces reads the autoload.psr-4 / psr-0 namespaces of the
// installed package, without the trailing backslash.
func vendorNamespaces(manifestDir, pkg string) (nss, underscored []string) {
	data, err := os.ReadFile(filepath.Join(manifestDir, "vendor", filepath.FromSlash(pkg), "composer.json"))
	if err != nil {
		return nil, nil
	}
	var c struct {
		Autoload struct {
			PSR4 map[string]json.RawMessage `json:"psr-4"`
			PSR0 map[string]json.RawMessage `json:"psr-0"`
		} `json:"autoload"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil, nil
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
	sort.Strings(out)
	sort.Strings(underscored)
	return out, underscored
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

// lineHasNamespace reports whether the lowercased line references one of the
// lowercased namespaces: a boundary before and no identifier character right
// after (covers `use NS`, `new NS`, `\NS\` and `NS\`).
func lineHasNamespace(lower string, nss []string) bool {
	for _, ns := range nss {
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
			// A namespace ending in "_" (psr-0 style) is a prefix of the class name.
			if end := i + len(ns); !strings.HasSuffix(ns, "_") && end < len(lower) && isIdentByte(lower[end]) {
				continue
			}
			return true
		}
	}
	return false
}

func findPHP(projectRoot, manifestDir string, others []string, pkg string, exclude []string) (CallSites, error) {
	files, err := userFiles(projectRoot, manifestDir, others, exclude, []string{".php", ".phtml", ".twig"})
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
	if nss, us := vendorNamespaces(manifestDir, pkg); len(nss) > 0 {
		res, err := search(append(append([]string{}, nss...), us...))
		res.Quality, res.Namespaces = "psr4", nss
		return res, err
	}
	var nss []string
	if ns := probableNamespace(pkg); ns != "" {
		nss = []string{ns}
	}
	res, err := search(nss)
	res.Namespaces = nss
	if res.Count > 0 {
		res.Quality = "name"
	} else {
		res.Quality = "low"
	}
	return res, err
}
