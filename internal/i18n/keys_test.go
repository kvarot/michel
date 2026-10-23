package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// dynamicPrefixes are catalog families whose keys are built at run time
// (enum values, severity labels, glossary terms, reasons, event types), so a
// key under them may have no literal reference in the code.
var dynamicPrefixes = []string{
	"explain.label.risk_", "explain.label.rec_", "explain.label.jump_", "explain.label.quality_",
	"explain.label.method_", "explain.label.term_", "explain.severity.", "glossary.", "digest.reason.", "notify.type.",
}

// family says how a call names a catalog key: the prefix added to the
// literal, whether it is a plural key (key.one / key.other) and which
// argument holds the key.
type family struct {
	prefix string
	plural bool
	arg    int
}

var (
	qualified = map[string]family{
		"i18n.T": {"", false, 1}, "i18n.N": {"", true, 1},
		"explain.Label": {"explain.label.", false, 1}, "explain.Term": {"glossary.", false, 1},
	}
	// inExplain are the unqualified calls inside package explain.
	inExplain = map[string]family{"Label": {"explain.label.", false, 1}, "Term": {"glossary.", false, 1}}
	// depsMethods are the wrappers on the CLI dependencies (deps.T, d.N...).
	depsMethods = map[string]family{"T": {"", false, 0}, "N": {"", true, 0}, "Errorf": {"", false, 0}}
)

type keyRef struct {
	key  string
	pos  string
	test bool
}

// collectKeyRefs parses every Go file of the module except this package and
// returns the literal catalog keys the code asks for.
func collectKeyRefs(t *testing.T, root string) []keyRef {
	t.Helper()
	var refs []keyRef
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, root))
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".superpowers", "node_modules", "web", "testdata":
				return filepath.SkipDir
			}
			if strings.HasSuffix(rel, "/internal/i18n") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		refs = append(refs, fileKeyRefs(fset, f, strings.HasSuffix(p, "_test.go"))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// callFamily tells whether call names a catalog key, given the closures of
// the file that forward to a key function (aliases).
func callFamily(call *ast.CallExpr, pkg string, aliases map[string]family) (family, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fam, ok := aliases[fn.Name]; ok {
			return fam, true
		}
		if pkg == "explain" {
			fam, ok := inExplain[fn.Name]
			return fam, ok
		}
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		if !ok {
			return family{}, false
		}
		if fam, ok := qualified[x.Name+"."+fn.Sel.Name]; ok {
			return fam, true
		}
		if x.Name == "deps" || x.Name == "d" {
			fam, ok := depsMethods[fn.Sel.Name]
			return fam, ok
		}
	}
	return family{}, false
}

func fileKeyRefs(fset *token.FileSet, f *ast.File, test bool) []keyRef {
	var refs []keyRef
	aliases := map[string]family{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			// L := func(k string) string { return explain.Label(lang, k) }
			if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
				return true
			}
			name, ok1 := n.Lhs[0].(*ast.Ident)
			lit, ok2 := n.Rhs[0].(*ast.FuncLit)
			if !ok1 || !ok2 {
				return true
			}
			params := map[string]int{}
			i := 0
			for _, field := range lit.Type.Params.List {
				for _, pn := range field.Names {
					params[pn.Name] = i
					i++
				}
			}
			ast.Inspect(lit.Body, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				fam, ok := callFamily(call, f.Name.Name, aliases)
				if !ok || fam.arg >= len(call.Args) {
					return true
				}
				if id, ok := call.Args[fam.arg].(*ast.Ident); ok {
					if idx, ok := params[id.Name]; ok {
						aliases[name.Name] = family{fam.prefix, fam.plural, idx}
					}
				}
				return true
			})
		case *ast.CallExpr:
			fam, ok := callFamily(n, f.Name.Name, aliases)
			if !ok || fam.arg >= len(n.Args) {
				return true
			}
			lit, ok := n.Args[fam.arg].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			pos := fset.Position(lit.Pos()).String()
			key := fam.prefix + s
			if fam.plural {
				refs = append(refs, keyRef{key + ".one", pos, test}, keyRef{key + ".other", pos, test})
			} else {
				refs = append(refs, keyRef{key, pos, test})
			}
		}
		return true
	})
	return refs
}

func TestEveryReferencedKeyExists(t *testing.T) {
	refs := collectKeyRefs(t, moduleRoot(t))
	if len(refs) == 0 {
		t.Fatal("no key reference found: the scanner is broken")
	}
	for _, r := range refs {
		// Tests may ask for a missing key on purpose (fallback cases).
		if !r.test && !Has(r.key) {
			t.Errorf("%s: key %q is not in the catalog", r.pos, r.key)
		}
	}
}

func TestEveryCatalogKeyIsReferenced(t *testing.T) {
	used := map[string]bool{}
	for _, r := range collectKeyRefs(t, moduleRoot(t)) {
		used[r.key] = true
	}
	var unused []string
	for _, k := range Keys() {
		if used[k] {
			continue
		}
		dynamic := false
		for _, p := range dynamicPrefixes {
			if strings.HasPrefix(k, p) {
				dynamic = true
				break
			}
		}
		if !dynamic {
			unused = append(unused, k)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Errorf("catalog keys never referenced (remove them or declare the prefix dynamic):\n  %s", strings.Join(unused, "\n  "))
	}
}

func TestKeyScannerFindsAliasesAndWrappers(t *testing.T) {
	src := `package cli
func f() {
	L := func(k string) string { return explain.Label(lang, k) }
	H := func(k string) string { return L(k) + ":" }
	_ = H("what")
	_ = i18n.N(lang, "cli.files", 2)
	_ = deps.T("cli.hello")
	_ = d.Errorf("cli.oops", 1)
	_ = i18n.T(lang, dyn)
	_ = t.Errorf("not.a.key")
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range fileKeyRefs(fset, f, false) {
		got = append(got, r.key)
	}
	want := "explain.label.what cli.files.one cli.files.other cli.hello cli.oops"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", strings.Join(got, " "), want)
	}
}
