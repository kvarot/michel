package egress

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenSelectors are the package-level identifiers that reach the network
// without the egress allowlist. Only internal/egress may build HTTP clients
// or dial raw connections (SMTP goes through Gateway.DialContext).
var forbiddenSelectors = map[string]map[string]bool{
	"net/http":   {"DefaultClient": true, "DefaultTransport": true, "Get": true, "Post": true, "Head": true, "PostForm": true},
	"net":        {"Dial": true, "DialTimeout": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true},
	"crypto/tls": {"Dial": true, "DialWithDialer": true},
	"net/smtp":   {"Dial": true},
}

// forbiddenLiterals are the types that must not be built outside egress.
var forbiddenLiterals = map[string]map[string]bool{
	"net/http":   {"Client": true, "Transport": true},
	"net":        {"Dialer": true},
	"crypto/tls": {"Dialer": true},
}

// moduleRoot finds the folder holding go.mod, walking up from the test's
// working directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test folder")
		}
		dir = parent
	}
}

// boundaryViolations parses one Go file and lists the direct network uses.
func boundaryViolations(fset *token.FileSet, name string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	// Local name of each watched import, aliases included.
	local := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if _, ok := forbiddenSelectors[p]; !ok {
			continue
		}
		n := filepath.Base(p)
		if imp.Name != nil {
			n = imp.Name.Name
		}
		local[n] = p
	}
	if len(local) == 0 {
		return nil, nil
	}
	pkgSel := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		p, ok := local[id.Name]
		return p, sel.Sel.Name, ok
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if p, name, ok := pkgSel(n.Type); ok && forbiddenLiterals[p][name] {
				out = append(out, fmt.Sprintf("%s: %s.%s{} literal", fset.Position(n.Pos()), p, name))
			}
		case *ast.SelectorExpr:
			if p, name, ok := pkgSel(n); ok && forbiddenSelectors[p][name] {
				out = append(out, fmt.Sprintf("%s: %s.%s", fset.Position(n.Pos()), p, name))
			}
		}
		return true
	})
	return out, nil
}

// TestNoDirectHTTPOutsideEgress enforces that every outbound connection goes
// through internal/egress, where the policy allowlist and the audit apply.
func TestNoDirectHTTPOutsideEgress(t *testing.T) {
	root := moduleRoot(t)
	egressDir := filepath.Join(root, "internal", "egress")
	fset := token.NewFileSet()
	checked := 0
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (path == egressDir || name == "vendor" || name == "testdata" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checked++
		seen[filepath.ToSlash(filepath.Dir(path))] = true
		v, err := boundaryViolations(fset, path, nil)
		if err != nil {
			return err
		}
		for _, s := range v {
			t.Errorf("%s: outbound network use outside internal/egress; build the client with egress.Gateway.Client instead", s)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d Go files checked under %s: the walk is not seeing the module", checked, root)
	}
	// The packages that read the sources must be among those checked.
	for _, dir := range []string{"internal/sourceupdate", "internal/sourceupdate/readers", "internal/enrich", "internal/osvdb"} {
		if !seen[filepath.ToSlash(filepath.Join(root, dir))] {
			t.Errorf("the boundary walk did not check %s", dir)
		}
	}
}

func TestBoundaryCheckDetectsViolations(t *testing.T) {
	src := `package x

import (
	h "net/http"
	"net"
)

func f() {
	_ = h.DefaultClient
	_ = h.DefaultTransport
	h.Get("u")
	h.Post("u", "", nil)
	h.Head("u")
	h.PostForm("u", nil)
	_ = &h.Client{}
	_ = h.Transport{}
	net.Dial("tcp", "x")
	net.DialTimeout("tcp", "x", 0)
	_ = net.Dialer{}
	_ = h.NewRequest
	_ = h.StatusOK
}
`
	v, err := boundaryViolations(token.NewFileSet(), "x.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 11 {
		t.Fatalf("got %d violations, want 11:\n%s", len(v), strings.Join(v, "\n"))
	}
}

// TestNoDirectDialOutsideEgress checks that the raw dialers used for
// non-HTTP protocols (SMTP, TLS, UDP) are watched too: outside
// internal/egress they must go through Gateway.DialContext. The module walk
// of TestNoDirectHTTPOutsideEgress applies the same forbidden lists.
func TestNoDirectDialOutsideEgress(t *testing.T) {
	src := `package x

import (
	"crypto/tls"
	"net"
	mail "net/smtp"
)

func f() {
	net.Dial("tcp", "x")
	net.DialTimeout("tcp", "x", 0)
	net.DialTCP("tcp", nil, nil)
	net.DialUDP("udp", nil, nil)
	net.DialIP("ip4:1", nil, nil)
	net.DialUnix("unix", nil, nil)
	_ = &tls.Dialer{}
	_ = net.Dialer{}
	tls.Dial("tcp", "x", nil)
	tls.DialWithDialer(nil, "tcp", "x", nil)
	mail.Dial("x")
	_ = tls.Config{}
	_ = net.SplitHostPort
	_ = mail.PlainAuth
}
`
	v, err := boundaryViolations(token.NewFileSet(), "x.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 11 {
		t.Fatalf("got %d violations, want 11:\n%s", len(v), strings.Join(v, "\n"))
	}
}
