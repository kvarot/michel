package hygiene

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// nonPortableSQL are the SQLite-only forms that PostgreSQL has no equal of.
var nonPortableSQL = regexp.MustCompile(`(?i)\browid\b|\bautoincrement\b|\binsert\s+or\s+replace\b|\bdatetime\(`)

// shippedNonPortable is the closed list of files already shipped with such a
// form: a migration is never edited once shipped. Nothing may join it.
var shippedNonPortable = map[string]bool{
	"internal/store/migrations/0001_init.sql": true, // audit_event's rowid column, replaced by seq in 0026
}

// TestSQLIsPortable keeps the SQL of the migrations and of the code portable
// to PostgreSQL: no rowid, AUTOINCREMENT, INSERT OR REPLACE or datetime(.
// Test files are not checked (they may build old databases on purpose).
func TestSQLIsPortable(t *testing.T) {
	root := moduleRoot(t)
	var bad []string
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, "_test.go") || (!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".sql")) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if shippedNonPortable[rel] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if m := nonPortableSQL.FindString(line); m != "" {
				bad = append(bad, rel+":"+strconv.Itoa(i+1)+": "+m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("SQL that PostgreSQL cannot run:\n  %s", strings.Join(bad, "\n  "))
	}
	for f := range shippedNonPortable {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
			t.Errorf("the closed list names %s, which is gone: %v", f, err)
		}
	}
}
