package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HeadFile returns the path of the head anchor next to the database.
func HeadFile(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), "audit.head") }

// writeHead atomically records "<count> <hash>\n" (temp file + rename).
func writeHead(dbPath string, count int, hash string) error {
	dst := HeadFile(dbPath)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %s\n", count, hash)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readHead returns ok=false when the file is absent or unreadable.
func readHead(dbPath string) (count int, hash string, ok bool) {
	b, err := os.ReadFile(HeadFile(dbPath))
	if err != nil {
		return 0, "", false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, "", false
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return 0, "", false
	}
	return n, f[1], true
}
