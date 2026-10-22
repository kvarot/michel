package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// renameAttempts and renameDelay bound the retries of the head rename: on
// Windows a reader holding the file open makes the rename fail briefly.
const (
	renameAttempts = 5
	renameDelay    = 20 * time.Millisecond
)

// rename is os.Rename; tests replace it to simulate sharing violations.
var rename = os.Rename

// HeadFile returns the path of the head anchor next to the database.
func HeadFile(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), "audit.head") }

// writeHead atomically records "<count> <hash>\n" (temp file + rename).
func writeHead(dbPath string, count int, hash string) error {
	dst := HeadFile(dbPath)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %s\n", count, hash)), 0o600); err != nil {
		return err
	}
	var err error
	for i := 0; i < renameAttempts; i++ {
		if i > 0 {
			time.Sleep(renameDelay)
		}
		if err = rename(tmp, dst); err == nil {
			return nil
		}
	}
	os.Remove(tmp)
	return err
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
