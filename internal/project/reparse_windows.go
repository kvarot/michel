//go:build windows

package project

import (
	"os"
	"syscall"
)

// isReparsePoint tells a folder that hands its opening over to something else:
// a junction, a symbolic link, a mounted volume. Lstat opens the entry itself,
// never what it leads to.
func isReparsePoint(fi os.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
