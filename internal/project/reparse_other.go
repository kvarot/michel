//go:build !windows

package project

import "os"

// isReparsePoint: there is none outside Windows. A symbolic link is followed
// there, and the folder it leads to is what CheckFolder checks.
func isReparsePoint(os.FileInfo) bool { return false }
