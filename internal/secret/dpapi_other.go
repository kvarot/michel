//go:build !windows

package secret

// Protected reports whether values are encrypted at rest on this OS (true on Windows).
func Protected() bool { return false }

// protect stores the value as is: the file mode (0600) is the protection.
func protect(plain []byte) ([]byte, error) { return append([]byte(nil), plain...), nil }

func unprotect(data []byte) ([]byte, error) { return data, nil }
