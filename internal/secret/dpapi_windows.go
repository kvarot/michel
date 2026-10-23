//go:build windows

package secret

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// entropy is mixed into every DPAPI blob, so another program running as the
// same user cannot decrypt Michel's files by a plain CryptUnprotectData.
var entropy = []byte("michel-secret-v1")

// Protected reports whether values are encrypted at rest on this OS (true on Windows).
func Protected() bool { return true }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies out and releases it, wiping it first when wipe is set.
func takeBlob(out windows.DataBlob, wipe bool) []byte {
	if out.Data == nil {
		return []byte{}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	src := unsafe.Slice(out.Data, out.Size)
	v := append([]byte(nil), src...)
	if wipe {
		clear(src)
	}
	return v
}

// protect encrypts plain for the current Windows user (no UI, no description).
func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plain), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(out, false), nil
}

// unprotect decrypts data written by protect for the same user.
func unprotect(data []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(data), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(out, true), nil
}
