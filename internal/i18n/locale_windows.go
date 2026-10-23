package i18n

import (
	"os"
	"syscall"
)

// langFrench is the primary language id of French in a Windows LANGID.
const langFrench = 0x0C

// detectSystemLocale asks Windows for the user interface language. When the
// call is unavailable it falls back to the POSIX variables (Git Bash, MSYS).
func detectSystemLocale() string {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")
	if err := proc.Find(); err != nil {
		return localeFromEnv(os.Getenv)
	}
	id, _, _ := proc.Call()
	if id&0x3FF == langFrench {
		return "fr"
	}
	return "en"
}
