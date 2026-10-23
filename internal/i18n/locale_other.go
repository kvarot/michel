//go:build !windows

package i18n

import "os"

func detectSystemLocale() string { return localeFromEnv(os.Getenv) }
