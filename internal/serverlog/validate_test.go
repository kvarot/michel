package serverlog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidatePathRefusals(t *testing.T) {
	bad := map[string]string{
		"empty":                 "",
		"relative":              "var/log/app.log",
		"dot relative":          "./app.log",
		"parent":                "/var/log/../etc/app.log",
		"parent at the end":     "/var/log/..",
		"wildcard in a folder":  "/var/*/app.log",
		"wildcard in a folder2": "/var/log?/app.log",
		"newline":               "/var/log/app.log\n/etc/passwd",
		"carriage return":       "/var/log/app.log\r",
		"nul":                   "/var/log/app.log\x00",
		"tab":                   "/var/log/a\tb.log",
		"folder":                "/var/log/",
		"current folder":        "/var/log/.",
		"quote":                 "/var/log/a'b.log",
		"dollar":                "/var/log/$(id).log",
		"semicolon":             "/var/log/a;b.log",
		"backtick":              "/var/log/`id`.log",
		"bracket class":         "/var/log/app-[0-9].log",
		"too long":              "/var/log/" + strings.Repeat("a", 2000),
	}
	for name, p := range bad {
		err := ValidatePath(p)
		if err == nil {
			t.Errorf("%s: %q was accepted", name, p)
			continue
		}
		if !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%s: want ErrInvalidPath, got %v", name, err)
		}
		if p != "" && strings.Contains(err.Error(), p) {
			t.Errorf("%s: the error repeats the path: %v", name, err)
		}
	}
	for _, p := range []string{
		"/var/log/php_errors.log", "/var/log/postgresql/postgresql-*.log", "/srv/my app/storage/logs/laravel-*.log",
		"/var/log/app-????-??-??.log", "/home/demo/logs/php.log", "/a",
	} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%q was refused: %v", p, err)
		}
	}
}

// ValidatePath must never accept what the filter script would refuse: a path
// that passes here is one Script builds.
func TestValidatePathAcceptsNoMoreThanScript(t *testing.T) {
	for c := 0; c < 256; c++ {
		for _, shape := range []string{"/var/log/a%sb.log", "/var/log/%s/b.log", "/var/log/b.log%s", "%s/var/log/b.log"} {
			p := fmt.Sprintf(shape, string(rune(c)))
			if c >= 0x80 {
				p = fmt.Sprintf(shape, string([]byte{byte(c)}))
			}
			if ValidatePath(p) != nil {
				continue
			}
			if _, err := Script(Source{Path: p, Format: FormatPHP}, nil, FilterOptions{}); err != nil {
				t.Errorf("%q passes ValidatePath but not Script: %v", p, err)
			}
		}
	}
	for _, p := range []string{"/var/log/**", "/var/log/a b.log", "/var/log/a//b.log", "/var/log/~x", "/var/log/a:b,c=d+e.log"} {
		if ValidatePath(p) != nil {
			continue
		}
		if _, err := Script(Source{Path: p, Format: FormatPHP}, nil, FilterOptions{}); err != nil {
			t.Errorf("%q passes ValidatePath but not Script: %v", p, err)
		}
	}
}
