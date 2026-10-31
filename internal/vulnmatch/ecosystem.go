// Package vulnmatch matches the operating system packages read on a server
// against the distribution OSV databases kept by osvdb.
package vulnmatch

import (
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/target"
)

// Ecosystem maps an os-release identity to the OSV ecosystem name of its
// distribution release, such as "Debian:12". ok is false when the
// distribution or its release is not one Michel can match.
func Ecosystem(os target.OSInfo) (eco string, ok bool) {
	id := strings.ToLower(strings.TrimSpace(os.ID))
	major, minor, _ := strings.Cut(strings.TrimSpace(os.VersionID), ".")
	y, err := strconv.Atoi(major)
	if err != nil {
		return "", false
	}
	switch id {
	case "debian":
		return "Debian:" + major, true
	case "ubuntu":
		minor, _, _ = strings.Cut(minor, ".")
		if minor == "" {
			return "", false
		}
		if minor == "04" && y%2 == 0 {
			return "Ubuntu:" + major + "." + minor + ":LTS", true
		}
		return "Ubuntu:" + major + "." + minor, true
	case "alpine":
		minor, _, _ = strings.Cut(minor, ".")
		minor = leadingDigits(minor)
		if minor == "" {
			return "", false
		}
		return "Alpine:v" + major + "." + minor, true
	case "almalinux":
		return "AlmaLinux:" + major, true
	case "rocky":
		return "Rocky Linux:" + major, true
	}
	return "", false
}

// base returns the ecosystem without its release: the name of the OSV
// database directory ("Debian:12" gives "Debian").
func base(eco string) string {
	b, _, _ := strings.Cut(eco, ":")
	return b
}

// CatalogKey returns the source catalog key that provides the database of an
// ecosystem ("Debian:12" gives "osv.debian", "Rocky Linux:9" "osv.rocky-linux").
func CatalogKey(eco string) string {
	return "osv." + strings.ToLower(strings.ReplaceAll(base(eco), " ", "-"))
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}
