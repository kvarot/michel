package gitrepo

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// licenseRules map a distinctive phrase of a licence text (upper case,
// spaces collapsed) to its SPDX identifier. Order matters: the Affero and
// Lesser GPL before the GPL, BSD-3 (its "neither the name" clause) before
// BSD-2.
var licenseRules = []struct {
	spdx string
	all  []string
}{
	{"AGPL-3.0", []string{"GNU AFFERO GENERAL PUBLIC LICENSE"}},
	{"LGPL-3.0", []string{"GNU LESSER GENERAL PUBLIC LICENSE", "VERSION 3"}},
	{"LGPL-2.1", []string{"GNU LESSER GENERAL PUBLIC LICENSE", "VERSION 2.1"}},
	{"LGPL-2.1", []string{"GNU LIBRARY GENERAL PUBLIC LICENSE"}},
	{"GPL-3.0", []string{"GNU GENERAL PUBLIC LICENSE", "VERSION 3"}},
	{"GPL-2.0", []string{"GNU GENERAL PUBLIC LICENSE", "VERSION 2"}},
	{"MPL-2.0", []string{"MOZILLA PUBLIC LICENSE", "2.0"}},
	{"Apache-2.0", []string{"APACHE LICENSE", "VERSION 2.0"}},
	{"MIT", []string{"PERMISSION IS HEREBY GRANTED, FREE OF CHARGE"}},
	{"BSD-3-Clause", []string{"REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS", "NEITHER THE NAME"}},
	{"BSD-2-Clause", []string{"REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS"}},
	{"CC-BY-SA-4.0", []string{"ATTRIBUTION-SHAREALIKE 4.0"}},
	{"ISC", []string{"PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE"}},
	{"Unlicense", []string{"THIS IS FREE AND UNENCUMBERED SOFTWARE RELEASED INTO THE PUBLIC DOMAIN"}},
}

// maxLicenseBytes is how much of a licence file is read.
const maxLicenseBytes = 64 << 10

// licenseFile reports whether name is a licence file (LICENSE*, LICENCE*,
// COPYING*).
func licenseFile(name string) bool {
	u := strings.ToUpper(name)
	return strings.HasPrefix(u, "LICENSE") || strings.HasPrefix(u, "LICENCE") || strings.HasPrefix(u, "COPYING")
}

// DetectLicense reads the licence files at the top of dir and names the
// first licence it recognises; SPDX is "unknown" otherwise.
func DetectLicense(dir string) License {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return License{SPDX: "unknown"}
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && licenseFile(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := os.Open(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(f, maxLicenseBytes))
		f.Close()
		text := strings.Join(strings.Fields(strings.ToUpper(string(b))), " ")
		for _, r := range licenseRules {
			ok := true
			for _, p := range r.all {
				if !strings.Contains(text, p) {
					ok = false
					break
				}
			}
			if ok {
				return License{SPDX: r.spdx, File: n}
			}
		}
	}
	return License{SPDX: "unknown"}
}
