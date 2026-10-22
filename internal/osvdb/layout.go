// Package osvdb manages the offline OSV vulnerability databases.
package osvdb

import "path/filepath"

// Host is the only host the databases are downloaded from.
const Host = "osv-vulnerabilities.storage.googleapis.com"

// Ecosystems lists the OSV ecosystems Michel watches. The names are the
// directory names of the OSV bucket and of osv-scalibr's local matcher.
var Ecosystems = []string{"Packagist", "npm"}

// ZipPath returns where osv-scalibr's local matcher looks for an ecosystem's
// archive when it is given root as its local database path:
// <root>/osv-scalibr/<ecosystem>/all.zip
// (osv-scalibr enricher/vulnmatch/osvlocal/matcher.go setupLocalDBDirectory
// appends "osv-scalibr"; zip.go newZippedDB appends <ecosystem>/all.zip).
func ZipPath(root, ecosystem string) string {
	return filepath.Join(root, "osv-scalibr", ecosystem, "all.zip")
}

// SetBaseURLForTest points downloads at another server (an httptest server)
// and returns a function that restores the real one. Tests only.
func SetBaseURLForTest(u string) (restore func()) {
	old := baseURL
	baseURL = u
	return func() { baseURL = old }
}

func fetchedAtPath(root, ecosystem string) string {
	return filepath.Join(root, "osv-scalibr", ecosystem, "fetched_at")
}
