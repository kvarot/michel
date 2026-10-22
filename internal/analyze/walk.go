package analyze

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxFileSize = 2 << 20 // 2 MiB

var fixedExcludes = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"dist": true, "build": true, ".cache": true,
}

// generatedDirs are framework caches, relative to the manifest directory
// (forward slashes): compiled templates and proxies there repeat the user's
// code and would count the same use several times.
var generatedDirs = map[string]bool{
	"var/cache": true, "storage/framework": true, "bootstrap/cache": true, ".phpunit.cache": true,
}

func isExcludedDir(name string, exclude []string) bool {
	if fixedExcludes[name] {
		return true
	}
	for _, e := range exclude {
		if e == name {
			return true
		}
	}
	return false
}

// findOtherManifestDirs lists the directories under root (other than
// manifestDir) that hold their own composer.lock or package-lock.json.
func findOtherManifestDirs(root, manifestDir string, exclude []string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if p != root && isExcludedDir(d.Name(), exclude) {
				return filepath.SkipDir
			}
			return nil
		}
		if n := d.Name(); n == "composer.lock" || n == "package-lock.json" {
			if dir := filepath.Dir(p); dir != manifestDir {
				dirs = append(dirs, dir)
			}
		}
		return nil
	})
	return dirs, err
}

// userFiles returns, sorted, the files under manifestDir having one of the
// given extensions, skipping excluded directories, directories of other
// manifests, symlinks and files larger than 2 MiB.
func userFiles(root, manifestDir string, otherManifestDirs []string, exclude []string, exts []string) ([]string, error) {
	skip := make(map[string]bool, len(otherManifestDirs))
	for _, d := range otherManifestDirs {
		skip[d] = true
	}
	var files []string
	err := filepath.WalkDir(manifestDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if p == manifestDir {
				return nil
			}
			if isExcludedDir(d.Name(), exclude) || skip[p] {
				return filepath.SkipDir
			}
			if rel, err := filepath.Rel(manifestDir, p); err == nil && generatedDirs[filepath.ToSlash(rel)] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		for _, e := range exts {
			if ext == e {
				if info, err := os.Stat(p); err == nil && info.Size() <= maxFileSize {
					files = append(files, p)
				}
				break
			}
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}
