package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Load reads the policy at path. A missing file gives the built-in defaults.
// A present file is decoded strictly on top of the defaults, so omitted keys
// keep their default value. Load does not validate; call Validate.
func Load(path string, dataDir string) (Policy, Source, error) {
	p := Defaults()
	p.DB.OSVPath = filepath.Join(dataDir, "osv")

	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return p, SourceDefaults, nil
	}
	if err != nil {
		return Policy{}, "", fmt.Errorf("cannot read policy file %s: %w", path, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, "", fmt.Errorf("cannot parse policy file %s: %w", path, err)
	}
	return p, SourceFile, nil
}
