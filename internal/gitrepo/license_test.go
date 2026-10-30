package gitrepo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLicenseSPDX(t *testing.T) {
	cases := []struct {
		file, text, want string
	}{
		{"LICENSE", "MIT License\n\nPermission is hereby granted, free of charge, to any person", "MIT"},
		{"LICENSE.txt", "                                 Apache License\n                           Version 2.0, January 2004", "Apache-2.0"},
		{"COPYING", "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007", "GPL-3.0"},
		{"LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991", "GPL-2.0"},
		{"LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE\n Version 2.1, February 1999", "LGPL-2.1"},
		{"LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007", "AGPL-3.0"},
		{"LICENSE.md", "Mozilla Public License Version 2.0", "MPL-2.0"},
		{"LICENCE", "Redistribution and use in source and binary forms, with or without modification... 3. Neither the name of", "BSD-3-Clause"},
		{"LICENSE", "Redistribution and use in source and binary forms, with or without modification", "BSD-2-Clause"},
		{"LICENSE", "Attribution-ShareAlike 4.0 International", "CC-BY-SA-4.0"},
		{"LICENSE", "All rights reserved.", "unknown"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.text), 0o644); err != nil {
			t.Fatal(err)
		}
		got := DetectLicense(dir)
		if got.SPDX != c.want {
			t.Errorf("%s %q: got %q, want %q", c.file, c.text[:20], got.SPDX, c.want)
		}
		if c.want != "unknown" && got.File != c.file {
			t.Errorf("%s: file = %q", c.want, got.File)
		}
	}
	if got := DetectLicense(t.TempDir()); got.SPDX != "unknown" || got.File != "" {
		t.Errorf("no file: %+v", got)
	}
}
