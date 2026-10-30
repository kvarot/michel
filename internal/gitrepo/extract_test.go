package gitrepo

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtractRefusesTraversalAndSymlinks(t *testing.T) {
	root := "skill-" + shaA + "/"
	cases := []struct {
		name  string
		entry tarEntry
		want  error
	}{
		{"parent", tarEntry{name: "../x", body: "x"}, ErrTraversal},
		{"parent inside", tarEntry{name: root + "a/../../x", body: "x"}, ErrTraversal},
		{"absolute", tarEntry{name: "/etc/x", body: "x"}, ErrTraversal},
		{"drive letter", tarEntry{name: root + "C:/x", body: "x"}, ErrTraversal},
		{"backslash", tarEntry{name: root + `a\..\..\x`, body: "x"}, ErrTraversal},
		{"symlink", tarEntry{name: root + "link", typ: tar.TypeSymlink, link: "/etc/passwd"}, ErrSymlink},
		{"hard link", tarEntry{name: root + "hard", typ: tar.TypeLink, link: root + "README.md"}, ErrSymlink},
		{"device", tarEntry{name: root + "dev", typ: tar.TypeChar}, ErrSpecialFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := t.TempDir()
			_, err := Extract(bytes.NewReader(buildTarGz(t, file("README.md", "hi"), c.entry)), dst)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "x")); err == nil {
				t.Error("a file was written outside the destination")
			}
		})
	}

	dst := t.TempDir()
	files, err := Extract(bytes.NewReader(skillArchive(t, "---\nname: demo\n---\n")), dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 || files[0].Path != "LICENSE" {
		t.Fatalf("files = %+v", files)
	}
	fi, err := os.Stat(filepath.Join(dst, "skills", "demo", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 != 0 && runtime.GOOS != "windows" {
		t.Errorf("run.sh mode = %v, want no executable bit", fi.Mode())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("run.sh mode = %v, want 0644", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dst, "pax_global_header")); err == nil {
		t.Error("the pax global header was written as a file")
	}
}

func TestExtractCapsFilesAndBytes(t *testing.T) {
	defer setLimitsForTest(1<<20, 10, 3)()
	_, err := Extract(bytes.NewReader(buildTarGz(t, file("a", "1"), file("b", "2"), file("c", "3"), file("d", "4"))), t.TempDir())
	if !errors.Is(err, ErrTooManyFiles) {
		t.Errorf("4 files, cap 3: err = %v", err)
	}
	_, err = Extract(bytes.NewReader(buildTarGz(t, file("a", "123456"), file("b", "123456"))), t.TempDir())
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("12 bytes, cap 10: err = %v", err)
	}
	big := buildTarGz(t, file("a", strings.Repeat("x", 4000)))
	defer setLimitsForTest(int64(len(big)-1), 1<<20, 10)()
	if _, err := Extract(bytes.NewReader(big), t.TempDir()); !errors.Is(err, ErrTooLarge) {
		t.Errorf("archive over the compressed cap: err = %v", err)
	}
}

func TestExtractPathKeepsOnlyTheFolderAndRootLicence(t *testing.T) {
	root := "skill-" + shaA + "/"
	arch := buildTarGz(t, file("LICENSE", "MIT"), file("skills/demo/SKILL.md", "x"),
		tarEntry{name: root + "elsewhere/link", typ: tar.TypeSymlink, link: "/etc/passwd"}, file("elsewhere/a.md", "a"))
	dst := t.TempDir()
	files, err := extract(bytes.NewReader(arch), dst, "skills/demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Path != "LICENSE" || files[1].Path != "skills/demo/SKILL.md" {
		t.Errorf("files = %+v", files)
	}
	if _, err := os.Stat(filepath.Join(dst, "elsewhere")); err == nil {
		t.Error("a member outside the folder was written")
	}
	// A link inside the folder still refuses the whole archive.
	arch = buildTarGz(t, tarEntry{name: root + "skills/demo/link", typ: tar.TypeSymlink, link: "../../x"})
	if _, err := extract(bytes.NewReader(arch), t.TempDir(), "skills/demo"); !errors.Is(err, ErrSymlink) {
		t.Errorf("link in folder: err = %v", err)
	}
}
