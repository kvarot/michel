package secret

// SetLink replaces the hard link call of Create (tests of the file systems
// without hard links); the returned func puts it back.
func SetLink(f func(oldname, newname string) error) func() {
	old := link
	link = f
	return func() { link = old }
}
