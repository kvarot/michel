// Package web embeds the built front of the "Today" page (web/dist, made by
// 'make web'). A checkout without Node holds only dist/.gitkeep: the binary
// still builds, and michel serve answers "/" with a short text page.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the dist subtree; false if index.html is absent.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}
