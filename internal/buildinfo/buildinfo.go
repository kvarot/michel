// Package buildinfo holds values injected at build time.
package buildinfo

// Version is the release version. Override it at build time with
// -ldflags "-X github.com/kvarot/michel/internal/buildinfo.Version=1.2.3".
var Version = "dev"
