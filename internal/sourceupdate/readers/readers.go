// Package readers holds the adapters that read each kind of source for
// sourceupdate. Each file registers its reader in init; importing the
// package (internal/cli does) wires them all.
package readers
