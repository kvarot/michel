//go:build !michel_local_remote

package cli

// allowLocalRemote is false in every build but the throwaway one of the novice
// trial (R33): a push to a remote on this disk would run that repository's hooks.
// No variable, flag or setting opens it at run time.
const allowLocalRemote = false
