//go:build !windows && !linux && !darwin

package notify

// platformCommand refuses: this system has no supported toast.
var platformCommand toastCommand = unsupportedCommand
