//go:build !windows && !linux && !darwin

package notify

import "errors"

// platformCommand refuses: this system has no supported toast.
var platformCommand toastCommand = unsupportedCommand

// unsupportedCommand is the toast of a system without one.
func unsupportedCommand(string, string) (string, []string, []byte, error) {
	return "", nil, nil, errors.New("notify: desktop notifications are not supported on this system")
}
