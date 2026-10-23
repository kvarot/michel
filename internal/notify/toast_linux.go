package notify

import "os/exec"

// platformCommand is the Linux toast: notify-send when it is installed.
var platformCommand = linuxCommand(exec.LookPath)
