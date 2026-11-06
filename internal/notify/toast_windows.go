package notify

import "os"

// platformCommand is the Windows toast: Windows PowerShell 5.1 from
// %SystemRoot%, never resolved through PATH.
var platformCommand = windowsCommand(systemRoot())

// systemRoot returns %SystemRoot%, C:\Windows when unset.
func systemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}
