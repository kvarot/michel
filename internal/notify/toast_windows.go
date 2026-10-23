package notify

// platformCommand is the Windows toast: Windows PowerShell 5.1 from
// %SystemRoot%, never resolved through PATH.
var platformCommand = windowsCommand(systemRoot())
