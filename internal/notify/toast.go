package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/kvarot/michel/internal/digest"
)

// toastTimeout bounds the toast subprocess. It runs locally and contacts no
// network, so it is not under the egress gateway.
const toastTimeout = 15 * time.Second

// toastCommand turns a title and a body into the closed-list subprocess
// that shows them.
type toastCommand func(title, body string) (name string, args []string, err error)

// toast shows a desktop notification through a subprocess.
type toast struct {
	base
	command toastCommand
}

func newToast(b base) *toast { return &toast{base: b, command: platformCommand} }

func (t *toast) Target() (string, string) { return "local", "" }

func (t *toast) Send(ctx context.Context, d digest.Digest) error {
	_, err := t.send(ctx, d)
	return err
}

func (t *toast) Test(ctx context.Context) error {
	_, err := t.test(ctx)
	return err
}

func (t *toast) send(ctx context.Context, d digest.Digest) (int, error) {
	title, body := digest.ToastLines(d)
	return t.show(ctx, title, body)
}

func (t *toast) test(ctx context.Context) (int, error) {
	title, body := testMessage(t.deps.Lang)
	return t.show(ctx, title, body)
}

func (t *toast) show(ctx context.Context, title, body string) (int, error) {
	title, body = oneLine(title), oneLine(body)
	name, args, err := t.command(title, body)
	if err != nil {
		return 0, err
	}
	r := t.deps.Runner
	if r == nil {
		r = execRunner{}
	}
	ctx, cancel := context.WithTimeout(ctx, toastTimeout)
	defer cancel()
	if err := r.Run(ctx, name, args, nil); err != nil {
		return 0, err
	}
	return len(title) + len(body), nil
}

// oneLine replaces control characters (line breaks included) by spaces: XML
// 1.0 refuses most of them and a toast shows one line per text anyway.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// execRunner runs the subprocess for real.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin []byte) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("notify: %s failed: %w", filepath.Base(name), err)
	}
	return nil
}

// powerShellAUMID is the application id of Windows PowerShell: showing the
// toast under it needs no application registration.
const powerShellAUMID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

// windowsCommand shows the toast with Windows PowerShell 5.1 and WinRT,
// from systemRoot (%SystemRoot%). The texts are XML-escaped, which also
// removes every single quote that could end the PowerShell string.
func windowsCommand(systemRoot string) toastCommand {
	return func(title, body string) (string, []string, error) {
		xml := `<toast><visual><binding template="ToastGeneric"><text>` + html.EscapeString(title) + `</text><text>` +
			html.EscapeString(body) + `</text></binding></visual></toast>`
		script := strings.Join([]string{
			`$ErrorActionPreference = 'Stop'`,
			`$ProgressPreference = 'SilentlyContinue'`,
			`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null`,
			`[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null`,
			`$xml = New-Object Windows.Data.Xml.Dom.XmlDocument`,
			`$xml.LoadXml('` + xml + `')`,
			`$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)`,
			`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('` + powerShellAUMID + `').Show($toast)`,
		}, "\r\n")
		units := utf16.Encode([]rune(script))
		raw := make([]byte, 0, 2*len(units))
		for _, u := range units {
			raw = append(raw, byte(u), byte(u>>8))
		}
		// Built with backslashes on any system, so the command is the same
		// wherever it is computed (tests run everywhere).
		exe := strings.TrimRight(systemRoot, `\/`) + `\System32\WindowsPowerShell\v1.0\powershell.exe`
		return exe, []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}, nil
	}
}

// systemRoot returns %SystemRoot%, C:\Windows when unset.
func systemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// linuxCommand shows the toast with notify-send, found with lookPath.
func linuxCommand(lookPath func(string) (string, error)) toastCommand {
	return func(title, body string) (string, []string, error) {
		exe, err := lookPath("notify-send")
		if err != nil {
			return "", nil, errors.New("notify: notify-send not found")
		}
		return exe, []string{digest.DefaultAssistant, toastText(title, body)}, nil
	}
}

// darwinCommand shows the toast with osascript (best effort).
func darwinCommand(title, body string) (string, []string, error) {
	return "osascript", []string{"-e", `display notification "` + appleScriptEscape(toastText(title, body)) +
		`" with title "` + digest.DefaultAssistant + `"`}, nil
}

// toastText is the single text of a toast that has a fixed title.
func toastText(title, body string) string {
	if body == "" {
		return title
	}
	return title + " — " + body
}

// appleScriptEscape escapes a text for an AppleScript string literal.
func appleScriptEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// unsupportedCommand is the toast of a system without one.
func unsupportedCommand(string, string) (string, []string, error) {
	return "", nil, errors.New("notify: desktop notifications are not supported on this system")
}
