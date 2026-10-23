package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
// that shows them, with what to write on its stdin (nil for nothing).
type toastCommand func(title, body string) (name string, args []string, stdin []byte, err error)

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
	title, body = plainText(title), plainText(body)
	name, args, stdin, err := t.command(title, body)
	if err != nil {
		return 0, err
	}
	r := t.deps.Runner
	if r == nil {
		r = execRunner{}
	}
	ctx, cancel := context.WithTimeout(ctx, toastTimeout)
	defer cancel()
	if err := r.Run(ctx, name, args, stdin); err != nil {
		return 0, err
	}
	return len(title) + len(body), nil
}

// plainText replaces the control characters XML 1.0 refuses by spaces; line
// breaks and tabs are kept.
func plainText(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
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

// toastScript is the whole PowerShell script of the Windows toast. It is a
// constant: the title and the body never enter it. They arrive on stdin as
// JSON and become XML text nodes through the DOM (CreateTextNode), so no
// text can end a string literal or an XML element, whatever it holds.
var toastScript = strings.Join([]string{
	`$ErrorActionPreference = 'Stop'`,
	`$ProgressPreference = 'SilentlyContinue'`,
	`[Console]::InputEncoding = [Text.Encoding]::UTF8`,
	`$in = [Console]::In.ReadToEnd() | ConvertFrom-Json`,
	`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null`,
	`[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null`,
	`$xml = New-Object Windows.Data.Xml.Dom.XmlDocument`,
	`$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text/><text/></binding></visual></toast>')`,
	`$texts = $xml.GetElementsByTagName('text')`,
	`$texts.Item(0).AppendChild($xml.CreateTextNode([string]$in.title)) | Out-Null`,
	`$texts.Item(1).AppendChild($xml.CreateTextNode([string]$in.body)) | Out-Null`,
	`$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)`,
	`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('` + powerShellAUMID + `').Show($toast)`,
}, "\r\n")

// encodedToastScript is toastScript as -EncodedCommand wants it: UTF-16LE,
// base64.
var encodedToastScript = func() string {
	units := utf16.Encode([]rune(toastScript))
	raw := make([]byte, 0, 2*len(units))
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}()

// asciiJSON marshals v and escapes every non-ASCII character as \uXXXX, so
// the bytes read the same whatever the console's input encoding.
func asciiJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, r := range string(raw) {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u%04x`, u)
		}
	}
	return []byte(b.String()), nil
}

// windowsCommand shows the toast with Windows PowerShell 5.1 (from
// systemRoot, %SystemRoot%) and WinRT. The script is constant; the texts go
// through stdin.
func windowsCommand(systemRoot string) toastCommand {
	return func(title, body string) (string, []string, []byte, error) {
		stdin, err := asciiJSON(map[string]string{"title": title, "body": body})
		if err != nil {
			return "", nil, nil, err
		}
		// Built with backslashes on any system, so the command is the same
		// wherever it is computed (tests run everywhere).
		exe := strings.TrimRight(systemRoot, `\/`) + `\System32\WindowsPowerShell\v1.0\powershell.exe`
		return exe, []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", encodedToastScript}, stdin, nil
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
	return func(title, body string) (string, []string, []byte, error) {
		exe, err := lookPath("notify-send")
		if err != nil {
			return "", nil, nil, errors.New("notify: notify-send not found")
		}
		// "--" ends the options: a text starting with "-" stays a text.
		return exe, []string{"--", digest.DefaultAssistant, toastText(title, body)}, nil, nil
	}
}

// darwinCommand shows the toast with /usr/bin/osascript (best effort),
// never resolved through PATH.
func darwinCommand(title, body string) (string, []string, []byte, error) {
	return "/usr/bin/osascript", []string{"-e", `display notification "` + appleScriptEscape(toastText(title, body)) +
		`" with title "` + digest.DefaultAssistant + `"`}, nil, nil
}

// toastText is the single text of a toast that has a fixed title.
func toastText(title, body string) string {
	if body == "" {
		return title
	}
	return title + " — " + body
}

// appleScriptEscape escapes a text for an AppleScript string literal; line
// breaks and tabs become spaces.
func appleScriptEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ", "\t", " ").Replace(s)
}

// unsupportedCommand is the toast of a system without one.
func unsupportedCommand(string, string) (string, []string, []byte, error) {
	return "", nil, nil, errors.New("notify: desktop notifications are not supported on this system")
}
