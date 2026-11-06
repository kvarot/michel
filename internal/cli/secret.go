package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/secret"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// maxSecretBytes bounds a value read from stdin: a secret is a password or a
// token, not a file.
const maxSecretBytes = 64 << 10

func newSecretCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "secret",
		Short: "Store the passwords and tokens Michel needs, outside the policy file",
		Long: "Secret keeps passwords and tokens (SMTP password, webhook token) in the data folder, one file per name. " +
			"On Windows each file is encrypted for your user account (DPAPI); elsewhere it is plain text readable by " +
			"your account only (mode 0600). Values are never printed, never written to the audit log.",
	}
	c.AddCommand(newSecretSetCmd(deps), newSecretListCmd(deps), newSecretDeleteCmd(deps))
	return c
}

// openSecrets opens the secret store of the data folder.
func openSecrets(cmd *cobra.Command, deps *Deps) (secret.Store, error) {
	dir, _ := cmd.Flags().GetString("data-dir")
	st, err := secret.Open(dir)
	if err != nil {
		return nil, deps.Wrapf("cli.secret.open_failed", err, dir)
	}
	return st, nil
}

// secretNameError explains a name refused by the store.
func secretNameError(deps *Deps, name string, err error) error {
	switch {
	case errors.Is(err, secret.ErrInvalidName):
		// The rejected name is not echoed: it may be a value typed by mistake.
		return deps.Errorf("cli.secret.invalid_name")
	case errors.Is(err, secret.ErrNotFound):
		return deps.Errorf("cli.secret.not_found", name)
	}
	return nil
}

// recordSecret writes the audit event of a change: the name only.
func recordSecret(cmd *cobra.Command, deps *Deps, action, name string) error {
	_, err := deps.Audit.Record(cmd.Context(), audit.Event{
		Actor: "cli", Action: action, Target: name, Result: "ok",
		Evidence: map[string]any{"name": name},
	})
	if err != nil {
		return deps.Wrapf("cli.secret.audit_failed", err, name)
	}
	return nil
}

// readSecretValue reads the value from stdin: everything when it is a pipe or
// a file (one trailing line break removed), a hidden line when it is a
// terminal.
func readSecretValue(deps *Deps, name string) ([]byte, error) {
	in := deps.Stdin
	if in == nil {
		in = os.Stdin
	}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(deps.Stderr, deps.T("cli.secret.prompt", name))
		v, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(deps.Stderr)
		if err != nil {
			return nil, deps.Wrapf("cli.secret.read_failed", err)
		}
		return v, nil
	}
	v, err := io.ReadAll(io.LimitReader(in, maxSecretBytes+1))
	if err != nil {
		return nil, deps.Wrapf("cli.secret.read_failed", err)
	}
	if len(v) > maxSecretBytes {
		return nil, deps.Errorf("cli.secret.too_long", name, maxSecretBytes)
	}
	if b, ok := bytes.CutSuffix(v, []byte("\r\n")); ok {
		v = b
	} else {
		v, _ = bytes.CutSuffix(v, []byte("\n"))
	}
	return v, nil
}

func newSecretSetCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "set <name>",
		Short: "Store a secret; the value is read from stdin or typed hidden, never given as an argument",
		Long: "Set stores the value under name (1 to 64 lowercase letters, digits or hyphens), replacing any previous " +
			"value. Pipe the value in (printf '%s' \"$TOKEN\" | michel secret set webhook-token) or type it when asked: " +
			"it is never an argument, so it stays out of the shell history. The name api-token is reserved for michel serve.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if name == secret.ReservedAPIToken {
				return deps.Errorf("cli.secret.reserved", name)
			}
			if name == secret.ReservedAuditKey {
				return deps.Errorf("cli.secret.reserved_audit_key", name)
			}
			if !secret.ValidName(name) { // before touching the folder or asking for the value
				return secretNameError(deps, name, secret.ErrInvalidName)
			}
			st, err := openSecrets(cmd, deps)
			if err != nil {
				return err
			}
			value, err := readSecretValue(deps, name)
			if err != nil {
				return err
			}
			defer clear(value)
			if len(bytes.TrimSpace(value)) == 0 {
				return deps.Errorf("cli.secret.empty", name)
			}
			if err := st.Set(name, value); err != nil {
				if e := secretNameError(deps, name, err); e != nil {
					return e
				}
				return deps.Wrapf("cli.secret.set_failed", err, name)
			}
			if !secret.Protected() {
				fmt.Fprintln(deps.Stderr, deps.T("cli.secret.plain_warning", runtime.GOOS))
			}
			if err := recordSecret(cmd, deps, "secret.set", name); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.secret.set_done", name))
			return nil
		},
	}
}

func newSecretListCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the names of the stored secrets (never their values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openSecrets(cmd, deps)
			if err != nil {
				return err
			}
			all, err := st.List()
			if err != nil {
				return deps.Wrapf("cli.secret.list_failed", err)
			}
			// The key of the audit seals is Michel's own: it is not listed.
			names := []string{}
			for _, n := range all {
				if n != secret.ReservedAuditKey {
					names = append(names, n)
				}
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				enc := json.NewEncoder(deps.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"names": names, "protected": secret.Protected()})
			}
			if len(names) == 0 {
				fmt.Fprintln(deps.Stdout, deps.T("cli.secret.list_empty"))
				return nil
			}
			for _, n := range names {
				fmt.Fprintln(deps.Stdout, n)
			}
			return nil
		},
	}
}

func newSecretDeleteCmd(deps *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a stored secret",
		Long: "Delete removes the secret name. Deleting api-token makes michel serve create a new token at its next " +
			"start.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if name == secret.ReservedAuditKey {
				// Without it, the seals of the audit log can no longer be checked.
				return deps.Errorf("cli.secret.reserved_audit_key", name)
			}
			if !secret.ValidName(name) {
				return secretNameError(deps, name, secret.ErrInvalidName)
			}
			st, err := openSecrets(cmd, deps)
			if err != nil {
				return err
			}
			if err := st.Delete(name); err != nil {
				if e := secretNameError(deps, name, err); e != nil {
					return e
				}
				return deps.Wrapf("cli.secret.delete_failed", err, name)
			}
			if err := recordSecret(cmd, deps, "secret.delete", name); err != nil {
				return err
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.secret.deleted", name))
			return nil
		},
	}
}
