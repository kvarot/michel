package cli

import (
	"errors"

	"github.com/kvarot/michel/internal/i18n"
)

// Every message a command prints or returns to the user goes through these
// helpers, so it is read from the catalog in the user's language. Before the
// language is resolved (deps.Lang == ""), the catalog falls back to English.

// T returns the catalog text for key in the user's language, formatted with
// args.
func (d *Deps) T(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }

// N returns the plural form of key for n (key.one / key.other), formatted
// with n first, then args.
func (d *Deps) N(key string, n int, args ...any) string { return i18n.N(d.Lang, key, n, args...) }

// Errorf returns an error whose message is the catalog text for key.
func (d *Deps) Errorf(key string, args ...any) error { return errors.New(d.T(key, args...)) }

// Wrapf returns an error whose message is the catalog text for key, formatted
// with args then err as the last argument (the text places it with %v, or
// with an explicit index when it is not last), and that unwraps to err.
func (d *Deps) Wrapf(key string, err error, args ...any) error {
	return &wrapError{msg: d.T(key, append(args[:len(args):len(args)], err)...), err: err}
}

// wrapError is a translated message that keeps the error it explains.
type wrapError struct {
	msg string
	err error
}

func (e *wrapError) Error() string { return e.msg }
func (e *wrapError) Unwrap() error { return e.err }
