package serverlog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/sshx"
)

// ErrOutputCut means the server's answer went past what the SSH client keeps.
// The file lines come last, after the records: a cut answer has no reliable
// positions, so the read counts as failed and nothing moves.
var ErrOutputCut = errors.New("the log read failed: the answer was too long and was cut")

// ErrReadFailed means the filter did not run to its end on the server.
var ErrReadFailed = errors.New("the log read failed")

// Read runs the filter of src on the server, with `sh -s` and no privilege, and
// revalidates what comes back (ParseOutput). cursors are the positions saved so
// far for the source. The returned cursors are the ones to store, each replacing
// the saved one of the same file: the files read in this pass, plus a placeholder
// when nothing at all was located.
//
// An activation (no cursor) locates the files at their end and reads nothing. If
// it finds no file, the placeholder is returned (see placeholderCursor): a file
// that appears later is read from its start, as any file appeared after the
// activation.
//
// Any failure (connection, exit status, timeout, cut or empty answer) returns
// an error, no output and no cursor: nothing moves, the next pass starts again
// from the saved positions. Nothing the server wrote on its error stream is
// repeated in the error.
func Read(ctx context.Context, c *sshx.Client, src Source, cursors []Cursor, o FilterOptions, timeout time.Duration, now time.Time) (Output, []Cursor, error) {
	out, err := execute(ctx, c, src, cursors, o, timeout, now)
	if err != nil {
		return Output{}, nil, err
	}
	next := make([]Cursor, 0, len(out.Files)+1)
	for _, f := range out.Files {
		next = append(next, Cursor{SourceID: src.ID, File: f.File, FileID: f.FileID, Offset: f.Offset, ReadAt: now})
	}
	if len(cursors) == 0 && len(out.Files) == 0 {
		next = append(next, placeholderCursor(src, now))
	}
	return out, next, nil
}

// Try runs the filter once and returns exactly what would come back, from the
// start of each file and within the caps. It stores nothing and moves no
// position: it returns no cursor, and the caller saves none.
func Try(ctx context.Context, c *sshx.Client, src Source, o FilterOptions, timeout time.Duration, now time.Time) (Output, error) {
	// A cursor makes the filter read: without any, it would only locate the ends.
	return execute(ctx, c, src, []Cursor{placeholderCursor(src, now)}, o, timeout, now)
}

// placeholderCursor says that the source was activated, without naming a file:
// its path ends with a slash, which no file path does (ValidatePath refuses a
// folder), so it matches nothing in the filter. The wildcards of the source are
// replaced, since a position names a plain path (Script refuses `*` and `?`
// there). Any cursor at all makes the next read take a file for one that
// appeared since.
func placeholderCursor(src Source, now time.Time) Cursor {
	plain := strings.NewReplacer("*", "_", "?", "_").Replace(src.Path)
	return Cursor{SourceID: src.ID, File: plain + "/", ReadAt: now}
}

func execute(ctx context.Context, c *sshx.Client, src Source, cursors []Cursor, o FilterOptions, timeout time.Duration, now time.Time) (Output, error) {
	script, err := Script(src, cursors, o)
	if err != nil {
		return Output{}, err
	}
	res, err := c.RunWith(ctx, []string{"sh", "-s"}, strings.NewReader(script), sshx.RunOptions{Timeout: timeout})
	if err != nil {
		return Output{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	switch {
	case res.Truncated:
		return Output{}, ErrOutputCut
	case res.Exit != 0:
		return Output{}, fmt.Errorf("%w: the filter ended with status %d", ErrReadFailed, res.Exit)
	case len(res.Stdout) == 0:
		// The filter always says something: a file, an unseen path or a cap.
		return Output{}, fmt.Errorf("%w: the filter said nothing", ErrReadFailed)
	}
	return ParseOutput(res.Stdout, src, o, now), nil
}
