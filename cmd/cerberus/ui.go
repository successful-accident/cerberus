package main

import (
	"errors"
	"io"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

// ui asks questions with huh, one at a time.
type ui struct {
	in         io.Reader
	out        io.Writer
	accessible bool
}

func (a *app) ui(cmd *cobra.Command) *ui {
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); a.accessible && !(ok && isCharDevice(f)) {
		in = byteReader{in}
	}
	return &ui{in: in, out: cmd.OutOrStdout(), accessible: a.accessible}
}

// byteReader hands out one byte per read. huh's accessible prompts each wrap
// the input in their own scanner, so piped answers would otherwise vanish
// into the first prompt's buffer.
type byteReader struct{ r io.Reader }

func (b byteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return b.r.Read(p[:1])
}

func (u *ui) run(f huh.Field) error {
	form := huh.NewForm(huh.NewGroup(f))
	if u.accessible {
		form = form.WithAccessible(true).WithInput(u.in).WithOutput(u.out)
	}
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errCancelled
		}
		return err
	}
	return nil
}

func (u *ui) confirm(title string, def bool) (bool, error) {
	v := def
	err := u.run(huh.NewConfirm().Title(title).Value(&v))
	return v, err
}

func (u *ui) input(title, def string, validate func(string) error) (string, error) {
	v := def
	f := huh.NewInput().Title(title).Value(&v)
	if validate != nil {
		f = f.Validate(validate)
	}
	err := u.run(f)
	return v, err
}

// secret asks for text without echoing it.
func (u *ui) secret(title string, validate func(string) error) (string, error) {
	var v string
	err := u.run(huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&v).Validate(validate))
	return v, err
}

func choose[T comparable](u *ui, title string, def T, opts ...huh.Option[T]) (T, error) {
	v := def
	err := u.run(huh.NewSelect[T]().Title(title).Options(opts...).Value(&v))
	return v, err
}

// pick is a filterable checklist with current pre-checked.
func (u *ui) pick(title string, opts []huh.Option[string], current []string) ([]string, error) {
	v := append([]string(nil), current...)
	err := u.run(huh.NewMultiSelect[string]().Title(title).Options(opts...).Filterable(true).Height(15).Value(&v))
	return v, err
}
