// Package terminal restores terminal state even when passphrase entry is interrupted.
package terminal

import (
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
)

func Password(input *os.File, status io.Writer) ([]byte, error) {
	fd := int(input.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("noninteractive use requires --passphrase-file")
	}
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupt := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupt, terminationSignals...)
	defer signal.Stop(interrupt)
	defer close(done)
	go func() {
		select {
		case s := <-interrupt:
			_ = term.Restore(fd, state)
			fmt.Fprintln(status)
			os.Exit(exitStatus(s))
		case <-done:
		}
	}()
	fmt.Fprint(status, "Identity passphrase: ")
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(status)
	return p, err
}
