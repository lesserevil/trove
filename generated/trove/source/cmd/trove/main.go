package main

import (
	"fmt"
	"os"
	"trove/internal/app"
	"trove/internal/pgp"
	"trove/internal/terminal"
)

var version = "development"

func main() {
	a := app.App{Crypto: pgp.Backend{}, In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Version: version,
		Prompt: func() ([]byte, error) {
			return terminal.Password(os.Stdin, os.Stderr)
		}}
	if err := a.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trove:", err)
		os.Exit(1)
	}
}
