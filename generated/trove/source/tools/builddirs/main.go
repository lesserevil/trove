package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	clean := len(args) > 0 && args[0] == "--clean"
	if clean {
		args = args[1:]
	}
	for _, p := range args {
		var err error
		if clean {
			err = os.RemoveAll(p)
		} else {
			err = os.MkdirAll(p, 0700)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
