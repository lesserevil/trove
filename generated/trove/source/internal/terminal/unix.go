//go:build !windows

package terminal

import (
	"os"
	"syscall"
)

var terminationSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

func exitStatus(s os.Signal) int {
	if n, ok := s.(syscall.Signal); ok {
		return 128 + int(n)
	}
	return 130
}
