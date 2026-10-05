//go:build windows

package terminal

import "os"

var terminationSignals = []os.Signal{os.Interrupt}

func exitStatus(s os.Signal) int { return 130 }
