//go:build !windows
// +build !windows

package utils

import (
	"os"
	"os/signal"
	"syscall"
)

// ReloadSignals returns a channel that receives SIGHUP, the conventional
// signal to reload the configuration.
func ReloadSignals() <-chan os.Signal {
	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, syscall.SIGHUP)

	return sigChan
}
