//go:build !linux

package acceptretry

import "syscall"

// acceptedConnErrnos is Linux-specific, see errno_linux.go.
var acceptedConnErrnos []syscall.Errno
