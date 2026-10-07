// Package acceptretry decides how an accept loop reacts to Accept errors.
//
// It is shared by mtglib (the proxy accept loop) and internal/utils (the
// listeners) without widening the public API of mtglib.
package acceptretry

import (
	"errors"
	"net"
	"syscall"
	"time"
)

const (
	// MinDelay is the pause after the first temporary error.
	MinDelay = 5 * time.Millisecond

	// MaxDelay caps the pause between attempts.
	MaxDelay = time.Second
)

// IsTemporary reports whether an Accept error is transient: the listener is
// still usable and accepting should be retried after a pause. Running out of
// file descriptors under a connection flood (EMFILE/ENFILE) is the important
// case: returning from the accept loop on such an error leaves the process
// alive but deaf until it is restarted.
func IsTemporary(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET)
}

// NextDelay returns the pause before the next Accept attempt after a temporary
// error: it starts at MinDelay and doubles up to MaxDelay, like net/http.
func NextDelay(previous time.Duration) time.Duration {
	if previous == 0 {
		return MinDelay
	}

	return min(previous*2, MaxDelay)
}
