//go:build linux

package mtglib

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

// On Linux accept(2) returns pending network errors of the new connection.
// They must not end the accept loop: the next connection is accepted at once.
func TestAcceptWithRetrySkipsAcceptedConnErrors(t *testing.T) {
	t.Parallel()

	for _, errno := range []syscall.Errno{syscall.ENETDOWN, syscall.EPROTO, syscall.ENOPROTOOPT, syscall.EHOSTDOWN, syscall.ENONET, syscall.EHOSTUNREACH, syscall.EOPNOTSUPP, syscall.ENETUNREACH} {
		wrapped := &net.OpError{Op: "accept", Err: os.NewSyscallError("accept4", errno)}
		listener := &scriptedListener{results: []error{wrapped, wrapped, nil}}

		conn, err := acceptWithRetry(context.Background(), listener, NoopLogger{})
		if err != nil {
			t.Fatalf("%v: expected the next connection, got %v", errno, err)
		}

		conn.Close() //nolint: errcheck

		if listener.calls != 3 {
			t.Fatalf("%v: expected 3 Accept calls, got %d", errno, listener.calls)
		}
	}
}

// After shutdown the loop must stop even on these errors.
func TestAcceptWithRetryStopsOnShutdownWithAcceptedConnError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := acceptWithRetry(ctx, &scriptedListener{results: []error{syscall.ENETUNREACH, nil}}, NoopLogger{})
	if err == nil {
		t.Fatal("expected an error after shutdown")
	}
}
