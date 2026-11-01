package acceptretry_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/dolonet/mtg-multi/internal/acceptretry"
)

func TestIsAcceptedConn(t *testing.T) {
	t.Parallel()

	if len(acceptretry.AcceptedConnErrnos) != 8 {
		t.Fatalf("expected the 8 errnos from accept(2), got %d", len(acceptretry.AcceptedConnErrnos))
	}

	for _, errno := range acceptretry.AcceptedConnErrnos {
		wrapped := &net.OpError{Op: "accept", Err: os.NewSyscallError("accept4", errno)}
		if !acceptretry.IsAcceptedConn(wrapped) {
			t.Errorf("%v must be an accepted connection error", errno)
		}
	}

	for _, err := range []error{nil, net.ErrClosed, syscall.EMFILE, syscall.EBADF, fmt.Errorf("x: %w", errors.New("boom"))} {
		if acceptretry.IsAcceptedConn(err) {
			t.Errorf("%v must not be an accepted connection error", err)
		}
	}
}
