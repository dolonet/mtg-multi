package acceptretry_test

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/dolonet/mtg-multi/internal/acceptretry"
)

func TestIsTemporary(t *testing.T) {
	t.Parallel()

	temporary := []error{
		syscall.EMFILE,
		fmt.Errorf("accept tcp: %w", syscall.ENFILE),
		&net.OpError{Op: "accept", Err: syscall.ECONNABORTED},
		syscall.ENOBUFS,
	}
	for _, err := range temporary {
		if !acceptretry.IsTemporary(err) {
			t.Errorf("%v must be temporary", err)
		}
	}

	permanent := []error{nil, net.ErrClosed, fmt.Errorf("wrapped: %w", net.ErrClosed), errors.New("boom")}
	for _, err := range permanent {
		if acceptretry.IsTemporary(err) {
			t.Errorf("%v must not be temporary", err)
		}
	}
}

func TestNextDelayGrowsUpToMax(t *testing.T) {
	t.Parallel()

	delay := acceptretry.NextDelay(0)
	if delay != acceptretry.MinDelay {
		t.Fatalf("first delay: got %v", delay)
	}

	for range 20 {
		delay = acceptretry.NextDelay(delay)
	}

	if delay != acceptretry.MaxDelay {
		t.Fatalf("delay must be capped at %v, got %v", acceptretry.MaxDelay, delay)
	}
}
