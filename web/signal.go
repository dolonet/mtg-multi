package web

import (
	"context"
	"os"
	"time"
)

// broadcast is a "something changed" signal that any number of goroutines can
// wait on at once. It is guarded by the owner's mutex.
//
// A single-slot channel is not enough here: one send wakes exactly one
// waiter, and the others (writers of other streams, the long poll) would keep
// sleeping, with a zero deadline forever. Closing a channel wakes everybody.
type broadcast struct {
	ch chan struct{}
}

// wait returns the channel that is closed on the next notify. The caller holds
// the owner's mutex, takes the channel, unlocks and only then waits on it, so
// a change made right after the unlock is not missed.
func (b *broadcast) wait() <-chan struct{} {
	if b.ch == nil {
		b.ch = make(chan struct{})
	}

	return b.ch
}

// notify wakes every current waiter. The caller holds the owner's mutex.
func (b *broadcast) notify() {
	if b.ch != nil {
		close(b.ch)
		b.ch = nil
	}
}

// waitChange waits for the signal, the deadline (zero means none) or the
// cancellation of done (nil means none).
func waitChange(changed <-chan struct{}, deadline time.Time, done <-chan struct{}) error {
	var timeout <-chan time.Time

	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return os.ErrDeadlineExceeded
		}

		timer := time.NewTimer(remaining)
		defer timer.Stop()

		timeout = timer.C
	}

	select {
	case <-changed:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	case <-done:
		return context.Canceled
	}
}
