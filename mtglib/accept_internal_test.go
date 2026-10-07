package mtglib

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scriptedListener returns the scripted results of Accept in order and then
// net.ErrClosed.
type scriptedListener struct {
	mu      sync.Mutex
	results []error
	calls   int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++

	if len(l.results) == 0 {
		return nil, net.ErrClosed
	}

	err := l.results[0]
	l.results = l.results[1:]

	if err != nil {
		return nil, err
	}

	client, server := net.Pipe()
	client.Close() //nolint: errcheck

	return server, nil
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

// Running out of file descriptors under a connection flood must not stop the
// accept loop: the next connection is accepted once descriptors are available.
func TestAcceptWithRetrySurvivesTemporaryErrors(t *testing.T) {
	t.Parallel()

	listener := &scriptedListener{results: []error{syscall.EMFILE, syscall.EMFILE, nil}}

	conn, err := acceptWithRetry(context.Background(), listener, NoopLogger{})
	if err != nil {
		t.Fatalf("expected a connection after temporary errors, got %v", err)
	}

	conn.Close() //nolint: errcheck

	if listener.calls != 3 {
		t.Fatalf("expected 3 Accept calls, got %d", listener.calls)
	}
}

func TestAcceptWithRetryStopsOnClosedListener(t *testing.T) {
	t.Parallel()

	_, err := acceptWithRetry(context.Background(), &scriptedListener{}, NoopLogger{})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

func TestAcceptWithRetryStopsOnShutdownDuringPause(t *testing.T) {
	t.Parallel()

	errs := make([]error, 100)
	for i := range errs {
		errs[i] = syscall.EMFILE
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()

	_, err := acceptWithRetry(ctx, &scriptedListener{results: errs}, NoopLogger{})
	if err == nil {
		t.Fatal("expected an error after shutdown")
	}

	if time.Since(start) > time.Second {
		t.Fatalf("shutdown must interrupt the retry pause, took %v", time.Since(start))
	}
}
