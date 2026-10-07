package utils_test

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/utils"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/stretchr/testify/suite"
)

type MultiListenerTestSuite struct {
	suite.Suite
}

func (suite *MultiListenerTestSuite) TestAcceptFromMultipleListeners() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l1.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l2.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	for range 2 {
		conn, err := ml.Accept()
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}

	wg.Wait()
}

func (suite *MultiListenerTestSuite) TestSingleListener() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l)
	defer ml.Close() //nolint: errcheck

	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	conn, err := ml.Accept()
	suite.NoError(err)

	conn.Close() //nolint: errcheck
}

func (suite *MultiListenerTestSuite) TestCloseStopsAccept() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)

	errCh := make(chan error, 1)

	go func() {
		_, err := ml.Accept()
		errCh <- err
	}()

	suite.NoError(ml.Close())
	suite.Error(<-errCh)
}

func (suite *MultiListenerTestSuite) TestConcurrentAccept() {
	const numListeners = 3
	const connsPerListener = 10

	listeners := make([]net.Listener, numListeners)

	for i := range numListeners {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		suite.Require().NoError(err)

		listeners[i] = l
	}

	ml := utils.NewMultiListener(listeners...)
	defer ml.Close() //nolint: errcheck

	var accepted atomic.Int32

	go func() {
		for range numListeners * connsPerListener {
			conn, err := ml.Accept()
			if err != nil {
				return
			}

			accepted.Add(1)

			conn.Close() //nolint: errcheck
		}
	}()

	var wg sync.WaitGroup

	for _, l := range listeners {
		for range connsPerListener {
			wg.Add(1)

			go func() {
				defer wg.Done()

				conn, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					return
				}

				conn.Close() //nolint: errcheck
			}()
		}
	}

	wg.Wait()

	suite.Eventually(func() bool {
		return accepted.Load() == numListeners*connsPerListener
	}, 2_000_000_000, 10_000_000) // 2s timeout, 10ms poll
}

func (suite *MultiListenerTestSuite) TestAddr() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	suite.Equal(l1.Addr(), ml.Addr())
}

// flakyListener returns one temporary error and then delegates to a real
// listener.
type flakyListener struct {
	net.Listener

	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, syscall.EMFILE
	}

	return l.Listener.Accept()
}

// A temporary error on one listener must not stop accepting on it forever.
func (suite *MultiListenerTestSuite) TestTemporaryErrorDoesNotStopListener() {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(&flakyListener{Listener: base})
	defer ml.Close() //nolint: errcheck

	_, err = ml.Accept()
	suite.True(errors.Is(err, syscall.EMFILE))

	go func() {
		conn, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			conn.Close() //nolint: errcheck
		}
	}()

	accepted := make(chan error, 1)

	go func() {
		conn, err := ml.Accept()
		if err == nil {
			conn.Close() //nolint: errcheck
		}

		accepted <- err
	}()

	select {
	case err := <-accepted:
		suite.NoError(err)
	case <-time.After(2 * time.Second):
		suite.Fail("listener stopped accepting after a temporary error")
	}
}

// failingListener fails every Accept with a temporary error until it is
// closed and counts the calls.
type failingListener struct {
	net.Listener

	calls  atomic.Int32
	closed atomic.Bool
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calls.Add(1)

	if l.closed.Load() {
		return nil, net.ErrClosed
	}

	return nil, syscall.EMFILE
}

func (l *failingListener) Close() error {
	l.closed.Store(true)

	return l.Listener.Close() //nolint: wrapcheck
}

func (suite *MultiListenerTestSuite) newFailingMultiListener() (*utils.MultiListener, *failingListener) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	failing := &failingListener{Listener: base}
	ml := utils.NewMultiListener(failing)

	suite.T().Cleanup(func() {
		ml.Close() //nolint: errcheck

		// Drain until the accept loop reports the closed listener and exits.
		deadline := time.After(2 * time.Second)

		for {
			result := make(chan error, 1)

			go func() {
				_, err := ml.Accept()
				result <- err
			}()

			select {
			case err := <-result:
				if errors.Is(err, net.ErrClosed) {
					return
				}
			case <-deadline:
				return
			}
		}
	})

	return ml, failing
}

// MultiListener must not pause after a temporary error: the consumer
// (Proxy.Serve) owns the retry pause, and pausing in both places applied the
// delay twice.
func (suite *MultiListenerTestSuite) TestTemporaryErrorsAreForwardedWithoutPause() {
	ml, _ := suite.newFailingMultiListener()

	const errorsToRead = 8

	start := time.Now()

	for range errorsToRead {
		_, err := ml.Accept()
		suite.Require().ErrorIs(err, syscall.EMFILE)
	}

	// With a pause of 5ms doubling on each error inside MultiListener, reading
	// 8 errors took at least 5+10+...+320 = 635ms.
	suite.Less(time.Since(start), 300*time.Millisecond)
}

// Without its own pause the accept loop must still not spin: it retries
// Accept only as fast as the consumer takes the results.
func (suite *MultiListenerTestSuite) TestTemporaryErrorsDoNotSpin() {
	ml, failing := suite.newFailingMultiListener()

	_, err := ml.Accept()
	suite.Require().ErrorIs(err, syscall.EMFILE)

	time.Sleep(100 * time.Millisecond)

	// One result taken, one in the channel buffer, one blocked on send.
	suite.LessOrEqual(failing.calls.Load(), int32(3))
}

func TestMultiListener(t *testing.T) {
	t.Parallel()
	suite.Run(t, &MultiListenerTestSuite{})
}

// firstConnBroken returns an already closed TCP connection first (setting
// socket options on it fails) and then real connections.
type firstConnBroken struct {
	net.Listener

	done atomic.Bool
}

func (l *firstConnBroken) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if l.done.CompareAndSwap(false, true) {
		conn.Close() //nolint: errcheck
	}

	return conn, nil
}

// One connection whose socket options cannot be set (for example, reset by
// the client right away) must be skipped, not stop the whole accept loop.
func TestListenerSkipsConnectionWithBrokenSocket(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	log := &recordingLogger{}

	listener := utils.WrapListener(&firstConnBroken{Listener: base}, log)
	defer listener.Close() //nolint: errcheck

	for range 2 {
		go func() {
			conn, err := net.Dial("tcp", base.Addr().String())
			if err == nil {
				time.Sleep(200 * time.Millisecond)
				conn.Close() //nolint: errcheck
			}
		}()
	}

	result := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close() //nolint: errcheck
		}

		result <- err
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("expected the second connection, got error %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return the next connection")
	}

	// The skipped connection must not vanish silently.
	if warnings := log.warnings(); len(warnings) != 1 {
		t.Fatalf("expected one warning about the skipped connection, got %v", warnings)
	}
}

// brokenConns returns only already closed TCP connections: setting socket
// options fails on every one of them.
type brokenConns struct {
	net.Listener

	calls atomic.Int32
}

func (l *brokenConns) Accept() (net.Conn, error) {
	l.calls.Add(1)

	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	conn.Close() //nolint: errcheck

	return conn, nil
}

// If setting socket options fails for every connection, the warning must be
// rate limited instead of written per connection.
func TestListenerRateLimitsSkipWarning(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	log := &recordingLogger{}
	broken := &brokenConns{Listener: base}

	listener := utils.WrapListener(broken, log)

	const conns = 10

	var dialed sync.WaitGroup

	for range conns {
		dialed.Go(func() {
			conn, err := net.Dial("tcp", base.Addr().String())
			if err == nil {
				conn.Close() //nolint: errcheck
			}
		})
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		listener.Accept() //nolint: errcheck
	}()

	dialed.Wait()

	// The listener has skipped every connection once it asks for one more.
	deadline := time.Now().Add(2 * time.Second)

	for broken.calls.Load() <= conns && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	listener.Close() //nolint: errcheck
	<-done

	if got := broken.calls.Load(); got <= conns {
		t.Fatalf("expected %d skipped connections, got %d", conns, got-1)
	}

	if warnings := log.warnings(); len(warnings) != 1 {
		t.Fatalf("expected one rate-limited warning for %d skipped connections, got %v", conns, warnings)
	}
}

// recordingLogger records warnings.
type recordingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *recordingLogger) Named(_ string) mtglib.Logger          { return l }
func (l *recordingLogger) BindInt(_ string, _ int) mtglib.Logger { return l }
func (l *recordingLogger) BindStr(_, _ string) mtglib.Logger     { return l }
func (l *recordingLogger) BindJSON(_, _ string) mtglib.Logger    { return l }
func (l *recordingLogger) Printf(_ string, _ ...any)             {}
func (l *recordingLogger) Info(_ string)                         {}
func (l *recordingLogger) InfoError(_ string, _ error)           {}
func (l *recordingLogger) Warning(msg string)                    { l.record(msg) }
func (l *recordingLogger) Debug(_ string)                        {}
func (l *recordingLogger) DebugError(_ string, _ error)          {}

func (l *recordingLogger) WarningError(msg string, err error) {
	l.record(msg + ": " + err.Error())
}

func (l *recordingLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.msgs = append(l.msgs, msg)
}

func (l *recordingLogger) warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.msgs...)
}
