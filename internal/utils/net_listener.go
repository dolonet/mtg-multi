package utils

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/dolonet/mtg-multi/internal/logthrottle"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
)

// socketOptionsLogInterval limits the warning about connections dropped
// because their socket options cannot be set: one line per interval, with the
// number of suppressed ones.
const socketOptionsLogInterval = 10 * time.Second

// Listener applies client socket options to accepted connections.
type Listener struct {
	net.Listener

	logger   mtglib.Logger
	throttle *logthrottle.Throttle
}

// WrapListener returns a Listener that accepts connections from base.
func WrapListener(base net.Listener, logger mtglib.Logger) *Listener {
	return &Listener{
		Listener: base,
		logger:   logger,
		throttle: logthrottle.New(socketOptionsLogInterval),
	}
}

// Accept returns the next connection with client socket options applied. A
// connection whose options cannot be set (typically it was reset by the client
// right after the handshake) is closed and skipped: returning an error here
// would stop the whole accept loop because of one bad client.
//
// The skip is logged as a warning, rate limited: if setting the options starts
// failing for every connection (a bad option, an unsupported platform), the
// proxy must not drop everything silently, nor flood the log under load.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err //nolint: wrapcheck
		}

		if err := network.SetClientSocketOptions(conn, 0); err != nil {
			l.logSkipped(conn, err)
			conn.Close() //nolint: errcheck

			continue
		}

		return conn, nil
	}
}

func (l *Listener) logSkipped(conn net.Conn, err error) {
	ok, suppressed := l.throttle.Allow()
	if !ok {
		return
	}

	logger := l.logger.BindInt("suppressed", suppressed)

	if addr := conn.RemoteAddr(); addr != nil {
		logger = logger.BindStr("ip", addr.String())
	}

	logger.WarningError("cannot set client socket options, the connection is dropped", err)
}

func NewListener(bindTo string, bufferSize int, logger mtglib.Logger) (net.Listener, error) {
	base, err := net.Listen("tcp", bindTo)
	if err != nil {
		return nil, fmt.Errorf("cannot build a base listener: %w", err)
	}

	return WrapListener(base, logger), nil
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// MultiListener fans-in Accept calls from multiple underlying listeners.
type MultiListener struct {
	listeners []net.Listener
	connCh    chan acceptResult
}

func NewMultiListener(listeners ...net.Listener) *MultiListener {
	ml := &MultiListener{
		listeners: listeners,
		connCh:    make(chan acceptResult, len(listeners)),
	}

	for _, l := range listeners {
		go ml.acceptLoop(l)
	}

	return ml
}

// acceptLoop forwards connections and errors from one listener. It stops only
// when the listener is closed: a temporary error (for example, out of file
// descriptors) must not silently stop accepting on this listener forever.
//
// It does not pause after a temporary error: the error is handed to the
// consumer (Proxy.Serve), which owns the retry policy, logs the error and
// pauses before the next Accept. Pausing here as well applied the delay twice.
// The loop cannot spin either: the send to connCh blocks while its buffer is
// full, so Accept is retried at the consumer's pace.
func (ml *MultiListener) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		ml.connCh <- acceptResult{conn: conn, err: err}

		if errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

func (ml *MultiListener) Accept() (net.Conn, error) {
	r := <-ml.connCh
	return r.conn, r.err
}

func (ml *MultiListener) Close() error {
	var firstErr error

	for _, l := range ml.listeners {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func (ml *MultiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}
