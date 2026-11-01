package web

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

// Compile-time check: a stream must satisfy essentials.Conn, otherwise it
// cannot be passed to Proxy.ServeConn.
var _ essentials.Conn = (*Stream)(nil)

// streamSink is where a stream hands frames for the client. It is a separate
// interface so that a stream can be tested without HTTP and without a whole
// session.
type streamSink interface {
	// sendData sends a chunk of stream data to the client, honoring window credit.
	sendData(streamID uint32, payload []byte, deadline time.Time) error
	// sendClose tells the client that the stream is closed.
	sendClose(streamID uint32)
	// returnWindow returns consumed credit to the client.
	returnWindow(streamID uint32, amount uint32)
	// dropStream removes the stream from the session table.
	dropStream(streamID uint32)
}

// Stream is a single logical MTProto connection inside a WEB session.
//
// It implements essentials.Conn, so it goes to Proxy.ServeConn like a regular
// socket: the whole existing mtg path (handshake, stats, DC pool) works
// without a single change. That is the point: WEB adds a transport, not a
// second parallel proxy.
type Stream struct {
	id      uint32
	sink    streamSink
	inbound *pipe

	local  net.Addr
	remote net.Addr

	// consumed is how many bytes were read since the last credit return.
	// Credit is returned in batches rather than per byte: a WINDOW frame for
	// every 10 bytes read would triple the control traffic.
	consumedMu sync.Mutex
	consumed   uint32

	closeOnce sync.Once
}

// windowReturnThreshold is the credit return threshold: a quarter of the window.
const windowReturnThreshold = InitialStreamWindow / 4

// Addresses MUST be *net.TCPAddr rather than a custom type: mtg asserts the
// type unconditionally (stream_context.go: RemoteAddr().(*net.TCPAddr).IP),
// and any other type crashes the process on the very first stream. This was
// caught by a live probe, not by unit tests, because those only called
// String().
func newStream(id uint32, sink streamSink, clientIP net.IP, bufferCapacity int) *Stream {
	remote := &net.TCPAddr{IP: clientIP}
	if clientIP == nil {
		remote.IP = net.IPv4zero
	}

	return &Stream{
		id:      id,
		sink:    sink,
		inbound: newPipe(bufferCapacity),
		// Port 443: this is what the client connected to from outside, over real
		// HTTPS.
		local:  &net.TCPAddr{IP: net.IPv4zero, Port: 443},
		remote: remote,
	}
}

// ID returns the logical stream number.
func (s *Stream) ID() uint32 { return s.id }

// deliver puts data received from the client into the stream, waiting for
// room until deadline or until done is closed. pipe.write copies the data, so
// payload may point into a reused read buffer.
func (s *Stream) deliver(payload []byte, deadline time.Time, done <-chan struct{}) error {
	return s.inbound.write(payload, deadline, done)
}

// finish closes the stream from the client side: the reader drains the rest.
func (s *Stream) finish(err error) {
	s.inbound.closeWrite(err)
}

func (s *Stream) Read(dst []byte) (int, error) {
	n, err := s.inbound.Read(dst)
	if n > 0 {
		s.creditConsumed(uint32(n))
	}

	return n, err
}

// creditConsumed accumulates bytes read and returns credit in batches.
func (s *Stream) creditConsumed(n uint32) {
	s.consumedMu.Lock()

	s.consumed += n

	var release uint32

	if s.consumed >= windowReturnThreshold {
		release = s.consumed
		s.consumed = 0
	}

	s.consumedMu.Unlock()

	if release > 0 {
		s.sink.returnWindow(s.id, release)
	}
}

func (s *Stream) Write(src []byte) (int, error) {
	deadline := s.inbound.getWriteDeadline()
	written := 0

	// Split into chunks: a single frame must not exceed the agreed cap,
	// otherwise the client rejects the whole body.
	for written < len(src) {
		end := min(written+DataChunkBytes, len(src))

		if err := s.sink.sendData(s.id, src[written:end], deadline); err != nil {
			return written, err
		}

		written = end
	}

	return written, nil
}

// Close closes the stream in both directions and removes it from the session.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.inbound.closeRead()
		s.inbound.closeWrite(io.EOF)
		s.sink.sendClose(s.id)
		s.sink.dropStream(s.id)
	})

	return nil
}

// CloseRead closes the read side, leaving the write side intact.
func (s *Stream) CloseRead() error {
	s.inbound.closeRead()

	return nil
}

// CloseWrite tells the client that no more data will follow.
func (s *Stream) CloseWrite() error {
	s.sink.sendClose(s.id)

	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return s.local }
func (s *Stream) RemoteAddr() net.Addr { return s.remote }

func (s *Stream) SetDeadline(t time.Time) error {
	s.inbound.setReadDeadline(t)
	s.inbound.setWriteDeadline(t)

	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.inbound.setReadDeadline(t)

	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.inbound.setWriteDeadline(t)

	return nil
}
