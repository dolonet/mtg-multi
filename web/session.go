package web

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Session is a single WEB session: a user, their logical streams and the
// queue of frames waiting to be sent to the client.
//
// The client talks to us with plain HTTP requests: it posts its frames to /up
// and fetches ours from /down. The session keeps state between these requests,
// which is what sets it apart from a regular socket, where the kernel keeps the
// state.
type Session struct {
	token    Token
	profile  Profile
	clientIP net.IP
	cfg      SessionConfig

	// handle is called for every new stream. It is Proxy.ServeStream, i.e. the
	// whole regular mtg path; the session knows nothing about MTProto.
	handle func(*Stream)

	mu      sync.Mutex
	streams map[uint32]*Stream
	// credit is how many bytes we may still send to the client on each stream.
	credit map[uint32]uint32
	// outbound holds frames waiting for the next /down.
	outbound [][]byte
	// outboundBytes is the queue size. Data waits for room when it reaches
	// MaxOutboundBytes, so a client that stops fetching cannot make the
	// server buffer for it without bound.
	outboundBytes int
	closed        bool

	// changed wakes everything that waits on the session: the long poll,
	// writers short of credit, writers waiting for room in the queue.
	changed broadcast

	lastSeen time.Time

	// upBusy and downBusy allow one /up and one /down at a time. The bridge
	// page never overlaps them, and two parallel bodies would reorder frames
	// of the same stream.
	upBusy   atomic.Bool
	downBusy atomic.Bool
}

// Token is the session ID the client carries in the Authorization header.
type Token [32]byte

// Session-level errors.
var (
	// ErrSessionClosed means the session has already ended.
	ErrSessionClosed = errors.New("web: session is closed")
	// ErrTooManyStreams means the session has more streams than allowed.
	ErrTooManyStreams = errors.New("web: too many streams in session")
	// ErrControlOverflow means control frames piled up in a queue the client
	// does not fetch.
	ErrControlOverflow = errors.New("web: control frames overflow the outbound queue")
	// ErrUnknownStream means a frame is addressed to a nonexistent stream.
	ErrUnknownStream = errors.New("web: frame for unknown stream")
)

// controlHeadroom is how far control frames (CLOSE, WINDOW) may go past the
// outbound cap. They are never delayed: a CLOSE that waits behind data could
// wait forever. They are tiny, and a client that lets 64 KB of them pile up
// is not fetching /down at all.
const controlHeadroom = 64 * 1024

// SessionConfig holds the limits of a single session.
//
// Worst case memory of one session with the defaults: 64 streams x 128 KB of
// inbound buffer, 1 MB + 64 KB of outbound queue, one 64 KB frame buffer of a
// running /up and one /down response, about 10 MB. Real sessions hold much
// less: buffers grow only while the other side does not read.
type SessionConfig struct {
	// MaxStreams caps concurrent logical streams. Telegram Desktop opens one
	// stream per MTProto connection: the main one plus download and upload
	// connections per data center, a few dozen at peak.
	MaxStreams int
	// MaxOutboundBytes caps the outbound queue. A full queue makes writers
	// wait, it does not fail them: the queue is emptied by every /down, so 1
	// MB per round trip is already tens of Mbit/s.
	MaxOutboundBytes int
	// StreamBufferBytes is the inbound buffer of each stream, like a socket
	// receive buffer. When it is full, /up waits for mtg to read. It must
	// hold at least one frame payload (64 KB).
	StreamBufferBytes int
	// DeliverTimeout is how long /up waits for room in a stream buffer. A
	// stream that does not take its data in this time is closed (CLOSE to
	// the client), so one stalled stream does not hold the others forever.
	DeliverTimeout time.Duration
	Limits         Limits
}

// DefaultSessionConfig returns the default values.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxStreams:        64,
		MaxOutboundBytes:  1024 * 1024,
		StreamBufferBytes: 128 * 1024,
		DeliverTimeout:    10 * time.Second,
		Limits:            DefaultLimits(),
	}
}

// NewSession creates a session. handle is called in a separate goroutine for
// every stream the client opens.
func NewSession(token Token, profile Profile, clientIP net.IP, cfg SessionConfig, handle func(*Stream)) *Session {
	// A frame payload must always fit: a buffer smaller than one frame would
	// refuse legitimate data no matter how long we wait.
	cfg.StreamBufferBytes = max(cfg.StreamBufferBytes, cfg.Limits.MaxFramePayloadLen)
	cfg.MaxOutboundBytes = max(cfg.MaxOutboundBytes, HeaderBytes+DataChunkBytes)

	return &Session{
		token:    token,
		profile:  profile,
		clientIP: clientIP,
		cfg:      cfg,
		handle:   handle,
		streams:  make(map[uint32]*Stream),
		credit:   make(map[uint32]uint32),
		lastSeen: time.Now(),
	}
}

// Token returns the session ID.
func (s *Session) Token() Token { return s.token }

// User returns the user name (also the mtg stats key).
func (s *Session) User() string { return s.profile.User }

// LastSeen reports the time of the last activity. It is used to clean up
// abandoned sessions: the client may just quit Telegram without notice.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastSeen
}

func (s *Session) touch() {
	s.lastSeen = time.Now()
}

// Accept reads a /up request body frame by frame and applies the frames.
//
// A malformed frame means the client does not speak our protocol, and the
// error tears the whole session down: continuing to parse a stream whose sync
// we are not sure about is more dangerous than dropping it. Frames for streams
// that are already gone are not an error (see deliverData).
func (s *Session) Accept(ctx context.Context, body io.Reader) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrSessionClosed
	}

	s.touch()
	s.mu.Unlock()

	reader := NewFrameReader(body, s.cfg.Limits)

	for count := 0; ; count++ {
		frame, err := reader.Next()

		switch {
		case errors.Is(err, io.EOF) && count == 0:
			return ErrEmptyBatch
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}

		if err := ValidateClientShape(frame); err != nil {
			return err
		}

		if err := s.applyFrame(ctx, frame); err != nil {
			return err
		}
	}
}

func (s *Session) applyFrame(ctx context.Context, frame Frame) error {
	switch frame.Type {
	case FrameOpen:
		return s.openStream(frame.StreamID)
	case FrameData:
		return s.deliverData(ctx, frame.StreamID, frame.Payload)
	case FrameClose:
		s.closeStream(frame.StreamID)

		return nil
	case FrameWindow:
		amount, err := WindowAmount(frame.Payload)
		if err != nil {
			return err
		}

		s.addCredit(frame.StreamID, amount)

		return nil
	case FramePong:
		return nil // liveness signal, state already updated in Accept
	case FramePing, FrameHello, FrameWelcome, FrameBye:
		// These frames never arrive on /up: HELLO is handled at session
		// creation, and the rest are server-only.
		return ErrInvalidShape
	default:
		return ErrInvalidShape
	}
}

func (s *Session) openStream(id uint32) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrSessionClosed
	}

	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()

		// A repeated OPEN on a live stream means the state is out of sync, and
		// the numbering can no longer be trusted.
		return ErrInvalidShape
	}

	if len(s.streams) >= s.cfg.MaxStreams {
		s.mu.Unlock()

		return ErrTooManyStreams
	}

	stream := newStream(id, s, s.clientIP, s.cfg.StreamBufferBytes)
	s.streams[id] = stream
	s.credit[id] = InitialStreamWindow
	s.mu.Unlock()

	go s.handle(stream)

	return nil
}

// deliverData hands DATA to its stream.
//
// A stream may already be gone on our side (Telegram closed the connection,
// an idle timeout fired) while the client still has DATA for it in flight or
// in the same body: our CLOSE has not reached it yet. That is a normal race,
// not a protocol violation, so such DATA is dropped and the session goes on;
// the client learns about the stream from that CLOSE. The same holds for a
// stream closed by the client itself or with a closed read side.
//
// A stream that does not take its data within DeliverTimeout is closed
// explicitly: dropping the bytes silently would desync MTProto, and waiting
// longer would stall every other stream of the session.
//
// The only error is the cancelled request: the client is gone, the rest of
// the body is lost with it, and the session must not go on.
func (s *Session) deliverData(ctx context.Context, id uint32, payload []byte) error {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()

	if stream == nil {
		return nil
	}

	err := stream.deliver(payload, time.Now().Add(s.cfg.DeliverTimeout), ctx.Done())

	switch {
	case err == nil, errors.Is(err, io.ErrClosedPipe):
		return nil
	case errors.Is(err, ErrPipeFull):
		stream.Close() //nolint: errcheck

		return nil
	default:
		return err
	}
}

func (s *Session) closeStream(id uint32) {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()

	if stream != nil {
		stream.finish(nil)
	}
}

func (s *Session) addCredit(id uint32, amount uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.credit[id]; !ok {
		return
	}

	// Saturate rather than overflow: the client controls this number.
	if s.credit[id] > ^uint32(0)-amount {
		s.credit[id] = ^uint32(0)
	} else {
		s.credit[id] += amount
	}

	s.changed.notify()
}

// ── streamSink ──────────────────────────────────────────────────────────────

// sendData queues data, waiting for window credit and for room in the queue.
func (s *Session) sendData(streamID uint32, payload []byte, deadline time.Time) error {
	remaining := payload

	for len(remaining) > 0 {
		allowed, err := s.reserveCredit(streamID, len(remaining), deadline)
		if err != nil {
			return err
		}

		chunk := remaining[:allowed]
		remaining = remaining[allowed:]

		if err := s.enqueueData(streamID, Encode(FrameData, streamID, chunk), deadline); err != nil {
			return err
		}
	}

	return nil
}

// reserveCredit takes the available credit, waiting for it until the deadline.
func (s *Session) reserveCredit(streamID uint32, want int, deadline time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if s.closed {
			return 0, ErrSessionClosed
		}

		available, ok := s.credit[streamID]
		if !ok {
			return 0, ErrUnknownStream
		}

		if available > 0 {
			allowed := min(want, int(available))
			s.credit[streamID] = available - uint32(allowed) //nolint: gosec

			return allowed, nil
		}

		if err := s.waitLocked(deadline, nil); err != nil {
			return 0, err
		}
	}
}

// enqueueData puts a DATA frame into the queue, waiting for room until the
// deadline. The stream may be closed meanwhile: then the data has nowhere to
// go.
func (s *Session) enqueueData(streamID uint32, frame []byte, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if s.closed {
			return ErrSessionClosed
		}

		if _, ok := s.credit[streamID]; !ok {
			return ErrUnknownStream
		}

		if s.outboundBytes+len(frame) <= s.cfg.MaxOutboundBytes {
			s.outbound = append(s.outbound, frame)
			s.outboundBytes += len(frame)
			s.changed.notify()

			return nil
		}

		if err := s.waitLocked(deadline, nil); err != nil {
			return err
		}
	}
}

// enqueueControl puts a control frame into the queue without waiting. Past
// the cap plus controlHeadroom the client is not fetching anything, and the
// session is closed: that is explicit, unlike losing a CLOSE or a WINDOW.
func (s *Session) enqueueControl(frame []byte) {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return
	}

	if s.outboundBytes+len(frame) > s.cfg.MaxOutboundBytes+controlHeadroom {
		s.mu.Unlock()
		s.Close()

		return
	}

	s.outbound = append(s.outbound, frame)
	s.outboundBytes += len(frame)
	s.changed.notify()
	s.mu.Unlock()
}

// waitLocked releases the mutex, waits for any change of the session, the
// deadline or done, and takes the mutex back.
func (s *Session) waitLocked(deadline time.Time, done <-chan struct{}) error {
	changed := s.changed.wait()

	s.mu.Unlock()
	defer s.mu.Lock()

	return waitChange(changed, deadline, done)
}

func (s *Session) sendClose(streamID uint32) {
	s.enqueueControl(Encode(FrameClose, streamID, nil))
}

func (s *Session) returnWindow(streamID uint32, amount uint32) {
	s.enqueueControl(Encode(FrameWindow, streamID, WindowPayload(amount)))
}

func (s *Session) dropStream(streamID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streams, streamID)
	delete(s.credit, streamID)
	// Writers of this stream may wait for credit or room: let them see that
	// the stream is gone.
	s.changed.notify()
}

// ── delivery to the client ──────────────────────────────────────────────────

// Drain takes the queued frames. If the queue is empty, it waits until wait
// elapses. This is the long poll: without it the client would hammer the
// server for nothing.
//
// Frames are taken only for a request that is still alive: if ctx is
// cancelled (the client went away, nginx dropped the request), Drain returns
// the context error and leaves the queue as is. Frames have no sequence
// numbers or acks, so frames handed to a dead response would be lost without
// a trace; the caller closes the session in that case instead.
func (s *Session) Drain(ctx context.Context, wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)

	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		if s.closed {
			return nil, ErrSessionClosed
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		s.touch()

		if len(s.outbound) > 0 {
			body := make([]byte, 0, s.outboundBytes)
			for _, frame := range s.outbound {
				body = append(body, frame...)
			}

			s.outbound = s.outbound[:0]
			s.outboundBytes = 0
			s.changed.notify() // room for waiting writers

			return body, nil
		}

		err := s.waitLocked(deadline, ctx.Done())

		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			// A long poll deadline is normal, not an error: return empty.
			return nil, nil
		case err != nil:
			return nil, ctx.Err()
		}
	}
}

// Close ends the session and all its streams.
func (s *Session) Close() {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return
	}

	s.closed = true
	streams := make([]*Stream, 0, len(s.streams))

	for _, stream := range s.streams {
		streams = append(streams, stream)
	}

	s.outbound = nil
	s.outboundBytes = 0
	// Wake every waiter at once: the long poll and all blocked writers.
	s.changed.notify()
	s.mu.Unlock()

	for _, stream := range streams {
		stream.finish(ErrSessionClosed)
		_ = stream.CloseRead()
	}
}

// Closed reports whether the session has ended.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.closed
}

// StreamCount reports the number of live streams.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.streams)
}
