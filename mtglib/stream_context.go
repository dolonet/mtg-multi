package mtglib

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

type streamContext struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	clientConn   essentials.Conn
	telegramConn essentials.Conn
	// rawConn is the original client connection. Unlike clientConn it is never
	// replaced, so only it may be closed from another goroutine (secret reload,
	// shutdown): ServeConn replaces clientConn/telegramConn with wrappers, and
	// reading an interface value while it is written is a data race.
	rawConn essentials.Conn
	// userStats is the stats entry this session is counted in. It is the one
	// decremented: after a user is removed and added back, a lookup by name
	// would find the new entry and drive its counter negative.
	userStats     *secretStats
	streamID      string
	dc            int
	matchedSecret Secret
	secretName    string
	// secured is true for a secured ("dd") client: plain obfuscated2 without
	// FakeTLS. Its obfuscated2 handshake is done in doSecuredHandshake, so
	// ServeConn skips the FakeTLS-specific steps.
	secured bool
	logger  Logger

	// handshakeDeadline is when the whole handshake must be done. Steps that
	// use a shorter read deadline restore this one afterwards.
	handshakeDeadline time.Time

	// releasePendingHandshake frees the per-IP pending-handshake slot, if any.
	releasePendingHandshake func()
}

// finishPendingHandshake releases the pending-handshake slot of this stream.
// It is safe to call several times.
func (s *streamContext) finishPendingHandshake() {
	if s.releasePendingHandshake != nil {
		s.releasePendingHandshake()
	}
}

func (s *streamContext) Deadline() (time.Time, bool) {
	return s.ctx.Deadline()
}

func (s *streamContext) Done() <-chan struct{} {
	return s.ctx.Done()
}

func (s *streamContext) Err() error {
	return s.ctx.Err() //nolint: wrapcheck
}

func (s *streamContext) Value(key any) any {
	return s.ctx.Value(key)
}

func (s *streamContext) Close() {
	s.ctxCancel()

	if s.clientConn != nil {
		s.clientConn.Close() //nolint: errcheck
	}

	if s.telegramConn != nil {
		s.telegramConn.Close() //nolint: errcheck
	}
}

// closeFromOutside aborts a session from another goroutine: it cancels the
// context and closes the original connection. ServeConn closes the rest in
// its own defer.
func (s *streamContext) closeFromOutside() {
	s.ctxCancel()

	if s.rawConn != nil {
		s.rawConn.Close() //nolint: errcheck
	}
}

func (s *streamContext) ClientIP() net.IP {
	return s.clientConn.RemoteAddr().(*net.TCPAddr).IP //nolint: forcetypeassert
}

func newStreamContext(ctx context.Context, logger Logger, clientConn essentials.Conn) *streamContext {
	connIDBytes := make([]byte, ConnectionIDBytesLength)

	if _, err := rand.Read(connIDBytes); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	streamCtx := &streamContext{
		ctx:        ctx,
		ctxCancel:  cancel,
		clientConn: clientConn,
		rawConn:    clientConn,
		streamID:   base64.RawURLEncoding.EncodeToString(connIDBytes),
	}
	streamCtx.logger = logger.
		BindStr("stream-id", streamCtx.streamID).
		BindStr("client-ip", streamCtx.ClientIP().String())

	return streamCtx
}
