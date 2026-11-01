package web_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// accept feeds a /up body to the session the way the server does.
func accept(session *web.Session, body []byte) error {
	return session.Accept(context.Background(), bytes.NewReader(body))
}

func newTestSession(t *testing.T, handle func(*web.Stream)) *web.Session {
	t.Helper()

	if handle == nil {
		handle = func(*web.Stream) {}
	}

	session := web.NewSession(
		web.Token{1, 2, 3},
		web.Profile{User: "petya_1", SecretMode: web.SecretModeDD},
		net.ParseIP("203.0.113.7"),
		web.DefaultSessionConfig(),
		handle,
	)
	t.Cleanup(session.Close)

	return session
}

// End-to-end scenario: the client opens a stream and sends bytes, the handler
// reads them as from a regular socket and replies, and the reply goes back to
// the client as frames. This is the very reason the whole package exists.
func TestSessionRoundTrip(t *testing.T) {
	handled := make(chan struct{})

	session := newTestSession(t, func(stream *web.Stream) {
		defer close(handled)

		buf := make([]byte, 16)

		n, err := stream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "ping", string(buf[:n]))

		_, err = stream.Write([]byte("pong"))
		assert.NoError(t, err)
	})

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("ping"))...,
	)
	require.NoError(t, accept(session, body))

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not run")
	}

	out, err := session.Drain(context.Background(), time.Second)
	require.NoError(t, err)

	frames, err := web.ParseAll(out, web.DefaultLimits())
	require.NoError(t, err)
	require.NotEmpty(t, frames)

	assert.Equal(t, web.FrameData, frames[0].Type)
	assert.Equal(t, uint32(1), frames[0].StreamID)
	assert.Equal(t, []byte("pong"), frames[0].Payload)
}

// The client IP must reach the stream: mtg stats and per-address limits rely
// on it. Without it all WEB clients would look like a single one.
func TestStreamCarriesClientIP(t *testing.T) {
	got := make(chan string, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

	select {
	case host := <-got:
		assert.Equal(t, "203.0.113.7", host)
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not open")
	}
}

// mtg sets a deadline for the handshake and expects Read to break out when it
// fires. If deadlines do not work, a silent client holds a goroutine and a
// slot forever.
func TestStreamReadDeadline(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		require.NoError(t, stream.SetDeadline(time.Now().Add(150*time.Millisecond)))

		_, err := stream.Read(make([]byte, 8))
		done <- err
	})

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

	select {
	case err := <-done:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not return on deadline")
	}
}

// CLOSE from the client means end of data: the reader must get EOF rather
// than hang.
func TestSessionCloseStreamGivesEOF(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		_, err := io.ReadAll(stream)
		done <- err
	})

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("x"))...,
	)
	body = append(body, web.Encode(web.FrameClose, 1, nil)...)
	require.NoError(t, accept(session, body))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not finish after CLOSE")
	}
}

func TestSessionRejectsBadFrames(t *testing.T) {
	t.Run("repeated OPEN of the same stream", func(t *testing.T) {
		session := newTestSession(t, nil)
		require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

		err := accept(session, web.Encode(web.FrameOpen, 1, nil))
		assert.ErrorIs(t, err, web.ErrInvalidShape)
	})

	t.Run("HELLO inside a live session", func(t *testing.T) {
		session := newTestSession(t, nil)
		err := accept(session, web.Encode(web.FrameHello, 0, []byte{1}))
		assert.ErrorIs(t, err, web.ErrInvalidShape)
	})

	// The client chooses the number of streams, so a cap is mandatory:
	// otherwise a single session eats memory and stats slots.
	t.Run("more streams than the cap", func(t *testing.T) {
		cfg := web.DefaultSessionConfig()
		cfg.MaxStreams = 2

		session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(*web.Stream) {})
		t.Cleanup(session.Close)

		require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))
		require.NoError(t, accept(session, web.Encode(web.FrameOpen, 2, nil)))

		err := accept(session, web.Encode(web.FrameOpen, 3, nil))
		assert.ErrorIs(t, err, web.ErrTooManyStreams)
	})
}

// Long polling: if there is nothing to send, Drain waits and returns empty
// instead of making the client hammer the server for nothing.
func TestSessionDrainWaitsAndReturnsEmpty(t *testing.T) {
	session := newTestSession(t, nil)

	start := time.Now()
	body, err := session.Drain(context.Background(), 200*time.Millisecond)

	require.NoError(t, err)
	assert.Empty(t, body)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)
}

// Window credit: the server may not send more than the client allowed.
func TestSessionRespectsWindowCredit(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.MaxOutboundBytes = 64 * 1024 * 1024

	blocked := make(chan struct{})
	finished := make(chan int, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		close(blocked)
		// Ask to send more than the initial window: the last chunk must wait
		// until the client returns credit with a WINDOW frame.
		n, _ := stream.Write(make([]byte, web.InitialStreamWindow+1024))
		finished <- n
	})
	t.Cleanup(session.Close)

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))
	<-blocked

	select {
	case <-finished:
		t.Fatal("write completed in full despite insufficient window credit")
	case <-time.After(300 * time.Millisecond):
	}

	require.NoError(t, accept(session, web.Encode(web.FrameWindow, 1, web.WindowPayload(4096))))

	select {
	case n := <-finished:
		assert.Equal(t, web.InitialStreamWindow+1024, n)
	case <-time.After(2 * time.Second):
		t.Fatal("write did not resume after credit was returned")
	}
}

// Closing a session must wake every stream: otherwise handler goroutines would
// hang around after the client is gone.
func TestSessionCloseReleasesStreams(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		_, err := stream.Read(make([]byte, 8))
		done <- err
	})

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))
	time.Sleep(50 * time.Millisecond)
	session.Close()

	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("stream was not woken when the session closed")
	}

	assert.ErrorIs(t, accept(session, web.Encode(web.FrameOpen, 2, nil)), web.ErrSessionClosed)
}
