package web_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func drainFrames(t *testing.T, session *web.Session, wait time.Duration) []web.Frame {
	t.Helper()

	body, err := session.Drain(context.Background(), wait)
	require.NoError(t, err)

	if len(body) == 0 {
		return nil
	}

	frames, err := web.ParseAll(body, web.DefaultLimits())
	require.NoError(t, err)

	return frames
}

func hasFrame(frames []web.Frame, frameType web.FrameType, streamID uint32) bool {
	for _, frame := range frames {
		if frame.Type == frameType && frame.StreamID == streamID {
			return true
		}
	}

	return false
}

// DATA that arrives for a stream that is already gone on our side is a normal
// race (our CLOSE has not reached the client yet), not a protocol violation.
// It must not take down the other streams of the session.
func TestSessionIgnoresDataForGoneStreams(t *testing.T) {
	received := make(chan string, 4)

	session := newTestSession(t, func(stream *web.Stream) {
		if stream.ID() == 1 {
			// Telegram closed this connection on our side.
			stream.Close() //nolint: errcheck

			return
		}

		buf := make([]byte, 16)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}

			received <- string(buf[:n])
		}
	})

	require.NoError(t, accept(session, append(web.Encode(web.FrameOpen, 1, nil), web.Encode(web.FrameOpen, 2, nil)...)))

	require.Eventually(t, func() bool { return session.StreamCount() == 1 }, 2*time.Second, 5*time.Millisecond)

	body := web.Encode(web.FrameData, 1, []byte("late"))                         // closed on our side
	body = append(body, web.Encode(web.FrameData, 9, []byte("never opened"))...) // unknown
	body = append(body, web.Encode(web.FrameData, 2, []byte("alive"))...)
	require.NoError(t, accept(session, body))

	select {
	case got := <-received:
		assert.Equal(t, "alive", got)
	case <-time.After(2 * time.Second):
		t.Fatal("the live stream did not get its data")
	}

	// DATA after the client's own CLOSE is dropped as well.
	require.NoError(t, accept(session, append(web.Encode(web.FrameClose, 2, nil),
		web.Encode(web.FrameData, 2, []byte("after close"))...)))
	assert.False(t, session.Closed())

	// The client learns about stream 1 from our CLOSE.
	assert.True(t, hasFrame(drainFrames(t, session, time.Second), web.FrameClose, 1))
}

// A stream that does not take its data in time is closed explicitly with a
// CLOSE, and the session goes on. Dropping the bytes silently would desync
// MTProto; waiting forever would stall the other streams.
func TestSessionClosesStalledStream(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.StreamBufferBytes = web.DataChunkBytes
	cfg.DeliverTimeout = 100 * time.Millisecond

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(*web.Stream) {
		// Never reads.
	})
	t.Cleanup(session.Close)

	body := web.Encode(web.FrameOpen, 1, nil)
	body = append(body, web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))...)
	body = append(body, web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))...)

	start := time.Now()
	require.NoError(t, accept(session, body))
	assert.GreaterOrEqual(t, time.Since(start), 90*time.Millisecond, "/up must wait for room first")

	assert.False(t, session.Closed())
	assert.Equal(t, 0, session.StreamCount())
	assert.True(t, hasFrame(drainFrames(t, session, time.Second), web.FrameClose, 1))
}

// A full stream buffer makes /up wait for the reader instead of failing: the
// buffer works like a socket receive buffer.
func TestSessionInboundBackpressure(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.StreamBufferBytes = web.DataChunkBytes

	release := make(chan struct{})
	total := make(chan int, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		<-release

		n, _ := io.Copy(io.Discard, stream)
		total <- int(n)
	})
	t.Cleanup(session.Close)

	body := web.Encode(web.FrameOpen, 1, nil)
	for range 4 {
		body = append(body, web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))...)
	}

	body = append(body, web.Encode(web.FrameClose, 1, nil)...)

	time.AfterFunc(100*time.Millisecond, func() { close(release) })
	require.NoError(t, accept(session, body))

	select {
	case n := <-total:
		assert.Equal(t, 4*web.DataChunkBytes, n)
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not get all data")
	}
}

// A request cancelled mid-body (the client went away) is an error: the rest
// of the body is lost, so the session must not go on.
func TestSessionAcceptStopsOnCancelledRequest(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.StreamBufferBytes = web.DataChunkBytes

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(*web.Stream) {})
	t.Cleanup(session.Close)

	body := web.Encode(web.FrameOpen, 1, nil)
	body = append(body, web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))...)
	body = append(body, web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))...)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := session.Accept(ctx, bytes.NewReader(body))
	assert.ErrorIs(t, err, context.Canceled)
}

// A full outbound queue makes writers wait for the next /down instead of
// failing the stream, and a write deadline still applies.
func TestSessionOutboundBackpressure(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.MaxOutboundBytes = 1 // raised to one full frame

	written := make(chan error, 2)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		_, err := stream.Write(make([]byte, 3*web.DataChunkBytes))
		written <- err

		require.NoError(t, stream.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))
		_, err = stream.Write(make([]byte, 2*web.DataChunkBytes))
		written <- err
	})
	t.Cleanup(session.Close)

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

	select {
	case <-written:
		t.Fatal("write must wait while the queue is full")
	case <-time.After(200 * time.Millisecond):
	}

	got := 0
	for got < 3*web.DataChunkBytes {
		for _, frame := range drainFrames(t, session, time.Second) {
			got += len(frame.Payload)
		}
	}

	select {
	case err := <-written:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("write did not resume after /down")
	}

	select {
	case err := <-written:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("write deadline did not fire while the queue was full")
	}
}

// creditBlockedSession opens streams whose writers write the whole initial window, so the next write waits for
// credit. The queue cap is raised so that only credit blocks.
func creditBlockedSession(t *testing.T, streams int, results chan<- error) *web.Session {
	t.Helper()

	cfg := web.DefaultSessionConfig()
	cfg.MaxOutboundBytes = (streams + 1) * (web.InitialStreamWindow + 1024*1024)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		if _, err := stream.Write(make([]byte, web.InitialStreamWindow)); err != nil {
			results <- err

			return
		}

		_, err := stream.Write([]byte("x")) // waits for credit, no deadline
		results <- err
	})
	t.Cleanup(session.Close)

	body := []byte{}
	for id := 1; id <= streams; id++ {
		body = append(body, web.Encode(web.FrameOpen, uint32(id), nil)...)
	}

	require.NoError(t, accept(session, body))

	return session
}

// Several goroutines wait on a session at once: writers of different streams
// short of credit and the long poll. Closing the session must wake all of
// them, not just one; with a zero deadline the rest would wait forever.
func TestSessionCloseWakesEveryWaiter(t *testing.T) {
	const streams = 3

	results := make(chan error, streams)
	session := creditBlockedSession(t, streams, results)

	drained := make(chan error, 1)

	go func() {
		// Waits on the same session as the writers. The queue has data at
		// first, so keep taking it until the long poll waits on an empty
		// queue and ends with an error.
		for {
			if _, err := session.Drain(context.Background(), time.Minute); err != nil {
				drained <- err

				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	session.Close()

	for range streams {
		select {
		case err := <-results:
			assert.ErrorIs(t, err, web.ErrSessionClosed)
		case <-time.After(2 * time.Second):
			t.Fatal("a writer waiting for credit was not woken by Close")
		}
	}

	select {
	case err := <-drained:
		assert.ErrorIs(t, err, web.ErrSessionClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("the long poll was not woken by Close")
	}
}

// Credit for one stream must reach that stream's writer even when writers of
// other streams wait too.
func TestSessionCreditWakesTheRightWriter(t *testing.T) {
	const streams = 3

	results := make(chan error, streams)
	session := creditBlockedSession(t, streams, results)

	time.Sleep(200 * time.Millisecond)

	for id := streams; id >= 1; id-- {
		require.NoError(t, accept(session, web.Encode(web.FrameWindow, uint32(id), web.WindowPayload(1))))

		select {
		case err := <-results:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatalf("credit for stream %d did not wake its writer", id)
		}
	}
}

// New data must wake the long poll even while writers of other streams wait
// for credit: with a single-slot signal a writer could take the wake-up, and
// the data would sit in the queue until the long poll timed out.
func TestSessionDataWakesLongPollDespiteWaitingWriters(t *testing.T) {
	results := make(chan error, 2)
	session := creditBlockedSession(t, 2, results)

	time.Sleep(200 * time.Millisecond)

	// Empty the queue so the next Drain waits.
	_ = drainFrames(t, session, time.Second)

	got := make(chan time.Duration, 1)

	go func() {
		start := time.Now()
		_, _ = session.Drain(context.Background(), 10*time.Second)
		got <- time.Since(start)
	}()

	time.Sleep(100 * time.Millisecond)
	// A WINDOW reply is queued for the client (returned credit) - any new
	// frame will do. Credit for stream 1 wakes its writer, which queues DATA.
	require.NoError(t, accept(session, web.Encode(web.FrameWindow, 1, web.WindowPayload(1))))

	select {
	case elapsed := <-got:
		assert.Less(t, elapsed, 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("the long poll was not woken by new data")
	}
}

// Drain takes frames only for a live request. A cancelled one gets an error
// and leaves the queue intact, so nothing is handed to a dead response.
func TestSessionDrainKeepsFramesForCancelledRequest(t *testing.T) {
	written := make(chan struct{})

	session := newTestSession(t, func(stream *web.Stream) {
		_, _ = stream.Write([]byte("reply"))
		close(written)
	})

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))
	<-written

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	body, err := session.Drain(ctx, time.Second)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Empty(t, body)

	frames := drainFrames(t, session, time.Second)
	require.NotEmpty(t, frames)
	assert.Equal(t, []byte("reply"), frames[0].Payload)
}

// A long poll that is waiting returns as soon as its request is cancelled.
func TestSessionDrainReturnsOnCancel(t *testing.T) {
	session := newTestSession(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_, err := session.Drain(ctx, 10*time.Second)

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 2*time.Second)
}
