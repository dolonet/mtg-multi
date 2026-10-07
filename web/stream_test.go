package web_test

import (
	"net"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mtg asserts the client address type unconditionally:
// RemoteAddr().(*net.TCPAddr).IP. A custom address type crashed the process on
// the very first open stream. It was caught by a live probe rather than by
// tests, because the tests only called String().
func TestStreamAddrsAreTCPAddr(t *testing.T) {
	got := make(chan net.Addr, 2)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, net.ParseIP("203.0.113.7"),
		web.DefaultSessionConfig(), func(stream *web.Stream) {
			got <- stream.RemoteAddr()
			got <- stream.LocalAddr()
		})
	t.Cleanup(session.Close)

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

	select {
	case remote := <-got:
		tcp, ok := remote.(*net.TCPAddr)
		require.True(t, ok, "RemoteAddr must be *net.TCPAddr")
		assert.Equal(t, "203.0.113.7", tcp.IP.String())

		_, ok = (<-got).(*net.TCPAddr)
		assert.True(t, ok, "LocalAddr must be *net.TCPAddr")
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not open")
	}
}

// Without a client address the type assertion must still not panic.
func TestStreamAddrWithoutClientIP(t *testing.T) {
	got := make(chan net.Addr, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil,
		web.DefaultSessionConfig(), func(stream *web.Stream) { got <- stream.RemoteAddr() })
	t.Cleanup(session.Close)

	require.NoError(t, accept(session, web.Encode(web.FrameOpen, 1, nil)))

	select {
	case remote := <-got:
		tcp, ok := remote.(*net.TCPAddr)
		require.True(t, ok)
		assert.NotNil(t, tcp.IP)
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not open")
	}
}
