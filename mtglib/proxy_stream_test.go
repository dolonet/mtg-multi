package mtglib_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/ipblocklist"
	"github.com/dolonet/mtg-multi/ipblocklist/files"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/require"
	"github.com/yl2chen/cidranger"
)

// streamConn is a connection that did not come from a listener, like a
// WEB-mode logical stream: the client address is whatever the transport says.
type streamConn struct {
	essentials.Conn

	remote net.Addr
}

func (c streamConn) RemoteAddr() net.Addr { return c.remote }

func newFirehol(t *testing.T, networks ...*net.IPNet) mtglib.IPBlocklist {
	t.Helper()

	list, err := ipblocklist.NewFireholFromFiles(logger.NewNoopLogger(), 1,
		[]files.File{files.NewMem(networks)}, nil)
	require.NoError(t, err)

	go list.Run(time.Hour)

	t.Cleanup(list.Shutdown)

	return list
}

// ServeStream applies the same admission as Serve: a stream from a blocked
// address is closed without reaching the handshake.
func TestServeStreamAppliesBlocklist(t *testing.T) {
	t.Parallel()

	_, blocked, err := net.ParseCIDR("203.0.113.0/24")
	require.NoError(t, err)

	blocklist := newFirehol(t, blocked)
	allowlist := newFirehol(t, cidranger.AllIPv4, cidranger.AllIPv6)

	require.Eventually(t, func() bool {
		return blocklist.Contains(net.ParseIP("203.0.113.7")) &&
			allowlist.Contains(net.ParseIP("198.51.100.1"))
	}, 5*time.Second, 10*time.Millisecond)

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:           mtglib.GenerateSecret("httpbin.org"),
		Network:          ntw,
		AntiReplayCache:  antireplay.NewNoop(),
		IPBlocklist:      blocklist,
		IPAllowlist:      allowlist,
		EventStream:      events.NewNoopStream(),
		Logger:           logger.NewNoopLogger(),
		HandshakeTimeout: 10 * time.Second,
		UseTestDCs:       true,
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	serve := func(ip string) net.Conn {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close() }) //nolint: errcheck

		proxy.ServeStream(streamConn{
			Conn:   essentials.WrapNetConn(server),
			remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 443},
		})

		return client
	}

	closed := func(conn net.Conn, within time.Duration) bool {
		_ = conn.SetReadDeadline(time.Now().Add(within))

		_, err := conn.Read(make([]byte, 1))

		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
	}

	require.True(t, closed(serve("203.0.113.7"), 2*time.Second),
		"a stream from a blocklisted address must be closed")
	require.False(t, closed(serve("198.51.100.1"), 300*time.Millisecond),
		"an allowed stream must reach the handshake and wait for the client")
}
