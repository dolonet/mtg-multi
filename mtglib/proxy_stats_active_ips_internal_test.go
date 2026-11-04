package mtglib

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readStats returns the raw /stats response.
func readStats(t *testing.T, stats *ProxyStats) []byte {
	t.Helper()

	rec := httptest.NewRecorder()
	stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	return rec.Body.Bytes()
}

func readActiveIPs(t *testing.T, stats *ProxyStats, name string) []string {
	t.Helper()

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(readStats(t, stats), &resp))

	user, ok := resp.Users[name]
	require.True(t, ok, "user %q is missing in /stats", name)

	return user.ActiveIPs
}

// sessionFrom is authenticatedSession for a client at addr.
func sessionFrom(t *testing.T, p *Proxy, name string, secret Secret, addr string) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream := &streamContext{
		ctx:           ctx,
		ctxCancel:     cancel,
		secretName:    name,
		matchedSecret: secret,
		clientAddr:    netip.MustParseAddr(addr),
	}

	require.True(t, p.trackSession(stream))

	return stream
}

// finish ends a session the way ServeConn does on return.
func finish(p *Proxy, stream *streamContext) {
	stream.userStats.endSession(stream.clientAddr)
	p.sessions.remove(stream)
}

func TestClientAddr(t *testing.T) {
	t.Parallel()

	testData := map[string]struct {
		ip   net.IP
		want netip.Addr
	}{
		"nil":                {ip: nil},
		"unspecified v4":     {ip: net.IPv4zero},
		"unspecified v6":     {ip: net.IPv6unspecified},
		"garbage":            {ip: net.IP{1, 2, 3}},
		"v4 in 16 bytes":     {ip: net.ParseIP("203.0.113.7"), want: netip.MustParseAddr("203.0.113.7")},
		"v4 in 4 bytes":      {ip: net.IPv4(203, 0, 113, 7).To4(), want: netip.MustParseAddr("203.0.113.7")},
		"v4-mapped v6":       {ip: net.ParseIP("::ffff:203.0.113.7"), want: netip.MustParseAddr("203.0.113.7")},
		"v6":                 {ip: net.ParseIP("2001:db8::1"), want: netip.MustParseAddr("2001:db8::1")},
		"v6 loopback (kept)": {ip: net.IPv6loopback, want: netip.MustParseAddr("::1")},
	}

	for name, tc := range testData {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, clientAddr(tc.ip))
		})
	}
}

// Sessions are counted per address: an address stays while it has at least
// one live session and goes away with the last one.
func TestActiveIPsCountSessionsPerAddress(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	st := stats.lookup("alice")

	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("198.51.100.2")

	st.startSession(a)
	st.startSession(a)
	st.startSession(b)
	assert.Equal(t, []string{"192.0.2.1", "198.51.100.2"}, readActiveIPs(t, stats, "alice"))

	st.endSession(a)
	assert.Equal(t, []string{"192.0.2.1", "198.51.100.2"}, readActiveIPs(t, stats, "alice"),
		"192.0.2.1 still has a live session")

	st.endSession(b)
	assert.Equal(t, []string{"192.0.2.1"}, readActiveIPs(t, stats, "alice"))

	st.endSession(a)
	assert.Empty(t, readActiveIPs(t, stats, "alice"))
	assert.Zero(t, st.connections.Load())
	assert.Nil(t, st.ips, "an empty map is dropped so it does not keep its memory")

	// An extra end (cannot happen in ServeConn) does not go negative or
	// resurrect the address.
	st.removeIP(a)
	assert.Nil(t, st.ips)
}

// A session with an unknown address is counted in connections but not listed.
func TestActiveIPsSkipUnknownAddress(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	st := stats.lookup("alice")

	st.startSession(clientAddr(net.IPv4zero))
	assert.EqualValues(t, 1, st.connections.Load())
	assert.Empty(t, readActiveIPs(t, stats, "alice"))
	assert.Nil(t, st.ips)

	st.endSession(clientAddr(net.IPv4zero))
	assert.Zero(t, st.connections.Load())
}

// The exact wire format: a JSON array of plain address strings under
// users.<name>.active_ips, [] (not null) when there are none, IPv4 before
// IPv6, numeric order, IPv4-mapped addresses as plain IPv4.
func TestActiveIPsJSONShape(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.PreRegister("idle")
	st := stats.lookup("alice")

	for _, ip := range []string{"2001:db8::1", "10.0.0.10", "::ffff:10.0.0.2", "10.0.0.2"} {
		st.startSession(clientAddr(net.ParseIP(ip)))
	}

	var raw struct {
		Users map[string]map[string]json.RawMessage `json:"users"`
	}
	require.NoError(t, json.Unmarshal(readStats(t, stats), &raw))

	assert.JSONEq(t, `["10.0.0.2","10.0.0.10","2001:db8::1"]`, string(raw.Users["alice"]["active_ips"]))
	assert.JSONEq(t, `[]`, string(raw.Users["idle"]["active_ips"]))

	// The other per-user fields are still there.
	for _, field := range []string{"connections", "bytes_in", "bytes_out", "last_seen"} {
		assert.Contains(t, raw.Users["alice"], field)
	}

	assert.JSONEq(t, `4`, string(raw.Users["alice"]["connections"]))
}

// Sessions start and end from many goroutines while /stats is read; run with
// -race. At the end nothing is left.
func TestActiveIPsConcurrent(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	st := stats.lookup("alice")

	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
	}

	stop := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)

		for {
			select {
			case <-stop:
				return
			default:
				rec := httptest.NewRecorder()
				stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
			}
		}
	}()

	var wg sync.WaitGroup

	for i := range 16 {
		wg.Go(func() {
			addr := addrs[i%len(addrs)]

			for range 500 {
				st.startSession(addr)
				st.endSession(addr)
			}
		})
	}

	// A long-lived session from one address must survive all the churn.
	keep := netip.MustParseAddr("203.0.113.9")
	st.startSession(keep)

	wg.Wait()
	close(stop)
	<-readerDone

	assert.Equal(t, []string{"203.0.113.9"}, readActiveIPs(t, stats, "alice"))
	assert.EqualValues(t, 1, st.connections.Load())

	st.endSession(keep)
	assert.Empty(t, readActiveIPs(t, stats, "alice"))
	assert.Nil(t, st.ips)
}

// SIGHUP reload: a removed user disappears from /stats together with its
// addresses; a user with a rotated key keeps its entry but its closed
// sessions take their addresses away; a kept user is not touched.
func TestActiveIPsAfterUpdateSecrets(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	carol := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob, "carol": carol})

	aliceSession := sessionFrom(t, p, "alice", alice, "192.0.2.1")
	bobSession := sessionFrom(t, p, "bob", bob, "192.0.2.2")
	carolSession := sessionFrom(t, p, "carol", carol, "192.0.2.3")

	_, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com"), "carol": carol})
	require.NoError(t, err)

	require.True(t, isClosed(aliceSession))
	require.True(t, isClosed(bobSession))
	require.False(t, isClosed(carolSession))

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(readStats(t, p.stats), &resp))
	assert.NotContains(t, resp.Users, "alice")

	// ServeConn returns for the closed sessions.
	finish(p, aliceSession)
	finish(p, bobSession)

	assert.Nil(t, p.stats.lookup("alice"), "a late end does not bring a removed user back")
	assert.Empty(t, readActiveIPs(t, p.stats, "bob"))
	assert.Zero(t, p.stats.lookup("bob").connections.Load())
	assert.Equal(t, []string{"192.0.2.3"}, readActiveIPs(t, p.stats, "carol"))
}

// A user is removed and added back (a rename back and forth looks the same)
// while its old session is still running. The old session ends in the old
// entry and does not take away the address of a new session from the same
// client.
func TestActiveIPsReaddedUser(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	old := sessionFrom(t, p, "alice", alice, "192.0.2.1")

	_, err := p.UpdateSecrets(map[string]Secret{"bob": bob})
	require.NoError(t, err)
	_, err = p.UpdateSecrets(map[string]Secret{"alice": alice, "bob": bob})
	require.NoError(t, err)

	assert.Empty(t, readActiveIPs(t, p.stats, "alice"), "the new entry starts empty")

	fresh := sessionFrom(t, p, "alice", alice, "192.0.2.1")

	finish(p, old)
	assert.Equal(t, []string{"192.0.2.1"}, readActiveIPs(t, p.stats, "alice"))
	assert.EqualValues(t, 1, p.stats.lookup("alice").connections.Load())

	finish(p, fresh)
	assert.Empty(t, readActiveIPs(t, p.stats, "alice"))
}

// The address comes from the stream's RemoteAddr, which is the real client
// for every path: a TCP client, a PROXY protocol connection (the listener
// wrapper reports the address from the header) and a WEB stream (its
// RemoteAddr carries X-Forwarded-For).
func TestActiveIPsAddressFromStream(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	server, _ := tcpPair(t)
	stream := newStreamContext(context.Background(), NoopLogger{}, remoteAddrConn{
		TCPConn: server,
		remote:  &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 443},
	})
	t.Cleanup(stream.Close)

	stream.secretName = "alice"
	stream.matchedSecret = alice
	// This is what ServeConn does before trackSession.
	stream.clientAddr = clientAddr(stream.ClientIP())
	require.True(t, p.trackSession(stream))

	assert.Equal(t, []string{"203.0.113.7"}, readActiveIPs(t, p.stats, "alice"))

	finish(p, stream)
	assert.Empty(t, readActiveIPs(t, p.stats, "alice"))
}

type remoteAddrConn struct {
	*net.TCPConn

	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

// staticIPList is an IP allowlist or blocklist that gives the same answer for
// every address (the ipblocklist package cannot be imported from here).
type staticIPList bool

func (l staticIPList) Contains(net.IP) bool { return bool(l) }
func (l staticIPList) Run(time.Duration)    {}
func (l staticIPList) Shutdown()            {}

// End to end: a real secured client goes through Serve and ServeConn over
// loopback TCP, so the address is captured from the accepted connection and
// released when ServeConn returns. Telegram is a local stand-in. The other
// tests set clientAddr by hand and do not cover these lines of ServeConn.
func TestActiveIPsThroughServeConn(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	telegramAddr, dcs := fakeTelegram(t)

	proxy, err := NewProxy(ProxyOpts{
		Secrets:          map[string]Secret{"alice": alice, "bob": bob},
		Network:          &dcPoolTestNetwork{addr: telegramAddr},
		AntiReplayCache:  &mapAntiReplayCache{seen: map[string]bool{}},
		IPBlocklist:      staticIPList(false),
		IPAllowlist:      staticIPList(true),
		EventStream:      &dcPoolTestEvents{},
		Logger:           NoopLogger{},
		HandshakeTimeout: 10 * time.Second,
		SecuredEnabled:   true,
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := make(chan struct{})

	go func() {
		defer close(served)

		proxy.Serve(listener) //nolint: errcheck
	}()

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck
		<-served
		proxy.Shutdown()
	})

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	defer client.Close() //nolint: errcheck

	_, err = obfuscation.Obfuscator{Secret: alice.Key[:]}.SendHandshake(essentials.WrapNetConn(client), 2)
	require.NoError(t, err)

	// Telegram gets the handshake only after the session is tracked, and the
	// session lasts until the client goes away.
	expectHandshakeDC(t, dcs, 2)

	assert.Equal(t, []string{"127.0.0.1"}, readActiveIPs(t, proxy.stats, "alice"))
	assert.Empty(t, readActiveIPs(t, proxy.stats, "bob"))
	assert.EqualValues(t, 1, proxy.stats.lookup("alice").connections.Load())

	require.NoError(t, client.Close())

	// endSession drops the address and then the connection, so wait for both.
	require.Eventually(t, func() bool {
		st := proxy.stats.lookup("alice")

		return len(st.activeIPs()) == 0 && st.connections.Load() == 0
	}, 5*time.Second, 10*time.Millisecond, "the session is still listed after the client went away")
	assert.Empty(t, readActiveIPs(t, proxy.stats, "alice"))
}
