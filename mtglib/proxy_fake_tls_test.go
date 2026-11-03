package mtglib_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/ipblocklist"
	"github.com/dolonet/mtg-multi/ipblocklist/files"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yl2chen/cidranger"
)

// fakeTLSTestSecret signed the real ClientHello snapshots in testdata of the
// fake package; its hostname is the SNI of the snapshots.
const fakeTLSTestSecret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

const (
	clientHelloRandomOffset = 11
	clientHelloRandomLen    = 32
)

// fakeTLSClientHello returns a real ClientHello snapshot (Chrome, 2021)
// re-signed with fakeTLSTestSecret for the given timestamp. variant changes
// the session ID before signing, so different variants are different
// clients.
func fakeTLSClientHello(t testing.TB, timestamp uint32, variant uint64) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(
		"internal", "tls", "fake", "testdata", "client-hello-ok-19dfe38384b9884b.json"))
	require.NoError(t, err)

	snapshot := struct {
		Full string `json:"full"`
	}{}
	require.NoError(t, json.Unmarshal(data, &snapshot))

	hello, err := base64.StdEncoding.DecodeString(snapshot.Full)
	require.NoError(t, err)

	sessionIDOffset := clientHelloRandomOffset + clientHelloRandomLen + 1
	require.EqualValues(t, 32, hello[sessionIDOffset-1], "the snapshot has a 32-byte session ID")
	binary.LittleEndian.PutUint64(hello[sessionIDOffset:], variant)

	secret, err := mtglib.ParseSecret(fakeTLSTestSecret)
	require.NoError(t, err)

	random := hello[clientHelloRandomOffset : clientHelloRandomOffset+clientHelloRandomLen]
	clear(random)

	mac := hmac.New(sha256.New, secret.Key[:])
	mac.Write(hello)
	copy(random, mac.Sum(nil))

	tail := binary.LittleEndian.Uint32(random[clientHelloRandomLen-4:])
	binary.LittleEndian.PutUint32(random[clientHelloRandomLen-4:], tail^timestamp)

	return hello
}

func unixNow() uint32 {
	return uint32(time.Now().Unix()) //nolint: gosec
}

type fakeTLSProxy struct {
	addr       string
	frontConns chan net.Conn
}

// startFakeTLSProxy runs a FakeTLS proxy for fakeTLSTestSecret whose fronting
// host is a local listener. setup adjusts the options before the proxy is
// created.
func startFakeTLSProxy(t *testing.T, setup func(*mtglib.ProxyOpts)) *fakeTLSProxy {
	t.Helper()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { front.Close() }) //nolint: errcheck

	frontConns := make(chan net.Conn, 16)

	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}

			frontConns <- conn
		}
	}()

	_, frontPort, _ := net.SplitHostPort(front.Addr().String())
	port, _ := strconv.Atoi(frontPort)

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	allowlist, err := ipblocklist.NewFireholFromFiles(logger.NewNoopLogger(), 1,
		[]files.File{files.NewMem([]*net.IPNet{cidranger.AllIPv4, cidranger.AllIPv6})}, nil)
	require.NoError(t, err)

	go allowlist.Run(time.Second)

	require.Eventually(t, func() bool {
		return allowlist.Contains(net.ParseIP("127.0.0.1"))
	}, 2*time.Second, 10*time.Millisecond)

	secret, err := mtglib.ParseSecret(fakeTLSTestSecret)
	require.NoError(t, err)

	opts := mtglib.ProxyOpts{
		Secret:             secret,
		Network:            ntw,
		AntiReplayCache:    antireplay.NewNoop(),
		IPBlocklist:        ipblocklist.NewNoop(),
		IPAllowlist:        allowlist,
		EventStream:        events.NewNoopStream(),
		Logger:             logger.NewNoopLogger(),
		UseTestDCs:         true,
		DomainFrontingHost: "127.0.0.1",
		DomainFrontingPort: uint(port), //nolint: gosec
	}

	if setup != nil {
		setup(&opts)
	}

	proxy, err := mtglib.NewProxy(opts)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go proxy.Serve(listener) //nolint: errcheck

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck
		proxy.Shutdown()
	})

	return &fakeTLSProxy{addr: listener.Addr().String(), frontConns: frontConns}
}

type fakeTLSOutcome struct {
	// served is true if the proxy answered with a ServerHello, false if the
	// ClientHello reached the fronting host.
	served bool
	// elapsed is the time from sending the ClientHello to the ServerHello or
	// to the ClientHello arriving at the fronting host.
	elapsed time.Duration
}

// handshake sends hello and reports what the proxy did with it.
func (p *fakeTLSProxy) handshake(t *testing.T, hello []byte) fakeTLSOutcome {
	t.Helper()

	client, err := net.Dial("tcp", p.addr)
	require.NoError(t, err)

	defer client.Close() //nolint: errcheck

	started := time.Now()

	_, err = client.Write(hello)
	require.NoError(t, err)

	served := make(chan time.Duration, 1)

	go func() {
		client.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint: errcheck

		header := make([]byte, 3)
		if _, err := io.ReadFull(client, header); err == nil && bytes.Equal(header, []byte{0x16, 3, 3}) {
			served <- time.Since(started)
		}

		close(served)
	}()

	select {
	case elapsed, ok := <-served:
		if !ok {
			t.Fatal("the connection was closed without a ServerHello")
		}

		return fakeTLSOutcome{served: true, elapsed: elapsed}
	case front := <-p.frontConns:
		defer front.Close() //nolint: errcheck

		front.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint: errcheck

		got := make([]byte, len(hello))
		_, err := io.ReadFull(front, got)
		require.NoError(t, err)

		elapsed := time.Since(started)

		require.Equal(t, hello, got, "the fronting host must get the ClientHello byte for byte")

		return fakeTLSOutcome{served: false, elapsed: elapsed}
	case <-time.After(5 * time.Second):
		t.Fatal("neither a ServerHello nor fronting")
	}

	return fakeTLSOutcome{}
}

func withExactAntiReplay(opts *mtglib.ProxyOpts) {
	window := opts.TolerateTimeSkewness
	if window == 0 {
		window = mtglib.DefaultTolerateTimeSkewnessExact
	}

	opts.FakeTLSAntiReplayCache = antireplay.NewExact(antireplay.TTLForTimeSkewness(window), 0)
}

// A replayed ClientHello goes to the fronting host, fresh ones are served.
func TestFakeTLSExactAntiReplay(t *testing.T) {
	t.Parallel()

	proxy := startFakeTLSProxy(t, func(opts *mtglib.ProxyOpts) {
		opts.TolerateTimeSkewness = 10 * time.Second
		withExactAntiReplay(opts)
	})

	now := unixNow()
	first := fakeTLSClientHello(t, now, 1)
	second := fakeTLSClientHello(t, now, 2)

	assert.True(t, proxy.handshake(t, first).served)
	assert.False(t, proxy.handshake(t, first).served, "replay")
	assert.True(t, proxy.handshake(t, second).served, "another client")
	assert.False(t, proxy.handshake(t, second).served, "replay")
	assert.False(t, proxy.handshake(t, first).served, "replay")
}

// A FakeTLS cache that forgets a ClientHello while its timestamp is still
// accepted is a configuration error.
func TestFakeTLSAntiReplayTTLTooShort(t *testing.T) {
	t.Parallel()

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	_, err = mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:                 mtglib.GenerateSecret("example.com"),
		Network:                ntw,
		AntiReplayCache:        antireplay.NewNoop(),
		FakeTLSAntiReplayCache: antireplay.NewExact(20*time.Second, 0),
		IPBlocklist:            ipblocklist.NewNoop(),
		IPAllowlist:            ipblocklist.NewNoop(),
		EventStream:            events.NewNoopStream(),
		Logger:                 logger.NewNoopLogger(),
		TolerateTimeSkewness:   10 * time.Second,
	})
	require.ErrorIs(t, err, mtglib.ErrAntiReplayTTLTooShort)
}

// With an exact FakeTLS cache the default window is 2 minutes, and a replay
// anywhere in it is still caught.
func TestFakeTLSDefaultWindowWithExactCache(t *testing.T) {
	t.Parallel()

	proxy := startFakeTLSProxy(t, func(opts *mtglib.ProxyOpts) {
		opts.FakeTLSAntiReplayCache = antireplay.NewExact(
			antireplay.TTLForTimeSkewness(mtglib.DefaultTolerateTimeSkewnessExact), 0)
	})

	now := unixNow()

	for i, offset := range []int64{-110, -30, 0, 30, 110} {
		hello := fakeTLSClientHello(t, uint32(int64(now)+offset), uint64(i)) //nolint: gosec

		assert.True(t, proxy.handshake(t, hello).served, "offset %d", offset)
		assert.False(t, proxy.handshake(t, hello).served, "replay at offset %d", offset)
	}

	assert.False(t, proxy.handshake(t, fakeTLSClientHello(t, now-130, 10)).served)
	assert.False(t, proxy.handshake(t, fakeTLSClientHello(t, now+130, 11)).served)
}

// Without the exact cache the default window stays at 3 seconds.
func TestFakeTLSDefaultWindowWithoutExactCache(t *testing.T) {
	t.Parallel()

	proxy := startFakeTLSProxy(t, nil)
	now := unixNow()

	assert.True(t, proxy.handshake(t, fakeTLSClientHello(t, now, 1)).served)
	assert.False(t, proxy.handshake(t, fakeTLSClientHello(t, now-30, 2)).served)
}

func TestFakeTLSBootTimeTimestamps(t *testing.T) {
	t.Parallel()

	proxy := startFakeTLSProxy(t, func(opts *mtglib.ProxyOpts) {
		opts.BootTimeTimestampsBelow = mtglib.BootTimeTimestampsMax
		withExactAntiReplay(opts)
	})

	uptime := fakeTLSClientHello(t, 3*24*60*60, 1)

	assert.True(t, proxy.handshake(t, uptime).served)
	assert.False(t, proxy.handshake(t, uptime).served, "replay")
	assert.True(t, proxy.handshake(t, fakeTLSClientHello(t, unixNow(), 2)).served)
	assert.False(t, proxy.handshake(t, fakeTLSClientHello(t, 7*24*60*60, 3)).served, "7 days is not boot time")

	disabled := startFakeTLSProxy(t, withExactAntiReplay)

	assert.False(t, disabled.handshake(t, fakeTLSClientHello(t, 1000, 4)).served)
}

func TestFakeTLSBootTimeTimestampsLimit(t *testing.T) {
	t.Parallel()

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	_, err = mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:                  mtglib.GenerateSecret("example.com"),
		Network:                 ntw,
		AntiReplayCache:         antireplay.NewNoop(),
		IPBlocklist:             ipblocklist.NewNoop(),
		IPAllowlist:             ipblocklist.NewNoop(),
		EventStream:             events.NewNoopStream(),
		Logger:                  logger.NewNoopLogger(),
		BootTimeTimestampsBelow: mtglib.BootTimeTimestampsMax + time.Second,
	})
	require.ErrorIs(t, err, mtglib.ErrBootTimeTimestampsBelowTooLarge)
}

// Whenever two moments both accept the same timestamp, they are less than
// FakeTLSReplayTTL apart: a replay that passes the timestamp check always
// finds the first ClientHello still in the cache.
func TestFakeTLSReplayTTLCoversWindow(t *testing.T) {
	t.Parallel()

	timestamp := time.Unix(1_800_000_000, 0)

	// covers sweeps the first sight and the replay over the window and a
	// little around it, with sub-second offsets, and reports whether every
	// replay that passes the timestamp check comes within ttl.
	covers := func(window, ttl time.Duration) bool {
		step := window / 50

		accepted := func(at time.Time) bool {
			return at.Sub(timestamp).Abs() <= window
		}

		for first := -window - time.Second; first <= window+time.Second; first += step {
			for replay := first; replay <= window+time.Second; replay += step / 3 {
				seen, replayed := timestamp.Add(first), timestamp.Add(replay)

				if accepted(seen) && accepted(replayed) && replayed.Sub(seen) >= ttl {
					return false
				}
			}
		}

		return true
	}

	for _, window := range []time.Duration{time.Second, 3 * time.Second, 2 * time.Minute} {
		assert.True(t, covers(window, mtglib.FakeTLSReplayTTL(window)), "window %v", window)
		// A TTL of the window alone is not enough: a client clock ahead by
		// the whole window makes its ClientHello replayable for 2*window.
		assert.False(t, covers(window, window), "window %v", window)
	}
}
