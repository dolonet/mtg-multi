package mtglib_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
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

// limitsSnapshotSecret signed the real ClientHello snapshot in testdata of
// the fake package.
const limitsSnapshotSecret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

// streamCounter is an EventStream that counts started and finished streams,
// so a test can wait for all of them before Shutdown: Shutdown must not
// overlap with a handshake still going on.
type streamCounter struct {
	started  atomic.Int64
	finished atomic.Int64
}

func (s *streamCounter) Send(_ context.Context, evt mtglib.Event) {
	switch evt.(type) {
	case mtglib.EventStart:
		s.started.Add(1)
	case mtglib.EventFinish:
		s.finished.Add(1)
	}
}

func limitsClientHello(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(
		"internal", "tls", "fake", "testdata", "client-hello-ok-19dfe38384b9884b.json"))
	require.NoError(t, err)

	snapshot := struct {
		Full string `json:"full"`
	}{}
	require.NoError(t, json.Unmarshal(data, &snapshot))

	full, err := base64.StdEncoding.DecodeString(snapshot.Full)
	require.NoError(t, err)

	return full
}

// startLimitsProxy runs a proxy with the users alice (the snapshot secret)
// and bob, fronting to a local listener. It returns the proxy, its address
// and the connections accepted by the fronting host.
func startLimitsProxy(t *testing.T, limits map[string]mtglib.SecretLimits) (*mtglib.Proxy, string, <-chan net.Conn) {
	t.Helper()

	alice, err := mtglib.ParseSecret(limitsSnapshotSecret)
	require.NoError(t, err)

	front, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { front.Close() }) //nolint: errcheck

	frontConns := make(chan net.Conn, 4)

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

	streams := &streamCounter{}

	allowlist, err := ipblocklist.NewFireholFromFiles(logger.NewNoopLogger(), 1,
		[]files.File{files.NewMem([]*net.IPNet{cidranger.AllIPv4, cidranger.AllIPv6})}, nil)
	require.NoError(t, err)

	go allowlist.Run(time.Second)

	require.Eventually(t, func() bool {
		return allowlist.Contains(net.ParseIP("127.0.0.1"))
	}, 5*time.Second, 10*time.Millisecond)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secrets: map[string]mtglib.Secret{
			"alice": alice,
			"bob":   mtglib.GenerateSecret("example.com"),
		},
		SecretLimits:       limits,
		Network:            ntw,
		AntiReplayCache:    antireplay.NewNoop(),
		IPBlocklist:        ipblocklist.NewNoop(),
		IPAllowlist:        allowlist,
		EventStream:        streams,
		Logger:             logger.NewNoopLogger(),
		UseTestDCs:         true,
		DomainFrontingHost: "127.0.0.1",
		DomainFrontingPort: uint(port), //nolint: gosec
		// The ClientHello snapshot was taken in 2021.
		TolerateTimeSkewness: 100 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go proxy.Serve(listener) //nolint: errcheck

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck

		// helloOutcome closes its client; wait for the streams to end.
		assert.Eventually(t, func() bool {
			return streams.finished.Load() == streams.started.Load()
		}, 10*time.Second, 10*time.Millisecond)

		proxy.Shutdown()
	})

	return proxy, listener.Addr().String(), frontConns
}

// helloOutcome sends alice's ClientHello and reports whether the proxy
// answered with a ServerHello (true) or the fronting host got the ClientHello
// byte for byte (false).
func helloOutcome(t *testing.T, addr string, frontConns <-chan net.Conn) bool {
	t.Helper()

	hello := limitsClientHello(t)

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	defer client.Close() //nolint: errcheck

	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = client.Write(hello)
	require.NoError(t, err)

	answered := make(chan []byte, 1)

	go func() {
		header := make([]byte, 3)
		if _, err := io.ReadFull(client, header); err == nil {
			answered <- header
		}

		close(answered)
	}()

	select {
	case front := <-frontConns:
		defer front.Close() //nolint: errcheck

		require.NoError(t, front.SetDeadline(time.Now().Add(10*time.Second)))

		got := make([]byte, len(hello))
		_, err := io.ReadFull(front, got)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(hello, got), "the fronting host must get the ClientHello unchanged")

		return false
	case header, ok := <-answered:
		require.True(t, ok, "the proxy closed the connection without an answer")
		assert.Equal(t, []byte{0x16, 0x03, 0x03}, header, "expected a TLS handshake record")

		return true
	case <-time.After(10 * time.Second):
		t.Fatal("neither a ServerHello nor fronting")
	}

	return false
}

// A disabled or expired user is fronted exactly like a wrong secret: the
// fronting host gets the very ClientHello and the client gets no ServerHello.
func TestProxySecretLimitsRejectLikeWrongSecret(t *testing.T) {
	t.Parallel()

	testData := map[string]map[string]mtglib.SecretLimits{
		"disabled": {"alice": {Disabled: true}},
		"expired":  {"alice": {ExpiresAt: time.Now().Add(-time.Minute)}},
	}

	for name, limits := range testData {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, addr, frontConns := startLimitsProxy(t, limits)
			assert.False(t, helloOutcome(t, addr, frontConns))
		})
	}
}

// Limits of other users and limits that allow the connection change nothing.
func TestProxySecretLimitsLetOthersIn(t *testing.T) {
	t.Parallel()

	testData := map[string]map[string]mtglib.SecretLimits{
		"no limits":      nil,
		"other disabled": {"bob": {Disabled: true}},
		"not expired": {"alice": {
			ExpiresAt:  time.Now().Add(time.Hour),
			QuotaBytes: 1 << 30,
			QuotaReset: mtglib.QuotaResetDaily,
		}},
	}

	for name, limits := range testData {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, addr, frontConns := startLimitsProxy(t, limits)
			assert.True(t, helloOutcome(t, addr, frontConns))
		})
	}
}

// A reload applies new limits to new connections without a restart.
func TestProxySecretLimitsReload(t *testing.T) {
	t.Parallel()

	proxy, addr, frontConns := startLimitsProxy(t, nil)
	require.True(t, helloOutcome(t, addr, frontConns))

	alice, err := mtglib.ParseSecret(limitsSnapshotSecret)
	require.NoError(t, err)

	secrets := map[string]mtglib.Secret{"alice": alice, "bob": mtglib.GenerateSecret("example.com")}

	update, err := proxy.UpdateSecretsWithLimits(secrets, map[string]mtglib.SecretLimits{"alice": {Disabled: true}})
	require.NoError(t, err)
	assert.Equal(t, 1, update.Changed, "bob got a new key")
	assert.False(t, helloOutcome(t, addr, frontConns))

	_, err = proxy.UpdateSecretsWithLimits(secrets, nil)
	require.NoError(t, err)
	assert.True(t, helloOutcome(t, addr, frontConns))
}

func TestNewProxyRejectsInvalidSecretLimits(t *testing.T) {
	t.Parallel()

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	for name, limits := range map[string]map[string]mtglib.SecretLimits{
		"unknown secret": {"ghost": {Disabled: true}},
		"negative quota": {"alice": {QuotaBytes: -1}},
	} {
		_, err := mtglib.NewProxy(mtglib.ProxyOpts{
			Secrets:         map[string]mtglib.Secret{"alice": mtglib.GenerateSecret("example.com")},
			SecretLimits:    limits,
			Network:         ntw,
			AntiReplayCache: antireplay.NewNoop(),
			IPBlocklist:     ipblocklist.NewNoop(),
			IPAllowlist:     ipblocklist.NewNoop(),
			EventStream:     events.NewNoopStream(),
			Logger:          logger.NewNoopLogger(),
			UseTestDCs:      true,
		})
		assert.Error(t, err, name)
	}
}
