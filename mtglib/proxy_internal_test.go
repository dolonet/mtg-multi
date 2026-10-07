package mtglib

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
)

func TestIsFakeTLSHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		firstBytes [5]byte
		want       bool
	}{
		{
			name:       "fake TLS client hello",
			firstBytes: [5]byte{0x16, 0x03, 0x01, 0x06, 0xe1},
			want:       true,
		},
		{
			name:       "secured obfuscated handshake",
			firstBytes: [5]byte{0x91, 0x82, 0x07, 0x14, 0xfb},
			want:       false,
		},
		{
			name:       "TLS application data is not a client hello",
			firstBytes: [5]byte{0x17, 0x03, 0x03, 0x00, 0x10},
			want:       false,
		},
		{
			name:       "unsupported record version",
			firstBytes: [5]byte{0x16, 0x03, 0x03, 0x00, 0x10},
			want:       false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isFakeTLSHandshake(tt.firstBytes); got != tt.want {
				t.Fatalf("isFakeTLSHandshake() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mapAntiReplayCache struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (m *mapAntiReplayCache) SeenBefore(data []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.seen[string(data)] {
		return true
	}

	m.seen[string(data)] = true

	return false
}

type countingEventStream struct {
	mu      sync.Mutex
	replays int
}

func (c *countingEventStream) Send(_ context.Context, evt Event) {
	if _, ok := evt.(EventReplayAttack); ok {
		c.mu.Lock()
		c.replays++
		c.mu.Unlock()
	}
}

// securedTestConn returns the server side of a loopback TCP connection whose
// client side has already sent payload.
func securedTestConn(t *testing.T, payload []byte) essentials.Conn {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	return essentials.WrapNetConn(server)
}

// recordingConn captures what is written to it, so the 64-byte frame that a
// client would send can be taken from Obfuscator.SendHandshake.
type recordingConn struct {
	essentials.Conn

	buf bytes.Buffer
}

func (r *recordingConn) Write(p []byte) (int, error) {
	return r.buf.Write(p) //nolint: wrapcheck
}

// The second connection that replays a captured secured handshake is
// rejected by the anti-replay cache, and its bytes stay available for the
// fronting replay unchanged.
func TestDoSecuredHandshakeReplay(t *testing.T) {
	t.Parallel()

	secret := GenerateSecret("example.com")
	events := &countingEventStream{}
	proxy := &Proxy{
		ctx:                 context.Background(),
		secrets:             []Secret{secret},
		secretNames:         []string{"main"},
		antiReplayCache:     &mapAntiReplayCache{seen: map[string]bool{}},
		eventStream:         events,
		logger:              NoopLogger{},
		securedFrameTimeout: time.Second,
	}

	rec := &recordingConn{}
	if _, err := (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(rec, 2); err != nil {
		t.Fatal(err)
	}

	frame := rec.buf.Bytes()

	first := newStreamContext(context.Background(), NoopLogger{}, securedTestConn(t, frame))
	if err := proxy.doSecuredHandshake(first, newConnRewind(first.clientConn)); err != nil {
		t.Fatalf("the first secured handshake must succeed: %v", err)
	}

	if !first.secured || first.dc != 2 || first.secretName != "main" {
		t.Fatalf("unexpected stream state: secured=%v dc=%d secret=%q", first.secured, first.dc, first.secretName)
	}

	second := newStreamContext(context.Background(), NoopLogger{}, securedTestConn(t, frame))
	rewind := newConnRewind(second.clientConn)

	if err := proxy.doSecuredHandshake(second, rewind); err == nil {
		t.Fatal("a replayed secured handshake must be rejected")
	}

	if second.secured {
		t.Fatal("a replayed secured handshake must not mark the stream as secured")
	}

	if events.replays != 1 {
		t.Fatalf("want 1 replay event, got %d", events.replays)
	}

	rewind.FinalRewind()

	replayed := make([]byte, len(frame))
	if _, err := io.ReadFull(rewind, replayed); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(replayed, frame) {
		t.Fatal("the fronting replay must carry the original handshake bytes")
	}
}

type securedStub struct {
	essentials.Conn

	secured bool
}

func (s securedStub) SecuredTransport() bool { return s.secured }

// WEB streams mark themselves as secured transport: the dd handshake is
// accepted for them without enabling it on the FakeTLS listener.
func TestIsSecuredTransport(t *testing.T) {
	t.Parallel()

	if !isSecuredTransport(securedStub{secured: true}) {
		t.Fatal("a connection that reports SecuredTransport must be recognized")
	}

	if isSecuredTransport(securedStub{secured: false}) {
		t.Fatal("SecuredTransport() == false must not enable the secured handshake")
	}

	if isSecuredTransport(essentials.WrapNetConn(nil)) {
		t.Fatal("a regular connection must not be a secured transport")
	}
}

// A WEB stream (secured transport) keeps the whole handshake deadline: its
// 64-byte frame may come in a later HTTP request than the stream OPEN, and the
// short frame timeout meant for probes on the listener must not cut it off.
func TestReadSecuredFrameSkipsShortTimeoutForSecuredTransport(t *testing.T) {
	t.Parallel()

	secret := GenerateSecret("example.com")
	proxy := &Proxy{
		ctx:                 context.Background(),
		secrets:             []Secret{secret},
		secretNames:         []string{"main"},
		antiReplayCache:     &mapAntiReplayCache{seen: map[string]bool{}},
		eventStream:         &countingEventStream{},
		logger:              NoopLogger{},
		securedFrameTimeout: 50 * time.Millisecond,
	}

	rec := &recordingConn{}
	if _, err := (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(rec, 2); err != nil {
		t.Fatal(err)
	}

	frame := rec.buf.Bytes()

	delayed := func(secured bool) error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close() //nolint: errcheck

		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close() //nolint: errcheck

		server, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close() //nolint: errcheck

		time.AfterFunc(200*time.Millisecond, func() { client.Write(frame) }) //nolint: errcheck

		conn := securedStub{Conn: essentials.WrapNetConn(server), secured: secured}
		ctx := newStreamContext(context.Background(), NoopLogger{}, conn)
		ctx.handshakeDeadline = time.Now().Add(5 * time.Second)

		return proxy.doSecuredHandshake(ctx, newConnRewind(ctx.clientConn))
	}

	if err := delayed(true); err != nil {
		t.Fatalf("a secured transport must wait for its frame: %v", err)
	}

	if err := delayed(false); err == nil {
		t.Fatal("a listener connection must still get the short frame timeout")
	}
}
