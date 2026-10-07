package mtglib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newUpdateTestProxy(secrets map[string]Secret) *Proxy {
	p := &Proxy{
		stats:    NewProxyStats(),
		sessions: newSessionRegistry(),
	}
	set := newSecretSet(secrets)

	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secretSet.Store(set)

	return p
}

// authenticatedSession imitates a stream that has passed the handshake with
// the given secret and registers it like ServeConn does.
func authenticatedSession(t *testing.T, p *Proxy, name string, secret Secret) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream := &streamContext{
		ctx:           ctx,
		ctxCancel:     cancel,
		secretName:    name,
		matchedSecret: secret,
	}

	require.True(t, p.trackSession(stream))

	return stream
}

func isClosed(stream *streamContext) bool {
	select {
	case <-stream.Done():
		return true
	default:
		return false
	}
}

func TestNewSecretSet(t *testing.T) {
	t.Parallel()

	a := GenerateSecret("a.example.com")
	b := GenerateSecret("b.example.com")
	c := GenerateSecret("a.example.com")

	set := newSecretSet(map[string]Secret{"carol": c, "alice": a, "bob": b})

	assert.Equal(t, []string{"alice", "bob", "carol"}, set.names)
	assert.Equal(t, []Secret{a, b, c}, set.secrets)
	assert.Equal(t, [][]byte{a.Key[:], b.Key[:], c.Key[:]}, set.keys)
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, set.hostnames)
	assert.True(t, set.sameSecret("bob", b))
	assert.False(t, set.sameSecret("bob", a))
	assert.False(t, set.sameSecret("dave", a))

	// Same key, different host: not the same secret.
	bMoved := b
	bMoved.Host = "c.example.com"
	assert.False(t, set.sameSecret("bob", bMoved))
}

func TestUpdateSecretsRejectsInvalidSet(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})
	stream := authenticatedSession(t, p, "alice", alice)

	_, err := p.UpdateSecrets(map[string]Secret{})
	require.ErrorIs(t, err, ErrSecretEmpty)

	_, err = p.UpdateSecrets(map[string]Secret{"bob": {}})
	require.Error(t, err)

	// A failed update leaves everything as it was.
	assert.Equal(t, []string{"alice"}, p.secretSet.Load().names)
	assert.False(t, isClosed(stream))
}

func TestUpdateSecretsKeepsUnchangedSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	aliceSession := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)

	carol := GenerateSecret("other.example.com")
	update, err := p.UpdateSecrets(map[string]Secret{"alice": alice, "bob": bob, "carol": carol})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Added: 1}, update)
	assert.False(t, isClosed(aliceSession))
	assert.False(t, isClosed(bobSession))

	set := p.secretSet.Load()
	assert.Equal(t, []string{"alice", "bob", "carol"}, set.names)
	assert.Equal(t, []string{"example.com", "other.example.com"}, set.hostnames)
	assert.NotNil(t, p.stats.lookup("carol"))
}

func TestUpdateSecretsClosesRemovedAndChanged(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	carol := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob, "carol": carol})

	alice1 := authenticatedSession(t, p, "alice", alice)
	alice2 := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)
	carolSession := authenticatedSession(t, p, "carol", carol)

	// alice is removed, bob gets a new key, carol is kept.
	bobRotated := GenerateSecret("example.com")
	update, err := p.UpdateSecrets(map[string]Secret{"bob": bobRotated, "carol": carol})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Removed: 1, Changed: 1, ClosedSessions: 3}, update)
	assert.True(t, isClosed(alice1))
	assert.True(t, isClosed(alice2))
	assert.True(t, isClosed(bobSession))
	assert.False(t, isClosed(carolSession))

	// The removed user disappears from the stats, and late updates from its
	// closing sessions do not bring it back.
	assert.Nil(t, p.stats.lookup("alice"))
	p.stats.OnDisconnect("alice")
	p.stats.AddBytesIn("alice", 10)
	p.stats.AddBytesOut("alice", 10)
	p.stats.UpdateLastSeen("alice")
	assert.Nil(t, p.stats.lookup("alice"))

	// The kept user still has its stats.
	assert.EqualValues(t, 1, p.stats.lookup("carol").connections.Load())

	// Closed sessions unregister themselves as ServeConn does on return.
	p.sessions.remove(alice1)
	p.sessions.remove(alice2)
	p.sessions.remove(bobSession)
	assert.Len(t, p.sessions.sessions, 1)
}

func TestUpdateSecretsHostChangeClosesSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("old.example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})
	stream := authenticatedSession(t, p, "alice", alice)

	moved := alice
	moved.Host = "new.example.com"

	update, err := p.UpdateSecrets(map[string]Secret{"alice": moved})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Changed: 1, ClosedSessions: 1}, update)
	assert.True(t, isClosed(stream))
	assert.Equal(t, []string{"new.example.com"}, p.secretSet.Load().hostnames)
}

// A handshake that matched a secret before an update must not register a
// session after the update has removed or rotated that secret: the session
// would escape the sweep.
func TestTrackSessionAfterSecretRemoved(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	_, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com")})
	require.NoError(t, err)

	for name, secret := range map[string]Secret{"alice": alice, "bob": bob} {
		ctx, cancel := context.WithCancel(context.Background())
		stream := &streamContext{
			ctx:           ctx,
			ctxCancel:     cancel,
			secretName:    name,
			matchedSecret: secret,
		}

		assert.False(t, p.trackSession(stream), name)
		cancel()
	}

	assert.Empty(t, p.sessions.sessions)
	// A rejected session is not counted, and the removed user is not
	// brought back into the stats.
	assert.Nil(t, p.stats.lookup("alice"))
	assert.Zero(t, p.stats.lookup("bob").connections.Load())
}

// A handshake that matched the old host of a user must not register a
// session after an update that only changes the host: the key is the same,
// but UpdateSecrets closes the sessions of such a user, and a late one would
// escape the sweep.
func TestTrackSessionAfterHostChanged(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("old.example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	moved := alice
	moved.Host = "new.example.com"

	_, err := p.UpdateSecrets(map[string]Secret{"alice": moved})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stale := &streamContext{
		ctx:           ctx,
		ctxCancel:     cancel,
		secretName:    "alice",
		matchedSecret: alice,
	}
	assert.False(t, p.trackSession(stale))
	assert.Empty(t, p.sessions.sessions)
	assert.Zero(t, p.stats.lookup("alice").connections.Load())

	// A handshake with the new host is accepted.
	fresh := authenticatedSession(t, p, "alice", moved)
	assert.False(t, isClosed(fresh))
}

func TestUpdateSecretsConcurrentWithSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	done := make(chan struct{})

	go func() {
		defer close(done)

		for range 1000 {
			ctx, cancel := context.WithCancel(context.Background())
			stream := &streamContext{
				ctx:           ctx,
				ctxCancel:     cancel,
				secretName:    "alice",
				matchedSecret: alice,
			}

			if p.trackSession(stream) {
				p.sessions.remove(stream)
			}

			cancel()
		}
	}()

	for i := range 200 {
		secrets := map[string]Secret{"alice": alice}
		if i%2 == 0 {
			secrets["bob"] = GenerateSecret("example.com")
		}

		_, err := p.UpdateSecrets(secrets)
		require.NoError(t, err)
	}

	<-done

	assert.Empty(t, p.sessions.sessions)
}

// tcpPair returns a real TCP pair: newStreamContext needs a TCP address.
func tcpPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() }) //nolint: errcheck

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	s := <-accepted
	require.NotNil(t, s)
	t.Cleanup(func() { s.Close(); c.Close() }) //nolint: errcheck

	return s.(*net.TCPConn), c.(*net.TCPConn) //nolint: forcetypeassert
}

type wrappedConn struct {
	essentials.Conn
}

// UpdateSecrets used to close a session with ctx.Close(), which reads
// clientConn/telegramConn while ServeConn replaces them with wrappers: a data
// race on an interface value that can crash the process. Now only the
// original connection is closed. go test -race catches the old behaviour.
func TestUpdateSecretsClosesWhileServeConnRewrapsConn(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	server, client := tcpPair(t)
	stream := newStreamContext(context.Background(), NoopLogger{}, server)
	stream.secretName = "alice"
	stream.matchedSecret = alice
	require.True(t, p.trackSession(stream))

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			select {
			case <-stop:
				return
			default:
				// This is how ServeConn wraps the connection after registration.
				stream.clientConn = wrappedConn{Conn: stream.clientConn}
				stream.telegramConn = wrappedConn{Conn: server}
			}
		}
	}()

	update, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com")})
	require.NoError(t, err)
	close(stop)
	<-done

	assert.Equal(t, 1, update.ClosedSessions)
	assert.True(t, isClosed(stream))

	// The original connection is closed: the client sees EOF.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// A user is removed, added back by the next reload, and only then its old
// sessions finish: the counter of the new entry used to go negative.
func TestReaddedUserCountersStayConsistent(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	old := authenticatedSession(t, p, "alice", alice)

	_, err := p.UpdateSecrets(map[string]Secret{"bob": bob})
	require.NoError(t, err)
	_, err = p.UpdateSecrets(map[string]Secret{"alice": alice, "bob": bob})
	require.NoError(t, err)

	// This is how the old session finishes in ServeConn.
	old.userStats.connections.Add(-1)
	p.sessions.remove(old)

	assert.Zero(t, p.stats.lookup("alice").connections.Load())
}

// With throttling enabled, CanConnect used getOrCreate and brought a removed
// user back into /stats.
func TestCanConnectDoesNotRecreateForgottenUser(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.SetThrottle(10, time.Second)
	stats.PreRegister("alice")
	stats.throttleCaps["alice"] = 1
	stats.Forget("alice")

	assert.True(t, stats.CanConnect("alice"))
	assert.Nil(t, stats.lookup("alice"))
}

func TestSecretsDigest(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"bob": bob, "alice": alice})
	p.stats.SetSecretsDigest(p.secretSet.Load().digest())

	want := sha256.Sum256([]byte("alice=" + alice.Hex() + "\nbob=" + bob.Hex()))
	assert.Equal(t, hex.EncodeToString(want[:]), p.secretSet.Load().digest())

	readDigest := func() string {
		rec := httptest.NewRecorder()
		p.stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

		var resp StatsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		return resp.SecretsSHA256
	}

	before := readDigest()
	assert.Equal(t, hex.EncodeToString(want[:]), before)

	// Same names, another key: the fingerprint must change.
	_, err := p.UpdateSecrets(map[string]Secret{"alice": GenerateSecret("example.com"), "bob": bob})
	require.NoError(t, err)
	assert.NotEqual(t, before, readDigest())
}

// securedSession runs a real secured (dd) handshake for secret against the
// given snapshot of the secrets, the way doFakeTLSHandshake does with
// [secured] enabled. It returns the stream and the client side of its
// connection.
func securedSession(t *testing.T, p *Proxy, set *secretSet, secret Secret) (*streamContext, *net.TCPConn) {
	t.Helper()

	p.ctx = context.Background()
	p.logger = NoopLogger{}
	p.eventStream = &countingEventStream{}
	p.antiReplayCache = &mapAntiReplayCache{seen: map[string]bool{}}
	p.securedFrameTimeout = time.Second

	frame := &recordingConn{}
	_, err := (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(frame, 2)
	require.NoError(t, err)

	server, client := tcpPair(t)
	_, err = client.Write(frame.buf.Bytes())
	require.NoError(t, err)

	stream := newStreamContext(context.Background(), NoopLogger{}, essentials.WrapNetConn(server))
	t.Cleanup(stream.ctxCancel)

	require.NoError(t, p.doSecuredHandshake(stream, newConnRewind(stream.clientConn), set))
	require.True(t, stream.secured)

	return stream, client
}

// A dd session is registered under the user whose key matched, with the
// whole secret of that user from the same snapshot, and is closed when the
// user is removed. The session's clientConn is the obfuscated2 wrapper, so
// the close must reach the original connection.
func TestUpdateSecretsClosesSecuredSession(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	aliceStream, aliceClient := securedSession(t, p, p.secretSet.Load(), alice)
	assert.Equal(t, "alice", aliceStream.secretName)
	assert.Equal(t, alice, aliceStream.matchedSecret)
	require.True(t, p.trackSession(aliceStream))

	bobStream, _ := securedSession(t, p, p.secretSet.Load(), bob)
	assert.Equal(t, "bob", bobStream.secretName)
	require.True(t, p.trackSession(bobStream))

	update, err := p.UpdateSecrets(map[string]Secret{"bob": bob})
	require.NoError(t, err)

	assert.Equal(t, 1, update.ClosedSessions)
	assert.True(t, isClosed(aliceStream))
	assert.False(t, isClosed(bobStream))

	require.NoError(t, aliceClient.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = aliceClient.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// A dd handshake that matched a user against the old snapshot must not
// register a session after the user has been removed.
func TestTrackSecuredSessionAfterSecretRemoved(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	stream, _ := securedSession(t, p, p.secretSet.Load(), alice)

	_, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com")})
	require.NoError(t, err)

	assert.False(t, p.trackSession(stream))
	assert.Empty(t, p.sessions.sessions)
	assert.Nil(t, p.stats.lookup("alice"))
}
