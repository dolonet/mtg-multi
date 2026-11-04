package mtglib

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedClientHello builds a minimal FakeTLS ClientHello record for key and
// host, signed the way Telegram clients do it: the client random is the
// HMAC-SHA256 of the record with a zero random, XORed with the timestamp in
// its last 4 bytes.
func signedClientHello(t *testing.T, key []byte, host string, sessionID []byte, at time.Time) []byte {
	t.Helper()

	sni := &bytes.Buffer{}
	binary.Write(sni, binary.BigEndian, uint16(len(host)+3)) //nolint: errcheck
	sni.WriteByte(0)                                         // DNS hostname
	binary.Write(sni, binary.BigEndian, uint16(len(host)))   //nolint: errcheck
	sni.WriteString(host)

	extensions := &bytes.Buffer{}
	extensions.Write([]byte{0, 0})                                // server_name
	binary.Write(extensions, binary.BigEndian, uint16(sni.Len())) //nolint: errcheck
	extensions.Write(sni.Bytes())

	body := &bytes.Buffer{}
	body.Write([]byte{3, 3})
	body.Write(make([]byte, fake.RandomLen))
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	body.Write([]byte{0, 2, 0x13, 0x01})                           // one cipher suite
	body.Write([]byte{1, 0})                                       // no compression
	binary.Write(body, binary.BigEndian, uint16(extensions.Len())) //nolint: errcheck
	body.Write(extensions.Bytes())

	record := &bytes.Buffer{}
	record.Write([]byte{0x16, 3, 1})
	binary.Write(record, binary.BigEndian, uint16(4+body.Len())) //nolint: errcheck
	record.WriteByte(fake.TypeHandshakeClient)
	record.Write([]byte{0, byte(body.Len() >> 8), byte(body.Len())})
	record.Write(body.Bytes())

	data := record.Bytes()

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	random := mac.Sum(nil)

	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], uint32(at.Unix()))

	for i := range 4 {
		random[fake.RandomLen-4+i] ^= ts[i]
	}

	copy(data[fake.RandomOffset:], random)

	return data
}

// parseHello runs data through the real ClientHello parser and HMAC check.
func parseHello(t *testing.T, key []byte, host string, data []byte) *fake.ClientHello {
	t.Helper()

	server, client := net.Pipe()
	defer server.Close() //nolint: errcheck

	go func() {
		client.Write(data) //nolint: errcheck
		client.Close()     //nolint: errcheck
	}()

	result, err := fake.ReadClientHelloMulti(server, [][]byte{key}, []string{host}, time.Minute)
	require.NoError(t, err)

	return result.Hello
}

func TestFakeTLSReplayKeyIsClientRandom(t *testing.T) {
	t.Parallel()

	secret := GenerateSecret("example.com")
	key := secret.Key[:]
	now := time.Now()

	sessionID := make([]byte, 32)
	_, err := rand.Read(sessionID)
	require.NoError(t, err)

	for name, sid := range map[string][]byte{"random session id": sessionID, "empty session id": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := &Proxy{antiReplayCache: &mapAntiReplayCache{seen: map[string]bool{}}}

			first := signedClientHello(t, key, secret.Host, sid, now)
			// Another valid hello with the same session ID: a different
			// timestamp gives a different signature.
			second := signedClientHello(t, key, secret.Host, sid, now.Add(-time.Second))
			require.NotEqual(t, first, second)

			assert.False(t, p.isFakeTLSReplay(parseHello(t, key, secret.Host, first)))
			assert.False(t, p.isFakeTLSReplay(parseHello(t, key, secret.Host, second)),
				"a distinct valid hello sharing the session ID is not a replay")
			assert.True(t, p.isFakeTLSReplay(parseHello(t, key, secret.Host, first)),
				"the same bytes again are a replay")
			assert.True(t, p.isFakeTLSReplay(parseHello(t, key, secret.Host, second)))
		})
	}
}
