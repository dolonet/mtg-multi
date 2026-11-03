package fake_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policyTestSecret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

// signedClientHello returns a real ClientHello snapshot re-signed for the
// given timestamp.
func signedClientHello(t *testing.T, secret mtglib.Secret, timestamp uint32) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "client-hello-ok-19dfe38384b9884b.json"))
	require.NoError(t, err)

	snapshot := &clientHelloSnapshot{}
	require.NoError(t, json.Unmarshal(data, snapshot))

	hello := snapshot.GetFull()
	random := hello[fake.RandomOffset : fake.RandomOffset+fake.RandomLen]
	clear(random)

	mac := hmac.New(sha256.New, secret.Key[:])
	mac.Write(hello)
	copy(random, mac.Sum(nil))

	tail := binary.LittleEndian.Uint32(random[fake.RandomLen-4:])
	binary.LittleEndian.PutUint32(random[fake.RandomLen-4:], tail^timestamp)

	return hello
}

func TestReadClientHelloTimestampPolicy(t *testing.T) {
	t.Parallel()

	secret, err := mtglib.ParseSecret(policyTestSecret)
	require.NoError(t, err)

	const (
		window = 2 * time.Minute
		week   = uint32(7 * 24 * 60 * 60)
	)

	nowUnix := uint32(1_800_000_000)
	now := time.Unix(int64(nowUnix), 0)
	windowSecs := uint32(window / time.Second)

	cases := []struct {
		name      string
		timestamp uint32
		now       time.Time
		bootTime  time.Duration
		accepted  bool
		isBoot    bool
	}{
		{name: "now", timestamp: nowUnix, now: now, accepted: true},
		{name: "window in the past", timestamp: nowUnix - windowSecs, now: now, accepted: true},
		{name: "window in the future", timestamp: nowUnix + windowSecs, now: now, accepted: true},
		{name: "past the window in the past", timestamp: nowUnix - windowSecs - 1, now: now},
		{name: "past the window in the future", timestamp: nowUnix + windowSecs + 1, now: now},
		{
			name: "just past the window", timestamp: nowUnix - windowSecs,
			now: now.Add(time.Nanosecond),
		},
		{name: "boot time disabled", timestamp: 1000, now: now},
		{name: "zero timestamp disabled", timestamp: 0, now: now},
		{
			name: "boot time", timestamp: 1000, now: now,
			bootTime: mtglib.BootTimeTimestampsMax, accepted: true, isBoot: true,
		},
		{
			name: "zero boot time", timestamp: 0, now: now,
			bootTime: mtglib.BootTimeTimestampsMax, accepted: true, isBoot: true,
		},
		{
			name: "last boot-time second", timestamp: week - 1, now: now,
			bootTime: mtglib.BootTimeTimestampsMax, accepted: true, isBoot: true,
		},
		{
			name: "boot-time limit is exclusive", timestamp: week, now: now,
			bootTime: mtglib.BootTimeTimestampsMax,
		},
		{
			name: "short boot-time limit", timestamp: 120, now: now,
			bootTime: 2 * time.Minute,
		},
		{
			name: "under a short boot-time limit", timestamp: 119, now: now,
			bootTime: 2 * time.Minute, accepted: true, isBoot: true,
		},
		{
			name: "wall clock with boot time enabled", timestamp: nowUnix - windowSecs, now: now,
			bootTime: mtglib.BootTimeTimestampsMax, accepted: true,
		},
		{
			name: "wall clock past the window with boot time enabled", timestamp: nowUnix - windowSecs - 1,
			now: now, bootTime: mtglib.BootTimeTimestampsMax,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := &parseClientHelloConnMock{
				readBuf: bytes.NewBuffer(signedClientHello(t, secret, tc.timestamp)),
			}

			result, err := fake.ReadClientHelloWithPolicy(
				conn,
				[][]byte{secret.Key[:]},
				[]string{secret.Host},
				fake.TimestampPolicy{
					TolerateTimeSkewness: window,
					BootTimeBelow:        tc.bootTime,
					Now:                  func() time.Time { return tc.now },
				},
			)

			if !tc.accepted {
				require.ErrorIs(t, err, fake.ErrBadDigest)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, 0, result.MatchedIndex)
			assert.Equal(t, tc.isBoot, result.BootTime)
		})
	}
}

// The wrappers keep the old behaviour: the window around time.Now and no
// boot-time rule.
func TestReadClientHelloMultiUsesNow(t *testing.T) {
	t.Parallel()

	secret, err := mtglib.ParseSecret(policyTestSecret)
	require.NoError(t, err)

	now := uint32(time.Now().Unix()) //nolint: gosec

	conn := &parseClientHelloConnMock{readBuf: bytes.NewBuffer(signedClientHello(t, secret, now-60))}
	_, err = fake.ReadClientHello(conn, secret.Key[:], secret.Host, 2*time.Minute)
	require.NoError(t, err)

	conn = &parseClientHelloConnMock{readBuf: bytes.NewBuffer(signedClientHello(t, secret, now-60))}
	_, err = fake.ReadClientHello(conn, secret.Key[:], secret.Host, 3*time.Second)
	require.ErrorIs(t, err, fake.ErrBadDigest)

	conn = &parseClientHelloConnMock{readBuf: bytes.NewBuffer(signedClientHello(t, secret, 1000))}
	_, err = fake.ReadClientHello(conn, secret.Key[:], secret.Host, 2*time.Minute)
	require.ErrorIs(t, err, fake.ErrBadDigest)
}
