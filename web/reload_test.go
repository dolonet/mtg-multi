package web_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReloadServer builds a frontend the way Setup does, with a user table
// derived from secrets, and returns the profile of every user by name.
func newReloadServer(
	t *testing.T,
	handle func(*web.Stream),
	secrets map[string][]byte,
) (*web.Server, map[string]web.Profile) {
	t.Helper()

	srv, _ := newTestServer(t, handle, func(cfg *web.ServerConfig) {
		table, err := web.NewProfileTable(buildProfiles(t, secrets))
		require.NoError(t, err)

		cfg.VHosts = []web.VHost{{Host: testHost, Profiles: table, Decoy: stubDecoy{}, SecretMode: web.SecretModeDD}}
	})

	return srv, profilesByUser(t, secrets)
}

func buildProfiles(t *testing.T, secrets map[string][]byte) []web.Profile {
	t.Helper()

	profiles, err := web.BuildProfiles(secrets, testHost, web.SecretModeDD)
	require.NoError(t, err)

	return profiles
}

func profilesByUser(t *testing.T, secrets map[string][]byte) map[string]web.Profile {
	t.Helper()

	out := map[string]web.Profile{}
	for _, profile := range buildProfiles(t, secrets) {
		out[profile.User] = profile
	}

	return out
}

// openStream opens stream 1 in the session and returns the stream the
// handler received.
func openStream(t *testing.T, srv *web.Server, token string, streams <-chan *web.Stream) *web.Stream {
	t.Helper()

	require.Equal(t, http.StatusOK, do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))).Code)

	select {
	case stream := <-streams:
		return stream
	case <-time.After(2 * time.Second):
		t.Fatal("the stream was not handed to the proxy")
	}

	return nil
}

func sessionAlive(srv *web.Server, token string) bool {
	return do(srv, carrierRequest("/api/v1/down", token, nil)).Body.String() != decoyBody
}

func streamClosed(t *testing.T, stream *web.Stream) bool {
	t.Helper()

	require.NoError(t, stream.SetReadDeadline(time.Now().Add(200*time.Millisecond)))

	_, err := stream.Read(make([]byte, 1))

	return err != nil && !isTimeout(err)
}

func isTimeout(err error) bool {
	timeout, ok := err.(interface{ Timeout() bool }) //nolint: errorlint

	return ok && timeout.Timeout()
}

var (
	aliceKey = []byte("0123456789abcdef")
	bobKey   = []byte("fedcba9876543210")
	carolKey = []byte("abcdef0123456789")
)

// On a reload a removed user loses their WEB sessions (and the streams in
// them) and their bridge tokens, and their link no longer opens the bridge
// page. Other users keep their sessions, and a new user can connect at once,
// without a restart.
func TestUpdateSecretsClosesRemovedUser(t *testing.T) {
	streams := make(chan *web.Stream, 4)
	srv, users := newReloadServer(t, func(stream *web.Stream) { streams <- stream },
		map[string][]byte{"alice": aliceKey, "bob": bobKey})

	alice := openSession(t, srv, users["alice"])
	aliceStream := openStream(t, srv, alice, streams)
	bob := openSession(t, srv, users["bob"])
	bobStream := openStream(t, srv, bob, streams)
	bobPending := issueToken(t, srv, users["bob"])

	update, err := srv.PrepareSecrets(map[string][]byte{"alice": aliceKey, "carol": carolKey})
	require.NoError(t, err)

	result := update.Apply()
	assert.Equal(t, web.UpdateResult{ClosedSessions: 1, DroppedPending: 1}, result)

	assert.False(t, sessionAlive(srv, bob), "the removed user's session must be closed")
	assert.True(t, streamClosed(t, bobStream), "the removed user's stream must be closed")
	assert.Equal(t, decoyBody, hello(t, srv, bobPending), "the removed user's bridge token must be dropped")
	assert.Equal(t, decoyBody, do(srv, bridgeRequest(users["bob"])).Body.String(),
		"the removed user's link must get the decoy")

	assert.True(t, sessionAlive(srv, alice), "an unchanged user keeps the session")
	assert.False(t, streamClosed(t, aliceStream), "an unchanged user keeps the stream")
	assert.Equal(t, 1, srv.SessionCount())

	carol := profilesByUser(t, map[string][]byte{"carol": carolKey})["carol"]
	assert.True(t, sessionAlive(srv, openSession(t, srv, carol)), "a new user can connect without a restart")
}

// A user whose key has changed is closed too: the session was opened with a
// capability derived from the old key. The old link stops working, the new
// one works.
func TestUpdateSecretsClosesChangedUser(t *testing.T) {
	srv, users := newReloadServer(t, nil, map[string][]byte{"alice": aliceKey, "bob": bobKey})

	alice := openSession(t, srv, users["alice"])
	bob := openSession(t, srv, users["bob"])

	update, err := srv.PrepareSecrets(map[string][]byte{"alice": carolKey, "bob": bobKey})
	require.NoError(t, err)
	assert.Equal(t, 1, update.Apply().ClosedSessions)

	assert.False(t, sessionAlive(srv, alice))
	assert.True(t, sessionAlive(srv, bob))
	assert.Equal(t, decoyBody, do(srv, bridgeRequest(users["alice"])).Body.String())

	changed := profilesByUser(t, map[string][]byte{"alice": carolKey})["alice"]
	assert.True(t, sessionAlive(srv, openSession(t, srv, changed)))
}

// A set the frontend cannot take is refused before anything changes, so the
// caller keeps the current secrets everywhere.
func TestPrepareSecretsRefusesWithoutChanges(t *testing.T) {
	srv, users := newReloadServer(t, nil, map[string][]byte{"alice": aliceKey})
	alice := openSession(t, srv, users["alice"])

	_, err := srv.PrepareSecrets(map[string][]byte{})
	require.ErrorIs(t, err, web.ErrNoSecrets)

	// Two users with the same key are indistinguishable on the WEB side.
	_, err = srv.PrepareSecrets(map[string][]byte{"alice": aliceKey, "twin": aliceKey})
	require.Error(t, err)

	assert.True(t, sessionAlive(srv, alice))
	assert.NotEqual(t, decoyBody, do(srv, bridgeRequest(users["alice"])).Body.String())
}
