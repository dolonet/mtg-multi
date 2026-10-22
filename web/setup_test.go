package web_test

import (
	"path/filepath"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const setupHost = "proxy.example.com"

func TestSetup(t *testing.T) {
	secrets := map[string][]byte{"alice": []byte("0123456789abcdef")}

	t.Run("disabled without bind-to", func(t *testing.T) {
		srv, bind, err := web.Setup(web.Settings{Host: setupHost}, secrets, nil)
		require.NoError(t, err)
		assert.Nil(t, srv)
		assert.Empty(t, bind)
	})

	// The listener speaks plain HTTP: exposed, it would be a proxy without TLS
	// and without masking. TLS is terminated by a reverse proxy, so only
	// loopback is allowed.
	t.Run("cannot be exposed", func(t *testing.T) {
		_, _, err := web.Setup(web.Settings{BindTo: "0.0.0.0:18080", Host: setupHost}, secrets, nil)
		assert.ErrorIs(t, err, web.ErrPublicBind)
	})

	t.Run("requires a host", func(t *testing.T) {
		_, _, err := web.Setup(web.Settings{BindTo: "127.0.0.1:18080"}, secrets, nil)
		assert.ErrorIs(t, err, web.ErrNoHost)
	})

	t.Run("requires secrets", func(t *testing.T) {
		_, _, err := web.Setup(web.Settings{BindTo: "127.0.0.1:18080", Host: setupHost}, map[string][]byte{}, nil)
		assert.ErrorIs(t, err, web.ErrNoSecrets)
	})

	t.Run("builds with limits", func(t *testing.T) {
		srv, bind, err := web.Setup(web.Settings{
			BindTo:             "127.0.0.1:18080",
			Host:               setupHost,
			MaxSessions:        10,
			MaxPending:         20,
			MaxSessionsPerUser: 2,
			MaxPendingPerUser:  3,
		}, secrets, func(*web.Stream) {})
		require.NoError(t, err)
		require.NotNil(t, srv)

		t.Cleanup(srv.Close)
		assert.Equal(t, "127.0.0.1:18080", bind)
	})

	// A decoy directory that does not exist is a configuration error, not an
	// empty site discovered by the first visitor.
	t.Run("decoy directory must exist", func(t *testing.T) {
		_, _, err := web.Setup(web.Settings{
			BindTo:   "127.0.0.1:18080",
			Host:     setupHost,
			DecoyDir: filepath.Join(t.TempDir(), "missing"),
		}, secrets, func(*web.Stream) {})
		assert.Error(t, err)
	})
}

// A profile is derived from the same secret as regular MTProto: WEB is another
// transport for the same user, not a separate account.
func TestBuildProfilesUsesSameSecrets(t *testing.T) {
	secret := []byte("0123456789abcdef")

	profiles, err := web.BuildProfiles(map[string][]byte{"alice": secret}, setupHost, web.SecretModeDD)
	require.NoError(t, err)
	require.Len(t, profiles, 1)

	expected, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModeDD), setupHost)
	require.NoError(t, err)

	assert.Equal(t, "alice", profiles[0].User)
	assert.Equal(t, expected, profiles[0].Capability)
}
