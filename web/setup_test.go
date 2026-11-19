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

// A user served under an extra FakeTLS domain while old links still carry the
// previous one is listed twice: "alice" and "alice~sni1" with identical key
// bytes. For WEB they are one user (the capability depends only on the key and
// the vhost), so the alias is skipped and the profile stays under "alice"
// instead of the whole mode refusing to start.
func TestBuildProfilesSkipsAliasWithSameKey(t *testing.T) {
	shared := []byte("0123456789abcdef")
	other := []byte("fedcba9876543210")

	profiles, err := web.BuildProfiles(map[string][]byte{
		"alice~sni1": shared,
		"alice":      shared,
		"bob":        other,
	}, setupHost, web.SecretModeDD)
	require.NoError(t, err)
	require.Len(t, profiles, 2)

	users := []string{profiles[0].User, profiles[1].User}
	assert.ElementsMatch(t, []string{"alice", "bob"}, users)

	table, err := web.NewProfileTable(profiles)
	require.NoError(t, err)
	assert.Equal(t, 2, table.Len())
}

// Only a real alias is skipped: "<user>~..." with a different key is its own
// user, and so is a "~" name without its base user in the config.
func TestBuildProfilesKeepsNonAliases(t *testing.T) {
	profiles, err := web.BuildProfiles(map[string][]byte{
		"alice":      []byte("0123456789abcdef"),
		"alice~sni1": []byte("fedcba9876543210"),
		"carol~sni1": []byte("aaaaaaaaaaaaaaaa"),
	}, setupHost, web.SecretModeDD)
	require.NoError(t, err)

	users := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		users = append(users, profile.User)
	}

	assert.ElementsMatch(t, []string{"alice", "alice~sni1", "carol~sni1"}, users)
}

// Two unrelated names with one key are still indistinguishable twins: rejected.
func TestSetupStillRejectsTwinsWithSameKey(t *testing.T) {
	shared := []byte("0123456789abcdef")

	_, _, err := web.Setup(web.Settings{
		BindTo:   "127.0.0.1:0",
		Host:     setupHost,
		DecoyDir: t.TempDir(),
	}, map[string][]byte{"alice": shared, "twin": shared}, func(*web.Stream) {})
	require.Error(t, err)
}

// Setup with aliases sharing one key starts the WEB mode instead of failing.
func TestSetupAcceptsSharedSecretAliases(t *testing.T) {
	shared := []byte("0123456789abcdef")

	server, _, err := web.Setup(web.Settings{
		BindTo:   "127.0.0.1:0",
		Host:     setupHost,
		DecoyDir: t.TempDir(),
	}, map[string][]byte{"alice": shared, "alice~sni1": shared}, func(*web.Stream) {})
	require.NoError(t, err)
	require.NotNil(t, server)
}
