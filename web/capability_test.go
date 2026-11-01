package web_test

import (
	"encoding/hex"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors taken from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3; see
// web/LICENSE.telemt. They come from config/load/runtime_web.rs
// (later config/load/runtime_web/tests.rs), where the WEB server side was
// implemented first.
//
// They prove that our Go code computes exactly the value Telegram Desktop
// computes: if we diverged by a single byte, the client would just get the
// decoy instead of the proxy, and debugging that from a "does not connect"
// symptom is very hard.
func TestDeriveCapabilityReferenceVectors(t *testing.T) {
	secret, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)

	t.Run("plain", func(t *testing.T) {
		capability, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModePlain), "proxy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk", web.EncodeCapability(capability))
	})

	t.Run("dd", func(t *testing.T) {
		capability, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModeDD), "proxy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA", web.EncodeCapability(capability))
	})
}

func TestClientSecretDDPrefix(t *testing.T) {
	secret := []byte{0x01, 0x02}

	assert.Equal(t, []byte{0xdd, 0x01, 0x02}, web.ClientSecret(secret, web.SecretModeDD))
	assert.Equal(t, []byte{0x01, 0x02}, web.ClientSecret(secret, web.SecretModePlain))
}

// The same secret yields different values on different hosts: a leaked link
// cannot be moved to another of our domains.
func TestDeriveCapabilityDependsOnHost(t *testing.T) {
	secret := web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD)

	first, err := web.DeriveCapability(secret, "proxy.example.com")
	require.NoError(t, err)

	second, err := web.DeriveCapability(secret, "proxy2.example.com")
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

func TestDeriveCapabilityRejectsEmptySecret(t *testing.T) {
	_, err := web.DeriveCapability(nil, "proxy.example.com")
	assert.ErrorIs(t, err, web.ErrEmptySecret)
}

func TestParseBridgeQuery(t *testing.T) {
	secret := web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD)
	capability, err := web.DeriveCapability(secret, "proxy.example.com")
	require.NoError(t, err)

	encoded := web.EncodeCapability(capability)

	t.Run("canonical query is accepted", func(t *testing.T) {
		parsed, ok := web.ParseBridgeQuery("bridge=" + encoded)
		require.True(t, ok)
		assert.Equal(t, capability, parsed)
	})

	// Anything that is not the exact canonical form is not our client. Such
	// requests must go to the decoy, so a rejection matters here, not an error.
	for name, query := range map[string]string{
		"empty string":            "",
		"no prefix":               encoded,
		"foreign parameter":       "b=" + encoded,
		"extra parameter":         "bridge=" + encoded + "&x=1",
		"short value":             "bridge=" + encoded[:42],
		"long value":              "bridge=" + encoded + "A",
		"base64 padding":          "bridge=" + encoded[:40] + "===",
		"invalid characters":      "bridge=" + encoded[:40] + "!!!",
		"parameter without value": "bridge=",
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := web.ParseBridgeQuery(query)
			assert.False(t, ok)
		})
	}
}

func TestProfileTableMatch(t *testing.T) {
	const host = "proxy.example.com"

	makeProfile := func(user, secret string) web.Profile {
		capability, err := web.DeriveCapability(web.ClientSecret([]byte(secret), web.SecretModeDD), host)
		require.NoError(t, err)

		return web.Profile{User: user, Capability: capability, SecretMode: web.SecretModeDD}
	}

	petya := makeProfile("petya_1", "0123456789abcdef")
	vasya := makeProfile("vasya_2", "fedcba9876543210")

	table, err := web.NewProfileTable([]web.Profile{petya, vasya})
	require.NoError(t, err)
	assert.Equal(t, 2, table.Len())

	t.Run("finds the right user", func(t *testing.T) {
		profile, ok := table.Match(vasya.Capability)
		require.True(t, ok)
		assert.Equal(t, "vasya_2", profile.User)
	})

	t.Run("unknown user is rejected", func(t *testing.T) {
		alien := makeProfile("alien_3", "aaaaaaaaaaaaaaaa")
		_, ok := table.Match(alien.Capability)
		assert.False(t, ok)
	})
}

// The same capability for two users means the same secret: their traffic
// would be indistinguishable and one user's stats would go to the other. Such
// a configuration is rejected at startup instead of being found later from
// user complaints.
func TestProfileTableRejectsDuplicateCapability(t *testing.T) {
	capability, err := web.DeriveCapability(web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD), "web3")
	require.NoError(t, err)

	_, err = web.NewProfileTable([]web.Profile{
		{User: "petya_1", Capability: capability},
		{User: "vasya_2", Capability: capability},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "petya_1")
	assert.Contains(t, err.Error(), "vasya_2")
}
