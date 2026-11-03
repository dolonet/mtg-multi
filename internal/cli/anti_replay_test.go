package cli

import (
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseAntiReplayConfig(t *testing.T, section string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
` + section))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	return conf
}

func TestMakeAntiReplayCache(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		cache, fakeTLS := makeAntiReplayCache(parseAntiReplayConfig(t, ""), time.Minute)

		assert.Equal(t, antireplay.NewNoop(), cache)
		assert.Nil(t, fakeTLS)
	})

	t.Run("bloom", func(t *testing.T) {
		cache, fakeTLS := makeAntiReplayCache(parseAntiReplayConfig(t, `
[defense.anti-replay]
enabled = true
mode = "bloom"
`), time.Minute)

		assert.NotEqual(t, antireplay.NewNoop(), cache)
		assert.Nil(t, fakeTLS)
	})

	t.Run("exact", func(t *testing.T) {
		cache, fakeTLS := makeAntiReplayCache(parseAntiReplayConfig(t, `
[defense.anti-replay]
enabled = true
exact-max-size = "8mib"
`), time.Minute)

		assert.NotEqual(t, antireplay.NewNoop(), cache, "dd handshakes keep the bloom filter")

		exact, ok := fakeTLS.(*antireplay.Exact)
		require.True(t, ok)
		assert.Equal(t, 121*time.Second, exact.ReplayTTL())
		assert.Equal(t, 8*1024*1024/antireplay.ExactEntrySize/64*64, exact.Capacity())
	})

	t.Run("exact with the default window", func(t *testing.T) {
		conf := parseAntiReplayConfig(t, `
[defense.anti-replay]
enabled = true
`)
		_, fakeTLS := makeAntiReplayCache(conf, conf.GetTolerateTimeSkewness())

		exact, ok := fakeTLS.(*antireplay.Exact)
		require.True(t, ok)
		assert.Equal(t, 241*time.Second, exact.ReplayTTL())
		assert.Equal(t, antireplay.DefaultExactMaxSize/antireplay.ExactEntrySize/64*64, exact.Capacity())
	})
}
