package config_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretLimitsConfig is a config with users alice, bob and carol, followed by
// the given [secret-limits] tables.
func secretLimitsConfig(tables string) []byte {
	return fmt.Appendf(nil, `
bind-to = "127.0.0.1:443"
usage-state-file = "/var/lib/mtg/usage.json"

[secrets]
alice = "%s"
bob = "%s"
carol = "%s"

%s
`,
		mtglib.GenerateSecret("example.com").Hex(),
		mtglib.GenerateSecret("example.com").Hex(),
		mtglib.GenerateSecret("example.com").Hex(),
		tables,
	)
}

func TestSecretLimitsParse(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse(secretLimitsConfig(`
[secret-limits.alice]
quota = "10GB"
quota-reset = "monthly"
expires = "2026-12-31"
disabled = true

[secret-limits.bob]
quota = 1048576
expires = 2027-01-01T00:00:00+03:00

[secret-limits.carol]
quota = "500 MiB"
quota-reset = "Weekly"
expires = 2027-02-01
`))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Equal(t, "/var/lib/mtg/usage.json", conf.UsageStateFile)
	assert.Equal(t, map[string]mtglib.SecretLimits{
		"alice": {
			QuotaBytes: 10 << 30,
			QuotaReset: mtglib.QuotaResetMonthly,
			ExpiresAt:  time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
			Disabled:   true,
		},
		"bob": {
			QuotaBytes: 1048576,
			ExpiresAt:  time.Date(2026, 12, 31, 21, 0, 0, 0, time.UTC),
		},
		"carol": {
			QuotaBytes: 500 << 20,
			QuotaReset: mtglib.QuotaResetWeekly,
			ExpiresAt:  time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}, conf.GetSecretLimits())
}

func TestSecretLimitsRFC3339String(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse(secretLimitsConfig(`
[secret-limits.alice]
expires = "2027-01-01T00:00:00+03:00"
quota-reset = "none"
quota = "1kb"
`))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	lim := conf.GetSecretLimits()["alice"]
	assert.True(t, lim.ExpiresAt.Equal(time.Date(2026, 12, 31, 21, 0, 0, 0, time.UTC)))
	assert.Equal(t, int64(1024), lim.QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetNone, lim.QuotaReset)
}

// Without [secret-limits] nothing changes: no limits at all.
func TestSecretLimitsAbsent(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(fmt.Sprintf(`
bind-to = "127.0.0.1:443"

[secrets]
alice = "%s"
`, mtglib.GenerateSecret("example.com").Hex())))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Nil(t, conf.GetSecretLimits())
	assert.Empty(t, conf.UsageStateFile)
}

// The single "secret" is the user "default".
func TestSecretLimitsSingleSecret(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(fmt.Sprintf(`
bind-to = "127.0.0.1:443"
secret = "%s"

[secret-limits.default]
disabled = true
`, mtglib.GenerateSecret("example.com").Hex())))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Equal(t, map[string]mtglib.SecretLimits{"default": {Disabled: true}}, conf.GetSecretLimits())
}

func TestSecretLimitsParseErrors(t *testing.T) {
	t.Parallel()

	testData := map[string]struct {
		table string
		err   string
	}{
		"zero quota":           {`quota = "0"`, "secret-limits.alice.quota"},
		"zero quota number":    {`quota = 0`, "secret-limits.alice.quota"},
		"zero quota with unit": {`quota = "0GB"`, "secret-limits.alice.quota"},
		"negative quota":       {`quota = -5`, "secret-limits.alice.quota"},
		"negative size":        {`quota = "-1GB"`, "secret-limits.alice.quota"},
		"bad size":             {`quota = "lots"`, "secret-limits.alice.quota"},
		"bool quota":           {`quota = true`, "secret-limits.alice.quota"},
		"bad period":           {`quota = "1GB"` + "\n" + `quota-reset = "yearly"`, "secret-limits.alice.quota-reset"},
		"bad time":             {`expires = "tomorrow"`, "secret-limits.alice.expires"},
		"time without offset":  {`expires = "2026-12-31T00:00:00"`, "secret-limits.alice.expires"},
		"local datetime":       {`expires = 2026-12-31T00:00:00`, "secret-limits.alice.expires"},
		"number as time":       {`expires = 20261231`, "secret-limits.alice.expires"},
	}

	for name, tc := range testData {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Parse(secretLimitsConfig("[secret-limits.alice]\n" + tc.table))
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestSecretLimitsValidateErrors(t *testing.T) {
	t.Parallel()

	testData := map[string]struct {
		tables string
		err    string
	}{
		"unknown secret":            {"[secret-limits.ghost]\ndisabled = true", `unknown secret "ghost"`},
		"quota reset without quota": {"[secret-limits.alice]\nquota-reset = \"daily\"", "quota-reset needs a quota"},
	}

	for name, tc := range testData {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf, err := config.Parse(secretLimitsConfig(tc.tables))
			require.NoError(t, err)
			assert.ErrorContains(t, conf.Validate(), tc.err)
		})
	}
}

func TestTypeQuota(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]int64{
		"1":        1,
		"1048576":  1 << 20,
		"1kb":      1 << 10,
		"10GB":     10 << 30,
		"2 TiB":    2 << 40,
		" 500mb  ": 500 << 20,
	} {
		q := config.TypeQuota{}
		require.NoError(t, q.Set(value), value)
		assert.Equal(t, want, q.Get(0), value)
	}

	for _, value := range []string{"", "0", "-1", "0b", "-1kb", "1m", "abc"} {
		q := config.TypeQuota{}
		assert.Error(t, q.Set(value), value)
	}
}

func TestTypeExpiry(t *testing.T) {
	t.Parallel()

	e := config.TypeExpiry{}

	require.NoError(t, e.Set("2026-12-31"))
	assert.Equal(t, time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), e.Get(time.Time{}))
	assert.Equal(t, "2026-12-31T00:00:00Z", e.String())

	require.NoError(t, e.Set("2026-12-31T23:30:00-01:00"))
	assert.Equal(t, time.Date(2027, 1, 1, 0, 30, 0, 0, time.UTC), e.Get(time.Time{}))

	assert.Error(t, e.Set("31.12.2026"))
	assert.Error(t, e.Set(""))
}
