package mtglib

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClock is a settable clock for the limits.
type testClock struct {
	now atomic.Pointer[time.Time]
}

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.set(t)

	return c
}

func (c *testClock) set(t time.Time) { c.now.Store(&t) }

func (c *testClock) Now() time.Time { return *c.now.Load() }

// newLimitsTestProxy is newUpdateTestProxy with limits and a test clock.
func newLimitsTestProxy(
	t *testing.T,
	clock *testClock,
	secrets map[string]Secret,
	limits map[string]SecretLimits,
) *Proxy {
	t.Helper()

	stats := NewProxyStats()
	stats.now = clock.Now

	set, err := newSecretSetWithLimits(secrets, limits)
	require.NoError(t, err)

	for _, name := range set.names {
		stats.PreRegister(name)
	}

	stats.setLimits(set.limits)

	p := &Proxy{
		stats:    stats,
		sessions: newSessionRegistry(),
		logger:   NoopLogger{},
	}
	p.secretSet.Store(set)

	return p
}

// addTraffic counts traffic of a user the way countingConn does.
func addTraffic(p *Proxy, name string, in, out int64) {
	st := p.stats.lookup(name)
	st.bytesIn.Add(in)
	st.bytesOut.Add(out)
}

func readUser(t *testing.T, stats *ProxyStats, name string) map[string]any {
	t.Helper()

	var resp struct {
		Users map[string]map[string]any `json:"users"`
	}
	require.NoError(t, json.Unmarshal(readStats(t, stats), &resp))

	user, ok := resp.Users[name]
	require.True(t, ok, "user %q is missing in /stats", name)

	return user
}

func TestParseQuotaReset(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]QuotaReset{
		"":          QuotaResetNone,
		"none":      QuotaResetNone,
		"daily":     QuotaResetDaily,
		" Weekly ":  QuotaResetWeekly,
		"MONTHLY":   QuotaResetMonthly,
		"monthly\t": QuotaResetMonthly,
	} {
		got, err := ParseQuotaReset(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
		assert.Equal(t, want, mustParseQuotaReset(t, got.String()))
	}

	for _, value := range []string{"yearly", "hourly", "1d"} {
		_, err := ParseQuotaReset(value)
		assert.Error(t, err, value)
	}
}

func mustParseQuotaReset(t *testing.T, value string) QuotaReset {
	t.Helper()

	reset, err := ParseQuotaReset(value)
	require.NoError(t, err)

	return reset
}

func TestQuotaResetPeriods(t *testing.T) {
	t.Parallel()

	utc := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)

		return v
	}

	testData := []struct {
		reset     QuotaReset
		now       string
		start     string
		nextReset string
	}{
		{QuotaResetDaily, "2026-11-03T00:00:00Z", "2026-11-03T00:00:00Z", "2026-11-04T00:00:00Z"},
		{QuotaResetDaily, "2026-11-03T23:59:59Z", "2026-11-03T00:00:00Z", "2026-11-04T00:00:00Z"},
		// 01:30 in Moscow is still the previous day in UTC.
		{QuotaResetDaily, "2026-11-04T01:30:00+03:00", "2026-11-03T00:00:00Z", "2026-11-04T00:00:00Z"},
		{QuotaResetDaily, "2026-12-31T12:00:00Z", "2026-12-31T00:00:00Z", "2027-01-01T00:00:00Z"},
		// 2026-11-03 is a Tuesday, 2026-11-08 a Sunday, 2026-11-09 a Monday.
		{QuotaResetWeekly, "2026-11-03T10:00:00Z", "2026-11-02T00:00:00Z", "2026-11-09T00:00:00Z"},
		{QuotaResetWeekly, "2026-11-08T23:59:59Z", "2026-11-02T00:00:00Z", "2026-11-09T00:00:00Z"},
		{QuotaResetWeekly, "2026-11-09T00:00:00Z", "2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z"},
		{QuotaResetWeekly, "2026-12-30T00:00:00Z", "2026-12-28T00:00:00Z", "2027-01-04T00:00:00Z"},
		{QuotaResetMonthly, "2026-11-30T23:59:59Z", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"},
		{QuotaResetMonthly, "2026-12-01T01:00:00+03:00", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"},
		{QuotaResetMonthly, "2026-12-15T00:00:00Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"},
	}

	for _, tc := range testData {
		now := utc(tc.now)
		assert.Equal(t, utc(tc.start), tc.reset.periodStart(now), "%s %s", tc.reset, tc.now)
		assert.Equal(t, utc(tc.nextReset), tc.reset.nextReset(now), "%s %s", tc.reset, tc.now)
	}

	assert.True(t, QuotaResetNone.periodStart(utc(testData[0].now)).IsZero())
	assert.True(t, QuotaResetNone.nextReset(utc(testData[0].now)).IsZero())
}

func TestSecretLimitsValidate(t *testing.T) {
	t.Parallel()

	require.NoError(t, SecretLimits{}.Validate())
	require.NoError(t, SecretLimits{QuotaBytes: 1, QuotaReset: QuotaResetDaily}.Validate())
	assert.Error(t, SecretLimits{QuotaBytes: -1}.Validate())
	assert.Error(t, SecretLimits{QuotaReset: QuotaResetMonthly}.Validate())
	assert.Error(t, SecretLimits{QuotaBytes: 1, QuotaReset: QuotaReset(42)}.Validate())

	assert.True(t, SecretLimits{}.IsZero())
	assert.False(t, SecretLimits{Disabled: true}.IsZero())
}

func TestNewSecretSetWithLimits(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{"alice": GenerateSecret("example.com"), "bob": GenerateSecret("example.com")}

	set, err := newSecretSetWithLimits(secrets, map[string]SecretLimits{"alice": {Disabled: true}, "bob": {}})
	require.NoError(t, err)
	assert.Equal(t, map[string]SecretLimits{"alice": {Disabled: true}}, set.limits)

	set, err = newSecretSetWithLimits(secrets, nil)
	require.NoError(t, err)
	assert.Nil(t, set.limits)

	_, err = newSecretSetWithLimits(secrets, map[string]SecretLimits{"ghost": {Disabled: true}})
	assert.ErrorContains(t, err, "unknown secret")

	_, err = newSecretSetWithLimits(secrets, map[string]SecretLimits{"alice": {QuotaBytes: -1}})
	assert.ErrorContains(t, err, "invalid limits")
}

// Disabled, expired and over-quota secrets are rejected; the others are not
// affected by them.
func TestLimitDenial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	secrets := map[string]Secret{}

	for _, name := range []string{"free", "disabled", "expired", "valid", "full", "spare"} {
		secrets[name] = GenerateSecret("example.com")
	}

	p := newLimitsTestProxy(t, clock, secrets, map[string]SecretLimits{
		"disabled": {Disabled: true},
		"expired":  {ExpiresAt: now},
		"valid":    {ExpiresAt: now.Add(time.Second)},
		"full":     {QuotaBytes: 100},
		"spare":    {QuotaBytes: 100},
	})

	addTraffic(p, "full", 60, 40)
	addTraffic(p, "spare", 60, 39)
	addTraffic(p, "free", 1<<40, 1<<40)

	set := p.secretSet.Load()
	want := map[string]LimitState{
		"free":     LimitOK,
		"disabled": LimitDisabled,
		"expired":  LimitExpired,
		"valid":    LimitOK,
		"full":     LimitOverQuota,
		"spare":    LimitOK,
	}

	for name, state := range want {
		assert.Equal(t, state, p.limitDenial(set, name), name)
	}

	// A disabled secret reports "disabled" even when it has also expired.
	p2 := newLimitsTestProxy(t, clock, map[string]Secret{"a": secrets["free"]},
		map[string]SecretLimits{"a": {Disabled: true, ExpiresAt: now.Add(-time.Hour)}})
	assert.Equal(t, LimitDisabled, p2.limitDenial(p2.secretSet.Load(), "a"))
}

// A session of a rejected secret is not registered, even if the handshake
// has passed: the limits may change in between.
func TestTrackSessionRejectsLimitedSecret(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": alice, "bob": bob},
		map[string]SecretLimits{"alice": {Disabled: true}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream := &streamContext{ctx: ctx, ctxCancel: cancel, secretName: "alice", matchedSecret: alice}
	assert.False(t, p.trackSession(stream))
	assert.Empty(t, p.sessions.sessions["alice"])
	assert.Equal(t, int64(0), p.stats.lookup("alice").connections.Load())

	authenticatedSession(t, p, "bob", bob)
}

// A reload that disables a user closes its live sessions; other users keep
// theirs.
func TestUpdateSecretsWithLimitsClosesRejectedSessions(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	secrets := map[string]Secret{"alice": alice, "bob": bob}
	p := newLimitsTestProxy(t, clock, secrets, nil)

	aliceSession := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)

	update, err := p.UpdateSecretsWithLimits(secrets, map[string]SecretLimits{"alice": {Disabled: true}})
	require.NoError(t, err)

	assert.Equal(t, 1, update.LimitedSessions)
	assert.Equal(t, 0, update.ClosedSessions)
	assert.True(t, isClosed(aliceSession))
	assert.False(t, isClosed(bobSession))

	// A new session of alice is rejected, and enabling her again lets it in.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	assert.False(t, p.trackSession(&streamContext{ctx: ctx, ctxCancel: cancel, secretName: "alice", matchedSecret: alice}))

	update, err = p.UpdateSecretsWithLimits(secrets, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, update.LimitedSessions)

	authenticatedSession(t, p, "alice", alice)
	assert.False(t, isClosed(bobSession))
}

// The old UpdateSecrets keeps the limits of the users that stay.
func TestUpdateSecretsKeepsLimits(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": alice, "bob": bob},
		map[string]SecretLimits{"alice": {Disabled: true}, "bob": {QuotaBytes: 10}})

	_, err := p.UpdateSecrets(map[string]Secret{"alice": alice, "carol": GenerateSecret("example.com")})
	require.NoError(t, err)

	assert.Equal(t, map[string]SecretLimits{"alice": {Disabled: true}}, p.secretSet.Load().limits)
}

// A set with broken limits is refused as a whole, and the current one stays.
func TestUpdateSecretsWithLimitsRejectsInvalid(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": alice}, nil)
	before := p.secretSet.Load()

	_, err := p.UpdateSecretsWithLimits(map[string]Secret{"alice": alice}, map[string]SecretLimits{"ghost": {Disabled: true}})
	require.Error(t, err)

	_, err = p.UpdateSecretsWithLimits(map[string]Secret{"alice": alice}, map[string]SecretLimits{"alice": {QuotaReset: QuotaResetDaily}})
	require.Error(t, err)

	assert.Same(t, before, p.secretSet.Load())
}

// Live sessions are cut by the periodic check when the secret expires or goes
// over its quota; secrets within their limits keep their sessions.
func TestEnforceLimits(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	secrets := map[string]Secret{
		"expiring": GenerateSecret("example.com"),
		"metered":  GenerateSecret("example.com"),
		"free":     GenerateSecret("example.com"),
	}
	p := newLimitsTestProxy(t, clock, secrets, map[string]SecretLimits{
		"expiring": {ExpiresAt: now.Add(time.Hour)},
		"metered":  {QuotaBytes: 1000, QuotaReset: QuotaResetDaily},
	})

	expiring := authenticatedSession(t, p, "expiring", secrets["expiring"])
	metered := authenticatedSession(t, p, "metered", secrets["metered"])
	free := authenticatedSession(t, p, "free", secrets["free"])

	addTraffic(p, "metered", 500, 499)
	assert.Equal(t, 0, p.enforceLimits())

	addTraffic(p, "metered", 0, 1)
	assert.Equal(t, 1, p.enforceLimits())
	assert.True(t, isClosed(metered))
	assert.False(t, isClosed(expiring))

	clock.set(now.Add(time.Hour))
	assert.Equal(t, 1, p.enforceLimits())
	assert.True(t, isClosed(expiring))
	assert.False(t, isClosed(free))

	// The next day the quota is there again.
	finish(p, metered)
	clock.set(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, LimitOK, p.limitDenial(p.secretSet.Load(), "metered"))
	authenticatedSession(t, p, "metered", secrets["metered"])
}

// The used traffic starts from zero at the UTC boundary of the period, and
// traffic of the previous period is not counted in the new one.
func TestQuotaRollsOverAtUTCBoundary(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 30, 23, 59, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": alice},
		map[string]SecretLimits{"alice": {QuotaBytes: 100, QuotaReset: QuotaResetMonthly}})
	set := p.secretSet.Load()
	lim := set.limits["alice"]
	st := p.stats.lookup("alice")

	addTraffic(p, "alice", 70, 30)
	assert.Equal(t, int64(100), st.quotaUsed(lim, clock.Now()))
	assert.Equal(t, LimitOverQuota, p.limitDenial(set, "alice"))

	// 23:59:59.999 is still November.
	clock.set(time.Date(2026, 11, 30, 23, 59, 59, 999999999, time.UTC))
	assert.Equal(t, LimitOverQuota, p.limitDenial(set, "alice"))

	clock.set(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, LimitOK, p.limitDenial(set, "alice"))
	assert.Equal(t, int64(0), st.quotaUsed(lim, clock.Now()))

	addTraffic(p, "alice", 5, 5)
	assert.Equal(t, int64(10), st.quotaUsed(lim, clock.Now()))

	// The lifetime counters in /stats are not reset.
	user := readUser(t, p.stats, "alice")
	assert.InDelta(t, 75, user["bytes_in"], 0)
	assert.InDelta(t, 35, user["bytes_out"], 0)
	assert.InDelta(t, 10, user["quota_used"], 0)
}

// A quota without a reset period is never replenished.
func TestQuotaWithoutResetIsNotReplenished(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": GenerateSecret("example.com")},
		map[string]SecretLimits{"alice": {QuotaBytes: 10}})

	addTraffic(p, "alice", 10, 0)
	clock.set(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, LimitOverQuota, p.limitDenial(p.secretSet.Load(), "alice"))
}

// Reload semantics of the quota usage: kept for an unchanged user and for a
// changed quota or reset period; a quota that appears starts from zero; a
// removed quota and a removed user forget it.
func TestQuotaUsageAcrossReload(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	secrets := map[string]Secret{"alice": alice, "bob": bob}
	monthly := map[string]SecretLimits{
		"alice": {QuotaBytes: 1000, QuotaReset: QuotaResetMonthly},
		"bob":   {QuotaBytes: 1000},
	}
	p := newLimitsTestProxy(t, clock, secrets, monthly)

	used := func(name string) any {
		return readUser(t, p.stats, name)["quota_used"]
	}

	addTraffic(p, "alice", 100, 0)
	addTraffic(p, "bob", 200, 0)

	// Unchanged users keep their usage.
	_, err := p.UpdateSecretsWithLimits(secrets, monthly)
	require.NoError(t, err)
	assert.InDelta(t, 100, used("alice"), 0)
	assert.InDelta(t, 200, used("bob"), 0)

	// Another quota and another period keep it too.
	_, err = p.UpdateSecretsWithLimits(secrets, map[string]SecretLimits{
		"alice": {QuotaBytes: 5000, QuotaReset: QuotaResetDaily},
		"bob":   {QuotaBytes: 1000},
	})
	require.NoError(t, err)
	assert.InDelta(t, 100, used("alice"), 0)

	// ... until the next boundary of the new period.
	clock.set(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	assert.InDelta(t, 0, used("alice"), 0)

	// A removed quota forgets the usage; a quota that appears starts from
	// zero, without the traffic that came before it.
	_, err = p.UpdateSecretsWithLimits(secrets, map[string]SecretLimits{"alice": {QuotaBytes: 5000}})
	require.NoError(t, err)
	assert.Nil(t, used("bob"))

	addTraffic(p, "bob", 50, 0)

	_, err = p.UpdateSecretsWithLimits(secrets, monthly)
	require.NoError(t, err)
	assert.InDelta(t, 0, used("bob"), 0)

	addTraffic(p, "bob", 7, 0)
	assert.InDelta(t, 7, used("bob"), 0)

	// A removed and re-added user starts from zero.
	_, err = p.UpdateSecretsWithLimits(map[string]Secret{"alice": alice}, map[string]SecretLimits{"alice": monthly["alice"]})
	require.NoError(t, err)
	_, err = p.UpdateSecretsWithLimits(secrets, monthly)
	require.NoError(t, err)
	assert.InDelta(t, 0, used("bob"), 0)
}

// /stats: users without limits get only state and enabled; the existing
// fields are unchanged.
func TestStatsLimitFields(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	expires := time.Date(2026, 12, 31, 21, 0, 0, 0, time.UTC)
	p := newLimitsTestProxy(t, clock, map[string]Secret{
		"alice": GenerateSecret("example.com"),
		"bob":   GenerateSecret("example.com"),
		"carol": GenerateSecret("example.com"),
		"dave":  GenerateSecret("example.com"),
	}, map[string]SecretLimits{
		"alice": {QuotaBytes: 1000, QuotaReset: QuotaResetMonthly, ExpiresAt: expires},
		"carol": {Disabled: true},
		"dave":  {QuotaBytes: 10, ExpiresAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)},
	})

	addTraffic(p, "alice", 300, 200)
	addTraffic(p, "dave", 20, 0)

	var resp struct {
		Users map[string]json.RawMessage `json:"users"`
	}
	require.NoError(t, json.Unmarshal(readStats(t, p.stats), &resp))

	assert.JSONEq(t, `{
		"connections": 0, "bytes_in": 300, "bytes_out": 200, "last_seen": null, "active_ips": [],
		"state": "ok", "enabled": true,
		"quota_bytes": 1000, "quota_used": 500, "quota_reset": "monthly",
		"quota_resets_at": "2026-12-01T00:00:00Z",
		"expires_at": "2026-12-31T21:00:00Z"
	}`, string(resp.Users["alice"]))

	assert.JSONEq(t, `{
		"connections": 0, "bytes_in": 0, "bytes_out": 0, "last_seen": null, "active_ips": [],
		"state": "ok", "enabled": true
	}`, string(resp.Users["bob"]))

	assert.JSONEq(t, `{
		"connections": 0, "bytes_in": 0, "bytes_out": 0, "last_seen": null, "active_ips": [],
		"state": "disabled", "enabled": false
	}`, string(resp.Users["carol"]))

	// Expiry wins over the quota; a quota without reset has no reset time.
	assert.JSONEq(t, `{
		"connections": 0, "bytes_in": 20, "bytes_out": 0, "last_seen": null, "active_ips": [],
		"state": "expired", "enabled": true,
		"quota_bytes": 10, "quota_used": 20, "quota_reset": "none",
		"expires_at": "2026-11-01T00:00:00Z"
	}`, string(resp.Users["dave"]))

	// Over quota.
	addTraffic(p, "alice", 0, 500)
	assert.Equal(t, "over_quota", readUser(t, p.stats, "alice")["state"])
}

// The usage state file restores the quota usage of users that still have a
// quota; others start from zero.
func TestUsageStateFileRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "usage.json")
	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	secrets := map[string]Secret{
		"alice": GenerateSecret("example.com"),
		"bob":   GenerateSecret("example.com"),
		"carol": GenerateSecret("example.com"),
		"free":  GenerateSecret("example.com"),
	}
	limits := map[string]SecretLimits{
		"alice": {QuotaBytes: 1000, QuotaReset: QuotaResetMonthly},
		"bob":   {QuotaBytes: 1000, QuotaReset: QuotaResetDaily},
		"carol": {QuotaBytes: 1000},
	}
	p := newLimitsTestProxy(t, clock, secrets, limits)

	addTraffic(p, "alice", 100, 23)
	addTraffic(p, "bob", 50, 0)
	addTraffic(p, "carol", 9, 0)
	addTraffic(p, "free", 1000, 0)

	require.NoError(t, p.stats.FlushUsage(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.JSONEq(t, `{"version": 1, "users": {
		"alice": {"quota_used": 123, "quota_reset": "monthly", "period_start": "2026-11-01T00:00:00Z"},
		"bob":   {"quota_used": 50, "quota_reset": "daily", "period_start": "2026-11-03T00:00:00Z"},
		"carol": {"quota_used": 9, "quota_reset": "none"}
	}}`, string(data))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A restart the next day: alice keeps her month, bob has a new day, carol
	// lost her quota in the new config, a new user dave has nothing.
	clock.set(time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC))

	secrets["dave"] = GenerateSecret("example.com")
	newLimits := map[string]SecretLimits{
		"alice": limits["alice"],
		"bob":   limits["bob"],
		"dave":  {QuotaBytes: 1000},
	}

	restarted := NewProxyStats()
	restarted.now = clock.Now

	set, err := newSecretSetWithLimits(secrets, newLimits)
	require.NoError(t, err)

	for _, name := range set.names {
		restarted.PreRegister(name)
	}

	require.NoError(t, restarted.LoadUsage(path, set.limits))
	restarted.setLimits(set.limits)

	assert.InDelta(t, 123, readUser(t, restarted, "alice")["quota_used"], 0)
	assert.InDelta(t, 0, readUser(t, restarted, "bob")["quota_used"], 0)
	assert.Nil(t, readUser(t, restarted, "carol")["quota_used"])
	assert.InDelta(t, 0, readUser(t, restarted, "dave")["quota_used"], 0)

	// The lifetime counters still start from zero after a restart.
	assert.InDelta(t, 0, readUser(t, restarted, "alice")["bytes_in"], 0)

	restarted.lookup("alice").bytesOut.Add(877)
	assert.Equal(t, "over_quota", readUser(t, restarted, "alice")["state"])
}

func TestLoadUsageErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stats := NewProxyStats()
	stats.PreRegister("alice")

	limits := map[string]SecretLimits{"alice": {QuotaBytes: 10}}

	require.NoError(t, stats.LoadUsage(filepath.Join(dir, "missing.json"), limits))

	broken := filepath.Join(dir, "broken.json")
	require.NoError(t, os.WriteFile(broken, []byte(`{"version": 1, "users": `), 0o600))
	assert.Error(t, stats.LoadUsage(broken, limits))

	future := filepath.Join(dir, "future.json")
	require.NoError(t, os.WriteFile(future, []byte(`{"version": 2, "users": {}}`), 0o600))
	assert.ErrorContains(t, stats.LoadUsage(future, limits), "version")

	// Records that make no sense are skipped, not trusted.
	odd := filepath.Join(dir, "odd.json")
	require.NoError(t, os.WriteFile(odd, []byte(
		`{"version": 1, "users": {"alice": {"quota_used": -5, "quota_reset": "none"}}}`), 0o600))
	require.NoError(t, stats.LoadUsage(odd, limits))
	stats.setLimits(limits)
	assert.Equal(t, LimitOK, limitState(limits["alice"], stats.lookup("alice"), time.Now()))
}

// A secured (dd) client of a rejected secret fails the handshake before the
// replay buffer is committed, so ServeConn fronts it like a wrong secret.
func TestDoSecuredHandshakeRejectsLimitedSecret(t *testing.T) {
	t.Parallel()

	secret := GenerateSecret("example.com")
	clock := newTestClock(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	stats := NewProxyStats()
	stats.now = clock.Now
	stats.PreRegister("main")

	proxy := &Proxy{
		ctx:                 context.Background(),
		antiReplayCache:     &mapAntiReplayCache{seen: map[string]bool{}},
		eventStream:         &countingEventStream{},
		logger:              NoopLogger{},
		securedFrameTimeout: time.Second,
		stats:               stats,
	}

	set, err := newSecretSetWithLimits(map[string]Secret{"main": secret}, map[string]SecretLimits{"main": {Disabled: true}})
	require.NoError(t, err)

	rec := &recordingConn{}
	_, err = (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(rec, 2)
	require.NoError(t, err)

	frame := rec.buf.Bytes()
	stream := newStreamContext(context.Background(), NoopLogger{}, securedTestConn(t, frame))
	rewind := newConnRewind(stream.clientConn)

	err = proxy.doSecuredHandshake(stream, rewind, set)
	require.ErrorContains(t, err, "disabled")
	assert.False(t, stream.secured)
	assert.Equal(t, frame, rewind.buf.Bytes(), "the frame must stay recorded for the fronting replay")
}

// The periodic loop closes sessions of a secret that expires and writes the
// usage state file.
func TestLimitsLoop(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	alice := GenerateSecret("example.com")
	p := newLimitsTestProxy(t, clock, map[string]Secret{"alice": alice},
		map[string]SecretLimits{"alice": {ExpiresAt: now.Add(time.Minute), QuotaBytes: 1 << 20}})
	p.usageStateFile = filepath.Join(t.TempDir(), "usage.json")

	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx

	p.startLimitsLoop(10 * time.Millisecond)

	session := authenticatedSession(t, p, "alice", alice)

	assert.Eventually(t, func() bool {
		_, err := os.Stat(p.usageStateFile)

		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, isClosed(session))

	clock.set(now.Add(time.Minute))
	assert.Eventually(t, func() bool { return isClosed(session) }, 5*time.Second, 10*time.Millisecond)

	cancel()
	p.streamWaitGroup.Wait()
}

// Handshakes, reloads that flip the limits, periodic checks, traffic and
// /stats all at once, for the race detector.
func TestSecretLimitsConcurrent(t *testing.T) {
	t.Parallel()

	clock := newTestClock(time.Date(2026, 11, 3, 23, 59, 59, 0, time.UTC))
	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	secrets := map[string]Secret{"alice": alice, "bob": bob}
	p := newLimitsTestProxy(t, clock, secrets, nil)
	path := filepath.Join(t.TempDir(), "usage.json")

	var wg sync.WaitGroup

	stop := make(chan struct{})
	loop := func(f func(i int)) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					f(i)
				}
			}
		}()
	}

	loop(func(i int) {
		limits := map[string]SecretLimits{"alice": {QuotaBytes: 1 << 20, QuotaReset: QuotaResetDaily}}
		if i%2 == 0 {
			limits["bob"] = SecretLimits{Disabled: true}
		}

		_, err := p.UpdateSecretsWithLimits(secrets, limits)
		assert.NoError(t, err)
	})
	loop(func(int) { p.enforceLimits() })
	loop(func(int) { readStats(t, p.stats) })
	loop(func(int) { assert.NoError(t, p.stats.FlushUsage(path)) })
	loop(func(i int) {
		clock.set(time.Date(2026, 11, 3, 23, 59, 59, 0, time.UTC).Add(time.Duration(i%3) * time.Second))
	})

	for _, name := range []string{"alice", "bob"} {
		loop(func(int) {
			ctx, cancel := context.WithCancel(context.Background())
			stream := &streamContext{ctx: ctx, ctxCancel: cancel, secretName: name, matchedSecret: secrets[name]}

			if p.trackSession(stream) {
				stream.userStats.bytesIn.Add(100)
				stream.userStats.bytesOut.Add(100)
				finish(p, stream)
			}

			cancel()
		})
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
