package mtglib

// The design of per-secret limits (data quota, expiry, disable switch, usage
// state file) is ported from mhsanaei/mtg-multi, commit 85569c5
// ("feat(mtglib): per-user data quota, expiry and enable/disable").

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultSecretLimitsCheckInterval is how often live sessions are checked
// against their secret limits (and the usage state file is written, if any).
// A session of a secret that has expired or gone over its quota is closed at
// the next check, so the quota can be overrun by at most this interval of
// traffic.
const DefaultSecretLimitsCheckInterval = 30 * time.Second

// QuotaReset defines when the used traffic of a secret quota starts from
// zero again. Periods are calendar periods in UTC.
type QuotaReset int

const (
	// QuotaResetNone makes the quota a single allowance that is never
	// replenished.
	QuotaResetNone QuotaReset = iota

	// QuotaResetDaily resets the quota every day at 00:00 UTC.
	QuotaResetDaily

	// QuotaResetWeekly resets the quota every Monday at 00:00 UTC.
	QuotaResetWeekly

	// QuotaResetMonthly resets the quota on the 1st of every month at
	// 00:00 UTC.
	QuotaResetMonthly
)

// ParseQuotaReset parses the config spelling of a reset period. An empty
// string means QuotaResetNone.
func ParseQuotaReset(value string) (QuotaReset, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none":
		return QuotaResetNone, nil
	case "daily":
		return QuotaResetDaily, nil
	case "weekly":
		return QuotaResetWeekly, nil
	case "monthly":
		return QuotaResetMonthly, nil
	}

	return QuotaResetNone, fmt.Errorf("unknown quota reset %q: must be none, daily, weekly or monthly", value)
}

// String returns the config spelling of the reset period.
func (q QuotaReset) String() string {
	switch q {
	case QuotaResetDaily:
		return "daily"
	case QuotaResetWeekly:
		return "weekly"
	case QuotaResetMonthly:
		return "monthly"
	default:
		return "none"
	}
}

// periodStart returns the start of the period that contains now. It is the
// zero time for QuotaResetNone: such a quota has a single period.
func (q QuotaReset) periodStart(now time.Time) time.Time {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	switch q {
	case QuotaResetDaily:
		return day
	case QuotaResetWeekly:
		// time.Weekday counts from Sunday; ISO weeks start on Monday.
		offset := (int(day.Weekday()) + 6) % 7 //nolint: mnd

		return day.AddDate(0, 0, -offset)
	case QuotaResetMonthly:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Time{}
	}
}

// nextReset returns when the period that contains now ends, or the zero time
// for QuotaResetNone.
func (q QuotaReset) nextReset(now time.Time) time.Time {
	start := q.periodStart(now)

	switch q {
	case QuotaResetDaily:
		return start.AddDate(0, 0, 1)
	case QuotaResetWeekly:
		return start.AddDate(0, 0, 7) //nolint: mnd
	case QuotaResetMonthly:
		return start.AddDate(0, 1, 0)
	default:
		return time.Time{}
	}
}

// SecretLimits are the optional limits of one named secret. The zero value
// imposes no limits: unlimited traffic, never expires, enabled.
type SecretLimits struct {
	// QuotaBytes is the traffic allowed in one quota period: bytes read from
	// and written to the client, the same bytes as bytes_in + bytes_out in
	// the stats. 0 means unlimited.
	QuotaBytes int64

	// QuotaReset is when the used traffic starts from zero again. It is
	// meaningful only with QuotaBytes.
	QuotaReset QuotaReset

	// ExpiresAt is the moment the secret stops working. The zero time means
	// it never expires.
	ExpiresAt time.Time

	// Disabled rejects the secret without removing it.
	Disabled bool
}

// IsZero reports whether the limits impose nothing.
func (l SecretLimits) IsZero() bool {
	return l.QuotaBytes == 0 && l.QuotaReset == QuotaResetNone && l.ExpiresAt.IsZero() && !l.Disabled
}

// Validate checks the limits for values a config can never mean.
func (l SecretLimits) Validate() error {
	if l.QuotaBytes < 0 {
		return fmt.Errorf("quota must be positive, got %d", l.QuotaBytes)
	}

	if l.QuotaReset < QuotaResetNone || l.QuotaReset > QuotaResetMonthly {
		return fmt.Errorf("unknown quota reset %d", l.QuotaReset)
	}

	if l.QuotaReset != QuotaResetNone && l.QuotaBytes == 0 {
		return fmt.Errorf("quota reset %s is set without a quota", l.QuotaReset)
	}

	return nil
}

// LimitState is what the limits of a secret say about a new connection.
type LimitState int

const (
	// LimitOK lets the connection in.
	LimitOK LimitState = iota

	// LimitDisabled means the secret is disabled.
	LimitDisabled

	// LimitExpired means the secret has expired.
	LimitExpired

	// LimitOverQuota means the secret has used up its quota in the current
	// period.
	LimitOverQuota
)

// String returns the spelling of the state used in logs and in /stats.
func (s LimitState) String() string {
	switch s {
	case LimitDisabled:
		return "disabled"
	case LimitExpired:
		return "expired"
	case LimitOverQuota:
		return "over_quota"
	default:
		return "ok"
	}
}

// quotaState is the quota accounting of one secret. It does not count bytes
// itself: the used traffic is bytes_in + bytes_out of the secret minus their
// value at the start of the period (base). So the relay path is not touched at
// all; the state is only read when a session starts, by the periodic check
// and by /stats.
type quotaState struct {
	mu sync.Mutex

	// active is true while the secret has a quota. A quota that appears starts
	// counting from zero; a quota that is removed forgets its usage.
	active      bool
	base        int64
	reset       QuotaReset
	periodStart time.Time
}

// used returns the traffic used in the current period and rolls the period
// over if a boundary has passed. total is bytes_in + bytes_out of the secret.
//
// A change of the reset period keeps the used traffic until the next boundary
// of the new period: the quota may be overcounted for a while, but never
// handed out again by a config edit.
func (q *quotaState) used(reset QuotaReset, total int64, now time.Time) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()

	start := reset.periodStart(now)

	switch {
	case !q.active:
		q.active = true
		q.base = total
		q.reset = reset
		q.periodStart = start
	case q.reset != reset:
		q.reset = reset
		q.periodStart = start
	case start.After(q.periodStart):
		q.base = total
		q.periodStart = start
	}

	return total - q.base
}

// restore sets the usage loaded from the usage state file. total is the
// current bytes_in + bytes_out of the secret.
func (q *quotaState) restore(used int64, reset QuotaReset, periodStart time.Time, total int64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.active = true
	q.base = total - used
	q.reset = reset
	q.periodStart = periodStart
}

// drop forgets the usage of a secret whose quota is removed.
func (q *quotaState) drop() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.active = false
	q.base = 0
	q.periodStart = time.Time{}
}

// snapshot returns the usage for the usage state file without rolling the
// period over. ok is false when the secret has no quota.
func (q *quotaState) snapshot(total int64) (used int64, reset QuotaReset, periodStart time.Time, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.active {
		return 0, QuotaResetNone, time.Time{}, false
	}

	return total - q.base, q.reset, q.periodStart, true
}

// limitState checks one secret against its limits at now. st may be nil (a
// secret without stats has used nothing).
func limitState(lim SecretLimits, st *secretStats, now time.Time) LimitState {
	switch {
	case lim.Disabled:
		return LimitDisabled
	case !lim.ExpiresAt.IsZero() && !now.Before(lim.ExpiresAt):
		return LimitExpired
	case lim.QuotaBytes > 0 && st != nil && st.quotaUsed(lim, now) >= lim.QuotaBytes:
		return LimitOverQuota
	}

	return LimitOK
}
