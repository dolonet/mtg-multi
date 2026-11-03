package mtglib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type secretStats struct {
	connections atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	lastSeen    atomic.Value // stores time.Time

	// ips counts the live sessions of this secret per client address. An
	// address is removed when its last session ends, and the map itself is
	// dropped when it becomes empty, so it never holds more entries than
	// there are live sessions. It is touched once when a session starts and
	// once when it ends, never on the relay path.
	ipsMu sync.Mutex
	ips   map[netip.Addr]int

	// quota is the quota accounting of this secret, if it has a quota. It is
	// derived from bytesIn and bytesOut, see quotaState.
	quota quotaState
}

// quotaUsed returns the traffic of this secret in the current quota period.
func (st *secretStats) quotaUsed(lim SecretLimits, now time.Time) int64 {
	return st.quota.used(lim.QuotaReset, st.bytesIn.Load()+st.bytesOut.Load(), now)
}

// clientAddr converts a client IP to the key of secretStats.ips. An
// IPv4-mapped IPv6 address becomes plain IPv4. An unknown (nil or
// unspecified) address gives the zero Addr, which is not tracked.
func clientAddr(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}

	// net.IP keeps IPv4 in 16 bytes as ::ffff:a.b.c.d: unmap first, or
	// 0.0.0.0 would not look unspecified.
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}
	}

	return addr
}

// addIP counts a new session from addr. The zero Addr is ignored.
func (st *secretStats) addIP(addr netip.Addr) {
	if !addr.IsValid() {
		return
	}

	st.ipsMu.Lock()
	defer st.ipsMu.Unlock()

	if st.ips == nil {
		st.ips = make(map[netip.Addr]int, 1)
	}

	st.ips[addr]++
}

// removeIP uncounts a finished session from addr. The zero Addr is ignored.
func (st *secretStats) removeIP(addr netip.Addr) {
	if !addr.IsValid() {
		return
	}

	st.ipsMu.Lock()
	defer st.ipsMu.Unlock()

	switch n := st.ips[addr]; {
	case n > 1:
		st.ips[addr] = n - 1
	case n == 1:
		delete(st.ips, addr)

		if len(st.ips) == 0 {
			// Go maps do not shrink: drop the map so a burst of addresses
			// does not keep its memory after it is gone.
			st.ips = nil
		}
	}
}

// startSession counts a session that has passed the handshake.
func (st *secretStats) startSession(addr netip.Addr) {
	st.connections.Add(1)
	st.addIP(addr)
}

// endSession uncounts a session counted by startSession.
func (st *secretStats) endSession(addr netip.Addr) {
	st.removeIP(addr)
	st.connections.Add(-1)
}

// activeIPs returns the client addresses with live sessions, sorted
// numerically (IPv4 before IPv6). It is never nil, so JSON gets [] rather
// than null.
func (st *secretStats) activeIPs() []string {
	st.ipsMu.Lock()
	addrs := make([]netip.Addr, 0, len(st.ips))

	for addr := range st.ips {
		addrs = append(addrs, addr)
	}
	st.ipsMu.Unlock()

	slices.SortFunc(addrs, netip.Addr.Compare)

	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}

	return out
}

// ProxyStats tracks per-secret connection stats with atomic counters.
// Thread-safe for concurrent access from proxy goroutines.
type ProxyStats struct {
	mu        sync.RWMutex
	users     map[string]*secretStats
	startedAt time.Time

	// Throttle: per-user connection caps recomputed every throttleInterval.
	throttleMu       sync.RWMutex
	throttleCaps     map[string]int64
	throttleLimit    int64
	throttleInterval time.Duration
	throttleActive   atomic.Bool

	// secretsDigest is the fingerprint of the secret set (see secretSet.digest).
	secretsDigest atomic.Value // string

	// limits are the limits of the current secret set, for /stats. A name
	// absent here has no limits.
	limits atomic.Pointer[map[string]SecretLimits]

	// now is the clock of the limits (expiry, quota periods); tests replace
	// it before the stats are used.
	now func() time.Time

	// usageMu serializes writes of the usage state file.
	usageMu sync.Mutex
}

// NewProxyStats creates a new ProxyStats instance.
func NewProxyStats() *ProxyStats {
	return &ProxyStats{
		users:     make(map[string]*secretStats),
		startedAt: time.Now(),
		now:       time.Now,
	}
}

func (s *ProxyStats) getOrCreate(name string) *secretStats {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if ok {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok = s.users[name]; ok {
		return st
	}

	st = &secretStats{}
	st.lastSeen.Store(time.Time{})
	s.users[name] = st

	return st
}

// PreRegister adds a secret name to the stats map so it appears in output
// even if no connections have been made yet.
func (s *ProxyStats) PreRegister(name string) {
	s.getOrCreate(name)
}

// OnConnect increments the active connection count for the given secret.
func (s *ProxyStats) OnConnect(name string) {
	s.getOrCreate(name).connections.Add(1)
}

// OnDisconnect decrements the active connection count for the given secret.
// A forgotten secret is not recreated.
func (s *ProxyStats) OnDisconnect(name string) {
	if st := s.lookup(name); st != nil {
		st.connections.Add(-1)
	}
}

// AddBytesIn adds to the bytes-in counter for the given secret. A forgotten
// secret is not recreated.
func (s *ProxyStats) AddBytesIn(name string, n int64) {
	if st := s.lookup(name); st != nil {
		st.bytesIn.Add(n)
	}
}

// AddBytesOut adds to the bytes-out counter for the given secret. A forgotten
// secret is not recreated.
func (s *ProxyStats) AddBytesOut(name string, n int64) {
	if st := s.lookup(name); st != nil {
		st.bytesOut.Add(n)
	}
}

// Forget removes a secret from the stats, for example after it was removed
// by Proxy.UpdateSecrets. Late updates from its closing sessions are
// ignored.
func (s *ProxyStats) Forget(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.users, name)
}

func (s *ProxyStats) lookup(name string) *secretStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.users[name]
}

// UpdateLastSeen sets the last-seen timestamp for the given secret to now. A
// forgotten secret is not recreated.
func (s *ProxyStats) UpdateLastSeen(name string) {
	if st := s.lookup(name); st != nil {
		st.lastSeen.Store(time.Now())
	}
}

// SetThrottle configures connection throttling. Must be called before
// startThrottleLoop and before any connections arrive.
func (s *ProxyStats) SetThrottle(limit int64, interval time.Duration) {
	s.throttleLimit = limit
	s.throttleInterval = interval
	s.throttleCaps = make(map[string]int64)
}

// CanConnect returns true if the user is allowed to open a new connection
// under the current throttle caps. If throttling is not configured or the
// user has no cap, it always returns true.
func (s *ProxyStats) CanConnect(name string) bool {
	if s.throttleLimit == 0 {
		return true
	}

	s.throttleMu.RLock()
	cap, hasCap := s.throttleCaps[name]
	s.throttleMu.RUnlock()

	if !hasCap {
		return true
	}

	// lookup, not getOrCreate: do not bring back a user removed by a reload;
	// its connection is rejected by trackSession anyway.
	st := s.lookup(name)
	if st == nil {
		return true
	}

	return st.connections.Load() < cap
}

// SetSecretsDigest publishes the fingerprint of the current secret set in
// /stats, so an external sync can check that a reload has been applied.
func (s *ProxyStats) SetSecretsDigest(digest string) {
	s.secretsDigest.Store(digest)
}

// setLimits publishes the limits of a new secret set. Quotas that appear start
// counting from zero at once, so traffic of live sessions after the change is
// counted; quotas that are gone forget their usage.
func (s *ProxyStats) setLimits(limits map[string]SecretLimits) {
	s.limits.Store(&limits)

	now := s.now()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for name, st := range s.users {
		if lim := limits[name]; lim.QuotaBytes > 0 {
			st.quotaUsed(lim, now)
		} else {
			st.quota.drop()
		}
	}
}

// secretLimits returns the published limits of name.
func (s *ProxyStats) secretLimits(name string) SecretLimits {
	if limits := s.limits.Load(); limits != nil {
		return (*limits)[name]
	}

	return SecretLimits{}
}

// startThrottleLoop runs a background goroutine that recomputes per-user
// caps every throttleInterval.
func (s *ProxyStats) startThrottleLoop(ctx context.Context, logger Logger) {
	go func() {
		ticker := time.NewTicker(s.throttleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recomputeCaps(logger)
			}
		}
	}()

	logger.BindStr("limit", fmt.Sprintf("%d", s.throttleLimit)).
		BindStr("interval", s.throttleInterval.String()).
		Info("throttle loop started")
}

func (s *ProxyStats) recomputeCaps(logger Logger) {
	s.mu.RLock()
	userConns := make(map[string]int64, len(s.users))
	for name, st := range s.users {
		userConns[name] = st.connections.Load()
	}
	s.mu.RUnlock()

	caps := computeFairCaps(userConns, s.throttleLimit)
	wasActive := s.throttleActive.Load()
	nowActive := len(caps) > 0

	s.throttleMu.Lock()
	s.throttleCaps = caps
	s.throttleActive.Store(nowActive)
	s.throttleMu.Unlock()

	if nowActive && !wasActive {
		logger.Warning("throttle activated")
	} else if !nowActive && wasActive {
		logger.Info("throttle deactivated")
	}
}

// computeFairCaps implements the fair-share algorithm. Users below the equal
// share keep their connections; remaining budget is split equally among the
// rest. Returns nil when no throttling is needed.
func computeFairCaps(userConns map[string]int64, limit int64) map[string]int64 {
	var total int64
	for _, c := range userConns {
		total += c
	}

	if total <= limit {
		return nil
	}

	remaining := make(map[string]int64, len(userConns))
	for k, v := range userConns {
		remaining[k] = v
	}

	budget := limit
	caps := make(map[string]int64)

	for len(remaining) > 0 {
		fairShare := budget / int64(len(remaining))
		changed := false

		for name, conns := range remaining {
			if conns <= fairShare {
				budget -= conns
				delete(remaining, name)
				changed = true
			}
		}

		if !changed {
			for name := range remaining {
				caps[name] = fairShare
			}

			break
		}
	}

	return caps
}

// StatsResponse is the JSON response for the stats endpoint.
type StatsResponse struct {
	StartedAt        time.Time                `json:"started_at"`
	UptimeSeconds    int64                    `json:"uptime_seconds"`
	TotalConnections int64                    `json:"total_connections"`
	Throttle         *ThrottleJSON            `json:"throttle,omitempty"`
	Users            map[string]UserStatsJSON `json:"users"`
	// SecretsSHA256 is sha256 of "name=secret(hex)" lines sorted by name and
	// joined with \n. It changes on every applied key change, not only names.
	SecretsSHA256 string `json:"secrets_sha256,omitempty"`
}

// ThrottleJSON is the throttle portion of the stats JSON response.
type ThrottleJSON struct {
	Active bool             `json:"active"`
	Limit  int64            `json:"limit"`
	Caps   map[string]int64 `json:"caps,omitempty"`
}

// UserStatsJSON is the per-user portion of the stats JSON response.
type UserStatsJSON struct {
	Connections int64      `json:"connections"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
	LastSeen    *time.Time `json:"last_seen"`
	// ActiveIPs lists the client addresses with live sessions of this user,
	// each address once however many sessions it has.
	ActiveIPs []string `json:"active_ips"`

	// State is what the limits of the user say about a new connection: ok,
	// disabled, expired or over_quota.
	State string `json:"state"`
	// Enabled is false when the user is disabled in the limits.
	Enabled bool `json:"enabled"`
	// QuotaBytes is the traffic allowed per quota period; absent without a
	// quota.
	QuotaBytes int64 `json:"quota_bytes,omitempty"`
	// QuotaUsed is the traffic used in the current period (bytes in + out);
	// absent without a quota.
	QuotaUsed *int64 `json:"quota_used,omitempty"`
	// QuotaReset is none, daily, weekly or monthly; absent without a quota.
	QuotaReset string `json:"quota_reset,omitempty"`
	// QuotaResetsAt is when the used traffic starts from zero again; absent
	// without a quota or with quota_reset = none.
	QuotaResetsAt *time.Time `json:"quota_resets_at,omitempty"`
	// ExpiresAt is when the user stops working; absent if never.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// fillLimits adds the limit fields of one user to its stats.
func (u *UserStatsJSON) fillLimits(lim SecretLimits, st *secretStats, now time.Time) {
	u.State = limitState(lim, st, now).String()
	u.Enabled = !lim.Disabled

	if !lim.ExpiresAt.IsZero() {
		expires := lim.ExpiresAt.UTC()
		u.ExpiresAt = &expires
	}

	if lim.QuotaBytes == 0 {
		return
	}

	used := st.quotaUsed(lim, now)
	u.QuotaBytes = lim.QuotaBytes
	u.QuotaUsed = &used
	u.QuotaReset = lim.QuotaReset.String()

	if resetsAt := lim.QuotaReset.nextReset(now); !resetsAt.IsZero() {
		u.QuotaResetsAt = &resetsAt
	}
}

func (s *ProxyStats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalConns int64

	users := make(map[string]UserStatsJSON, len(s.users))
	now := s.now()

	for name, st := range s.users {
		conns := st.connections.Load()
		totalConns += conns

		lastSeen := st.lastSeen.Load().(time.Time) //nolint: forcetypeassert
		var lastSeenPtr *time.Time
		if !lastSeen.IsZero() {
			lastSeenPtr = &lastSeen
		}

		user := UserStatsJSON{
			Connections: conns,
			BytesIn:     st.bytesIn.Load(),
			BytesOut:    st.bytesOut.Load(),
			LastSeen:    lastSeenPtr,
			ActiveIPs:   st.activeIPs(),
		}
		user.fillLimits(s.secretLimits(name), st, now)

		users[name] = user
	}

	var throttle *ThrottleJSON
	if s.throttleLimit > 0 {
		s.throttleMu.RLock()
		active := s.throttleActive.Load()

		var capsCopy map[string]int64
		if len(s.throttleCaps) > 0 {
			capsCopy = make(map[string]int64, len(s.throttleCaps))
			for k, v := range s.throttleCaps {
				capsCopy[k] = v
			}
		}

		s.throttleMu.RUnlock()

		throttle = &ThrottleJSON{
			Active: active,
			Limit:  s.throttleLimit,
			Caps:   capsCopy,
		}
	}

	resp := StatsResponse{
		StartedAt:        s.startedAt,
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
		TotalConnections: totalConns,
		Throttle:         throttle,
		Users:            users,
	}

	if digest, ok := s.secretsDigest.Load().(string); ok {
		resp.SecretsSHA256 = digest
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StartServer starts an HTTP server for the stats API in a background goroutine.
// The server is shut down when ctx is cancelled.
func (s *ProxyStats) StartServer(ctx context.Context, bindTo string, logger Logger) {
	mux := http.NewServeMux()
	mux.Handle("/stats", s)

	srv := &http.Server{
		Addr:    bindTo,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", bindTo)
	if err != nil {
		logger.WarningError("cannot start stats API listener", err)
		return
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.WarningError("stats API server error", err)
		}
	}()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint: mnd
		defer cancel()

		srv.Shutdown(shutdownCtx) //nolint: errcheck
	}()

	logger.BindStr("bind", bindTo).Info("Stats API server started")
}
