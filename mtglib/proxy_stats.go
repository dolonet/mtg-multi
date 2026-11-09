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

	// reload is the outcome of configuration reloads (SIGHUP), nil until the
	// first one.
	reloadMu sync.Mutex
	reload   *ReloadJSON
}

// Stages a configuration reload can fail on, as reported in /stats.
const (
	// ReloadStageReadConfig: the configuration file could not be read or
	// parsed.
	ReloadStageReadConfig = "read_config"
	// ReloadStageApply: the configuration was read, but its secrets were
	// refused.
	ReloadStageApply = "apply"
)

// RecordReloadSuccess records a reload whose secrets have been applied.
func (s *ProxyStats) RecordReloadSuccess(update SecretsUpdate) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	now := time.Now()
	r := s.reloadOrNew()
	r.Succeeded++
	r.LastAt = now
	r.LastOK = true
	r.LastErrorStage = ""
	r.LastSuccessAt = &now
	r.Added = update.Added
	r.Removed = update.Removed
	r.Changed = update.Changed
}

// RecordReloadFailure records a reload that has been refused at the given
// stage (ReloadStageReadConfig or ReloadStageApply). The proxy keeps running
// on its current secrets, so the counts of the last successful reload stay.
func (s *ProxyStats) RecordReloadFailure(stage string) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	r := s.reloadOrNew()
	r.Failed++
	r.LastAt = time.Now()
	r.LastOK = false
	r.LastErrorStage = stage
}

func (s *ProxyStats) reloadOrNew() *ReloadJSON {
	if s.reload == nil {
		s.reload = &ReloadJSON{}
	}

	return s.reload
}

func (s *ProxyStats) reloadSnapshot() *ReloadJSON {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	if s.reload == nil {
		return nil
	}

	r := *s.reload
	if r.LastSuccessAt != nil {
		at := *r.LastSuccessAt
		r.LastSuccessAt = &at
	}

	return &r
}

// NewProxyStats creates a new ProxyStats instance.
func NewProxyStats() *ProxyStats {
	return &ProxyStats{
		users:     make(map[string]*secretStats),
		startedAt: time.Now(),
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
	// Reload is the outcome of configuration reloads (SIGHUP); omitted until
	// the first one.
	Reload *ReloadJSON `json:"reload,omitempty"`
}

// ReloadJSON is the reload portion of the stats JSON response. A refused
// reload keeps the current secrets, so secrets_sha256 alone cannot tell
// "refused" from "not reloaded yet"; last_ok and last_error_stage can. The
// error text itself is not exposed: a parse error may quote a line of the
// configuration, secrets included. It is in the log.
type ReloadJSON struct {
	// Succeeded and Failed count reloads since the start.
	Succeeded int64 `json:"succeeded"`
	Failed    int64 `json:"failed"`
	// LastAt is the time of the last reload, successful or not.
	LastAt time.Time `json:"last_at"`
	LastOK bool      `json:"last_ok"`
	// LastErrorStage is "read_config" or "apply" when the last reload has
	// been refused.
	LastErrorStage string `json:"last_error_stage,omitempty"`
	// LastSuccessAt and the counts below describe the last successful reload.
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	Added         int        `json:"added"`
	Removed       int        `json:"removed"`
	Changed       int        `json:"changed"`
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
}

func (s *ProxyStats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalConns int64

	users := make(map[string]UserStatsJSON, len(s.users))

	for name, st := range s.users {
		conns := st.connections.Load()
		totalConns += conns

		lastSeen := st.lastSeen.Load().(time.Time) //nolint: forcetypeassert
		var lastSeenPtr *time.Time
		if !lastSeen.IsZero() {
			lastSeenPtr = &lastSeen
		}

		users[name] = UserStatsJSON{
			Connections: conns,
			BytesIn:     st.bytesIn.Load(),
			BytesOut:    st.bytesOut.Load(),
			LastSeen:    lastSeenPtr,
			ActiveIPs:   st.activeIPs(),
		}
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

	resp.Reload = s.reloadSnapshot()

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
