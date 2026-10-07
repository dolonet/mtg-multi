package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transport paths. This is our own contract with the bridge page, which we
// serve ourselves, so they can be changed freely: Telegram does not know them.
const (
	pathSession = "/api/v1/session"
	pathUp      = "/api/v1/up"
	pathDown    = "/api/v1/down"
	// Debug endpoint for marks from the bridge page. It is enabled only while
	// troubleshooting: the embedded Telegram webview has no developer tools,
	// and otherwise there is no way to tell at which step the page stalls.
	pathDiag = "/api/v1/diag"
)

// carrierContentType is the content type of a frame body. A strict check
// filters out stray requests before parsing.
const carrierContentType = "application/octet-stream"

// TokenHash is the key a session is addressed by in the table. We store the
// hash rather than the token itself: a memory dump or a log must not allow
// impersonating the client.
type TokenHash [sha256.Size]byte

// BridgeRenderer serves the bridge HTML page with an embedded token.
type BridgeRenderer interface {
	Render(host, bootstrapToken string) (body string, contentSecurityPolicy string)
}

// Decoy is what anyone without business here sees: a browser, a scanner, a
// DPI probe. To an observer we are an ordinary web server, and this is not
// decoration but the core of the camouflage: a distinguishable response to a
// "wrong" request gives the whole proxy away.
type Decoy interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// VHost is a single WEB mode domain with its own user table.
type VHost struct {
	Host     string
	Profiles *ProfileTable
	Decoy    Decoy
}

// Logger receives the messages of the WEB frontend. mtglib.Logger satisfies
// it. nil discards them.
type Logger interface {
	Info(msg string)
	Warning(msg string)
}

// ServerConfig holds the HTTP frontend settings.
type ServerConfig struct {
	VHosts []VHost
	// LongPollTimeout is how long /down is held without data.
	LongPollTimeout time.Duration
	// SessionTTL is how much silence makes a session considered abandoned.
	SessionTTL time.Duration
	// MaxBodyBytes caps the /up body. The body is read frame by frame, not
	// into memory, so the cap bounds how long one request may run rather
	// than memory. It must not be small: the bridge page batches every frame
	// that arrived while the previous /up was running, and a client may have
	// up to the stream window (4 MB) in flight per stream.
	MaxBodyBytes int64
	// MaxSessions caps live sessions, MaxPending caps tokens issued by the
	// bridge but not used yet. Without them both tables would grow without
	// bound for anyone hitting the bridge page. When full, we answer with the
	// decoy, like an ordinary site.
	MaxSessions int
	MaxPending  int
	// MaxSessionsPerUser and MaxPendingPerUser keep one user (one leaked
	// link) from taking the whole tables. Past the cap the user's oldest
	// entry gives way to the new one: a client that reconnects is served,
	// and a flood from one link only competes with itself.
	MaxSessionsPerUser int
	MaxPendingPerUser  int
	Session            SessionConfig
	Bridge             BridgeRenderer
	// Handle is called for every logical stream; this is Proxy.ServeStream.
	Handle func(*Stream)
	// Diag receives marks from the bridge page. nil disables it, and the
	// request goes to the decoy like any stray one.
	Diag   func(clientIP, message string)
	Logger Logger
}

// DefaultServerConfig returns the default values.
//
// Memory: a session costs about 10 MB in the worst case (see SessionConfig),
// so 512 sessions bound the frontend at about 5 GB if every one of them is
// hostile at once, and one user (4 sessions) at about 40 MB. Legitimate
// sessions hold far less: buffers fill only while the other side stalls.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		LongPollTimeout:    25 * time.Second,
		SessionTTL:         2 * time.Minute,
		MaxBodyBytes:       32 * 1024 * 1024,
		MaxSessions:        512,
		MaxPending:         2048,
		MaxSessionsPerUser: 4,
		MaxPendingPerUser:  8,
		Session:            DefaultSessionConfig(),
	}
}

// Request body caps of the endpoints that carry no data. Both are tiny by
// contract: HELLO is 9 bytes, /down is empty.
const (
	helloMaxBytes = 64
	downMaxBytes  = 64
)

// Diagnostic endpoint limits: it is opt-in, but even then a page (or anyone
// holding a token) must not be able to flood the log.
const (
	diagMaxBytes     = 256
	diagPerSecond    = 20
	warnEachInterval = time.Minute
)

// shutdownTimeout bounds Close: in-flight long polls end as soon as their
// sessions are closed, so waiting longer means a stuck handler.
const shutdownTimeout = 5 * time.Second

// Server is the HTTP frontend of the WEB mode.
//
// It sits behind an external TLS terminator (nginx with a real certificate)
// and listens on localhost only; it does not terminate TLS itself. This
// greatly reduces the attack surface: certificates are handled by software
// built for that.
type Server struct {
	cfg    ServerConfig
	vhosts map[string]VHost

	mu       sync.Mutex
	sessions map[TokenHash]*Session
	// pending holds tokens issued by the bridge page for which no session has
	// been created yet. They belong to the server, not the package: two
	// frontends in one process must not see each other's tokens.
	pending        map[TokenHash]pendingToken
	sessionsByUser map[string]int
	pendingByUser  map[string]int
	httpServer     *http.Server

	limitMu    sync.Mutex
	lastWarn   map[string]time.Time
	diagWindow time.Time
	diagCount  int

	closeOnce sync.Once
	done      chan struct{}
}

// NewServer builds the frontend and starts collecting abandoned sessions.
func NewServer(cfg ServerConfig) *Server {
	vhosts := make(map[string]VHost, len(cfg.VHosts))
	for _, vhost := range cfg.VHosts {
		vhosts[strings.ToLower(vhost.Host)] = vhost
	}

	srv := &Server{
		cfg:            cfg,
		vhosts:         vhosts,
		sessions:       make(map[TokenHash]*Session),
		pending:        make(map[TokenHash]pendingToken),
		sessionsByUser: make(map[string]int),
		pendingByUser:  make(map[string]int),
		lastWarn:       make(map[string]time.Time),
		done:           make(chan struct{}),
	}

	go srv.collectExpired()

	return srv
}

// Start listens on bind and serves in the background. A listener that cannot
// be opened is an error right away, so the caller can refuse to start. The
// channel reports the error if serving stops on its own later; it is closed
// without a value after Close.
//
// Timeouts are explicit: without them a stuck request holds the connection
// forever. There is no overall WriteTimeout because the /down long poll holds
// the response on purpose, and ReadTimeout is generous because /up may wait
// for slow streams (DeliverTimeout per stalled stream).
func (s *Server) Start(bind string) (<-chan error, error) {
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       90 * time.Second,
	}

	s.mu.Lock()
	s.httpServer = httpServer
	s.mu.Unlock()

	errs := make(chan error, 1)

	go func() {
		defer close(errs)

		if err := httpServer.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	return errs, nil
}

// Close terminates all sessions, stops the HTTP listener and the collector.
//
// Sessions go first: that ends every long poll and every /up waiting for a
// stream, so the graceful Shutdown that follows does not wait for them.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.done)

		s.mu.Lock()
		sessions := make([]*Session, 0, len(s.sessions))

		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}

		s.sessions = make(map[TokenHash]*Session)
		s.pending = make(map[TokenHash]pendingToken)
		s.sessionsByUser = make(map[string]int)
		s.pendingByUser = make(map[string]int)
		httpServer := s.httpServer
		s.mu.Unlock()

		for _, session := range sessions {
			session.Close()
		}

		if httpServer == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			httpServer.Close() //nolint: errcheck
		}
	})
}

// SessionCount reports the number of live sessions.
func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sessions)
}

// PendingCount reports the number of bridge tokens not used yet.
func (s *Server) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.pending)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vhost, ok := s.matchVHost(r)
	if !ok {
		// Unknown Host: there is nothing to answer and no reason to.
		writeNginxError(w, r, http.StatusNotFound)

		return
	}

	switch r.URL.Path {
	case pathSession:
		s.handleSession(w, r, vhost)
	case pathUp:
		s.handleUp(w, r, vhost)
	case pathDown:
		s.handleDown(w, r, vhost)
	case pathDiag:
		s.handleDiag(w, r, vhost)
	case "/":
		s.handleRoot(w, r, vhost)
	default:
		vhost.serveDecoy(w, r)
	}
}

// matchVHost looks up the domain by the Host header.
//
// The only port allowed in Host is 443: the WEB link does not carry a port,
// the client always connects to 443, and any other value means it is not our
// client.
func (s *Server) matchVHost(r *http.Request) (VHost, bool) {
	host := strings.ToLower(r.Host)

	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.HasSuffix(host, "]") {
		if host[idx+1:] != "443" {
			return VHost{}, false
		}

		host = host[:idx]
	}

	vhost, ok := s.vhosts[host]

	return vhost, ok
}

func (v VHost) serveDecoy(w http.ResponseWriter, r *http.Request) {
	if v.Decoy == nil {
		writeNginxError(w, r, http.StatusNotFound)

		return
	}

	v.Decoy.ServeHTTP(w, r)
}

// handleRoot serves the bridge page if the request is canonical and the
// capability is known. In every other case it serves the decoy: an error
// instead of static content would tell a prober this is not just a website.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request, vhost VHost) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		vhost.serveDecoy(w, r)

		return
	}

	candidate, ok := ParseBridgeQuery(r.URL.RawQuery)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	profile, ok := vhost.Profiles.Match(candidate)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	// The address is needed for the allowlist, the blocklist and the stats.
	// Without a usable one we refuse the client rather than let it through
	// as 127.0.0.1, which the lists would not recognize.
	ip, ok := forwardedClientIP(r)
	if !ok {
		s.warnEach("xff", "web: a client was refused because X-Forwarded-For is missing, repeated or a list, "+
			"or the request did not come from a loopback address; mtg must sit behind a local reverse proxy "+
			"that sets exactly one address: proxy_set_header X-Forwarded-For $remote_addr")
		vhost.serveDecoy(w, r)

		return
	}

	token, err := newToken()
	if err != nil {
		vhost.serveDecoy(w, r)

		return
	}

	if !s.registerPending(tokenHash(token), profile, ip) {
		vhost.serveDecoy(w, r)

		return
	}

	body, csp := s.cfg.Bridge.Render(vhost.Host, encodeToken(token))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-DNS-Prefetch-Control", "off")
	w.Header().Set("Permissions-Policy", PermissionsPolicy)

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)

		return
	}

	_, _ = io.WriteString(w, body)
}

// pendingToken is a profile that was issued a token but has no session yet.
type pendingToken struct {
	profile  Profile
	clientIP net.IP
	issued   time.Time
}

// registerPending stores an issued token. It returns false when the table is
// full. A user at their own cap loses their oldest token instead.
func (s *Server) registerPending(hash TokenHash, profile Profile, ip net.IP) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.MaxPending > 0 && len(s.pending) >= s.cfg.MaxPending {
		return false
	}

	if s.cfg.MaxPendingPerUser > 0 && s.pendingByUser[profile.User] >= s.cfg.MaxPendingPerUser {
		s.evictOldestPendingLocked(profile.User)
	}

	s.pending[hash] = pendingToken{profile: profile, clientIP: ip, issued: time.Now()}
	s.pendingByUser[profile.User]++

	return true
}

func (s *Server) evictOldestPendingLocked(user string) {
	var (
		oldest     TokenHash
		oldestTime time.Time
		found      bool
	)

	for hash, issued := range s.pending {
		if issued.profile.User == user && (!found || issued.issued.Before(oldestTime)) {
			oldest, oldestTime, found = hash, issued.issued, true
		}
	}

	if found {
		s.removePendingLocked(oldest)
	}
}

func (s *Server) removePendingLocked(hash TokenHash) (pendingToken, bool) {
	issued, ok := s.pending[hash]
	if !ok {
		return pendingToken{}, false
	}

	delete(s.pending, hash)

	if s.pendingByUser[issued.profile.User]--; s.pendingByUser[issued.profile.User] <= 0 {
		delete(s.pendingByUser, issued.profile.User)
	}

	return issued, true
}

// takePending consumes an issued token exactly once: reusing the same bridge
// page must not bring up a second session.
func (s *Server) takePending(hash TokenHash) (pendingToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.removePendingLocked(hash)
}

func (s *Server) hasPending(hash TokenHash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.pending[hash]

	return ok
}

// addSession stores a new session. It returns false when the table is full.
// A user at their own cap loses the session that has been silent the longest.
func (s *Server) addSession(hash TokenHash, session *Session) bool {
	s.mu.Lock()

	if s.cfg.MaxSessions > 0 && len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()

		return false
	}

	var evicted *Session

	user := session.User()
	if s.cfg.MaxSessionsPerUser > 0 && s.sessionsByUser[user] >= s.cfg.MaxSessionsPerUser {
		evicted = s.evictStalestSessionLocked(user)
	}

	s.sessions[hash] = session
	s.sessionsByUser[user]++
	s.mu.Unlock()

	if evicted != nil {
		evicted.Close()
	}

	return true
}

func (s *Server) evictStalestSessionLocked(user string) *Session {
	var (
		stalest     TokenHash
		stalestTime time.Time
		found       bool
	)

	for hash, session := range s.sessions {
		if session.User() != user {
			continue
		}

		if seen := session.LastSeen(); !found || seen.Before(stalestTime) {
			stalest, stalestTime, found = hash, seen, true
		}
	}

	if !found {
		return nil
	}

	return s.removeSessionLocked(stalest)
}

func (s *Server) removeSessionLocked(hash TokenHash) *Session {
	session, ok := s.sessions[hash]
	if !ok {
		return nil
	}

	delete(s.sessions, hash)

	user := session.User()
	if s.sessionsByUser[user]--; s.sessionsByUser[user] <= 0 {
		delete(s.sessionsByUser, user)
	}

	return session
}

// handleSession creates a session from the first body carrying HELLO.
//
// The token is looked up before the body is read: a request with a
// well-formed but unknown token costs nothing beyond its headers.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, vhost VHost) {
	hash, ok := carrierToken(r)
	if !ok || !s.hasPending(hash) {
		vhost.serveDecoy(w, r)

		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, helloMaxBytes))
	if err != nil || !ValidateHello(body, s.cfg.Session.Limits) {
		vhost.serveDecoy(w, r)

		return
	}

	issued, ok := s.takePending(hash)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	session := NewSession(Token(hash), issued.profile, issued.clientIP, s.cfg.Session, s.cfg.Handle)

	if !s.addSession(hash, session) {
		session.Close()
		vhost.serveDecoy(w, r)

		return
	}

	// WELCOME has an EMPTY body. This frame goes straight to Telegram, which
	// expects it exactly like that: with a version byte inside, the client
	// gets something it does not expect and goes silent forever (verified
	// against a real client: the session was created, but not a single frame
	// followed). The asymmetry is intentional: the client's HELLO carries the
	// version, the reply does not.
	writeCarrier(w, Encode(FrameWelcome, 0, nil)) //nolint: errcheck
}

// handleUp receives client frames.
func (s *Server) handleUp(w http.ResponseWriter, r *http.Request, vhost VHost) {
	hash, ok := carrierToken(r)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	session := s.lookup(hash)
	if session == nil || !session.upBusy.CompareAndSwap(false, true) {
		vhost.serveDecoy(w, r)

		return
	}

	defer session.upBusy.Store(false)

	if err := session.Accept(r.Context(), http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)); err != nil {
		// The client does not speak our protocol, exceeded the limits or went
		// away mid-body. Tear the session down: continuing a stream whose sync
		// is uncertain is worse.
		s.drop(hash)
		vhost.serveDecoy(w, r)

		return
	}

	writeCarrier(w, nil) //nolint: errcheck
}

// handleDown returns queued frames, holding the request while the queue is
// empty.
//
// Frames carry no sequence numbers and the client sends no acks, so a frame
// is delivered exactly when it reaches a live response. If the request is
// cancelled while waiting, or writing the response fails, the frames may be
// lost; the session is closed then, so every stream ends explicitly instead
// of going on with a silent gap. The bridge page treats any failed /down as
// the end of the session too, so both sides agree.
func (s *Server) handleDown(w http.ResponseWriter, r *http.Request, vhost VHost) {
	hash, ok := carrierToken(r)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	session := s.lookup(hash)
	if session == nil || !session.downBusy.CompareAndSwap(false, true) {
		vhost.serveDecoy(w, r)

		return
	}

	defer session.downBusy.Store(false)

	if _, err := io.ReadAll(http.MaxBytesReader(w, r.Body, downMaxBytes)); err != nil {
		vhost.serveDecoy(w, r)

		return
	}

	body, err := session.Drain(r.Context(), s.cfg.LongPollTimeout)
	if err != nil {
		s.drop(hash)
		vhost.serveDecoy(w, r)

		return
	}

	if err := writeCarrier(w, body); err != nil {
		s.drop(hash)
	}
}

// handleDiag receives a short text message from the page. It is enabled only
// by the diag option and only for holders of a live token, with a size cap
// and a global rate cap.
func (s *Server) handleDiag(w http.ResponseWriter, r *http.Request, vhost VHost) {
	if s.cfg.Diag == nil || r.Method != http.MethodPost {
		vhost.serveDecoy(w, r)

		return
	}

	hash, ok := bearerTokenHash(r)
	if !ok || !s.knownToken(hash) {
		vhost.serveDecoy(w, r)

		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, diagMaxBytes))
	if err != nil {
		vhost.serveDecoy(w, r)

		return
	}

	if s.allowDiag() {
		ip := "unknown"
		if forwarded, ok := forwardedClientIP(r); ok {
			ip = forwarded.String()
		}

		// Quoted: the text comes from the network and must not forge log lines.
		s.cfg.Diag(ip, strconv.Quote(string(body)))
	}

	writeCarrier(w, nil) //nolint: errcheck
}

func (s *Server) knownToken(hash TokenHash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, pending := s.pending[hash]
	_, live := s.sessions[hash]

	return pending || live
}

// allowDiag is a fixed one-second window: enough to keep the log readable.
func (s *Server) allowDiag() bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()

	now := time.Now()
	if now.Sub(s.diagWindow) >= time.Second {
		s.diagWindow = now
		s.diagCount = 0
	}

	s.diagCount++

	return s.diagCount <= diagPerSecond
}

// warnEach logs a warning at most once per warnEachInterval for a key: loud
// enough to notice a misconfiguration, quiet enough not to flood the log.
func (s *Server) warnEach(key, message string) {
	if s.cfg.Logger == nil {
		return
	}

	s.limitMu.Lock()
	now := time.Now()
	last, seen := s.lastWarn[key]
	allowed := !seen || now.Sub(last) >= warnEachInterval

	if allowed {
		s.lastWarn[key] = now
	}
	s.limitMu.Unlock()

	if allowed {
		s.cfg.Logger.Warning(message)
	}
}

// carrierToken checks the request shape of the carrier endpoints and returns
// the token hash. Nothing is read from the body yet.
func carrierToken(r *http.Request) (TokenHash, bool) {
	if r.Method != http.MethodPost || !hasCarrierContentType(r) {
		return TokenHash{}, false
	}

	return bearerTokenHash(r)
}

// writeCarrier writes a carrier response and flushes it, so that a client
// that has gone away shows up as an error here.
func writeCarrier(w http.ResponseWriter, body []byte) error {
	w.Header().Set("Content-Type", carrierContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}

	if err := http.NewResponseController(w).Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}

	return nil
}

func (s *Server) lookup(hash TokenHash) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sessions[hash]
}

func (s *Server) drop(hash TokenHash) {
	s.mu.Lock()
	session := s.removeSessionLocked(hash)
	s.mu.Unlock()

	if session != nil {
		session.Close()
	}
}

// collectExpired removes sessions the client forgot about: Telegram may just
// quit, and BYE never reaches us.
func (s *Server) collectExpired() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.expire(time.Now().Add(-s.cfg.SessionTTL))
		}
	}
}

func (s *Server) expire(deadline time.Time) {
	s.mu.Lock()

	expired := make([]*Session, 0)

	for hash, session := range s.sessions {
		if session.Closed() || session.LastSeen().Before(deadline) {
			expired = append(expired, s.removeSessionLocked(hash))
		}
	}

	// Tokens that never turned into a session are not kept either.
	for hash, issued := range s.pending {
		if issued.issued.Before(deadline) {
			s.removePendingLocked(hash)
		}
	}

	s.mu.Unlock()

	for _, session := range expired {
		session.Close()
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func newToken() (Token, error) {
	var token Token

	_, err := rand.Read(token[:])

	return token, err
}

func encodeToken(token Token) string {
	return base64.RawURLEncoding.EncodeToString(token[:])
}

func tokenHash(token Token) TokenHash {
	return sha256.Sum256(token[:])
}

// bearerTokenHash parses the Authorization header in strictly canonical form.
func bearerTokenHash(r *http.Request) (TokenHash, bool) {
	var zero TokenHash

	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return zero, false
	}

	value := values[0]

	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return zero, false
	}

	token := value[len(prefix):]
	if len(token) != 43 || strings.Contains(token, " ") {
		return zero, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != sha256.Size {
		return zero, false
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != token {
		return zero, false
	}

	return sha256.Sum256(decoded), true
}

// hasCarrierContentType requires the exact type without parameters.
func hasCarrierContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(values[0])), []byte(carrierContentType)) == 1
}

// forwardedClientIP returns the client address set by the reverse proxy.
//
// mtg listens on loopback only, so every request comes from a local reverse
// proxy, and X-Forwarded-For is the only source of the client address. It is
// accepted in exactly one form: a single header with a single address, as
// nginx sets it with "proxy_set_header X-Forwarded-For $remote_addr". A
// missing header, a repeated one or a list (what $proxy_add_x_forwarded_for
// produces when the client sent its own header) is unusable: the first
// address of a list comes from the client and cannot be trusted. The caller
// refuses the request then instead of falling back to the peer address,
// which is always 127.0.0.1 here and would be invisible to the allowlist and
// the blocklist.
func forwardedClientIP(r *http.Request) (net.IP, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if peer := net.ParseIP(host); peer == nil || !peer.IsLoopback() {
		return nil, false
	}

	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return nil, false
	}

	value := strings.TrimSpace(values[0])
	if strings.Contains(value, ",") {
		return nil, false
	}

	ip := net.ParseIP(value)

	return ip, ip != nil
}
