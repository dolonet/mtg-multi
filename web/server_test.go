package web_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHost   = "proxy.example.com"
	testSecret = "0123456789abcdef"
	decoyBody  = "<html>regular site</html>"
)

type stubBridge struct{}

func (stubBridge) Render(host, token string) (string, string) {
	return "<html>bridge " + host + " " + token + "</html>", "default-src 'none'"
}

type stubDecoy struct{}

func (stubDecoy) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, decoyBody)
}

func newTestServer(t *testing.T, handle func(*web.Stream), opts ...func(*web.ServerConfig)) (*web.Server, web.Profile) {
	t.Helper()

	capability, err := web.DeriveCapability(web.ClientSecret([]byte(testSecret), web.SecretModeDD), testHost)
	require.NoError(t, err)

	profile := web.Profile{User: "petya_1", Capability: capability, SecretMode: web.SecretModeDD}

	table, err := web.NewProfileTable([]web.Profile{profile})
	require.NoError(t, err)

	cfg := web.DefaultServerConfig()
	cfg.VHosts = []web.VHost{{Host: testHost, Profiles: table, Decoy: stubDecoy{}}}
	cfg.Bridge = stubBridge{}
	cfg.LongPollTimeout = 300 * time.Millisecond

	if handle == nil {
		handle = func(*web.Stream) {}
	}

	cfg.Handle = handle

	for _, opt := range opts {
		opt(&cfg)
	}

	srv := web.NewServer(cfg)
	t.Cleanup(srv.Close)

	return srv, profile
}

func do(srv *web.Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	return rec
}

func bridgeRequest(profile web.Profile) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/?bridge="+web.EncodeCapability(profile.Capability), nil)
	r.Host = testHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	return r
}

func carrierRequest(path, token string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Host = testHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}

// The token is issued by the bridge page; the test follows the path of a real
// client.
func openSession(t *testing.T, srv *web.Server, profile web.Profile) string {
	t.Helper()

	rec := do(srv, bridgeRequest(profile))
	require.Equal(t, http.StatusOK, rec.Code)

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))
	token := fields[len(fields)-1]

	hello := web.Encode(web.FrameHello, 0, []byte{1})
	rec = do(srv, carrierRequest("/api/v1/session", token, hello))
	require.Equal(t, http.StatusOK, rec.Code)

	frames, err := web.ParseAll(rec.Body.Bytes(), web.DefaultLimits())
	require.NoError(t, err)
	require.Len(t, frames, 1)
	require.Equal(t, web.FrameWelcome, frames[0].Type)
	// The WELCOME body must be empty: the frame goes to Telegram, and with an
	// extra version byte the client goes silent after the session is created.
	require.Empty(t, frames[0].Payload)

	return token
}

// The key camouflage property: anything that is not a request from our client
// gets ordinary static content. A distinguishable response would give the
// proxy away to a probing DPI.
func TestServerServesDecoyForEverythingElse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	cases := map[string]*http.Request{
		"root without parameters": httptest.NewRequest(http.MethodGet, "/", nil),
		"foreign path":            httptest.NewRequest(http.MethodGet, "/wp-login.php", nil),
		"garbage in bridge":       httptest.NewRequest(http.MethodGet, "/?bridge=garbage", nil),
		"unknown capability":      httptest.NewRequest(http.MethodGet, "/?bridge="+strings.Repeat("A", 43), nil),
		"POST to root":            httptest.NewRequest(http.MethodPost, "/", nil),
		"transport without token": httptest.NewRequest(http.MethodPost, "/api/v1/up", nil),
	}

	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			r.Host = testHost
			r.RemoteAddr = "127.0.0.1:12345"

			rec := do(srv, r)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, decoyBody, rec.Body.String())
		})
	}

	// A canonical request from our own client, however, gets the bridge.
	rec := do(srv, bridgeRequest(profile))
	assert.Contains(t, rec.Body.String(), "bridge")
}

func TestServerRejectsForeignHost(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = "other.example.com"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// The WEB link carries no port: the client always connects to 443. A Host with
// any other port means it is not our client.
func TestServerRejectsNonStandardPort(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = testHost + ":8443"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// The full end-to-end scenario: bridge -> session -> stream open -> data both
// ways. This is what WEB looks like from the user's point of view.
func TestServerEndToEnd(t *testing.T) {
	handled := make(chan struct{})

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		defer close(handled)

		buf := make([]byte, 16)
		n, err := stream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "ping", string(buf[:n]))

		_, err = stream.Write([]byte("pong"))
		assert.NoError(t, err)
	})

	token := openSession(t, srv, profile)

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("ping"))...,
	)
	require.Equal(t, http.StatusOK, do(srv, carrierRequest("/api/v1/up", token, body)).Code)

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("stream was not handled")
	}

	rec := do(srv, carrierRequest("/api/v1/down", token, nil))
	require.Equal(t, http.StatusOK, rec.Code)

	frames, err := web.ParseAll(rec.Body.Bytes(), web.DefaultLimits())
	require.NoError(t, err)
	require.NotEmpty(t, frames)
	assert.Equal(t, []byte("pong"), frames[0].Payload)
}

// The client IP is taken from X-Forwarded-For set by the local reverse proxy:
// mtg listens on loopback only, so the peer address is always 127.0.0.1.
func TestServerTakesClientIPFromTrustedProxy(t *testing.T) {
	got := make(chan string, 1)

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	token := openSession(t, srv, profile)
	require.Equal(t, http.StatusOK,
		do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))).Code)

	select {
	case host := <-got:
		assert.Equal(t, "203.0.113.7", host)
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not open")
	}
}

// Without a usable X-Forwarded-For the client is refused, not let through as
// 127.0.0.1: the allowlist and the blocklist would not recognize it. The
// misconfiguration is logged, but not on every request.
func TestServerRefusesClientWithoutUsableForwardedFor(t *testing.T) {
	logger := &recordingLogger{}
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.Logger = logger })

	cases := map[string]func(r *http.Request){
		"missing":           func(r *http.Request) { r.Header.Del("X-Forwarded-For") },
		"repeated":          func(r *http.Request) { r.Header.Add("X-Forwarded-For", "198.51.100.5") },
		"list":              func(r *http.Request) { r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.7") },
		"not an address":    func(r *http.Request) { r.Header.Set("X-Forwarded-For", "unknown") },
		"empty":             func(r *http.Request) { r.Header.Set("X-Forwarded-For", "") },
		"peer is not local": func(r *http.Request) { r.RemoteAddr = "198.51.100.5:40000" },
		"peer without port": func(r *http.Request) { r.RemoteAddr = "garbage" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := bridgeRequest(profile)
			mutate(r)

			assert.Equal(t, decoyBody, do(srv, r).Body.String())
		})
	}

	assert.Equal(t, 0, srv.PendingCount())
	assert.Len(t, logger.warnings(), 1, "the warning is rate limited")
}

// The token is single-use: one bridge page brings up exactly one session.
func TestServerTokenIsSingleUse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	token := openSession(t, srv, profile)

	rec := do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1})))
	assert.Equal(t, decoyBody, rec.Body.String())
}

func TestServerRejectsBadCarrierRequests(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	t.Run("foreign content type", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))
		r.Header.Set("Content-Type", "application/json")

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("malformed token", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", strings.Repeat("!", 43), web.Encode(web.FrameOpen, 1, nil))

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("GET instead of POST", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, nil)
		r.Method = http.MethodGet

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})
}

// A broken frame tears the session down: the stream state can no longer be
// trusted.
func TestServerDropsSessionOnProtocolError(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	assert.Equal(t, 1, srv.SessionCount())

	// DATA on stream 0 violates the grammar.
	rec := do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameData, 0, []byte("x"))))
	assert.Equal(t, decoyBody, rec.Body.String())
	assert.Equal(t, 0, srv.SessionCount())
}

// Long polling: with an empty queue the request is held and returns empty.
func TestServerLongPollReturnsEmpty(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	start := time.Now()
	rec := do(srv, carrierRequest("/api/v1/down", token, nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes())
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond)
}

// The table of tokens issued by the bridge is capped: otherwise anyone hitting
// the bridge page could inflate it. When full, the regular decoy is served,
// like on an ordinary site.
func TestServerPendingTokensAreCapped(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxPending = 2 })

	for range 2 {
		rec := do(srv, bridgeRequest(profile))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "bridge")
	}

	rec := do(srv, bridgeRequest(profile))
	assert.Equal(t, decoyBody, rec.Body.String())
}

// There are at most MaxSessions live sessions; an extra one gets the decoy.
func TestServerSessionsAreCapped(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxSessions = 1 })

	openSession(t, srv, profile)
	require.Equal(t, 1, srv.SessionCount())

	rec := do(srv, bridgeRequest(profile))
	require.Equal(t, http.StatusOK, rec.Code)

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))
	token := fields[len(fields)-1]

	rec = do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1})))
	assert.Equal(t, decoyBody, rec.Body.String())
	assert.Equal(t, 1, srv.SessionCount())
}

type recordingLogger struct {
	mu    sync.Mutex
	infos []string
	warns []string
}

func (l *recordingLogger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.infos = append(l.infos, msg)
}

func (l *recordingLogger) Warning(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.warns = append(l.warns, msg)
}

func (l *recordingLogger) warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.warns...)
}

func issueToken(t *testing.T, srv *web.Server, profile web.Profile) string {
	t.Helper()

	rec := do(srv, bridgeRequest(profile))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "bridge")

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))

	return fields[len(fields)-1]
}

func hello(t *testing.T, srv *web.Server, token string) string {
	t.Helper()

	return do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1}))).Body.String()
}

// One user cannot take the whole pending table: past their own cap the
// oldest of their tokens gives way.
func TestServerPendingTokensPerUser(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxPendingPerUser = 2 })

	first := issueToken(t, srv, profile)
	issueToken(t, srv, profile)
	third := issueToken(t, srv, profile)

	assert.Equal(t, 2, srv.PendingCount())
	assert.Equal(t, decoyBody, hello(t, srv, first), "the oldest token was evicted")
	assert.NotEqual(t, decoyBody, hello(t, srv, third))
}

// One user cannot take the whole session table: past their own cap the
// session silent for the longest gives way to the new one.
func TestServerSessionsPerUser(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxSessionsPerUser = 1 })

	first := openSession(t, srv, profile)
	second := openSession(t, srv, profile)

	assert.Equal(t, 1, srv.SessionCount())
	assert.Equal(t, decoyBody, do(srv, carrierRequest("/api/v1/down", first, nil)).Body.String())

	rec := do(srv, carrierRequest("/api/v1/down", second, nil))
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
}

// DATA for a stream that is gone does not take the session down.
func TestServerKeepsSessionOnDataForGoneStream(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	rec := do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameData, 5, []byte("late"))))

	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, 1, srv.SessionCount())
}

// The server takes an /up body up to MaxBodyBytes and refuses a longer one.
// With the defaults it takes the largest body the bridge page sends (whole
// frames up to 512 KB).
func TestServerAcceptsUpBodyUpToMaxBodyBytes(t *testing.T) {
	// DATA for a stream that is not open is dropped and the session goes on,
	// so the body size is the only thing under test.
	frame := web.Encode(web.FrameData, 5, make([]byte, web.DataChunkBytes))

	t.Run("largest page batch with the defaults", func(t *testing.T) {
		srv, profile := newTestServer(t, nil)
		token := openSession(t, srv, profile)

		body := bytes.Repeat(frame, 512*1024/len(frame))

		rec := do(srv, carrierRequest("/api/v1/up", token, body))
		assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, 1, srv.SessionCount())
	})

	t.Run("exactly the limit and one frame over it", func(t *testing.T) {
		srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) {
			cfg.MaxBodyBytes = int64(3 * len(frame))
		})
		token := openSession(t, srv, profile)

		rec := do(srv, carrierRequest("/api/v1/up", token, bytes.Repeat(frame, 3)))
		assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, 1, srv.SessionCount())

		rec = do(srv, carrierRequest("/api/v1/up", token, bytes.Repeat(frame, 4)))
		assert.Equal(t, decoyBody, rec.Body.String())
		assert.Equal(t, 0, srv.SessionCount())
	})
}

// countingReader records whether the body was read at all.
type countingReader struct {
	read atomic.Int64
	data io.Reader
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.data.Read(p)
	r.read.Add(int64(n))

	return n, err
}

// A request with a well-formed but unknown token costs nothing beyond its
// headers: the body is not read before the token is found.
func TestServerDoesNotReadBodyForUnknownToken(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	unknown := strings.Repeat("A", 43)

	for _, path := range []string{"/api/v1/session", "/api/v1/up", "/api/v1/down"} {
		t.Run(path, func(t *testing.T) {
			body := &countingReader{data: bytes.NewReader(make([]byte, 1024*1024))}
			r := carrierRequest(path, unknown, nil)
			r.Body = io.NopCloser(body)

			assert.Equal(t, decoyBody, do(srv, r).Body.String())
			assert.Zero(t, body.read.Load())
		})
	}
}

// One /down at a time: two parallel long polls would split the queue between
// two responses and the client could reorder them.
func TestServerRejectsParallelDown(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.LongPollTimeout = time.Second })
	token := openSession(t, srv, profile)

	first := make(chan *httptest.ResponseRecorder, 1)

	go func() { first <- do(srv, carrierRequest("/api/v1/down", token, nil)) }()

	time.Sleep(200 * time.Millisecond) // the first long poll is waiting by now
	assert.Equal(t, decoyBody, do(srv, carrierRequest("/api/v1/down", token, nil)).Body.String())

	rec := <-first
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	assert.Equal(t, 1, srv.SessionCount())
}

// A long poll whose request is cancelled (the client went away) closes the
// session: frames have no acks, so going on would risk a silent gap.
func TestServerDropsSessionWhenDownIsCancelled(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.LongPollTimeout = 10 * time.Second })
	token := openSession(t, srv, profile)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	do(srv, carrierRequest("/api/v1/down", token, nil).WithContext(ctx))

	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, 0, srv.SessionCount())
}

func diagRequest(token, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/diag", strings.NewReader(body))
	r.Host = testHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}

// The diagnostic endpoint is off by default, accepts only holders of a live
// token, caps the message size and the rate, and quotes the text.
func TestServerDiag(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		srv, profile := newTestServer(t, nil)
		token := issueToken(t, srv, profile)

		assert.Equal(t, decoyBody, do(srv, diagRequest(token, "hi")).Body.String())
	})

	logged := make(chan string, 100)
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) {
		cfg.Diag = func(ip, message string) { logged <- ip + " " + message }
	})

	t.Run("unknown token", func(t *testing.T) {
		assert.Equal(t, decoyBody, do(srv, diagRequest(strings.Repeat("A", 43), "hi")).Body.String())
		assert.Empty(t, logged)
	})

	token := issueToken(t, srv, profile)

	t.Run("quoted and truncated", func(t *testing.T) {
		do(srv, diagRequest(token, "line\nforged"+strings.Repeat("x", 1000)))

		got := <-logged
		assert.True(t, strings.HasPrefix(got, `203.0.113.7 "line\nforged`), got)
		assert.LessOrEqual(t, len(got), len("203.0.113.7 ")+2*300)
	})

	t.Run("rate limited", func(t *testing.T) {
		for range 100 {
			do(srv, diagRequest(token, "x"))
		}

		assert.LessOrEqual(t, len(logged), 40)
	})
}

// Close ends every long poll right away, so shutdown does not wait for them.
func TestServerCloseEndsLongPoll(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.LongPollTimeout = 30 * time.Second })
	token := openSession(t, srv, profile)

	done := make(chan struct{})

	go func() {
		do(srv, carrierRequest("/api/v1/down", token, nil))
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	srv.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the long poll outlived Close")
	}
}

// A listener that cannot be opened is an error at start, not a warning later;
// Close shuts the HTTP server down.
func TestServerStart(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer busy.Close() //nolint: errcheck

	srv, _ := newTestServer(t, nil)

	_, err = srv.Start(busy.Addr().String())
	require.Error(t, err)

	srv2, _ := newTestServer(t, nil)

	errs, err := srv2.Start("127.0.0.1:0")
	require.NoError(t, err)

	srv2.Close()

	select {
	case err, ok := <-errs:
		assert.False(t, ok, "no error after Close: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the HTTP server did not stop on Close")
	}
}
