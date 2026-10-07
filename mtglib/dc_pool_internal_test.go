package mtglib

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/dc"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
)

// fakePoolConn is a minimal essentials.Conn for pool tests: the pool only
// needs Close/CloseRead/CloseWrite and never calls Read/Write (the embedded nil
// net.Conn is not used).
type fakePoolConn struct {
	net.Conn

	mu     sync.Mutex
	closed bool
}

func (f *fakePoolConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()

	return nil
}

func (f *fakePoolConn) CloseRead() error  { return nil }
func (f *fakePoolConn) CloseWrite() error { return nil }

func (f *fakePoolConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.closed
}

func testAddr() dc.Addr {
	return dc.Addr{Network: "tcp", Address: "149.154.167.50:443"}
}

// newTestPool builds a dcPool WITHOUT filler goroutines (deterministic unit
// tests of get/topUp).
func newTestPool(dial dcDialFunc, perDC int, maxAge time.Duration) *dcPool {
	return &dcPool{
		dial:     dial,
		logger:   NoopLogger{},
		dcs:      []int{2},
		warm:     map[int]struct{}{2: {}},
		perDC:    perDC,
		maxAge:   maxAge,
		interval: time.Hour,
		ready:    map[int][]warmConn{},
	}
}

func TestDCPoolTopUpAndGet(t *testing.T) {
	var dials int32

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		atomic.AddInt32(&dials, 1)

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 2, 20*time.Second)
	if err := p.topUp(context.Background(), 2); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected 2 warm dials, got %d", got)
	}

	// Two gets in a row return warm connections, the third one is a miss.
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #1: expected a warm connection")
	}
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #2: expected a warm connection")
	}
	if _, _, ok := p.get(2); ok {
		t.Fatal("get #3: expected a miss (empty pool)")
	}
}

func TestDCPoolGetEvictsAged(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	fresh := &fakePoolConn{}
	aged := &fakePoolConn{}

	// aged is older than maxAge: get closes and skips it, returns the fresh one.
	p.ready[2] = []warmConn{
		{conn: fresh, addr: testAddr(), created: time.Now()},
		{conn: aged, addr: testAddr(), created: time.Now().Add(-time.Hour)},
	}

	conn, _, ok := p.get(2)
	if !ok {
		t.Fatal("expected a fresh connection")
	}
	if !aged.isClosed() {
		t.Fatal("an aged connection must be closed")
	}
	if conn.(*fakePoolConn) != fresh {
		t.Fatal("expected exactly the fresh connection")
	}
}

func TestDCPoolGetEmptyIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	if _, _, ok := p.get(2); ok {
		t.Fatal("an empty pool must miss (fallback to a cold dial)")
	}
}

func TestDCPoolTopUpDropsDCMismatch(t *testing.T) {
	fake := &fakePoolConn{}

	// dial returned a connection to ANOTHER DC (fallback): it must not be pooled
	// under the requested DC and has to be closed.
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return fake, testAddr(), 999, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	if err := p.topUp(context.Background(), 2); !errors.Is(err, errDCPoolFallback) {
		t.Fatalf("expected errDCPoolFallback, got %v", err)
	}

	if len(p.ready[2]) != 0 {
		t.Fatalf("a connection to another DC must not be pooled, pool has %d", len(p.ready[2]))
	}
	if !fake.isClosed() {
		t.Fatal("a connection to another DC must be closed")
	}
}

func TestDCPoolTopUpDialFailureNoStore(t *testing.T) {
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return nil, dc.Addr{}, 0, errors.New("route down")
	}

	p := newTestPool(dial, 2, 20*time.Second)
	if err := p.topUp(context.Background(), 2); err == nil {
		t.Fatal("expected a dial error")
	}

	if len(p.ready[2]) != 0 {
		t.Fatalf("the pool must stay empty after a failed dial, pool has %d", len(p.ready[2]))
	}
}

func TestDCPoolShutdownClosesConns(t *testing.T) {
	var conns []*fakePoolConn
	var mu sync.Mutex

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		c := &fakePoolConn{}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()

		return c, testAddr(), dcID, nil
	}

	pool := newDCPool(context.Background(), dial, NoopLogger{}, nil,
		[]int{2}, 2, 20*time.Second, 5*time.Millisecond)

	// Wait until the filler fills the pool (perDC=2). Do NOT take connections via
	// get(): a taken connection belongs to the caller and Shutdown does not close
	// it (which is correct), so the test would fail falsely.
	poolLen := func() int {
		pool.mu.Lock()
		defer pool.mu.Unlock()

		return len(pool.ready[2])
	}

	deadline := time.Now().Add(2 * time.Second)
	for poolLen() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the filler did not fill the pool in 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	pool.Shutdown()

	mu.Lock()
	defer mu.Unlock()

	for i, c := range conns {
		if !c.isClosed() {
			t.Fatalf("connection #%d is not closed after Shutdown", i)
		}
	}
}

// recorder collects pool results to check the dc_pool metric.
type recorder struct {
	mu      sync.Mutex
	results []string
}

func (r *recorder) observe(_ int, result string) {
	r.mu.Lock()
	r.results = append(r.results, result)
	r.mu.Unlock()
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.results...)
}

func equalResults(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("results: got %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("results: got %v, want %v", got, want)
		}
	}
}

// A connection that the DC closed while it was pooled is not handed to a
// client: otherwise the first client write fails and the Telegram client goes
// into backoff.
func TestDCPoolGetSkipsDeadConn(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	alive := &fakePoolConn{}
	dead := &fakePoolConn{}
	p.alive = func(c essentials.Conn) bool { return c.(*fakePoolConn) != dead } //nolint: forcetypeassert

	p.ready[2] = []warmConn{
		{conn: alive, addr: testAddr(), created: time.Now()},
		{conn: dead, addr: testAddr(), created: time.Now()},
	}

	conn, _, ok := p.get(2)
	if !ok || conn.(*fakePoolConn) != alive { //nolint: forcetypeassert
		t.Fatal("expected a live connection")
	}

	if !dead.isClosed() {
		t.Fatal("a dead connection must be closed")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultHit})
}

// All pooled connections are dead: a miss, the client dials cold.
func TestDCPoolGetAllDeadIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe
	p.alive = func(essentials.Conn) bool { return false }

	p.ready[2] = []warmConn{
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
	}

	if _, _, ok := p.get(2); ok {
		t.Fatal("expected a miss")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultDead, DCPoolResultMiss})
}

// Filler and hand-out results: warm dial, eviction by age, failed warm dial,
// stale at hand-out, miss.
func TestDCPoolReportsResults(t *testing.T) {
	fail := false
	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		if fail {
			return nil, dc.Addr{}, 0, errors.New("dc down")
		}

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	p.topUp(context.Background(), 2) //nolint: errcheck // dial_ok

	p.mu.Lock()
	p.ready[2][0].created = time.Now().Add(-time.Hour)
	p.mu.Unlock()

	fail = true
	p.topUp(context.Background(), 2) //nolint: errcheck // expired + dial_fail

	p.ready[2] = []warmConn{{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now().Add(-time.Hour)}}
	p.get(2) // stale + miss

	equalResults(t, rec.all(), []string{
		DCPoolResultDialOK,
		DCPoolResultExpired, DCPoolResultDialFail,
		DCPoolResultStale, DCPoolResultMiss,
	})
}

// The real probe on net.Pipe: a silent connection is alive; one closed by the
// other side is dead; one where the DC sent data is dead too (this must not
// happen on a stream that has not started). The deadline is reset after the
// probe, so the connection reads normally afterwards.
func TestProbeAlive(t *testing.T) {
	t.Run("silent is alive, deadline reset", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		conn := essentials.WrapNetConn(local)
		if !probeAlive(conn) {
			t.Fatal("a silent connection must be alive")
		}

		go remote.Write([]byte{42}) //nolint: errcheck

		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil || buf[0] != 42 {
			t.Fatalf("reads must work after the probe: %v %v", buf, err)
		}
	})

	t.Run("closed by DC is dead", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close() //nolint: errcheck

		remote.Close() //nolint: errcheck

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("a closed connection must be dead")
		}
	})

	t.Run("data from DC is dead", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		go remote.Write([]byte{1}) //nolint: errcheck

		time.Sleep(10 * time.Millisecond)

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("a connection with unexpected data must be dead")
		}
	})
}

// A DC outside the warmed set is neither pooled nor reported: the DC id comes
// from the client, and a metric per arbitrary id would be unbounded.
func TestDCPoolGetUnwarmedDCNoMetric(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	for _, dcID := range []int{-2, 7, 203, 31337, -32768} {
		if _, _, ok := p.get(dcID); ok {
			t.Fatalf("DC %d is not warmed and must not be served from the pool", dcID)
		}
	}

	equalResults(t, rec.all(), nil)

	p.get(2) // a warmed DC with an empty pool is a real miss

	equalResults(t, rec.all(), []string{DCPoolResultMiss})
}

// Media (negative) DCs and the CDN DC 203 are pooled under their signed ids,
// separately from the regular DC with the same absolute number.
func TestDCPoolSignedAndCDNDCs(t *testing.T) {
	var (
		mu     sync.Mutex
		dialed = map[int]int{}
	)

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		mu.Lock()
		dialed[dcID]++
		mu.Unlock()

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	p.dcs = []int{-2, 203}
	p.warm = map[int]struct{}{-2: {}, 203: {}}

	p.topUp(context.Background(), -2)  //nolint: errcheck
	p.topUp(context.Background(), 203) //nolint: errcheck

	if dialed[-2] != 1 || dialed[203] != 1 || dialed[2] != 0 {
		t.Fatalf("unexpected dials: %v", dialed)
	}

	if _, _, ok := p.get(2); ok {
		t.Fatal("DC 2 is not warmed, a -2 connection must not be handed out for it")
	}

	if _, _, ok := p.get(-2); !ok {
		t.Fatal("expected a warm connection to media DC -2")
	}

	if _, _, ok := p.get(203); !ok {
		t.Fatal("expected a warm connection to CDN DC 203")
	}
}

func TestDCPoolBackoff(t *testing.T) {
	p := newTestPool(nil, 1, 20*time.Second)
	p.interval = 7 * time.Second
	p.maxBackoff = 2 * time.Minute

	want := []time.Duration{
		14 * time.Second, 28 * time.Second, 56 * time.Second, 112 * time.Second,
		2 * time.Minute, 2 * time.Minute,
	}

	for i, w := range want {
		if got := p.backoff(i + 1); got != w {
			t.Fatalf("backoff(%d) = %v, want %v", i+1, got, w)
		}
	}

	if got := p.backoff(1000); got != 2*time.Minute {
		t.Fatalf("backoff must not overflow, got %v", got)
	}
}

// A failing DC is not dialed on every tick.
func TestDCPoolFillerBacksOff(t *testing.T) {
	var dials int32

	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		atomic.AddInt32(&dials, 1)

		return nil, dc.Addr{}, 0, errors.New("route down")
	}

	pool := newDCPool(context.Background(), dial, NoopLogger{}, nil,
		[]int{2}, 1, 20*time.Second, 2*time.Millisecond)

	time.Sleep(200 * time.Millisecond)
	pool.Shutdown()

	// ~100 ticks; with backoff the attempts are at 0, 4, 12, 28, 60, 124 ms.
	if got := atomic.LoadInt32(&dials); got > 10 {
		t.Fatalf("a failing DC was dialed %d times in ~100 ticks, expected a backoff", got)
	}
}

// A dial that lands on another DC (fallback) is a failure, not a silent retry.
func TestDCPoolTopUpDCMismatchIsFailure(t *testing.T) {
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return &fakePoolConn{}, testAddr(), 2, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe
	p.warm[203] = struct{}{}

	err := p.topUp(context.Background(), 203)
	if !errors.Is(err, errDCPoolFallback) {
		t.Fatalf("expected errDCPoolFallback, got %v", err)
	}

	equalResults(t, rec.all(), []string{DCPoolResultDialFail})
}

// A warm dial has its own deadline even if the dialer never gives up.
func TestDCPoolDialTimeout(t *testing.T) {
	dial := func(ctx context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		<-ctx.Done()

		return nil, dc.Addr{}, 0, ctx.Err()
	}

	p := newTestPool(dial, 1, 20*time.Second)
	p.dialTimeout = 20 * time.Millisecond

	started := time.Now()
	err := p.topUp(context.Background(), 2)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a deadline error, got %v", err)
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the warm dial was not bounded: %v", elapsed)
	}
}

// Shutdown during an in-flight warm dial returns promptly, and a connection
// the dial produced after the cancellation is closed instead of pooled.
func TestDCPoolShutdownDuringDial(t *testing.T) {
	inDial := make(chan struct{})
	late := &fakePoolConn{}

	var once sync.Once

	dial := func(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		once.Do(func() { close(inDial) })
		<-ctx.Done()

		// The dialer ignores the cancellation and still returns a connection.
		return late, testAddr(), dcID, nil
	}

	pool := newDCPool(context.Background(), dial, NoopLogger{}, nil,
		[]int{2}, 1, 20*time.Second, time.Hour)

	select {
	case <-inDial:
	case <-time.After(2 * time.Second):
		t.Fatal("the filler did not start a dial")
	}

	done := make(chan struct{})

	go func() {
		pool.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown hung on an in-flight dial")
	}

	if !late.isClosed() {
		t.Fatal("a connection dialed after Shutdown must be closed")
	}

	if n := len(pool.ready[2]); n != 0 {
		t.Fatalf("nothing may be pooled after Shutdown, got %d", n)
	}
}

// dcPoolTestNetwork dials a local Telegram stand-in whatever address is asked.
type dcPoolTestNetwork struct {
	addr  string
	dials atomic.Int32
}

func (n *dcPoolTestNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *dcPoolTestNetwork) DialContext(ctx context.Context, _, _ string) (essentials.Conn, error) {
	n.dials.Add(1)

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	return essentials.WrapNetConn(conn), nil
}

func (n *dcPoolTestNetwork) MakeHTTPClient(func(context.Context, string, string) (essentials.Conn, error)) *http.Client {
	return nil
}

func (n *dcPoolTestNetwork) NativeDialer() *net.Dialer { return &net.Dialer{} }

// fakeTelegram accepts connections, reads the obfuscated2 handshake and
// records the DC id it carries.
func fakeTelegram(t *testing.T) (string, <-chan int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	dcs := make(chan int, 16)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close() //nolint: errcheck

				dcID, _, err := obfuscation.Obfuscator{}.ReadHandshake(essentials.WrapNetConn(conn))
				if err == nil {
					dcs <- dcID
				}

				io.Copy(io.Discard, conn) //nolint: errcheck
			}()
		}
	}()

	return listener.Addr().String(), dcs
}

type dcPoolTestEvents struct {
	mu     sync.Mutex
	events []Event
}

func (e *dcPoolTestEvents) Send(_ context.Context, evt Event) {
	e.mu.Lock()
	e.events = append(e.events, evt)
	e.mu.Unlock()
}

func newDCPoolTestProxy(t *testing.T, fallback bool) (*Proxy, *dcPoolTestNetwork, <-chan int) {
	t.Helper()

	addr, dcs := fakeTelegram(t)

	tg, err := dc.New("prefer-ipv4")
	if err != nil {
		t.Fatal(err)
	}

	network := &dcPoolTestNetwork{addr: addr}

	return &Proxy{
		telegram:                 tg,
		network:                  network,
		eventStream:              &dcPoolTestEvents{},
		allowFallbackOnUnknownDC: fallback,
		logger:                   NoopLogger{},
	}, network, dcs
}

func newDCPoolTestStream(dcID int) *streamContext {
	ctx, cancel := context.WithCancel(context.Background())

	return &streamContext{
		ctx:       ctx,
		ctxCancel: cancel,
		streamID:  "test",
		dc:        dcID,
		logger:    NoopLogger{},
	}
}

func expectHandshakeDC(t *testing.T, dcs <-chan int, want int) {
	t.Helper()

	select {
	case got := <-dcs:
		if got != want {
			t.Fatalf("Telegram got a handshake for DC %d, want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Telegram got no handshake")
	}
}

// doTelegramCall hands out a warm connection without dialing.
func TestDoTelegramCallPoolHit(t *testing.T) {
	proxy, network, _ := newDCPoolTestProxy(t, false)

	pool := newTestPool(nil, 1, 20*time.Second)
	rec := &recorder{}
	pool.observe = rec.observe
	pool.alive = nil

	warm := &fakePoolConn{}
	pool.ready[2] = []warmConn{{conn: warm, addr: testAddr(), created: time.Now()}}
	proxy.dcPool = pool

	stream := newDCPoolTestStream(2)
	defer stream.ctxCancel()

	if err := proxy.doTelegramCall(stream); err != nil {
		t.Fatal(err)
	}

	traffic, ok := stream.telegramConn.(connTraffic)
	if !ok || traffic.Conn != warm {
		t.Fatalf("the stream must get the warm connection, got %#v", stream.telegramConn)
	}

	if n := network.dials.Load(); n != 0 {
		t.Fatalf("a pool hit must not dial, dialed %d times", n)
	}

	equalResults(t, rec.all(), []string{DCPoolResultHit})
}

// A secured (dd) client goes through the same doTelegramCall and gets a warm
// connection for the DC from its obfuscated2 handshake.
func TestDoTelegramCallPoolHitSecured(t *testing.T) {
	proxy, network, _ := newDCPoolTestProxy(t, false)

	secret := GenerateSecret("example.com")
	proxy.ctx = context.Background()
	proxy.secrets = []Secret{secret}
	proxy.secretNames = []string{"main"}
	proxy.antiReplayCache = &mapAntiReplayCache{seen: map[string]bool{}}
	proxy.securedFrameTimeout = time.Second

	pool := newTestPool(nil, 1, 20*time.Second)
	rec := &recorder{}
	pool.observe = rec.observe
	pool.alive = nil

	warm := &fakePoolConn{}
	pool.ready[2] = []warmConn{{conn: warm, addr: testAddr(), created: time.Now()}}
	proxy.dcPool = pool

	frame := &recordingConn{}
	if _, err := (obfuscation.Obfuscator{Secret: secret.Key[:]}).SendHandshake(frame, 2); err != nil {
		t.Fatal(err)
	}

	stream := newStreamContext(context.Background(), NoopLogger{}, securedTestConn(t, frame.buf.Bytes()))
	defer stream.ctxCancel()

	if err := proxy.doSecuredHandshake(stream, newConnRewind(stream.clientConn)); err != nil {
		t.Fatalf("secured handshake: %v", err)
	}

	if !stream.secured || stream.dc != 2 {
		t.Fatalf("unexpected stream state: secured=%v dc=%d", stream.secured, stream.dc)
	}

	if err := proxy.doTelegramCall(stream); err != nil {
		t.Fatal(err)
	}

	traffic, ok := stream.telegramConn.(connTraffic)
	if !ok || traffic.Conn != warm {
		t.Fatalf("the dd stream must get the warm connection, got %#v", stream.telegramConn)
	}

	if n := network.dials.Load(); n != 0 {
		t.Fatalf("a pool hit must not dial, dialed %d times", n)
	}

	equalResults(t, rec.all(), []string{DCPoolResultHit})
}

// doTelegramCall falls back to a cold dial on a pool miss.
func TestDoTelegramCallPoolMiss(t *testing.T) {
	proxy, network, dcs := newDCPoolTestProxy(t, false)

	pool := newTestPool(nil, 1, 20*time.Second)
	rec := &recorder{}
	pool.observe = rec.observe
	proxy.dcPool = pool

	stream := newDCPoolTestStream(2)
	defer stream.Close()

	if err := proxy.doTelegramCall(stream); err != nil {
		t.Fatal(err)
	}

	if stream.telegramConn == nil {
		t.Fatal("the stream must get a cold connection")
	}

	if n := network.dials.Load(); n != 1 {
		t.Fatalf("a pool miss must dial once, dialed %d times", n)
	}

	expectHandshakeDC(t, dcs, 2)
	equalResults(t, rec.all(), []string{DCPoolResultMiss})
}

// A DC outside the warmed set dials cold and reports nothing.
func TestDoTelegramCallUnwarmedDC(t *testing.T) {
	proxy, network, dcs := newDCPoolTestProxy(t, false)

	pool := newTestPool(nil, 1, 20*time.Second)
	rec := &recorder{}
	pool.observe = rec.observe
	proxy.dcPool = pool

	stream := newDCPoolTestStream(-4)
	defer stream.Close()

	if err := proxy.doTelegramCall(stream); err != nil {
		t.Fatal(err)
	}

	if n := network.dials.Load(); n != 1 {
		t.Fatalf("expected one cold dial, got %d", n)
	}

	expectHandshakeDC(t, dcs, -4)
	equalResults(t, rec.all(), nil)
}

// The real warm dial keeps the sign of a media DC and the CDN DC 203 in the
// handshake (both have built-in addresses), and a DC without an address is
// not pooled as the default DC via the fallback.
func TestDCPoolRealDialSignedAndCDN(t *testing.T) {
	proxy, _, dcs := newDCPoolTestProxy(t, true)

	pool := newTestPool(proxy.dialAndHandshake, 1, 20*time.Second)
	pool.dcs = []int{-2, 203, 7}
	pool.warm = map[int]struct{}{-2: {}, 203: {}, 7: {}}
	pool.cancel = func() {}

	defer pool.Shutdown()

	for _, dcID := range []int{-2, 203} {
		if err := pool.topUp(context.Background(), dcID); err != nil {
			t.Fatal(err)
		}

		expectHandshakeDC(t, dcs, dcID)

		conn, _, ok := pool.get(dcID)
		if !ok {
			t.Fatalf("expected a warm connection to DC %d", dcID)
		}

		conn.Close() //nolint: errcheck
	}

	// DC 7 has no address, the dial falls back to DC 2: not pooled under 7.
	if err := pool.topUp(context.Background(), 7); !errors.Is(err, errDCPoolFallback) {
		t.Fatalf("expected errDCPoolFallback for a DC without an address, got %v", err)
	}

	if n := len(pool.ready[7]); n != 0 {
		t.Fatalf("a fallback connection must not be pooled under DC 7, got %d", n)
	}
}
