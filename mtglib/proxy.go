package mtglib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/dc"
	"github.com/dolonet/mtg-multi/mtglib/internal/doppel"
	"github.com/dolonet/mtg-multi/mtglib/internal/relay"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls/fake"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
	"github.com/panjf2000/ants/v2"
)

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	allowFallbackOnUnknownDC    bool
	pendingHandshakes           *pendingHandshakes
	pendingHandshakesPerIP      uint32
	pendingHandshakesDryRun     bool
	securedEnabled              bool
	securedFrameTimeout         time.Duration
	dcPool                      *dcPool
	tolerateTimeSkewness        time.Duration
	idleTimeout                 time.Duration
	handshakeTimeout            time.Duration
	domainFrontingPort          int
	domainFrontingHost          string
	domainFrontingProxyProtocol bool
	workerPool                  *ants.PoolWithFunc
	telegram                    *dc.Telegram
	configUpdater               *dc.PublicConfigUpdater
	doppelGanger                *doppel.Ganger

	stats           *ProxyStats
	secrets         []Secret
	secretNames     []string
	secretHostnames []string
	network         Network
	antiReplayCache AntiReplayCache
	blocklist       IPBlocklist
	allowlist       IPBlocklist
	eventStream     EventStream
	logger          Logger
}

// DomainFrontingAddress returns a host:port pair for a fronting domain.
// If a fronting host (literal IP or hostname) is configured, it is used
// instead of the secret's hostname. When secrets use different hostnames,
// pass the matched secret's host to front the correct domain.
func (p *Proxy) DomainFrontingAddress() string {
	return p.domainFrontingAddressForHost(p.secrets[0].Host)
}

func (p *Proxy) domainFrontingAddressForHost(host string) string {
	if p.domainFrontingHost != "" {
		host = p.domainFrontingHost
	}

	return net.JoinHostPort(host, strconv.Itoa(p.domainFrontingPort))
}

// ServeConn serves a connection. We do not check IP blocklist and concurrency
// limit here.
func (p *Proxy) ServeConn(conn essentials.Conn) {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	ctx := newStreamContext(p.ctx, p.logger, conn)
	defer ctx.Close()

	ctx.handshakeDeadline = time.Now().Add(p.handshakeTimeout)

	if err := ctx.clientConn.SetDeadline(ctx.handshakeDeadline); err != nil {
		ctx.logger.WarningError("cannot set handshake timeout", err)
		return
	}

	stop := context.AfterFunc(ctx, func() {
		ctx.Close()
	})
	defer stop()

	p.eventStream.Send(ctx, NewEventStart(ctx.streamID, ctx.ClientIP()))
	ctx.logger.Info("Stream has been started")

	defer func() {
		p.eventStream.Send(ctx, NewEventFinish(ctx.streamID))
		ctx.logger.Info("Stream has been finished")
	}()

	// Per-IP limit on pending (unauthenticated) handshakes. The slot is
	// released as soon as the secret is verified or the connection goes to the
	// fronting domain, so authenticated sessions never hold it.
	release, action, admitted := p.pendingHandshakes.acquire(
		ctx.ClientIP(), p.pendingHandshakesPerIP, p.pendingHandshakesDryRun)
	if action != "" {
		p.eventStream.Send(ctx, NewEventPendingHandshakeLimit(ctx.streamID, action))
	}

	if !admitted {
		ctx.logger.Info("too many pending handshakes from this ip")

		return
	}

	if release != nil {
		defer release()

		ctx.releasePendingHandshake = release
	}

	if !p.doFakeTLSHandshake(ctx) {
		return
	}

	ctx.finishPendingHandshake()

	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return
	}

	p.stats.OnConnect(ctx.secretName)
	p.stats.UpdateLastSeen(ctx.secretName)

	defer p.stats.OnDisconnect(ctx.secretName)

	// FakeTLS specifics: the doppelganger wrapper and a separate obfuscated2
	// handshake inside the unwrapped TLS stream. A secured client has already
	// done its obfuscated2 handshake in doSecuredHandshake.
	if !ctx.secured {
		clientConn, err := p.doppelGanger.NewConn(ctx.clientConn)
		if err != nil {
			ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
			return
		}
		defer clientConn.Stop()

		ctx.clientConn = clientConn

		if err := p.doObfuscatedHandshake(ctx); err != nil {
			ctx.logger.InfoError("obfuscated handshake is failed", err)
			return
		}
	}

	if err := ctx.clientConn.SetDeadline(time.Time{}); err != nil {
		ctx.logger.WarningError("cannot set deadline", err)
		return
	}

	if err := p.doTelegramCall(ctx); err != nil {
		ctx.logger.WarningError("cannot dial to telegram", err)
		return
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: ctx.telegramConn, tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, p.stats, ctx.secretName),
	)
}

// Serve starts a proxy on a given listener.
func (p *Proxy) Serve(listener net.Listener) error {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	for {
		conn, err := acceptWithRetry(p.ctx, listener, p.logger)
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}
		}

		ipAddr := conn.RemoteAddr().(*net.TCPAddr).IP //nolint: forcetypeassert
		logger := p.logger.BindStr("ip", ipAddr.String())

		if !p.allowlist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was rejected by allowlist")
			p.eventStream.Send(p.ctx, NewEventIPAllowlisted(ipAddr))

			continue
		}

		if p.blocklist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was blacklisted")
			p.eventStream.Send(p.ctx, NewEventIPBlocklisted(ipAddr))

			continue
		}

		err = p.workerPool.Invoke(conn)

		switch {
		case err == nil:
		case errors.Is(err, ants.ErrPoolClosed):
			return nil
		case errors.Is(err, ants.ErrPoolOverload):
			conn.Close() //nolint: errcheck
			logger.Info("connection was concurrency limited")
			p.eventStream.Send(p.ctx, NewEventConcurrencyLimited())
		}
	}
}

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	p.workerPool.Release()
	p.configUpdater.Wait()
	p.doppelGanger.Shutdown()

	p.allowlist.Shutdown()
	p.blocklist.Shutdown()

	if p.dcPool != nil {
		p.dcPool.Shutdown()
	}
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)

	// Build a slice of secret keys to try during HMAC validation.
	secretKeys := make([][]byte, len(p.secrets))
	for i := range p.secrets {
		secretKeys[i] = p.secrets[i].Key[:]
	}

	if p.securedEnabled {
		// Classify the transport before invoking a parser. A TLS ClientHello with
		// an invalid HMAC is an active probe and must reach the mask host byte for
		// byte; parsing its first 64 bytes as a secured handshake would consume and
		// corrupt the fallback stream.
		firstBytes := [5]byte{}
		if _, err := io.ReadFull(rewind, firstBytes[:]); err != nil {
			ctx.logger.InfoError("cannot read initial handshake bytes", err)
			p.doDomainFrontingForHost(ctx, rewind, p.secrets[0].Host)

			return false
		}

		rewind.Rewind()

		if !isFakeTLSHandshake(firstBytes) {
			// No obfuscated2 client starts with these bytes (an HTTP request,
			// for example): front right away, as with the option off, instead
			// of waiting for a 64-byte frame that will never come.
			if obfuscation.IsReservedFramePrefix(firstBytes[:4]) {
				ctx.logger.Info("first bytes cannot start a secured handshake")
				p.doDomainFrontingForHost(ctx, rewind, p.secrets[0].Host)

				return false
			}

			if err := p.doSecuredHandshake(ctx, rewind); err != nil {
				ctx.logger.InfoError("cannot process secured handshake", err)
				p.doDomainFrontingForHost(ctx, rewind, p.secrets[0].Host)

				return false
			}

			return true
		}
	}

	result, err := fake.ReadClientHelloMulti(
		rewind,
		secretKeys,
		p.secretHostnames,
		p.tolerateTimeSkewness,
	)
	if err != nil {
		p.logger.InfoError("cannot read client hello", err)

		frontHost := p.secrets[0].Host
		if result != nil && result.MatchedHost != "" {
			frontHost = result.MatchedHost
		}

		p.doDomainFrontingForHost(ctx, rewind, frontHost)

		return false
	}

	if p.antiReplayCache.SeenBefore(result.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	matchedSecret := p.secrets[result.MatchedIndex]
	ctx.matchedSecretKey = matchedSecret.Key[:]
	ctx.secretName = p.secretNames[result.MatchedIndex]
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	gangerNoise := p.doppelGanger.NoiseParams()
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	if err := fake.SendServerHello(ctx.clientConn, matchedSecret.Key[:], result.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.clientConn = tls.New(ctx.clientConn, true, false)

	return true
}

// isFakeTLSHandshake reports whether the first bytes look like a TLS 1.x
// ClientHello record (handshake type, version 3.1), which is what FakeTLS
// clients send.
func isFakeTLSHandshake(firstBytes [5]byte) bool {
	return firstBytes[0] == tls.TypeHandshake &&
		firstBytes[1] == 3 &&
		firstBytes[2] == 1
}

// doSecuredHandshake handles a secured ("dd") client: plain obfuscated2
// without FakeTLS. The secret is found by trying the keys of all configured
// secrets against the handshake frame (dd and ee secrets share the key).
func (p *Proxy) doSecuredHandshake(ctx *streamContext, rewind *connRewind) error {
	rewind.Rewind()

	secretKeys := make([][]byte, len(p.secrets))
	for i := range p.secrets {
		secretKeys[i] = p.secrets[i].Key[:]
	}

	idx, dcIdx, cn, replayKey, err := p.readSecuredFrame(ctx, rewind, secretKeys)
	if err != nil {
		return err
	}

	if p.antiReplayCache.SeenBefore(replayKey) {
		p.logger.Warning("replay attack has been detected (secured)!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))

		return errors.New("replay attack has been detected")
	}

	// Authenticated: stop recording the stream for replay.
	rewind.Commit()

	ctx.secured = true
	ctx.dc = dcIdx
	ctx.clientConn = cn
	ctx.matchedSecretKey = p.secrets[idx].Key[:]
	ctx.secretName = p.secretNames[idx]
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName).BindInt("dc", dcIdx)

	return nil
}

// readSecuredFrame reads the 64-byte obfuscated2 frame of a possible secured
// client under a short read deadline (securedFrameTimeout, capped by the
// handshake deadline). A real client sends the frame in one go, so a peer that
// stalls below 64 bytes is a probe and must reach the fronting host about as
// fast as with a real site, not after the whole handshake timeout. The bytes
// read so far stay in the rewind buffer for the fronting replay. The handshake
// deadline is restored in every case, so neither the fronting relay nor the
// secured session inherits the short one.
func (p *Proxy) readSecuredFrame(
	ctx *streamContext,
	rewind *connRewind,
	secretKeys [][]byte,
) (int, int, essentials.Conn, []byte, error) {
	deadline := time.Now().Add(p.securedFrameTimeout)
	if !ctx.handshakeDeadline.IsZero() && ctx.handshakeDeadline.Before(deadline) {
		deadline = ctx.handshakeDeadline
	}

	if err := ctx.clientConn.SetReadDeadline(deadline); err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot set secured frame deadline: %w", err)
	}

	defer ctx.clientConn.SetReadDeadline(ctx.handshakeDeadline) //nolint: errcheck

	idx, dcIdx, cn, replayKey, err := obfuscation.ReadHandshakeMulti(rewind, secretKeys)
	if err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot read secured handshake: %w", err)
	}

	return idx, dcIdx, cn, replayKey, nil
}

func (p *Proxy) doObfuscatedHandshake(ctx *streamContext) error {
	// Use the secret key that was matched during the FakeTLS handshake.
	obfs := obfuscation.Obfuscator{
		Secret: ctx.matchedSecretKey,
	}

	dc, conn, err := obfs.ReadHandshake(ctx.clientConn)
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.clientConn = conn
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	dcid := ctx.dc

	// Warm pool: if there is a ready connection to this DC, use it and skip the
	// cold dial and handshake (and the Telegram client backoff when the
	// node-to-DC route flaps).
	if p.dcPool != nil {
		if conn, addr, ok := p.dcPool.get(dcid); ok {
			p.attachTelegramConn(ctx, conn, addr)

			return nil
		}
	}

	conn, foundAddr, actualDC, err := p.dialAndHandshake(ctx, dcid)
	if err != nil {
		return err
	}

	if actualDC != dcid {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = actualDC
	}

	p.attachTelegramConn(ctx, conn, foundAddr)

	return nil
}

// dialAndHandshake dials dcID and performs the obfuscated2 handshake. It
// returns the wrapped connection (ready to relay), the chosen address and the
// actual DC (it may differ from the requested one with
// AllowFallbackOnUnknownDC). It does not touch streamContext, so both the
// client path and the dcPool fillers (which have no stream) use it.
func (p *Proxy) dialAndHandshake(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
	// Media DCs come with a negative id. Addresses are kept per absolute DC
	// number, but the sign must survive into the handshake with Telegram.
	lookupDC := dcID
	if lookupDC < 0 {
		lookupDC = -lookupDC
	}

	addresses := p.telegram.GetAddresses(lookupDC)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		if dcID < 0 {
			dcID = -dc.DefaultDC
		} else {
			dcID = dc.DefaultDC
		}

		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.DialContext(ctx, addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no available addresses for DC %d", dcID)
	}

	// The dial respects ctx, the handshake write does not: bound it by the ctx
	// deadline, if any (the dcPool fillers set one).
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetWriteDeadline(deadline) //nolint: errcheck
	}

	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, dcID)
	if err != nil {
		conn.Close() // nolint: errcheck

		return nil, dc.Addr{}, 0, fmt.Errorf("cannot perform server handshake: %w", err)
	}

	if hasDeadline {
		conn.SetWriteDeadline(time.Time{}) //nolint: errcheck
	}

	return tgConn, foundAddr, dcID, nil
}

// attachTelegramConn puts a ready (dialed and handshaked) DC connection on the
// stream and emits EventConnectedToDC. Shared tail of the cold dial and the
// warm pool paths.
func (p *Proxy) attachTelegramConn(ctx *streamContext, conn essentials.Conn, addr dc.Addr) {
	ctx.telegramConn = connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}

	if telegramHost, _, err := net.SplitHostPort(addr.Address); err == nil {
		p.eventStream.Send(
			ctx,
			NewEventConnectedToDC(ctx.streamID,
				net.ParseIP(telegramHost),
				ctx.dc),
		)
	}
}

func (p *Proxy) doDomainFrontingForHost(ctx *streamContext, conn *connRewind, host string) {
	// The handshake is over: a fronted connection must not hold a pending slot.
	ctx.finishPendingHandshake()

	p.eventStream.Send(p.ctx, NewEventDomainFronting(ctx.streamID))
	// No more protocol detection after this point: replay the recorded bytes
	// once and stop recording.
	conn.FinalRewind()

	nativeDialer := p.network.NativeDialer()
	fConn, err := nativeDialer.DialContext(ctx, "tcp", p.domainFrontingAddressForHost(host))
	if err != nil {
		p.logger.WarningError("cannot dial to the fronting domain", err)

		return
	}

	frontConn := essentials.WrapNetConn(fConn)

	if p.domainFrontingProxyProtocol {
		frontConn = newConnProxyProtocol(ctx.clientConn, frontConn)
	}

	frontConn = connTraffic{
		Conn:     frontConn,
		ctx:      ctx,
		streamID: ctx.streamID,
		stream:   p.eventStream,
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	secretsMap := opts.getSecrets()
	secretNames := make([]string, 0, len(secretsMap))

	for name := range secretsMap {
		secretNames = append(secretNames, name)
	}

	sort.Strings(secretNames)

	secretsList := make([]Secret, 0, len(secretsMap))

	for _, name := range secretNames {
		secretsList = append(secretsList, secretsMap[name])
	}

	// Collect unique hostnames across all secrets for SNI matching.
	hostnameSet := make(map[string]struct{}, len(secretsList))
	for _, s := range secretsList {
		hostnameSet[s.Host] = struct{}{}
	}

	secretHostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		secretHostnames = append(secretHostnames, h)
	}

	sort.Strings(secretHostnames)

	stats := NewProxyStats()
	for _, name := range secretNames {
		stats.PreRegister(name)
	}

	if opts.APIBindTo != "" {
		stats.StartServer(ctx, opts.APIBindTo, logger)
	}

	if opts.ThrottleMaxConnections > 0 {
		stats.SetThrottle(int64(opts.ThrottleMaxConnections), opts.getThrottleCheckInterval())
		stats.startThrottleLoop(ctx, logger)
	}

	if opts.DomainFrontingIP != "" {
		logger.Warning("mtglib.ProxyOpts.DomainFrontingIP is deprecated and ignored; use DomainFrontingHost instead")
	}

	proxy := &Proxy{
		ctx:                      ctx,
		ctxCancel:                cancel,
		stats:                    stats,
		secrets:                  secretsList,
		secretNames:              secretNames,
		secretHostnames:          secretHostnames,
		network:                  opts.Network,
		antiReplayCache:          opts.AntiReplayCache,
		blocklist:                opts.IPBlocklist,
		allowlist:                opts.IPAllowlist,
		eventStream:              opts.EventStream,
		logger:                   logger,
		domainFrontingPort:       opts.getDomainFrontingPort(),
		domainFrontingHost:       opts.DomainFrontingHost,
		tolerateTimeSkewness:     opts.getTolerateTimeSkewness(),
		idleTimeout:              opts.getIdleTimeout(),
		handshakeTimeout:         opts.getHandshakeTimeout(),
		allowFallbackOnUnknownDC: opts.AllowFallbackOnUnknownDC,
		pendingHandshakes:        newPendingHandshakes(),
		pendingHandshakesPerIP:   uint32(min(opts.PendingHandshakesPerIP, math.MaxUint32)), //nolint: gosec
		pendingHandshakesDryRun:  opts.PendingHandshakesDryRun,
		securedEnabled:           opts.SecuredEnabled,
		securedFrameTimeout:      opts.getSecuredFrameTimeout(),
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
		),
		configUpdater: dc.NewPublicConfigUpdater(
			tg,
			updatersLogger.Named("public-config"),
			opts.Network.MakeHTTPClient(nil),
		),
		domainFrontingProxyProtocol: opts.DomainFrontingProxyProtocol,
	}

	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	// Warm DC connection pool, opt-in. Fillers start right away and retry until
	// AutoUpdate brings DC addresses; clients are never blocked by it (a miss
	// falls back to a cold dial).
	if opts.DCPoolEnabled {
		proxy.dcPool = newDCPool(
			ctx,
			proxy.dialAndHandshake,
			logger.Named("dc-pool"),
			func(dcID int, result string) {
				proxy.eventStream.Send(proxy.ctx, NewEventDCPool(dcID, result))
			},
			opts.getDCPoolDCs(),
			opts.getDCPoolSize(),
			DCPoolConnMaxAge,
			DCPoolRefreshInterval,
		)
	}

	pool, err := ants.NewPoolWithFunc(opts.getConcurrency(),
		func(arg any) {
			proxy.ServeConn(arg.(essentials.Conn)) //nolint: forcetypeassert
		},
		ants.WithLogger(opts.getLogger("ants")),
		ants.WithNonblocking(true))
	if err != nil {
		panic(err)
	}

	proxy.workerPool = pool

	return proxy, nil
}
