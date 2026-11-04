package doppel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls"
)

// ConnMaxBufferedBytes bounds the data queued for the client. Write blocks
// while the queue is full, so a client that reads slowly throttles the
// Telegram side instead of making the proxy buffer it in memory.
const ConnMaxBufferedBytes = 4 * tls.MaxRecordSize

// ErrFlushTimeout is returned by Close and CloseWrite when the queued data
// was not sent within the flush timeout.
var ErrFlushTimeout = errors.New("doppel: timeout while flushing queued data")

// connFlushTimeout bounds how long Close and CloseWrite wait for the queued
// data to be sent. A variable so that tests can shorten it.
var connFlushTimeout = 3 * time.Second

var doppelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, tls.MaxRecordSize)
		return &b
	},
}

type Conn struct {
	essentials.Conn

	p *connPayload
}

type connPayload struct {
	ctx         context.Context
	ctxCancel   context.CancelCauseFunc
	stats       Stats
	wg          sync.WaitGroup
	writeStream bytes.Buffer
	// writtenCond is broadcast when data is queued, when queue space is
	// freed and when the connection is closed or its context is done.
	writtenCond sync.Cond
	// done is set by Stop: queued data is dropped.
	done bool
	// closed is set by Close/CloseWrite: queued data is still sent, but no
	// new data is accepted.
	closed bool

	// senderDone is closed when the sender goroutine exits.
	senderDone chan struct{}
	flushOnce  sync.Once
	flushErr   error
}

// Write queues p for the sender. It blocks while the queue holds
// ConnMaxBufferedBytes; a blocked Write is released when the sender frees
// space, when the connection is closed or stopped, or when the sender fails
// (for example, on a write deadline of the underlying connection).
func (c Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, context.Cause(c.p.ctx)
	}

	c.p.writtenCond.L.Lock()
	defer c.p.writtenCond.L.Unlock()

	written := 0

	for written < len(p) {
		for c.p.writeStream.Len() >= ConnMaxBufferedBytes && c.p.writable() {
			c.p.writtenCond.Wait()
		}

		if err := context.Cause(c.p.ctx); err != nil {
			return written, err //nolint: wrapcheck
		}

		if c.p.done || c.p.closed {
			return written, net.ErrClosed
		}

		chunk := min(ConnMaxBufferedBytes-c.p.writeStream.Len(), len(p)-written)
		c.p.writeStream.Write(p[written : written+chunk])
		written += chunk

		c.p.writtenCond.Broadcast()
	}

	return written, nil
}

// writable reports whether new data may still be queued. It must be called
// with writtenCond.L held.
func (p *connPayload) writable() bool {
	return !p.done && !p.closed && p.ctx.Err() == nil
}

// CloseWrite sends the queued data and then shuts down the write side of the
// underlying connection. If the data cannot be sent within the flush timeout,
// the underlying connection is closed and ErrFlushTimeout is returned.
func (c Conn) CloseWrite() error {
	if err := c.flush(); err != nil {
		return err
	}

	return c.Conn.CloseWrite() //nolint: wrapcheck
}

// Close sends the queued data and then closes the underlying connection. A
// flush error takes precedence over the error of closing.
func (c Conn) Close() error {
	flushErr := c.flush()
	closeErr := c.Conn.Close()

	if flushErr != nil {
		return flushErr
	}

	return closeErr //nolint: wrapcheck
}

// flush closes the queue for new data and waits until the sender has sent
// what is queued, keeping the usual pacing. It runs once; later calls return
// the same result.
func (c Conn) flush() error {
	c.p.flushOnce.Do(func() {
		c.p.writtenCond.L.Lock()
		c.p.closed = true
		c.p.writtenCond.L.Unlock()
		c.p.writtenCond.Broadcast()

		timer := time.NewTimer(connFlushTimeout)
		defer timer.Stop()

		select {
		case <-c.p.senderDone:
		case <-timer.C:
			c.p.ctxCancel(ErrFlushTimeout)
			// The sender may be blocked in a network write to a peer that
			// does not read; closing the connection releases it.
			c.Conn.Close() //nolint: errcheck
			<-c.p.senderDone
		}

		c.p.writtenCond.L.Lock()
		lost := c.p.writeStream.Len()
		c.p.writtenCond.L.Unlock()

		if err := context.Cause(c.p.ctx); err != nil && (lost > 0 || errors.Is(err, ErrFlushTimeout)) {
			c.p.flushErr = err
		}
	})

	return c.p.flushErr
}

func (c Conn) start() {
	defer close(c.p.senderDone)

	bp := doppelBufPool.Get().(*[]byte)
	buf := *bp
	defer doppelBufPool.Put(bp)

	timer := time.NewTimer(c.p.stats.Delay())
	defer timer.Stop()

	for {
		select {
		case <-c.p.ctx.Done():
			return
		case <-timer.C:
			timer.Reset(c.p.stats.Delay())
		}

		size := c.p.stats.Size()

		c.p.writtenCond.L.Lock()
		for c.p.writeStream.Len() == 0 && c.p.writable() {
			c.p.writtenCond.Wait()
		}

		// An empty queue here means the connection was closed (everything
		// is sent), stopped or its context is done.
		if c.p.writeStream.Len() == 0 {
			c.p.writtenCond.L.Unlock()
			return
		}

		n, _ := c.p.writeStream.Read(buf[tls.SizeHeader : tls.SizeHeader+size])
		c.p.writtenCond.L.Unlock()
		c.p.writtenCond.Broadcast()

		if err := tls.WriteRecordInPlace(c.Conn, buf, n); err != nil {
			c.p.ctxCancel(err)
			return
		}
	}
}

func (c Conn) Stop() {
	c.p.ctxCancel(nil)

	c.p.writtenCond.L.Lock()
	c.p.done = true
	c.p.writtenCond.L.Unlock()
	c.p.writtenCond.Broadcast()

	c.p.wg.Wait()
}

func NewConn(ctx context.Context, conn essentials.Conn, stats Stats) Conn {
	ctx, cancel := context.WithCancelCause(ctx)
	rv := Conn{
		Conn: conn,
		p: &connPayload{
			ctx:       ctx,
			ctxCancel: cancel,
			stats:     stats,
			writtenCond: sync.Cond{
				L: &sync.Mutex{},
			},
			senderDone: make(chan struct{}),
		},
	}

	rv.p.writeStream.Grow(tls.DefaultBufferSize)

	// Wake a blocked Write or the waiting sender when the context is done.
	// Taking the lock orders the broadcast after a waiter's check.
	context.AfterFunc(ctx, func() {
		rv.p.writtenCond.L.Lock()
		rv.p.writtenCond.L.Unlock() //nolint: staticcheck
		rv.p.writtenCond.Broadcast()
	})

	rv.p.wg.Go(func() {
		rv.start()
	})

	return rv
}
