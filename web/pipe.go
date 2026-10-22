package web

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// pipe is a buffer between the HTTP handler and a logical stream.
//
// Why not net.Pipe: net.Pipe is synchronous and has no capacity, so every
// write would wait for a matching read. Here the buffer works like a socket
// receive buffer: the /up handler puts data in and moves on while there is
// room, and waits (backpressure on the client) when there is none.
//
// Deadlines are mandatory: mtg calls SetDeadline for the handshake and expects
// Read to break out when it fires. Without that, a stalled client would hold a
// goroutine and a stats slot forever.
type pipe struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	changed  broadcast
	capacity int

	readClosed  bool
	writeClosed bool
	// err is the reason the stream ended (nil means a normal close).
	err error

	readDeadline  time.Time
	writeDeadline time.Time
}

// ErrPipeFull means the stream did not take the data in time: the reader
// (mtg) stopped reading, and holding the client any longer would stall the
// other streams of the session.
var ErrPipeFull = errors.New("web: stream buffer is full")

func newPipe(capacity int) *pipe {
	return &pipe{capacity: capacity}
}

// write puts data into the buffer, waiting for room until deadline or until
// done is closed. Data larger than the whole buffer can never fit and is
// refused at once; the frame limit keeps legitimate data below that.
func (p *pipe) write(data []byte, deadline time.Time, done <-chan struct{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(data) > p.capacity {
		return ErrPipeFull
	}

	for {
		if p.writeClosed || p.readClosed {
			return io.ErrClosedPipe
		}

		if p.buf.Len()+len(data) <= p.capacity {
			p.buf.Write(data)
			p.changed.notify()

			return nil
		}

		changed := p.changed.wait()
		p.mu.Unlock()
		err := waitChange(changed, deadline, done)
		p.mu.Lock()

		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			return ErrPipeFull
		case err != nil:
			return err
		}
	}
}

// Read returns buffered bytes, waiting for them until the deadline.
func (p *pipe) Read(dst []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		if p.buf.Len() > 0 {
			n, _ := p.buf.Read(dst)
			p.changed.notify() // room was freed

			return n, nil
		}

		if p.writeClosed {
			if p.err != nil {
				return 0, p.err
			}

			return 0, io.EOF
		}

		if p.readClosed {
			return 0, io.ErrClosedPipe
		}

		changed := p.changed.wait()
		deadline := p.readDeadline
		p.mu.Unlock()
		err := waitChange(changed, deadline, nil)
		p.mu.Lock()

		if err != nil {
			return 0, err
		}
	}
}

// closeWrite closes the write side: the reader drains the rest and then gets
// EOF (or the given reason).
func (p *pipe) closeWrite(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.writeClosed {
		return
	}

	p.writeClosed = true
	p.err = err
	p.changed.notify()
}

// closeRead closes the read side and discards unread data.
func (p *pipe) closeRead() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.readClosed = true
	p.buf.Reset()
	p.changed.notify()
}

func (p *pipe) setReadDeadline(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.readDeadline = t
	p.changed.notify()
}

func (p *pipe) setWriteDeadline(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.writeDeadline = t
	p.changed.notify()
}

func (p *pipe) getWriteDeadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.writeDeadline
}
