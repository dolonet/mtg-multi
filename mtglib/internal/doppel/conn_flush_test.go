package doppel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are not parallel: some of them shorten connFlushTimeout.

func newPipeConn(t *testing.T) (Conn, net.Conn) {
	t.Helper()

	local, remote := net.Pipe()
	t.Cleanup(func() {
		local.Close()  //nolint: errcheck
		remote.Close() //nolint: errcheck
	})

	c := NewConn(context.Background(), essentials.WrapNetConn(local), Stats{k: 2.0, lambda: 0.01})
	t.Cleanup(c.Stop)

	return c, remote
}

// readRecords reads TLS records until EOF and returns their joined payload.
func readRecords(r io.Reader) ([]byte, error) {
	var payload bytes.Buffer

	header := make([]byte, tls.SizeHeader)

	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if errors.Is(err, io.EOF) {
				return payload.Bytes(), nil
			}

			return payload.Bytes(), err
		}

		size := int(binary.BigEndian.Uint16(header[3:]))
		if _, err := io.CopyN(&payload, r, int64(size)); err != nil {
			return payload.Bytes(), err
		}
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return b
}

func TestConnWriteBlocksWhileQueueIsFull(t *testing.T) {
	c, remote := newPipeConn(t)
	payload := randomBytes(t, ConnMaxBufferedBytes+3*tls.MaxRecordSize)

	type result struct {
		n   int
		err error
	}

	done := make(chan result, 1)

	go func() {
		n, err := c.Write(payload)
		done <- result{n, err}
	}()

	select {
	case <-done:
		t.Fatal("Write returned while the peer read nothing and the queue was full")
	case <-time.After(200 * time.Millisecond):
	}

	go io.Copy(io.Discard, remote) //nolint: errcheck

	select {
	case r := <-done:
		require.NoError(t, r.err)
		assert.Equal(t, len(payload), r.n)
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not return after the peer started reading")
	}
}

func TestConnCloseSendsQueuedData(t *testing.T) {
	for _, closeFn := range []struct {
		name string
		fn   func(Conn) error
	}{
		{"Close", Conn.Close},
		{"CloseWrite", Conn.CloseWrite},
	} {
		t.Run(closeFn.name, func(t *testing.T) {
			c, remote := newPipeConn(t)
			payload := randomBytes(t, 3*ConnMaxBufferedBytes+1234)

			type result struct {
				data []byte
				err  error
			}

			received := make(chan result, 1)

			go func() {
				data, err := readRecords(remote)
				received <- result{data, err}
			}()

			n, err := c.Write(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)

			// Most of the payload is still queued here: Close must deliver
			// it before closing the underlying connection.
			require.NoError(t, closeFn.fn(c))

			select {
			case r := <-received:
				require.NoError(t, r.err)
				assert.True(t, bytes.Equal(payload, r.data), "got %d of %d bytes", len(r.data), len(payload))
			case <-time.After(5 * time.Second):
				t.Fatal("the peer did not receive EOF")
			}

			_, err = c.Write([]byte{1})
			assert.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func TestConnCloseWriteReportsFlushTimeout(t *testing.T) {
	old := connFlushTimeout
	connFlushTimeout = 100 * time.Millisecond

	t.Cleanup(func() { connFlushTimeout = old })

	c, _ := newPipeConn(t) // nobody reads the remote end

	payload := randomBytes(t, 2*ConnMaxBufferedBytes)
	writeErr := make(chan error, 1)

	go func() {
		_, err := c.Write(payload)
		writeErr <- err
	}()

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	err := c.CloseWrite()

	assert.ErrorIs(t, err, ErrFlushTimeout)
	assert.Less(t, time.Since(start), 2*time.Second)

	// The blocked Write is released with an error as well.
	select {
	case err := <-writeErr:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Write was not released")
	}

	// Later calls report the same result.
	assert.ErrorIs(t, c.Close(), ErrFlushTimeout)
}
