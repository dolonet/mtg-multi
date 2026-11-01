package web_test

import (
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The frame format is defined by Telegram Desktop. The test pins the layout
// byte by byte: an 8-byte header with type, 24-bit stream ID and length, all
// big-endian.
func TestEncodeLayout(t *testing.T) {
	encoded := web.Encode(web.FrameData, 0x0102_03, []byte("abc"))

	assert.Equal(t, []byte{
		0x02,             // type
		0x01, 0x02, 0x03, // stream
		0x00, 0x00, 0x00, 0x03, // length
		'a', 'b', 'c',
	}, encoded)
}

func TestParseAllRoundTrip(t *testing.T) {
	body := append(
		web.Encode(web.FrameOpen, 7, nil),
		web.Encode(web.FrameData, 7, []byte("hello"))...,
	)
	body = append(body, web.Encode(web.FrameClose, 7, nil)...)

	frames, err := web.ParseAll(body, web.DefaultLimits())
	require.NoError(t, err)
	require.Len(t, frames, 3)

	assert.Equal(t, web.FrameOpen, frames[0].Type)
	assert.Equal(t, uint32(7), frames[0].StreamID)
	assert.Empty(t, frames[0].Payload)

	assert.Equal(t, web.FrameData, frames[1].Type)
	assert.Equal(t, []byte("hello"), frames[1].Payload)

	assert.Equal(t, web.FrameClose, frames[2].Type)
}

func TestParseAllMaxStreamID(t *testing.T) {
	frames, err := web.ParseAll(web.Encode(web.FrameOpen, web.MaxStreamID, nil), web.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, uint32(web.MaxStreamID), frames[0].StreamID)
}

// The body comes from the network, so parsing must reject garbage before any
// allocation: the declared length is not a promise but client-controlled input.
func TestParseAllRejects(t *testing.T) {
	limits := web.DefaultLimits()

	t.Run("empty body", func(t *testing.T) {
		_, err := web.ParseAll(nil, limits)
		assert.ErrorIs(t, err, web.ErrEmptyBatch)
	})

	t.Run("truncated header", func(t *testing.T) {
		_, err := web.ParseAll([]byte{0x02, 0x00, 0x00}, limits)
		assert.ErrorIs(t, err, web.ErrIncomplete)
	})

	t.Run("payload shorter than declared", func(t *testing.T) {
		frame := web.Encode(web.FrameData, 1, []byte("hello"))
		_, err := web.ParseAll(frame[:len(frame)-2], limits)
		assert.ErrorIs(t, err, web.ErrIncomplete)
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := web.ParseAll([]byte{0x7f, 0, 0, 1, 0, 0, 0, 0}, limits)
		assert.ErrorIs(t, err, web.ErrUnknownType)
	})

	t.Run("payload over limit", func(t *testing.T) {
		// A huge declared length with no data behind it: the classic attempt to
		// make the server allocate memory on someone else's word.
		_, err := web.ParseAll([]byte{0x02, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}, limits)
		assert.ErrorIs(t, err, web.ErrPayloadLimit)
	})

	// A length above 2^31 used to be converted to int before the checks. On a
	// 32-bit build it turned negative, slipped past them and panicked in the
	// slice expression, before any authentication (ValidateHello). With a
	// limit that does not stop it, it must still be a clean error.
	t.Run("huge length with a huge limit", func(t *testing.T) {
		for _, length := range [][4]byte{{0xff, 0xff, 0xff, 0xff}, {0x80, 0, 0, 0}, {0x7f, 0xff, 0xff, 0xf9}} {
			body := []byte{0x02, 0, 0, 1, length[0], length[1], length[2], length[3], 'x'}

			assert.NotPanics(t, func() {
				_, err := web.ParseAll(body, web.Limits{MaxFramePayloadLen: math.MaxInt})
				assert.Error(t, err)
			})
			assert.False(t, web.ValidateHello(body, web.Limits{MaxFramePayloadLen: math.MaxInt}))
		}
	})

	t.Run("negative limit", func(t *testing.T) {
		_, err := web.ParseAll(web.Encode(web.FrameOpen, 1, nil), web.Limits{MaxFramePayloadLen: -1})
		assert.ErrorIs(t, err, web.ErrPayloadLimit)
	})
}

func TestValidateClientShape(t *testing.T) {
	t.Run("valid frames", func(t *testing.T) {
		for name, frame := range map[string]web.Frame{
			"OPEN without payload":  {Type: web.FrameOpen, StreamID: 1},
			"CLOSE without payload": {Type: web.FrameClose, StreamID: 1},
			"DATA with payload":     {Type: web.FrameData, StreamID: 1, Payload: []byte("x")},
			"WINDOW with increment": {Type: web.FrameWindow, StreamID: 1, Payload: web.WindowPayload(1024)},
			"PONG on stream 0":      {Type: web.FramePong, StreamID: 0, Payload: []byte("t")},
		} {
			t.Run(name, func(t *testing.T) {
				assert.NoError(t, web.ValidateClientShape(frame))
			})
		}
	})

	t.Run("invalid frames", func(t *testing.T) {
		big := make([]byte, 65)

		for name, frame := range map[string]web.Frame{
			// Stream 0 is the control stream: the client sends only PONG on it.
			"DATA on stream 0":       {Type: web.FrameData, StreamID: 0, Payload: []byte("x")},
			"OPEN on stream 0":       {Type: web.FrameOpen, StreamID: 0},
			"PONG with long body":    {Type: web.FramePong, StreamID: 0, Payload: big},
			"OPEN with payload":      {Type: web.FrameOpen, StreamID: 1, Payload: []byte("x")},
			"DATA without payload":   {Type: web.FrameData, StreamID: 1},
			"WINDOW with zero":       {Type: web.FrameWindow, StreamID: 1, Payload: web.WindowPayload(0)},
			"WINDOW with bad length": {Type: web.FrameWindow, StreamID: 1, Payload: []byte{1, 2}},
			"PING from client":       {Type: web.FramePing, StreamID: 1},
			"WELCOME from client":    {Type: web.FrameWelcome, StreamID: 1},
			"HELLO on data stream":   {Type: web.FrameHello, StreamID: 1},
		} {
			t.Run(name, func(t *testing.T) {
				assert.ErrorIs(t, web.ValidateClientShape(frame), web.ErrInvalidShape)
			})
		}
	})
}

func TestValidateHello(t *testing.T) {
	limits := web.DefaultLimits()

	t.Run("exactly one HELLO version 1", func(t *testing.T) {
		assert.True(t, web.ValidateHello(web.Encode(web.FrameHello, 0, []byte{1}), limits))
	})

	t.Run("foreign version", func(t *testing.T) {
		assert.False(t, web.ValidateHello(web.Encode(web.FrameHello, 0, []byte{2}), limits))
	})

	t.Run("HELLO not on stream 0", func(t *testing.T) {
		assert.False(t, web.ValidateHello(web.Encode(web.FrameHello, 1, []byte{1}), limits))
	})

	t.Run("extra frame alongside", func(t *testing.T) {
		body := append(
			web.Encode(web.FrameHello, 0, []byte{1}),
			web.Encode(web.FrameOpen, 1, nil)...,
		)
		assert.False(t, web.ValidateHello(body, limits))
	})

	t.Run("empty body", func(t *testing.T) {
		assert.False(t, web.ValidateHello(nil, limits))
	})
}

func TestWindowAmount(t *testing.T) {
	amount, err := web.WindowAmount(web.WindowPayload(4096))
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), amount)

	_, err = web.WindowAmount(web.WindowPayload(0))
	assert.ErrorIs(t, err, web.ErrInvalidShape)
}

// /up bodies are read frame by frame; the reader must agree with ParseAll.
func TestFrameReader(t *testing.T) {
	limits := web.DefaultLimits()

	t.Run("round trip", func(t *testing.T) {
		body := append(web.Encode(web.FrameOpen, 1, nil), web.Encode(web.FrameData, 1, []byte("hello"))...)
		reader := web.NewFrameReader(bytes.NewReader(body), limits)

		frame, err := reader.Next()
		require.NoError(t, err)
		assert.Equal(t, web.FrameOpen, frame.Type)

		frame, err = reader.Next()
		require.NoError(t, err)
		assert.Equal(t, web.FrameData, frame.Type)
		assert.Equal(t, uint32(1), frame.StreamID)
		assert.Equal(t, []byte("hello"), frame.Payload)

		_, err = reader.Next()
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("truncated", func(t *testing.T) {
		frame := web.Encode(web.FrameData, 1, []byte("hello"))

		for _, cut := range []int{3, len(frame) - 2} {
			_, err := web.NewFrameReader(bytes.NewReader(frame[:cut]), limits).Next()
			assert.ErrorIs(t, err, web.ErrIncomplete)
		}
	})

	t.Run("over limit", func(t *testing.T) {
		_, err := web.NewFrameReader(bytes.NewReader([]byte{0x02, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}), limits).Next()
		assert.ErrorIs(t, err, web.ErrPayloadLimit)
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := web.NewFrameReader(bytes.NewReader([]byte{0x7f, 0, 0, 1, 0, 0, 0, 0}), limits).Next()
		assert.ErrorIs(t, err, web.ErrUnknownType)
	})
}
