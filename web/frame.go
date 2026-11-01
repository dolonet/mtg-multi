package web

import (
	"encoding/binary"
	"errors"
	"io"
)

// The frame format is defined by Telegram Desktop and must not be changed:
//
//	byte 0      - frame type
//	bytes 1..3  - logical stream ID, big-endian, 24 bits
//	bytes 4..7  - payload length, big-endian, 32 bits
//	rest        - the payload itself
//
// A single HTTP body may carry several frames back to back.
const (
	// HeaderBytes is the frame header size.
	HeaderBytes = 8
	// MaxStreamID is the upper bound of the 24-bit stream ID.
	MaxStreamID = 0x00ff_ffff
	// InitialStreamWindow is the initial stream credit in both directions.
	InitialStreamWindow = 4 * 1024 * 1024
	// DataChunkBytes is the largest data chunk the server sends.
	DataChunkBytes = 64 * 1024
)

// FrameType is a frame type code.
type FrameType uint8

const (
	// FrameOpen opens a logical stream (one MTProto connection).
	FrameOpen FrameType = 0x01
	// FrameData carries stream bytes.
	FrameData FrameType = 0x02
	// FrameClose closes a stream.
	FrameClose FrameType = 0x03
	// FrameWindow returns consumed credit.
	FrameWindow FrameType = 0x04
	// FramePing requests a liveness signal.
	FramePing FrameType = 0x05
	// FramePong answers a FramePing.
	FramePong FrameType = 0x06
	// FrameHello starts a session.
	FrameHello FrameType = 0x10
	// FrameWelcome confirms that a session was created.
	FrameWelcome FrameType = 0x11
	// FrameBye ends a session.
	FrameBye FrameType = 0x1f
)

// String returns the type name for logs.
func (f FrameType) String() string {
	switch f {
	case FrameOpen:
		return "OPEN"
	case FrameData:
		return "DATA"
	case FrameClose:
		return "CLOSE"
	case FrameWindow:
		return "WINDOW"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameHello:
		return "HELLO"
	case FrameWelcome:
		return "WELCOME"
	case FrameBye:
		return "BYE"
	default:
		return "UNKNOWN"
	}
}

func parseFrameType(value byte) (FrameType, bool) {
	switch FrameType(value) {
	case FrameOpen, FrameData, FrameClose, FrameWindow,
		FramePing, FramePong, FrameHello, FrameWelcome, FrameBye:
		return FrameType(value), true
	default:
		return 0, false
	}
}

// Frame is a single parsed frame. Payload points into the source buffer and
// no copy is made: the request body outlives parsing.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

// Parse errors. They are never shown to the client: any failure means "this
// is not our client", and the request goes to the decoy.
var (
	// ErrEmptyBatch is returned for an empty request body.
	ErrEmptyBatch = errors.New("web: body has no frames")
	// ErrIncomplete is returned when a header or payload is truncated.
	ErrIncomplete = errors.New("web: truncated frame")
	// ErrPayloadLimit is returned when a payload exceeds the limit.
	ErrPayloadLimit = errors.New("web: frame payload exceeds limit")
	// ErrUnknownType is returned for an unknown type code.
	ErrUnknownType = errors.New("web: unknown frame type")
	// ErrInvalidShape is returned when a frame of a known type violates the
	// grammar of its direction.
	ErrInvalidShape = errors.New("web: invalid frame shape")
)

// Limits are the bounds the client cannot exceed.
//
// They are enforced before any allocation: the body comes from the network,
// and "allocate whatever we are told" is a direct path to memory exhaustion.
type Limits struct {
	MaxFramePayloadLen int
}

// DefaultLimits are sensible default values.
func DefaultLimits() Limits {
	return Limits{
		MaxFramePayloadLen: DataChunkBytes,
	}
}

// ParseAll parses every frame in the body without copying payloads.
func ParseAll(input []byte, limits Limits) ([]Frame, error) {
	if len(input) == 0 {
		return nil, ErrEmptyBatch
	}

	frames := make([]Frame, 0, 8)
	rest := input

	for len(rest) > 0 {
		if len(rest) < HeaderBytes {
			return nil, ErrIncomplete
		}

		frameType, ok := parseFrameType(rest[0])
		if !ok {
			return nil, ErrUnknownType
		}

		streamID := uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])

		// Compare in uint64 before converting to int: on a 32-bit build a
		// length above 2^31 would turn negative as an int and slip past the
		// checks into a slice expression that panics. This runs before any
		// authentication (ValidateHello), so it must hold for any input.
		payloadLen := binary.BigEndian.Uint32(rest[4:HeaderBytes])
		if !payloadWithinLimit(payloadLen, limits) {
			return nil, ErrPayloadLimit
		}

		if uint64(payloadLen) > uint64(len(rest)-HeaderBytes) {
			return nil, ErrIncomplete
		}

		frameLen := HeaderBytes + int(payloadLen)

		frames = append(frames, Frame{
			Type:     frameType,
			StreamID: streamID,
			Payload:  rest[HeaderBytes:frameLen],
		})

		rest = rest[frameLen:]
	}

	return frames, nil
}

func payloadWithinLimit(payloadLen uint32, limits Limits) bool {
	return limits.MaxFramePayloadLen >= 0 && uint64(payloadLen) <= uint64(limits.MaxFramePayloadLen)
}

// FrameReader reads frames one by one from a request body.
//
// The /up body is not read into memory as a whole: only one frame at a time,
// so a session costs one payload buffer however much the client batches.
type FrameReader struct {
	r       io.Reader
	limits  Limits
	header  [HeaderBytes]byte
	payload []byte
}

// NewFrameReader creates a reader. The payload buffer is reused between
// frames: a frame is valid only until the next call to Next.
func NewFrameReader(r io.Reader, limits Limits) *FrameReader {
	return &FrameReader{
		r:       r,
		limits:  limits,
		payload: make([]byte, max(limits.MaxFramePayloadLen, 0)),
	}
}

// Next returns the next frame. io.EOF means the body ended exactly on a frame
// boundary; a body cut inside a frame is ErrIncomplete.
func (f *FrameReader) Next() (Frame, error) {
	if _, err := io.ReadFull(f.r, f.header[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, ErrIncomplete
		}

		return Frame{}, err
	}

	frameType, ok := parseFrameType(f.header[0])
	if !ok {
		return Frame{}, ErrUnknownType
	}

	payloadLen := binary.BigEndian.Uint32(f.header[4:HeaderBytes])
	if !payloadWithinLimit(payloadLen, f.limits) {
		return Frame{}, ErrPayloadLimit
	}

	payload := f.payload[:payloadLen]
	if _, err := io.ReadFull(f.r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, ErrIncomplete
		}

		return Frame{}, err
	}

	return Frame{
		Type:     frameType,
		StreamID: uint32(f.header[1])<<16 | uint32(f.header[2])<<8 | uint32(f.header[3]),
		Payload:  payload,
	}, nil
}

// ValidateClientShape checks the grammar of frames sent by the client.
//
// Stream 0 is the control stream: the client sends only PONG on it. Anything
// else on stream 0, or any malformed frame, means a foreign or broken client.
func ValidateClientShape(frame Frame) error {
	if frame.StreamID == 0 {
		if frame.Type == FramePong && len(frame.Payload) <= 64 {
			return nil
		}

		return ErrInvalidShape
	}

	switch frame.Type {
	case FrameOpen, FrameClose:
		if len(frame.Payload) == 0 {
			return nil
		}

		return ErrInvalidShape
	case FrameData:
		if len(frame.Payload) > 0 {
			return nil
		}

		return ErrInvalidShape
	case FrameWindow:
		_, err := WindowAmount(frame.Payload)

		return err
	default:
		// A PING from the client also lands here: only the server requests
		// liveness.
		return ErrInvalidShape
	}
}

// ValidateHello checks the very first body of a session.
//
// It requires exactly one HELLO frame on stream 0 with payload [1], which is
// the protocol version. Nothing else may appear in the first body.
func ValidateHello(input []byte, limits Limits) bool {
	frames, err := ParseAll(input, limits)
	if err != nil {
		return false
	}

	return len(frames) == 1 &&
		frames[0].Type == FrameHello &&
		frames[0].StreamID == 0 &&
		len(frames[0].Payload) == 1 &&
		frames[0].Payload[0] == 1
}

// Encode serializes a complete frame.
func Encode(frameType FrameType, streamID uint32, payload []byte) []byte {
	out := make([]byte, HeaderBytes+len(payload))
	out[0] = byte(frameType)
	out[1] = byte(streamID >> 16)
	out[2] = byte(streamID >> 8)
	out[3] = byte(streamID)
	binary.BigEndian.PutUint32(out[4:HeaderBytes], uint32(len(payload)))
	copy(out[HeaderBytes:], payload)

	return out
}

// WindowAmount reads a credit increment. A zero increment is forbidden: it
// moves nothing but still makes the server work, a cheap way to keep it busy
// for nothing.
func WindowAmount(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, ErrInvalidShape
	}

	amount := binary.BigEndian.Uint32(payload)
	if amount == 0 {
		return 0, ErrInvalidShape
	}

	return amount, nil
}

// WindowPayload encodes a credit increment.
func WindowPayload(amount uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, amount)

	return out
}
