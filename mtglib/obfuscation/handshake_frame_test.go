package obfuscation

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type HandshakeFrameTestSuite struct {
	suite.Suite

	frame    handshakeFrame
	reverted handshakeFrame
}

func (h *HandshakeFrameTestSuite) SetupSuite() {
	for i := range hfLen {
		h.frame.data[i] = byte(i + 1)
		h.reverted.data[i] = byte(hfLen - i)
	}
}

func (h *HandshakeFrameTestSuite) TestKey() {
	key := h.frame.key()
	h.EqualValues(8+1, key[0])
	h.EqualValues(8+hfLenKey, key[len(key)-1])
	h.Len(key, hfLenKey)
}

func (h *HandshakeFrameTestSuite) TestIV() {
	iv := h.frame.iv()
	h.EqualValues(40+1, iv[0])
	h.EqualValues(40+hfLenIV, iv[len(iv)-1])
	h.Len(iv, hfLenIV)
}

func (h *HandshakeFrameTestSuite) TestConnectionType() {
	connectionType := h.frame.connectionType()
	h.EqualValues(56+1, connectionType[0])
	h.EqualValues(56+hfLenConnectionType, connectionType[len(connectionType)-1])
	h.Len(connectionType, hfLenConnectionType)
}

func (h *HandshakeFrameTestSuite) TestDCSlice() {
	dcSlice := h.frame.dcSlice()
	h.EqualValues(61, dcSlice[0])
	h.EqualValues(61+1, dcSlice[1])
	h.Len(dcSlice, 2)
}

func (h *HandshakeFrameTestSuite) TestDC() {
	h.Equal(15933, h.frame.dc())
}

func (h *HandshakeFrameTestSuite) TestNegativeDC() {
	frame := h.frame
	frame.dcSlice()[0] = 0xfe
	frame.dcSlice()[1] = 0xff

	h.Equal(-2, frame.dc())
}

func (h *HandshakeFrameTestSuite) TestInt16MinimumDC() {
	frame := h.frame
	frame.dcSlice()[0] = 0x00
	frame.dcSlice()[1] = 0x80

	h.Equal(-32768, frame.dc())
}

func (h *HandshakeFrameTestSuite) TestRevert() {
	fr := h.frame
	fr.revert()

	h.Equal(h.reverted.key(), fr.key())
	h.Equal(h.reverted.iv(), fr.iv())
}

func TestHandshakeFrame(t *testing.T) {
	t.Parallel()
	suite.Run(t, &HandshakeFrameTestSuite{})
}

func TestIsReservedFramePrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		prefix []byte
		want   bool
	}{
		"http get":            {[]byte("GET / HTTP/1.1\r\n\r\n"), true},
		"http post":           {[]byte("POST"), true},
		"http head":           {[]byte("HEAD"), true},
		"http options":        {[]byte("OPTIONS * HTTP/1.1"), true},
		"abridged":            {[]byte{0xef, 0x01, 0x02, 0x03}, true},
		"intermediate":        {[]byte{0xee, 0xee, 0xee, 0xee}, true},
		"padded intermediate": {[]byte{0xdd, 0xdd, 0xdd, 0xdd}, true},
		"tls handshake":       {[]byte{0x16, 0x03, 0x01, 0x02}, true},
		"random":              {[]byte{0x91, 0x82, 0x07, 0x14}, false},
		"too short":           {[]byte("GET"), false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := IsReservedFramePrefix(tt.prefix); got != tt.want {
				t.Fatalf("IsReservedFramePrefix(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

// A generated handshake never starts with a reserved prefix, so a reserved
// prefix can be rejected without waiting for the rest of the frame.
func TestGenerateHandshakeAvoidsReservedPrefix(t *testing.T) {
	t.Parallel()

	for range 1000 {
		frame := generateHandshake(2)
		if IsReservedFramePrefix(frame.data[:4]) {
			t.Fatalf("generated frame starts with a reserved prefix: %x", frame.data[:4])
		}
	}
}
