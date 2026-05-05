package dcprobe_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib/dcprobe"
)

// TestProbeAgainstTelegramDCs makes outbound TCP connections to public
// Telegram DCs. Skipped by default; opt-in with MTG_PROBE_NETWORK=1.
func TestProbeAgainstTelegramDCs(t *testing.T) {
	if os.Getenv("MTG_PROBE_NETWORK") != "1" {
		t.Skip("skipping network probe (set MTG_PROBE_NETWORK=1 to enable)")
	}

	cases := []struct {
		dc   int
		addr string
	}{
		{1, "149.154.175.50:443"},
		{2, "149.154.167.51:443"},
		{2, "95.161.76.100:443"},
		{3, "149.154.175.100:443"},
		{4, "149.154.167.91:443"},
		{5, "149.154.171.5:443"},
		{1, "[2001:b28:f23d:f001::a]:443"},
		{2, "[2001:67c:04e8:f002::a]:443"},
	}

	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			d := net.Dialer{}
			rawConn, err := d.DialContext(ctx, "tcp", tc.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer rawConn.Close() //nolint: errcheck

			conn, ok := rawConn.(essentials.Conn)
			if !ok {
				t.Fatalf("dialed conn does not satisfy essentials.Conn (type %T)", rawConn)
			}

			rtt, err := dcprobe.Probe(ctx, conn, tc.dc)
			if err != nil {
				t.Fatalf("probe DC %d: %v", tc.dc, err)
			}
			t.Logf("DC %d (%s): rtt=%s", tc.dc, tc.addr, rtt)
		})
	}
}

// TestErrNotTelegramOnRandomService dials something that is not a Telegram DC
// and confirms the probe rejects it via ErrNotTelegram (or a network error).
// Opt-in: requires MTG_PROBE_NETWORK=1 and MTG_PROBE_FAKE_TARGET set to
// "host:port" of a TCP service that is NOT a Telegram DC (e.g. a local
// nginx on :443).
func TestErrNotTelegramOnRandomService(t *testing.T) {
	if os.Getenv("MTG_PROBE_NETWORK") != "1" {
		t.Skip("skipping network probe (set MTG_PROBE_NETWORK=1 to enable)")
	}

	target := os.Getenv("MTG_PROBE_FAKE_TARGET")
	if target == "" {
		t.Skip("set MTG_PROBE_FAKE_TARGET=host:port to a non-Telegram listener")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d := net.Dialer{}
	rawConn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial fake target: %v", err)
	}
	defer rawConn.Close() //nolint: errcheck

	conn, ok := rawConn.(essentials.Conn)
	if !ok {
		t.Fatalf("dialed conn does not satisfy essentials.Conn (type %T)", rawConn)
	}

	_, err = dcprobe.Probe(ctx, conn, 2)
	if err == nil {
		t.Fatalf("expected probe failure against %s, got nil", target)
	}
	t.Logf("probe vs %s: %v (errors.Is(ErrNotTelegram)=%v)",
		target, err, errors.Is(err, dcprobe.ErrNotTelegram))
}
