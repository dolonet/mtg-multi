package mtglib

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// serverHelloLogNormalSpread is the width of the central 98% of a standard
// normal distribution (2 * 2.326): sigma is chosen so that 98% of the
// log-normal samples fall between min and max before clamping.
const serverHelloLogNormalSpread = 4.65

// serverHelloDelay is the pause before the FakeTLS server answers a
// ClientHello, see ProxyOpts.ServerHelloDelayMax. The same delay is applied
// whether the answer is a ServerHello or the ClientHello goes to the fronting
// host, so the time to the first answer byte does not tell them apart.
type serverHelloDelay struct {
	min time.Duration
	max time.Duration
}

func (d serverHelloDelay) enabled() bool {
	return d.max > 0
}

// sample returns a random delay in [min, max].
//
// With min > 0 it is log-normal with the median at the geometric mean of min
// and max and 98% of the mass inside the bounds (the rest is clamped), which
// is what network round trips look like. With min = 0 a log-normal cannot be
// anchored, so it is uniform in [0, max].
func (d serverHelloDelay) sample() time.Duration {
	switch {
	case !d.enabled():
		return 0
	case d.min >= d.max:
		return d.max
	case d.min <= 0:
		return time.Duration(rand.Int64N(int64(d.max) + 1)) //nolint: gosec
	}

	low, high := float64(d.min), float64(d.max)
	mu := (math.Log(low) + math.Log(high)) / 2
	sigma := math.Log(high/low) / serverHelloLogNormalSpread
	raw := math.Exp(mu + sigma*rand.NormFloat64()) //nolint: gosec

	return time.Duration(min(max(raw, low), high))
}

// wait sleeps for a sampled delay. It returns false if ctx was done first.
func (d serverHelloDelay) wait(ctx context.Context) bool {
	delay := d.sample()
	if delay <= 0 {
		return true
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
