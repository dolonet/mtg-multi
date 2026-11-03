package mtglib

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleServerHelloDelays(d serverHelloDelay, count int) []time.Duration {
	samples := make([]time.Duration, count)
	for i := range samples {
		samples[i] = d.sample()
	}

	slices.Sort(samples)

	return samples
}

// Not parallel: the sampling is CPU-bound and would disturb the timing
// checks of other tests in this package.
func TestServerHelloDelayLogNormal(t *testing.T) {
	const count = 100_000

	d := serverHelloDelay{min: 8 * time.Millisecond, max: 24 * time.Millisecond}
	samples := sampleServerHelloDelays(d, count)

	assert.GreaterOrEqual(t, samples[0], d.min)
	assert.LessOrEqual(t, samples[count-1], d.max)

	// The median is the geometric mean of the bounds.
	median := float64(samples[count/2])
	geometricMean := math.Sqrt(float64(d.min) * float64(d.max))
	assert.InDelta(t, geometricMean, median, geometricMean*0.03)

	// About 1% of the mass is clamped to each bound.
	atMin, atMax := 0, 0

	for _, v := range samples {
		switch v {
		case d.min:
			atMin++
		case d.max:
			atMax++
		}
	}

	assert.InDelta(t, 0.01, float64(atMin)/count, 0.005)
	assert.InDelta(t, 0.01, float64(atMax)/count, 0.005)

	// And the rest is spread over the range, not stuck at one value.
	assert.Less(t, samples[count/10], samples[count*9/10])
}

// Not parallel: the sampling is CPU-bound and would disturb the timing
// checks of other tests in this package.
func TestServerHelloDelayUniformFromZero(t *testing.T) {
	const count = 100_000

	d := serverHelloDelay{max: 20 * time.Millisecond}
	samples := sampleServerHelloDelays(d, count)

	assert.GreaterOrEqual(t, samples[0], time.Duration(0))
	assert.LessOrEqual(t, samples[count-1], d.max)
	assert.InDelta(t, float64(d.max)/2, float64(samples[count/2]), float64(d.max)*0.02)
	assert.InDelta(t, float64(d.max)/10, float64(samples[count/10]), float64(d.max)*0.02)
}

func TestServerHelloDelayFixedAndDisabled(t *testing.T) {
	t.Parallel()

	fixed := serverHelloDelay{min: 15 * time.Millisecond, max: 15 * time.Millisecond}
	for range 100 {
		require.Equal(t, 15*time.Millisecond, fixed.sample())
	}

	disabled := serverHelloDelay{}
	assert.False(t, disabled.enabled())
	assert.Zero(t, disabled.sample())

	started := time.Now()
	assert.True(t, disabled.wait(context.Background()))
	assert.Less(t, time.Since(started), 50*time.Millisecond)
}

func TestServerHelloDelayWait(t *testing.T) {
	t.Parallel()

	d := serverHelloDelay{min: 100 * time.Millisecond, max: 100 * time.Millisecond}

	started := time.Now()
	assert.True(t, d.wait(context.Background()))
	assert.GreaterOrEqual(t, time.Since(started), 100*time.Millisecond)

	long := serverHelloDelay{min: time.Hour, max: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)

	defer cancel()

	started = time.Now()
	assert.False(t, long.wait(ctx))
	assert.Less(t, time.Since(started), 5*time.Second)
}

func TestValidateServerHelloDelay(t *testing.T) {
	t.Parallel()

	const timeout = 10 * time.Second

	assert.NoError(t, ValidateServerHelloDelay(0, 0, timeout))
	assert.NoError(t, ValidateServerHelloDelay(0, 20*time.Millisecond, timeout))
	assert.NoError(t, ValidateServerHelloDelay(8*time.Millisecond, 24*time.Millisecond, timeout))
	assert.NoError(t, ValidateServerHelloDelay(time.Second, time.Second, timeout))

	for _, bounds := range [][2]time.Duration{
		{time.Millisecond, 0},
		{30 * time.Millisecond, 20 * time.Millisecond},
		{0, timeout},
		{-time.Millisecond, time.Millisecond},
	} {
		assert.ErrorIs(t, ValidateServerHelloDelay(bounds[0], bounds[1], timeout),
			ErrServerHelloDelayInvalid, "bounds %v", bounds)
	}
}
