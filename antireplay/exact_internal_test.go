package antireplay

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mutex sync.Mutex
	now   time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.now = c.now.Add(d)
}

func newExactWithClock(ttl time.Duration, maxSize uint) (*Exact, *fakeClock) {
	cache := NewExact(ttl, maxSize)
	clock := &fakeClock{now: cache.origin}
	cache.now = clock.Now

	return cache, clock
}

func randomDigest(t testing.TB) []byte {
	t.Helper()

	data := make([]byte, 32)
	_, err := rand.Read(data)
	require.NoError(t, err)

	return data
}

func TestExactRejectsReplay(t *testing.T) {
	t.Parallel()

	cache, _ := newExactWithClock(time.Minute, 0)
	digest := randomDigest(t)

	assert.False(t, cache.SeenBefore(digest))
	assert.True(t, cache.SeenBefore(digest))
	assert.True(t, cache.SeenBefore(append([]byte(nil), digest...)))
	assert.Equal(t, 1, cache.Len())
}

// The stable Bloom filter of the default size and error rate settles at
// about 1.2 false positives per 1000 fresh digests after a couple of million
// handshakes; the exact cache must never report a digest it has not seen.
func TestExactNoFalsePositives(t *testing.T) {
	t.Parallel()

	const count = 100_000

	cache, _ := newExactWithClock(time.Hour, 0)
	require.GreaterOrEqual(t, cache.Capacity(), count)

	digests := make([][]byte, count)

	for i := range digests {
		digests[i] = randomDigest(t)

		require.False(t, cache.SeenBefore(digests[i]), "digest %d", i)
	}

	for i, digest := range digests {
		require.True(t, cache.SeenBefore(digest), "digest %d", i)
	}

	assert.Equal(t, count, cache.Len())
}

func TestExactTTL(t *testing.T) {
	t.Parallel()

	cache, clock := newExactWithClock(10*time.Second, 0)
	first := randomDigest(t)
	second := randomDigest(t)

	assert.False(t, cache.SeenBefore(first))
	clock.Advance(5 * time.Second)
	assert.False(t, cache.SeenBefore(second))

	clock.Advance(5*time.Second - time.Nanosecond)
	assert.True(t, cache.SeenBefore(first), "still inside the TTL")

	clock.Advance(time.Nanosecond)
	assert.False(t, cache.SeenBefore(first), "TTL has run out")
	assert.True(t, cache.SeenBefore(second), "the newer digest is kept")

	clock.Advance(5 * time.Second)
	assert.False(t, cache.SeenBefore(second))
	assert.Equal(t, 2, cache.Len(), "expired entries are dropped")
}

func TestExactCapacityEvictsOldest(t *testing.T) {
	t.Parallel()

	// One entry per shard.
	cache, clock := newExactWithClock(time.Hour, 1)
	require.Equal(t, exactShards, cache.Capacity())

	digests := make([][]byte, 10*exactShards)
	for i := range digests {
		digests[i] = randomDigest(t)

		cache.SeenBefore(digests[i])
		clock.Advance(time.Millisecond)

		require.LessOrEqual(t, cache.Len(), cache.Capacity())
	}

	// The last digest is always the newest in its shard.
	assert.True(t, cache.SeenBefore(digests[len(digests)-1]))
	assert.Equal(t, cache.Capacity(), cache.Len())
}

func TestExactShardFIFO(t *testing.T) {
	t.Parallel()

	shard := &exactShard{capacity: 3, index: map[exactKey]struct{}{}}
	key := func(i byte) exactKey { return exactKey{i} }

	assert.False(t, shard.seenBefore(key(1), 0, 100))
	assert.False(t, shard.seenBefore(key(2), 1, 100))
	assert.False(t, shard.seenBefore(key(3), 2, 100))
	assert.False(t, shard.seenBefore(key(4), 3, 100), "evicts 1")

	assert.False(t, shard.seenBefore(key(1), 4, 100), "1 was evicted, evicts 2")
	assert.True(t, shard.seenBefore(key(3), 5, 100))
	assert.True(t, shard.seenBefore(key(4), 5, 100))
	assert.True(t, shard.seenBefore(key(1), 5, 100))
	assert.False(t, shard.seenBefore(key(2), 5, 100))

	assert.False(t, shard.seenBefore(key(5), 1000, 100), "everything expired")
	assert.Equal(t, 1, shard.size)
	assert.Len(t, shard.index, 1)
}

// Concurrent handshakes with the same ClientHello must not both pass.
func TestExactConcurrentDuplicates(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 32
		digests    = 200
	)

	cache := NewExact(time.Hour, 0)
	keys := make([][]byte, digests)

	for i := range keys {
		keys[i] = randomDigest(t)
	}

	accepted := make([]atomic.Int32, digests)
	start := make(chan struct{})
	wg := sync.WaitGroup{}

	for range goroutines {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			for i, key := range keys {
				if !cache.SeenBefore(key) {
					accepted[i].Add(1)
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	for i := range accepted {
		assert.EqualValues(t, 1, accepted[i].Load(), "digest %d", i)
	}
}

// The heap actually used must stay within the configured budget, also after
// the cache was overfilled many times.
func TestExactMemoryBound(t *testing.T) {
	const maxSize = 4 * 1024 * 1024

	measure := func() uint64 {
		runtime.GC()

		stats := runtime.MemStats{}
		runtime.ReadMemStats(&stats)

		return stats.HeapAlloc
	}

	before := measure()
	cache := NewExact(time.Hour, maxSize)
	data := make([]byte, 8)

	for i := range 4 * cache.Capacity() {
		binary.LittleEndian.PutUint64(data, uint64(i)) //nolint: gosec
		cache.SeenBefore(data)
	}

	used := measure() - before

	require.Equal(t, cache.Capacity(), cache.Len())
	t.Logf("%d entries take %d bytes (%.1f per entry, budget %d)",
		cache.Len(), used, float64(used)/float64(cache.Len()), maxSize)
	assert.LessOrEqual(t, used, uint64(maxSize))

	runtime.KeepAlive(cache)
}

func TestTTLForTimeSkewness(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 241*time.Second, TTLForTimeSkewness(2*time.Minute))
	assert.Equal(t, 7*time.Second, TTLForTimeSkewness(3*time.Second))
}

func BenchmarkExactSeenBefore(b *testing.B) {
	cache := NewExact(time.Minute, 0)
	data := make([]byte, 32)

	b.RunParallel(func(pb *testing.PB) {
		local := make([]byte, len(data))
		_, _ = rand.Read(local)

		for i := uint64(0); pb.Next(); i++ {
			binary.LittleEndian.PutUint64(local, i)
			cache.SeenBefore(local)
		}
	})
}
