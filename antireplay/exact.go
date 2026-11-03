package antireplay

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/mtglib"
)

const (
	// DefaultExactMaxSize is a recommended memory budget of the exact cache.
	//
	// With a 2-minute FakeTLS window entries live for about 4
	// minutes, so 16 MiB (about 210k entries) absorbs a sustained rate of
	// roughly 850 authenticated handshakes per second before the oldest
	// entries are dropped ahead of their TTL.
	DefaultExactMaxSize = 16 * 1024 * 1024 // 16MiB

	// ExactEntrySize is the memory accounted to one entry of the exact cache:
	// a 16-byte key and an 8-byte expiry in the FIFO ring, plus the same key
	// in the hash index with its share of the map overhead. The heap use of a
	// full cache measures 60-75 bytes per entry, depending on how full the
	// map is after its last growth.
	ExactEntrySize = 80

	exactKeySize   = 16
	exactShardBits = 6
	exactShards    = 1 << exactShardBits
)

type exactKey [exactKeySize]byte

type exactEntry struct {
	key       exactKey
	expiresAt int64
}

// exactShard is a FIFO of keys ordered by insertion time and a set of the
// same keys. All entries share one TTL, so the FIFO is also ordered by expiry
// and both expiration and eviction only ever touch its head.
type exactShard struct {
	mutex    sync.Mutex
	index    map[exactKey]struct{}
	ring     []exactEntry
	head     int
	size     int
	capacity int
}

func (s *exactShard) popFront() {
	delete(s.index, s.ring[s.head].key)

	s.head = (s.head + 1) % len(s.ring)
	s.size--
}

// seenBefore is an atomic test-and-insert: of several concurrent calls with
// the same key exactly one returns false.
func (s *exactShard) seenBefore(key exactKey, now, ttl int64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for s.size > 0 && s.ring[s.head].expiresAt <= now {
		s.popFront()
	}

	if _, ok := s.index[key]; ok {
		return true
	}

	if s.size == s.capacity {
		// Full before the TTL ran out: drop the oldest entry. Only
		// authenticated handshakes are inserted, so a peer without a secret
		// cannot push entries out; this happens only under a sustained load
		// above the budget (see DefaultExactMaxSize).
		s.popFront()
	}

	if s.size == len(s.ring) {
		s.grow()
	}

	s.ring[(s.head+s.size)%len(s.ring)] = exactEntry{key: key, expiresAt: now + ttl}
	s.size++
	s.index[key] = struct{}{}

	return false
}

// grow doubles the ring up to the shard capacity, so an idle proxy does not
// hold the whole memory budget.
func (s *exactShard) grow() {
	newLen := min(max(2*len(s.ring), 64), s.capacity)
	ring := make([]exactEntry, newLen)

	for i := range s.size {
		ring[i] = s.ring[(s.head+i)%len(s.ring)]
	}

	s.ring = ring
	s.head = 0
}

// Exact is an anti-replay cache without false positives: it remembers every
// digest for a fixed TTL and answers exactly whether it was seen within it.
// See [NewExact].
type Exact struct {
	ttl    time.Duration
	origin time.Time
	now    func() time.Time
	shards [exactShards]exactShard
}

// SeenBefore reports whether data was passed to it within the TTL and
// remembers it if not. Concurrent calls with the same data are serialized:
// exactly one of them returns false.
func (e *Exact) SeenBefore(data []byte) bool {
	digest := sha256.Sum256(data)

	key := exactKey{}
	copy(key[:], digest[:exactKeySize])

	shard := &e.shards[binary.LittleEndian.Uint64(digest[exactKeySize:])&(exactShards-1)]

	return shard.seenBefore(key, int64(e.now().Sub(e.origin)), int64(e.ttl))
}

// ReplayTTL returns how long a digest is remembered. mtglib uses it to check
// that the cache covers the whole FakeTLS timestamp window.
func (e *Exact) ReplayTTL() time.Duration {
	return e.ttl
}

// Len returns the number of digests currently stored, including expired ones
// that were not dropped yet.
func (e *Exact) Len() int {
	total := 0

	for i := range e.shards {
		e.shards[i].mutex.Lock()
		total += e.shards[i].size
		e.shards[i].mutex.Unlock()
	}

	return total
}

// Capacity returns the maximum number of digests the cache holds.
func (e *Exact) Capacity() int {
	return exactShards * e.shards[0].capacity
}

// NewExact returns an anti-replay cache that remembers every digest for ttl.
//
// Unlike a Bloom filter, it never reports a digest it has not seen, so honest
// clients are never mistaken for a replay. To make it a complete replay
// protection for FakeTLS, ttl must cover the whole interval in which a
// ClientHello timestamp is accepted, see [TTLForTimeSkewness]: a replay inside
// that interval is caught here, a later one by the timestamp check.
//
// Digests are stored as 128-bit truncated SHA-256 hashes of data in 64 shards,
// each with its own lock. maxSize bounds the memory: the cache holds at most
// maxSize / [ExactEntrySize] digests (at least one per shard), and when it is
// full the oldest digest is dropped even if its TTL has not run out yet.
// Memory is allocated as entries arrive, up to that bound. Pass 0 for maxSize
// to use [DefaultExactMaxSize].
func NewExact(ttl time.Duration, maxSize uint) *Exact {
	if maxSize == 0 {
		maxSize = DefaultExactMaxSize
	}

	shardCapacity := max(int(maxSize/ExactEntrySize/exactShards), 1) //nolint: gosec

	cache := &Exact{
		ttl:    ttl,
		origin: time.Now(),
		now:    time.Now,
	}

	for i := range cache.shards {
		cache.shards[i].capacity = shardCapacity
		cache.shards[i].index = make(map[exactKey]struct{})
	}

	return cache
}

// TTLForTimeSkewness returns the TTL an exact cache needs to cover the
// FakeTLS timestamp window of the given skewness: twice the skewness plus one
// second, see [mtglib.FakeTLSReplayTTL].
func TTLForTimeSkewness(skewness time.Duration) time.Duration {
	return mtglib.FakeTLSReplayTTL(skewness)
}

var _ mtglib.AntiReplayCache = (*Exact)(nil)
