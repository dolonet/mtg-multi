// Antireplay package has cache implementations that are effective against
// replay attacks.
//
// To understand more about replay attacks, please read documentation for
// [mtglib.AntiReplayCache] interface. This package has a list of some
// implementations of this interface:
//
//   - [NewExact] remembers every digest for a fixed TTL and never reports a
//     digest it has not seen. It is meant for FakeTLS ClientHellos, whose
//     timestamp bounds how long a replay has to be remembered.
//   - [NewStableBloomFilter] has a fixed size and no TTL, but a false-positive
//     rate: some fresh digests are reported as seen.
//   - [NewNoop] accepts everything.
package antireplay

const (
	// DefaultStableBloomFilterMaxSize is a recommended byte size for a stable
	// bloom filter.
	DefaultStableBloomFilterMaxSize = 1024 * 1024 // 1MiB

	// DefaultStableBloomFilterErrorRate is a recommended default error rate for a
	// stable bloom filter.
	DefaultStableBloomFilterErrorRate = 0.001
)
