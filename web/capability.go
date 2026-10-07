// Package web implements the WEB mode: MTProto inside plain HTTPS.
//
// How it works on the client side. The user receives a link
// tg://webproxy?server=<host>&secret=dd<key>. Telegram Desktop derives a
// 32-byte value (called capability here) from the secret and the host, opens
// https://<host>/?bridge=<base64url(capability)> in a webview and hands the
// page a MessagePort. We serve the page with the JS; it shuttles frames
// between the port and HTTP requests to us. The frames carry regular
// obfuscated MTProto with the same secret, so the existing mtg path takes over
// from there.
//
// Exactly two things are fixed by Telegram Desktop: the capability formula
// (this file) and the frame format (frame.go). The transport between the page
// and the server is not fixed by Telegram, because the server ships the page
// itself.
//
// Origin: this is the WEB proxy protocol of Telegram Desktop. Its server side
// was first implemented in the telemt project (https://github.com/telemt/telemt).
// The Go server side here (this package except the bridge page) is written
// anew after telemt's protocol. The bridge page and its HTML, CSP and
// Permissions-Policy (bridge.go, bridge/runtime.js) are adapted from telemt,
// and the capability test vectors in capability_test.go are taken from it.
// Those parts are Copyright (c) 2026 Telemt and are used under the TELEMT
// LICENSE 3.3, whose full text is in web/LICENSE.telemt; the adapted files
// list their changes in their headers.
package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// capabilityContext is a Telegram Desktop protocol constant. It must not be
// changed: the client computes the HMAC with exactly this string, including
// the trailing newline.
const capabilityContext = "tdesktop-web-proxy-bridge-v1\n"

// CapabilityLen is the length of the value the client presents to the server.
const CapabilityLen = sha256.Size

// bridgeQueryLen is the length of base64url(32 bytes) without padding.
const bridgeQueryLen = 43

// SecretMode describes the form in which the key is put into the user link.
//
// Both the secret and the capability depend on it: the client computes the
// HMAC over the key exactly as it appears in the link.
type SecretMode string

const (
	// SecretModePlain means the link carries the bare 16-byte key.
	SecretModePlain SecretMode = "plain"
	// SecretModeDD means the link carries a dd key: the 0xdd byte followed by 16 bytes.
	SecretModeDD SecretMode = "dd"
)

// ErrEmptySecret is returned for an empty key: an HMAC without a key is
// meaningless, so this is a configuration error.
var ErrEmptySecret = errors.New("web: user secret is empty")

// ClientSecret builds the key in the form the client sees it.
func ClientSecret(secret []byte, mode SecretMode) []byte {
	if mode == SecretModeDD {
		out := make([]byte, 0, len(secret)+1)
		out = append(out, 0xdd)

		return append(out, secret...)
	}

	out := make([]byte, len(secret))
	copy(out, secret)

	return out
}

// DeriveCapability mirrors the Telegram Desktop computation:
// HMAC-SHA256(key-from-link, "tdesktop-web-proxy-bridge-v1\n" + host).
//
// The host is the one from the link, lowercased and without a port. The value
// differs between vhosts, so a leaked link cannot be reused on another domain.
func DeriveCapability(clientSecret []byte, host string) ([CapabilityLen]byte, error) {
	var out [CapabilityLen]byte

	if len(clientSecret) == 0 {
		return out, ErrEmptySecret
	}

	mac := hmac.New(sha256.New, clientSecret)
	_, _ = mac.Write([]byte(capabilityContext))
	_, _ = mac.Write([]byte(host))
	copy(out[:], mac.Sum(nil))

	return out, nil
}

// EncodeCapability encodes the value the way the query string expects it.
func EncodeCapability(capability [CapabilityLen]byte) string {
	return base64.RawURLEncoding.EncodeToString(capability[:])
}

// ParseBridgeQuery parses a query string of the form "bridge=<43 chars>".
//
// Only the canonical form is accepted: exactly one parameter, exactly 43
// characters, and re-encoding must yield the same string. Anything else is not
// our client, and such a request must go to the decoy rather than get an
// error: to an observer we are an ordinary web server.
func ParseBridgeQuery(query string) ([CapabilityLen]byte, bool) {
	var out [CapabilityLen]byte

	const prefix = "bridge="
	if len(query) != len(prefix)+bridgeQueryLen || query[:len(prefix)] != prefix {
		return out, false
	}

	value := query[len(prefix):]

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != CapabilityLen {
		return out, false
	}

	// Canonicalization: "abc=" and other spellings of the same value are rejected.
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return out, false
	}

	copy(out[:], decoded)

	return out, true
}

// Profile is a single user on a single vhost.
type Profile struct {
	// User is the secret name in the mtg config (also used in stats).
	User string
	// Capability is the precomputed value matched against ?bridge=.
	Capability [CapabilityLen]byte
	// SecretMode is the key form in the link issued to the user.
	SecretMode SecretMode
}

// ProfileTable is the profile table of a single vhost.
type ProfileTable struct {
	profiles []Profile
}

// NewProfileTable builds the table and rejects duplicate capabilities.
//
// A duplicate would mean two users are indistinguishable (same secret), and
// the traffic of one would be accounted to the other. It is better to fail at
// startup.
func NewProfileTable(profiles []Profile) (*ProfileTable, error) {
	seen := make(map[[CapabilityLen]byte]string, len(profiles))

	for _, profile := range profiles {
		if previous, ok := seen[profile.Capability]; ok {
			return nil, errors.New("web: users " + previous + " and " + profile.User + " have the same capability")
		}

		seen[profile.Capability] = profile.User
	}

	table := make([]Profile, len(profiles))
	copy(table, profiles)

	return &ProfileTable{profiles: table}, nil
}

// Match looks up a profile by the value from the query string.
//
// It walks the whole table and compares in constant time: the response time
// must depend neither on the user's position in the table nor on how many
// bytes of the value matched. Otherwise guessing a capability turns into a
// timing measurement exercise.
func (t *ProfileTable) Match(candidate [CapabilityLen]byte) (Profile, bool) {
	var (
		found Profile
		hit   int
	)

	for _, profile := range t.profiles {
		equal := subtle.ConstantTimeCompare(profile.Capability[:], candidate[:])
		if equal == 1 {
			found = profile
			hit = 1
		}
	}

	return found, hit == 1
}

// Len returns the number of profiles in the table.
func (t *ProfileTable) Len() int {
	return len(t.profiles)
}
