package mtglib

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// secretSet is an immutable snapshot of the configured secrets. The proxy
// swaps it atomically on UpdateSecrets, so a handshake always works with one
// consistent snapshot.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
	keys      [][]byte
	byName    map[string]Secret
}

func newSecretSet(secrets map[string]Secret) *secretSet {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}

	sort.Strings(names)

	set := &secretSet{
		secrets: make([]Secret, 0, len(names)),
		names:   names,
		keys:    make([][]byte, 0, len(names)),
		byName:  make(map[string]Secret, len(names)),
	}

	// Collect unique hostnames across all secrets for SNI matching.
	hostnameSet := make(map[string]struct{}, len(names))

	for _, name := range names {
		secret := secrets[name]
		set.secrets = append(set.secrets, secret)
		set.keys = append(set.keys, secret.Key[:])
		set.byName[name] = secret
		hostnameSet[secret.Host] = struct{}{}
	}

	set.hostnames = make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		set.hostnames = append(set.hostnames, h)
	}

	sort.Strings(set.hostnames)

	return set
}

// digest is sha256 of "name=secret(hex)" lines in name order joined with \n.
// An external sync computes the same from its config to check that a reload
// has been applied completely: key changes are invisible by names alone.
func (s *secretSet) digest() string {
	lines := make([]string, len(s.names))
	for i, name := range s.names {
		lines[i] = name + "=" + s.secrets[i].Hex()
	}

	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	return hex.EncodeToString(sum[:])
}

// sameSecret reports whether name is present in the set with exactly this
// secret. Both the key and the host are compared: UpdateSecrets closes live
// sessions of a user whose host has changed, so a handshake that matched the
// old host must not register a session after the swap either.
func (s *secretSet) sameSecret(name string, secret Secret) bool {
	current, ok := s.byName[name]

	return ok && current == secret
}

// SecretsUpdate describes the result of Proxy.UpdateSecrets.
type SecretsUpdate struct {
	// Added is the number of new secret names.
	Added int
	// Removed is the number of secret names that are gone.
	Removed int
	// Changed is the number of names that are kept with a different key or
	// host.
	Changed int
	// ClosedSessions is the number of live sessions that were closed because
	// their secret was removed or changed.
	ClosedSessions int
}

// sessionRegistry tracks authenticated sessions per secret name, so that
// sessions of a removed or changed secret can be closed on update.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]map[*streamContext]struct{}
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions: make(map[string]map[*streamContext]struct{}),
	}
}

func (r *sessionRegistry) add(ctx *streamContext) {
	byName := r.sessions[ctx.secretName]
	if byName == nil {
		byName = make(map[*streamContext]struct{})
		r.sessions[ctx.secretName] = byName
	}

	byName[ctx] = struct{}{}
}

func (r *sessionRegistry) remove(ctx *streamContext) {
	r.mu.Lock()
	defer r.mu.Unlock()

	byName := r.sessions[ctx.secretName]
	delete(byName, ctx)

	if len(byName) == 0 {
		delete(r.sessions, ctx.secretName)
	}
}
