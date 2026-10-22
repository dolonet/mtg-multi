package web

import "strings"

// SecretsUpdate is a prepared replacement of the user tables. Nothing changes
// until Apply: a set of secrets that cannot be applied (no secrets, two users
// with the same key) is refused by PrepareSecrets, and the caller keeps the
// current ones everywhere.
type SecretsUpdate struct {
	server *Server
	tables map[string]*ProfileTable
}

// UpdateResult describes what Apply has done.
type UpdateResult struct {
	// ClosedSessions is the number of live sessions closed because their
	// user was removed or got another key.
	ClosedSessions int
	// DroppedPending is the number of bridge tokens dropped for the same
	// reason.
	DroppedPending int
}

// PrepareSecrets builds new user tables for every domain from the same
// secrets as the proxy uses. The domains, the key form and the limits stay as
// they are: they come from the [web] section, which is read only at startup.
func (s *Server) PrepareSecrets(secrets map[string][]byte) (*SecretsUpdate, error) {
	if len(secrets) == 0 {
		return nil, ErrNoSecrets
	}

	s.vhostMu.RLock()
	defer s.vhostMu.RUnlock()

	tables := make(map[string]*ProfileTable, len(s.vhosts))

	for name, vhost := range s.vhosts {
		mode := vhost.SecretMode
		if mode != SecretModePlain {
			mode = SecretModeDD
		}

		profiles, err := BuildProfiles(secrets, strings.ToLower(vhost.Host), mode)
		if err != nil {
			return nil, err
		}

		table, err := NewProfileTable(profiles)
		if err != nil {
			return nil, err
		}

		tables[name] = table
	}

	return &SecretsUpdate{server: s, tables: tables}, nil
}

// Apply swaps in the new user tables. New bridge pages and sessions use them
// right away. Sessions and bridge tokens of a user that is gone, or whose key
// has changed, are closed: the capability they were opened with no longer
// matches. Sessions of the other users go on untouched.
func (u *SecretsUpdate) Apply() UpdateResult {
	s := u.server
	result := UpdateResult{}

	s.mu.Lock()

	s.vhostMu.Lock()

	for name, table := range u.tables {
		vhost := s.vhosts[name]
		vhost.Profiles = table
		s.vhosts[name] = vhost
	}

	s.current = profileSet(s.vhosts)

	s.vhostMu.Unlock()

	closed := []*Session{}

	for hash, session := range s.sessions {
		if _, ok := s.current[session.profile]; !ok {
			closed = append(closed, s.removeSessionLocked(hash))
		}
	}

	for hash, issued := range s.pending {
		if _, ok := s.current[issued.profile]; !ok {
			s.removePendingLocked(hash)

			result.DroppedPending++
		}
	}

	s.mu.Unlock()

	for _, session := range closed {
		session.Close()
	}

	result.ClosedSessions = len(closed)

	return result
}

func profileSet(vhosts map[string]VHost) map[Profile]struct{} {
	set := map[Profile]struct{}{}

	for _, vhost := range vhosts {
		if vhost.Profiles == nil {
			continue
		}

		for _, profile := range vhost.Profiles.profiles {
			set[profile] = struct{}{}
		}
	}

	return set
}
