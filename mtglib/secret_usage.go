package mtglib

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// usageStateVersion is the format version of the usage state file.
const usageStateVersion = 1

// usageState is the content of the usage state file: the quota usage of every
// secret that has a quota.
type usageState struct {
	Version int                    `json:"version"`
	Users   map[string]usageRecord `json:"users"`
}

type usageRecord struct {
	QuotaUsed   int64     `json:"quota_used"`
	QuotaReset  string    `json:"quota_reset"`
	PeriodStart time.Time `json:"period_start,omitzero"`
}

// LoadUsage restores the quota usage saved by FlushUsage. It must be called
// before any traffic is counted. Only secrets that are known and have a quota
// in limits are restored: a removed secret, or one whose quota is gone, starts
// from zero when it comes back. A missing file is not an error.
func (s *ProxyStats) LoadUsage(path string, limits map[string]SecretLimits) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("cannot read usage state: %w", err)
	}

	var state usageState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("cannot parse usage state %s: %w", path, err)
	}

	if state.Version != usageStateVersion {
		return fmt.Errorf("unsupported usage state version %d in %s", state.Version, path)
	}

	for name, rec := range state.Users {
		if limits[name].QuotaBytes == 0 || rec.QuotaUsed < 0 {
			continue
		}

		reset, err := ParseQuotaReset(rec.QuotaReset)
		if err != nil {
			continue
		}

		st := s.lookup(name)
		if st == nil {
			continue
		}

		st.quota.restore(rec.QuotaUsed, reset, rec.PeriodStart, st.bytesIn.Load()+st.bytesOut.Load())
	}

	return nil
}

// FlushUsage saves the quota usage of every secret that has a quota to path.
// The file is replaced atomically (a temporary file in the same directory,
// then rename), so a crash never leaves a truncated one.
func (s *ProxyStats) FlushUsage(path string) error {
	state := usageState{
		Version: usageStateVersion,
		Users:   map[string]usageRecord{},
	}

	s.mu.RLock()
	for name, st := range s.users {
		used, reset, periodStart, ok := st.quota.snapshot(st.bytesIn.Load() + st.bytesOut.Load())
		if !ok {
			continue
		}

		state.Users[name] = usageRecord{
			QuotaUsed:   used,
			QuotaReset:  reset.String(),
			PeriodStart: periodStart,
		}
	}
	s.mu.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("cannot encode usage state: %w", err)
	}

	s.usageMu.Lock()
	defer s.usageMu.Unlock()

	return writeFileAtomic(path, data)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("cannot create usage state: %w", err)
	}

	tmpName := tmp.Name()

	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}

	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err == nil {
		err = os.Rename(tmpName, path)
	}

	if err != nil {
		os.Remove(tmpName) //nolint: errcheck

		return fmt.Errorf("cannot write usage state: %w", err)
	}

	return nil
}
