package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// TypeQuota is a per-secret traffic quota: a size with a unit, like other
// sizes in the config ("10GB", "500 MiB"; units are powers of 1024), or a
// bare number of bytes. A quota must be positive: leave it out for unlimited.
type TypeQuota struct {
	Value int64
}

func (t *TypeQuota) Set(value string) error {
	value = strings.TrimSpace(value)

	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		if n <= 0 {
			return fmt.Errorf("quota must be positive, got %s", value)
		}

		t.Value = n

		return nil
	}

	size := TypeBytes{}
	if err := size.Set(value); err != nil {
		return fmt.Errorf("incorrect quota: %w", err)
	}

	if size.Value <= 0 || uint64(size.Value) > math.MaxInt64 {
		return fmt.Errorf("quota must be positive, got %s", value)
	}

	t.Value = int64(size.Value)

	return nil
}

func (t TypeQuota) Get(defaultValue int64) int64 {
	if t.Value == 0 {
		return defaultValue
	}

	return t.Value
}

func (t *TypeQuota) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeQuota) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeQuota) String() string {
	if t.Value == 0 {
		return ""
	}

	return strconv.FormatInt(t.Value, 10)
}
