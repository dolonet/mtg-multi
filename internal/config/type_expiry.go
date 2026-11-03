package config

import (
	"fmt"
	"strings"
	"time"
)

// TypeExpiry is when a secret stops working: an RFC3339 time with an offset
// ("2026-12-31T21:00:00Z", "2027-01-01T00:00:00+03:00") or a date
// ("2026-12-31"), which means 00:00 UTC of that day.
type TypeExpiry struct {
	Value time.Time
}

func (t *TypeExpiry) Set(value string) error {
	value = strings.TrimSpace(value)

	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		t.Value = parsed.UTC()

		return nil
	}

	if parsed, err := time.Parse(time.DateOnly, value); err == nil {
		t.Value = parsed

		return nil
	}

	return fmt.Errorf("incorrect expiry time %q: must be RFC3339 with an offset or YYYY-MM-DD", value)
}

func (t TypeExpiry) Get(defaultValue time.Time) time.Time {
	if t.Value.IsZero() {
		return defaultValue
	}

	return t.Value
}

func (t *TypeExpiry) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeExpiry) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeExpiry) String() string {
	if t.Value.IsZero() {
		return ""
	}

	return t.Value.Format(time.RFC3339)
}
