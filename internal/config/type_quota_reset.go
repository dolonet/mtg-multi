package config

import (
	"github.com/dolonet/mtg-multi/mtglib"
)

// TypeQuotaReset is when a per-secret quota starts from zero again: none
// (default), daily, weekly or monthly. Periods are calendar periods in UTC.
type TypeQuotaReset struct {
	Value mtglib.QuotaReset
}

func (t *TypeQuotaReset) Set(value string) error {
	reset, err := mtglib.ParseQuotaReset(value)
	if err != nil {
		return err //nolint: wrapcheck
	}

	t.Value = reset

	return nil
}

func (t TypeQuotaReset) Get(defaultValue mtglib.QuotaReset) mtglib.QuotaReset {
	if t.Value == mtglib.QuotaResetNone {
		return defaultValue
	}

	return t.Value
}

func (t *TypeQuotaReset) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeQuotaReset) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeQuotaReset) String() string {
	if t.Value == mtglib.QuotaResetNone {
		return ""
	}

	return t.Value.String()
}
