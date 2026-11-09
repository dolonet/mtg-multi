package cli

import (
	"errors"
	"sync"
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proxy and the WEB wrapper publish reload outcomes.
var (
	_ reloadRecorder = (*mtglib.Proxy)(nil)
	_ reloadRecorder = reloadWithWeb{}
)

type recordingUpdater struct {
	fakeSecretsUpdater

	mu        sync.Mutex
	successes []mtglib.SecretsUpdate
	failures  []string
}

func (r *recordingUpdater) RecordReloadSuccess(update mtglib.SecretsUpdate) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.successes = append(r.successes, update)
}

func (r *recordingUpdater) RecordReloadFailure(stage string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.failures = append(r.failures, stage)
}

func TestReloadSecretsRecordsSuccess(t *testing.T) {
	t.Parallel()

	updater := &recordingUpdater{}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
	}, updater, logger.NewNoopLogger())
	require.NoError(t, err)

	assert.Equal(t, []mtglib.SecretsUpdate{{Added: 1}}, updater.successes)
	assert.Empty(t, updater.failures)
}

func TestReloadSecretsRecordsReadFailure(t *testing.T) {
	t.Parallel()

	updater := &recordingUpdater{}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return nil, errors.New("cannot parse config")
	}, updater, logger.NewNoopLogger())
	require.Error(t, err)

	assert.Equal(t, []string{mtglib.ReloadStageReadConfig}, updater.failures)
	assert.Empty(t, updater.successes)
	assert.Zero(t, updater.callCount())
}

func TestReloadSecretsRecordsApplyFailure(t *testing.T) {
	t.Parallel()

	updater := &recordingUpdater{fakeSecretsUpdater: fakeSecretsUpdater{err: mtglib.ErrSecretEmpty}}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
	}, updater, logger.NewNoopLogger())
	require.Error(t, err)

	assert.Equal(t, []string{mtglib.ReloadStageApply}, updater.failures)
	assert.Empty(t, updater.successes)
}

// An updater that does not publish reloads still works.
func TestReloadSecretsWithoutRecorder(t *testing.T) {
	t.Parallel()

	_, err := reloadSecrets(func() (*config.Config, error) {
		return nil, errors.New("cannot parse config")
	}, &fakeSecretsUpdater{}, logger.NewNoopLogger())
	require.Error(t, err)
}

type failingWebUpdater struct{}

func (failingWebUpdater) PrepareSecrets(map[string][]byte) (*web.SecretsUpdate, error) {
	return nil, errors.New("web refused")
}

// In the WEB mode a set refused by the WEB frontend is a refused reload too,
// and it reaches the proxy's /stats.
func TestReloadWithWebRecordsOnProxy(t *testing.T) {
	t.Parallel()

	proxy := &recordingUpdater{}
	updater := reloadWithWeb{proxy: proxy, web: failingWebUpdater{}, logger: logger.NewNoopLogger()}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
	}, updater, logger.NewNoopLogger())
	require.Error(t, err)

	assert.Equal(t, []string{mtglib.ReloadStageApply}, proxy.failures)
	assert.Zero(t, proxy.callCount())
}

// The WEB wrapper over an updater without the recorder does nothing.
func TestReloadWithWebWithoutRecorder(t *testing.T) {
	t.Parallel()

	updater := reloadWithWeb{proxy: &fakeSecretsUpdater{}, web: failingWebUpdater{}, logger: logger.NewNoopLogger()}

	assert.NotPanics(t, func() {
		updater.RecordReloadSuccess(mtglib.SecretsUpdate{})
		updater.RecordReloadFailure(mtglib.ReloadStageApply)
	})
}
