package mtglib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveStats(t *testing.T, stats *ProxyStats) (StatsResponse, map[string]json.RawMessage) {
	t.Helper()

	rec := httptest.NewRecorder()
	stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	return resp, raw
}

// Before the first reload the field is absent, so the response of a proxy
// that is never reloaded does not change.
func TestServeHTTPReloadAbsentUntilFirstReload(t *testing.T) {
	t.Parallel()

	resp, raw := serveStats(t, NewProxyStats())

	assert.Nil(t, resp.Reload)
	assert.NotContains(t, raw, "reload")
}

func TestServeHTTPReloadSuccess(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.RecordReloadSuccess(SecretsUpdate{Added: 2, Removed: 1, Changed: 3, ClosedSessions: 4})

	resp, _ := serveStats(t, stats)

	require.NotNil(t, resp.Reload)
	assert.Equal(t, int64(1), resp.Reload.Succeeded)
	assert.Equal(t, int64(0), resp.Reload.Failed)
	assert.True(t, resp.Reload.LastOK)
	assert.Empty(t, resp.Reload.LastErrorStage)
	assert.False(t, resp.Reload.LastAt.IsZero())
	require.NotNil(t, resp.Reload.LastSuccessAt)
	assert.True(t, resp.Reload.LastSuccessAt.Equal(resp.Reload.LastAt))
	assert.Equal(t, 2, resp.Reload.Added)
	assert.Equal(t, 1, resp.Reload.Removed)
	assert.Equal(t, 3, resp.Reload.Changed)
}

// A refused reload keeps the current secrets: secrets_sha256 does not change,
// and only last_ok tells an external sync that its config has not been taken.
// The counts of the last successful reload stay.
func TestServeHTTPReloadFailureAfterSuccess(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.RecordReloadSuccess(SecretsUpdate{Added: 2})
	stats.RecordReloadFailure(ReloadStageReadConfig)

	resp, _ := serveStats(t, stats)

	require.NotNil(t, resp.Reload)
	assert.Equal(t, int64(1), resp.Reload.Succeeded)
	assert.Equal(t, int64(1), resp.Reload.Failed)
	assert.False(t, resp.Reload.LastOK)
	assert.Equal(t, ReloadStageReadConfig, resp.Reload.LastErrorStage)
	require.NotNil(t, resp.Reload.LastSuccessAt)
	assert.False(t, resp.Reload.LastAt.Before(*resp.Reload.LastSuccessAt))
	assert.Equal(t, 2, resp.Reload.Added)
}

func TestServeHTTPReloadFailureFirst(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.RecordReloadFailure(ReloadStageApply)

	resp, raw := serveStats(t, stats)

	require.NotNil(t, resp.Reload)
	assert.Equal(t, int64(1), resp.Reload.Failed)
	assert.False(t, resp.Reload.LastOK)
	assert.Equal(t, ReloadStageApply, resp.Reload.LastErrorStage)
	assert.Nil(t, resp.Reload.LastSuccessAt)

	var reload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["reload"], &reload))
	assert.NotContains(t, reload, "last_success_at")
}

// A success after a failure clears the error stage.
func TestServeHTTPReloadRecovers(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.RecordReloadFailure(ReloadStageApply)
	stats.RecordReloadSuccess(SecretsUpdate{Removed: 1})

	resp, _ := serveStats(t, stats)

	require.NotNil(t, resp.Reload)
	assert.True(t, resp.Reload.LastOK)
	assert.Empty(t, resp.Reload.LastErrorStage)
	assert.Equal(t, int64(1), resp.Reload.Succeeded)
	assert.Equal(t, int64(1), resp.Reload.Failed)
	assert.Equal(t, 1, resp.Reload.Removed)
}

// The snapshot is a copy: a reload recorded while a response is being
// encoded does not change it.
func TestReloadSnapshotIsACopy(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.RecordReloadSuccess(SecretsUpdate{Added: 1})

	snap := stats.reloadSnapshot()
	at := *snap.LastSuccessAt

	stats.RecordReloadSuccess(SecretsUpdate{Added: 5})

	assert.Equal(t, 1, snap.Added)
	assert.Equal(t, int64(1), snap.Succeeded)
	assert.True(t, snap.LastSuccessAt.Equal(at))
}
