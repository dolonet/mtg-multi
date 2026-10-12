package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const reloadWebHost = "proxy.example.com"

func newReloadWebServer(t *testing.T, secrets map[string]mtglib.Secret) *web.Server {
	t.Helper()

	srv, _, err := web.Setup(web.Settings{BindTo: "127.0.0.1:0", Host: reloadWebHost}, webSecrets(secrets), func(*web.Stream) {})
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	return srv
}

// webLinkOpens reports whether the WEB link of secret gets the bridge page.
// Without a decoy directory everything else gets 404.
func webLinkOpens(t *testing.T, srv *web.Server, secret mtglib.Secret) bool {
	t.Helper()

	capability, err := web.DeriveCapability(web.ClientSecret(secret.Key[:], web.SecretModeDD), reloadWebHost)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/?bridge="+web.EncodeCapability(capability), nil)
	r.Host = reloadWebHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	return rec.Code == http.StatusOK
}

// A SIGHUP updates the WEB users together with the proxy: a new user's WEB
// link works at once, and a removed user's link stops working.
func TestWatchReloadUpdatesWebUsers(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	carol := mtglib.GenerateSecret("example.com")
	srv := newReloadWebServer(t, map[string]mtglib.Secret{"alice": alice})
	proxy := &fakeSecretsUpdater{}

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		watchReload(ctx, signals, func() (*config.Config, error) {
			return &config.Config{Secrets: map[string]mtglib.Secret{"carol": carol}}, nil
		}, reloadWithWeb{proxy: proxy, web: srv, logger: logger.NewNoopLogger()},
			fakeResolver{}, nil, logger.NewNoopLogger())
	}()

	require.True(t, webLinkOpens(t, srv, alice))
	require.False(t, webLinkOpens(t, srv, carol))

	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return proxy.callCount() == 1 }, time.Second, 5*time.Millisecond)
	assert.Eventually(t, func() bool { return webLinkOpens(t, srv, carol) }, time.Second, 5*time.Millisecond)
	assert.False(t, webLinkOpens(t, srv, alice))

	cancel()
	<-done
}

// A set the WEB side cannot take (two users with one key) is refused before
// the proxy changes, so both keep the current secrets.
func TestReloadWithWebRefusedByWebKeepsProxy(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	srv := newReloadWebServer(t, map[string]mtglib.Secret{"alice": alice})
	proxy := &fakeSecretsUpdater{}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secrets: map[string]mtglib.Secret{"alice": alice, "twin": alice}}, nil
	}, reloadWithWeb{proxy: proxy, web: srv, logger: logger.NewNoopLogger()}, logger.NewNoopLogger())
	require.Error(t, err)

	assert.Equal(t, 0, proxy.callCount())
	assert.True(t, webLinkOpens(t, srv, alice))
}

// If the proxy refuses the set, the WEB users stay as they are too.
func TestReloadWithWebProxyErrorKeepsWeb(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	carol := mtglib.GenerateSecret("example.com")
	srv := newReloadWebServer(t, map[string]mtglib.Secret{"alice": alice})
	proxy := &fakeSecretsUpdater{err: errors.New("refused")}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secrets: map[string]mtglib.Secret{"carol": carol}}, nil
	}, reloadWithWeb{proxy: proxy, web: srv, logger: logger.NewNoopLogger()}, logger.NewNoopLogger())
	require.Error(t, err)

	assert.True(t, webLinkOpens(t, srv, alice))
	assert.False(t, webLinkOpens(t, srv, carol))
}
