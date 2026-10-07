package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSecretsUpdater struct {
	mu    sync.Mutex
	calls []map[string]mtglib.Secret
	err   error
}

func (f *fakeSecretsUpdater) UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, secrets)

	return mtglib.SecretsUpdate{Added: len(secrets)}, f.err
}

func (f *fakeSecretsUpdater) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.calls)
}

func TestReloadSecretsApplies(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	bob := mtglib.GenerateSecret("example.com")
	updater := &fakeSecretsUpdater{}

	applied, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secrets: map[string]mtglib.Secret{"alice": alice, "bob": bob}}, nil
	}, updater, logger.NewNoopLogger())
	require.NoError(t, err)
	assert.Equal(t, map[string]mtglib.Secret{"alice": alice, "bob": bob}, applied)

	require.Len(t, updater.calls, 1)
	assert.Equal(t, map[string]mtglib.Secret{"alice": alice, "bob": bob}, updater.calls[0])
}

func TestReloadSecretsSingleSecret(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("example.com")
	updater := &fakeSecretsUpdater{}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: secret}, nil
	}, updater, logger.NewNoopLogger())
	require.NoError(t, err)

	assert.Equal(t, map[string]mtglib.Secret{"default": secret}, updater.calls[0])
}

// A broken config (for example a half-written file) must not reach the proxy.
func TestReloadSecretsKeepsCurrentOnBrokenConfig(t *testing.T) {
	t.Parallel()

	updater := &fakeSecretsUpdater{}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return nil, errors.New("cannot parse config")
	}, updater, logger.NewNoopLogger())
	require.Error(t, err)
	assert.Zero(t, updater.callCount())
}

func TestReloadSecretsReportsUpdateError(t *testing.T) {
	t.Parallel()

	updater := &fakeSecretsUpdater{err: mtglib.ErrSecretEmpty}

	_, err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
	}, updater, logger.NewNoopLogger())
	require.ErrorIs(t, err, mtglib.ErrSecretEmpty)
}

func TestWatchReloadOnSignal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	updater := &fakeSecretsUpdater{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		watchReload(ctx, signals, func() (*config.Config, error) {
			return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
		}, updater, fakeResolver{}, nil, logger.NewNoopLogger())
	}()

	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return updater.callCount() == 2 }, time.Second, 5*time.Millisecond)

	cancel()
	<-done
}

// fakeResolver resolves the hostnames it knows and fails on the rest. It
// records every lookup.
type fakeResolver struct {
	known   map[string]bool
	lookups *[]string
	mu      *sync.Mutex
}

func newFakeResolver(known ...string) fakeResolver {
	r := fakeResolver{known: map[string]bool{}, lookups: &[]string{}, mu: &sync.Mutex{}}
	for _, host := range known {
		r.known[host] = true
	}

	return r
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if r.mu != nil {
		r.mu.Lock()
		*r.lookups = append(*r.lookups, host)
		r.mu.Unlock()
	}

	if r.known[host] {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (r fakeResolver) lookedUp() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), *r.lookups...)
}

// recordingLogger records warnings together with their bound strings.
type recordingLogger struct {
	mtglib.Logger

	binds    []string
	mu       *sync.Mutex
	warnings *[]string
}

func newRecordingLogger() recordingLogger {
	return recordingLogger{Logger: logger.NewNoopLogger(), mu: &sync.Mutex{}, warnings: &[]string{}}
}

func (l recordingLogger) Named(_ string) mtglib.Logger          { return l }
func (l recordingLogger) BindInt(_ string, _ int) mtglib.Logger { return l }

func (l recordingLogger) BindStr(name, value string) mtglib.Logger {
	l.binds = append(append([]string(nil), l.binds...), name+"="+value)

	return l
}

func (l recordingLogger) Warning(msg string) { l.record(msg) }

func (l recordingLogger) WarningError(msg string, err error) {
	l.record(fmt.Sprintf("%s: %v", msg, err))
}

func (l recordingLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	*l.warnings = append(*l.warnings, strings.Join(append(append([]string(nil), l.binds...), msg), " "))
}

func (l recordingLogger) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), *l.warnings...)
}

func TestWarnUnresolvedHostsChecksOnlyNewHosts(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("old.example.com")
	bob := mtglib.GenerateSecret("old.example.com")
	carol := mtglib.GenerateSecret("tpyo.example.com")
	dave := mtglib.GenerateSecret("new.example.com")

	bobMoved := bob
	bobMoved.Host = "tpyo.example.com"

	resolver := newFakeResolver("new.example.com")
	log := newRecordingLogger()

	warnUnresolvedHosts(context.Background(), resolver,
		map[string]mtglib.Secret{"alice": alice, "bob": bob},
		map[string]mtglib.Secret{"alice": alice, "bob": bobMoved, "carol": carol, "dave": dave},
		log)

	// old.example.com was in use before the reload and is not looked up
	// again; a hostname shared by several users is looked up once.
	assert.ElementsMatch(t, []string{"new.example.com", "tpyo.example.com"}, resolver.lookedUp())

	warnings := log.recorded()
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "hostname=tpyo.example.com")
	assert.Contains(t, warnings[0], "users=bob,carol")
	assert.Contains(t, warnings[0], "does not resolve")
}

func TestWarnUnresolvedHostsSilentWhenAllResolve(t *testing.T) {
	t.Parallel()

	resolver := newFakeResolver("a.example.com", "b.example.com")
	log := newRecordingLogger()

	warnUnresolvedHosts(context.Background(), resolver, nil, map[string]mtglib.Secret{
		"alice": mtglib.GenerateSecret("a.example.com"),
		"bob":   mtglib.GenerateSecret("b.example.com"),
	}, log)

	assert.Len(t, resolver.lookedUp(), 2)
	assert.Empty(t, log.recorded())
}

// A hostname that does not resolve is reported, but the new secrets are
// applied anyway, and the next reload compares against them.
func TestWatchReloadWarnsAboutUnresolvedHostAndApplies(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("good.example.com")
	bob := mtglib.GenerateSecret("tpyo.example.com")

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	updater := &fakeSecretsUpdater{}
	resolver := newFakeResolver("good.example.com")
	log := newRecordingLogger()
	done := make(chan struct{})

	go func() {
		defer close(done)
		watchReload(ctx, signals, func() (*config.Config, error) {
			return &config.Config{Secrets: map[string]mtglib.Secret{"alice": alice, "bob": bob}}, nil
		}, updater, resolver, map[string]mtglib.Secret{"alice": alice}, log)
	}()

	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return len(resolver.lookedUp()) == 1 }, time.Second, 5*time.Millisecond)

	// The same config again: tpyo.example.com is now in use and is not
	// looked up a second time.
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return updater.callCount() == 2 }, time.Second, 5*time.Millisecond)

	cancel()
	<-done

	assert.Equal(t, []string{"tpyo.example.com"}, resolver.lookedUp())

	unresolved := 0

	for _, w := range log.recorded() {
		if strings.Contains(w, "does not resolve") {
			unresolved++

			assert.Contains(t, w, "users=bob")
		}
	}

	assert.Equal(t, 1, unresolved)
}
