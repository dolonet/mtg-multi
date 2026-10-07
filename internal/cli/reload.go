package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
)

// reloadHostCheckTimeout bounds the DNS lookup of one new hostname after a
// reload.
const reloadHostCheckTimeout = 5 * time.Second

type secretsUpdater interface {
	UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error)
}

// hostResolver is the part of *net.Resolver used to check new hostnames. It
// is an interface so that tests do not need a network.
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// reloadSecrets re-reads the configuration and applies its secrets to a
// running proxy. Other options are not reloaded. On any error the current
// secrets are kept. It returns the secrets that have been applied.
func reloadSecrets(
	readConfig func() (*config.Config, error),
	proxy secretsUpdater,
	logger mtglib.Logger,
) (map[string]mtglib.Secret, error) {
	conf, err := readConfig()
	if err != nil {
		logger.WarningError("reload: cannot read config, keeping current secrets", err)

		return nil, err
	}

	secrets := conf.GetSecrets()

	update, err := proxy.UpdateSecrets(secrets)
	if err != nil {
		logger.WarningError("reload: cannot apply secrets, keeping current secrets", err)

		return nil, fmt.Errorf("cannot apply secrets: %w", err)
	}

	logger.
		BindInt("added", update.Added).
		BindInt("removed", update.Removed).
		BindInt("changed", update.Changed).
		BindInt("closed_sessions", update.ClosedSessions).
		// Warning, not Info: by default mtg logs warnings only, and an
		// operator needs to see the result of every reload.
		Warning("reload: secrets have been updated")

	return secrets, nil
}

// warnUnresolvedHosts resolves the hostnames that appear in current but not
// in previous and logs a warning for each one that does not resolve. This is
// the part of the startup SNI-DNS check that catches a typo: a hostname that
// does not resolve is applied anyway (the reload is not blocked), but domain
// fronting to it fails and the SNI does not match any real site. Hostnames
// that were already in use are not checked again.
func warnUnresolvedHosts(
	ctx context.Context,
	resolver hostResolver,
	previous, current map[string]mtglib.Secret,
	logger mtglib.Logger,
) {
	known := make(map[string]struct{}, len(previous))
	for _, secret := range previous {
		known[secret.Host] = struct{}{}
	}

	usersByHost := map[string][]string{}

	for name, secret := range current {
		if _, ok := known[secret.Host]; ok || secret.Host == "" {
			continue
		}

		usersByHost[secret.Host] = append(usersByHost[secret.Host], name)
	}

	hosts := make([]string, 0, len(usersByHost))
	for host := range usersByHost {
		hosts = append(hosts, host)
	}

	sort.Strings(hosts)

	for _, host := range hosts {
		users := usersByHost[host]
		sort.Strings(users)

		lookupCtx, cancel := context.WithTimeout(ctx, reloadHostCheckTimeout)
		addrs, err := resolver.LookupIPAddr(lookupCtx, host)

		cancel()

		if err == nil && len(addrs) == 0 {
			err = fmt.Errorf("no known addresses for %s", host)
		}

		if err != nil {
			logger.
				BindStr("hostname", host).
				BindStr("users", strings.Join(users, ",")).
				WarningError("reload: secret hostname does not resolve", err)
		}
	}
}

// watchReload reloads secrets on every signal until ctx is done. initial is
// the set of secrets the proxy has started with: hostnames from it are not
// checked again.
func watchReload(
	ctx context.Context,
	signals <-chan os.Signal,
	readConfig func() (*config.Config, error),
	proxy secretsUpdater,
	resolver hostResolver,
	initial map[string]mtglib.Secret,
	logger mtglib.Logger,
) {
	current := initial

	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			applied, err := reloadSecrets(readConfig, proxy, logger)
			if err != nil {
				continue
			}

			// The check runs after the swap, so it never delays or blocks
			// the new secrets.
			warnUnresolvedHosts(ctx, resolver, current, applied, logger)

			current = applied
		}
	}
}
