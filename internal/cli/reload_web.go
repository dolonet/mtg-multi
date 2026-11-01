package cli

import (
	"fmt"

	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/web"
)

// webSecretsUpdater is the part of *web.Server that a reload needs.
type webSecretsUpdater interface {
	PrepareSecrets(secrets map[string][]byte) (*web.SecretsUpdate, error)
}

// reloadWithWeb applies a reload to the proxy and to the WEB frontend, which
// has its own user table derived from the same secrets. The WEB table is
// built first, so a set that WEB cannot take is refused before the proxy
// changes, and both keep the current secrets. Then the proxy closes the
// sessions of removed and changed users (the dd and WEB streams alike), and
// the WEB frontend closes their WEB sessions and bridge tokens.
type reloadWithWeb struct {
	proxy  secretsUpdater
	web    webSecretsUpdater
	logger mtglib.Logger
}

func (r reloadWithWeb) UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error) {
	prepared, err := r.web.PrepareSecrets(webSecrets(secrets))
	if err != nil {
		return mtglib.SecretsUpdate{}, fmt.Errorf("web: %w", err)
	}

	update, err := r.proxy.UpdateSecrets(secrets)
	if err != nil {
		return update, err
	}

	result := prepared.Apply()

	r.logger.
		BindInt("closed_web_sessions", result.ClosedSessions).
		BindInt("dropped_web_tokens", result.DroppedPending).
		Warning("reload: web users have been updated")

	return update, nil
}

// webSecrets converts the proxy secrets into the keys the WEB frontend
// derives its capabilities from.
func webSecrets(secrets map[string]mtglib.Secret) map[string][]byte {
	out := make(map[string][]byte, len(secrets))

	for name, secret := range secrets {
		key := make([]byte, len(secret.Key))
		copy(key, secret.Key[:])
		out[name] = key
	}

	return out
}
