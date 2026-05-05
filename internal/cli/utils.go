package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/9seconds/mtg/v2/mtglib"
)

// defaultPublicIPEndpoints is the fallback used when network.public-ip-endpoints
// is not set in config. Each endpoint must return the client's public IP as a
// single address in the plain-text response body.
var defaultPublicIPEndpoints = []string{
	"https://ifconfig.co",
	"https://icanhazip.com",
	"https://ifconfig.me",
}

// resolvePublicIPEndpoints returns the configured endpoint list, falling back
// to defaultPublicIPEndpoints when none are configured.
func resolvePublicIPEndpoints(configured []config.TypeHttpsURL) []string {
	if len(configured) == 0 {
		return defaultPublicIPEndpoints
	}

	out := make([]string, 0, len(configured))
	for _, u := range configured {
		if v := u.Get(nil); v != nil {
			out = append(out, v.String())
		}
	}

	if len(out) == 0 {
		return defaultPublicIPEndpoints
	}

	return out
}

func getIP(ctx context.Context, ntw mtglib.Network, protocol string, endpoints []string) net.IP {
	dialer := ntw.NativeDialer()
	client := ntw.MakeHTTPClient(func(ctx context.Context, network, address string) (essentials.Conn, error) {
		conn, err := dialer.DialContext(ctx, protocol, address)
		if err != nil {
			return nil, err
		}
		return essentials.WrapNetConn(conn), err
	})

	for _, endpoint := range endpoints {
		if ip := fetchPublicIP(ctx, client, endpoint); ip != nil {
			return ip
		}
	}

	return nil
}

func fetchPublicIP(ctx context.Context, client *http.Client, endpoint string) net.IP {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "curl/8")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	defer func() {
		io.Copy(io.Discard, resp.Body) //nolint: errcheck
		resp.Body.Close()              //nolint: errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return net.ParseIP(strings.TrimSpace(string(data)))
}
