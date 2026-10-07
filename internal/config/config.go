package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/dolonet/mtg-multi/mtglib"
)

type Optional struct {
	Enabled TypeBool `json:"enabled"`
}

type ListConfig struct {
	Optional

	DownloadConcurrency TypeConcurrency    `json:"downloadConcurrency"`
	URLs                []TypeBlocklistURI `json:"urls"`
	UpdateEach          TypeDuration       `json:"updateEach"`
}

type Config struct {
	Debug                       TypeBool                 `json:"debug"`
	AllowFallbackOnUnknownDC    TypeBool                 `json:"allowFallbackOnUnknownDc"`
	Secret                      mtglib.Secret            `json:"secret"`
	Secrets                     map[string]mtglib.Secret `json:"secrets"`
	BindTo                      []TypeHostPort           `json:"bindTo"`
	ProxyProtocolListener       TypeBool                 `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP             `json:"preferIp"`
	AutoUpdate                  TypeBool                 `json:"autoUpdate"`
	DomainFrontingPort          TypePort                 `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP                   `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool                 `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration             `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency          `json:"concurrency"`
	PublicIPv4                  TypeIP                   `json:"publicIpv4"`
	PublicIPv6                  TypeIP                   `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		PendingHandshakes struct {
			MaxPerIP TypeConcurrency `json:"maxPerIp"`
			DryRun   TypeBool        `json:"dryRun"`
		} `json:"pendingHandshakes"`
		AntiReplay struct {
			Optional

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL  `json:"urls"`
			Repeats    TypeConcurrency `json:"repeats_per_raid"`
			UpdateEach TypeDuration    `json:"raid_each"`
			DRS        TypeBool        `json:"drs"`
		} `json:"doppelganger"`
	} `json:"defense"`
	Network struct {
		Timeout struct {
			TCP       TypeDuration `json:"tcp"`
			HTTP      TypeDuration `json:"http"`
			Idle      TypeDuration `json:"idle"`
			Handshake TypeDuration `json:"handshake"`
		} `json:"timeout"`
		KeepAlive struct {
			Disabled TypeBool        `json:"disabled"`
			Idle     TypeDuration    `json:"idle"`
			Interval TypeDuration    `json:"interval"`
			Count    TypeConcurrency `json:"count"`
		} `json:"keepAlive"`
		DOHIP           TypeIP         `json:"dohIp"`
		DNS             TypeDNSURI     `json:"dns"`
		Proxies         []TypeProxyURL `json:"proxies"`
		TCPNotSentLowat TypeBytes      `json:"tcpNotSentLowat"`
	} `json:"network"`
	APIBindTo TypeHostPort `json:"apiBindTo"`
	Throttle  struct {
		MaxConnections TypeConcurrency `json:"maxConnections"`
		CheckInterval  TypeDuration    `json:"checkInterval"`
	} `json:"throttle"`
	Web struct {
		BindTo             string          `json:"bindTo"`
		Host               string          `json:"host"`
		SecretMode         string          `json:"secretMode"`
		DecoyDir           string          `json:"decoyDir"`
		MaxSessions        TypeConcurrency `json:"maxSessions"`
		MaxPending         TypeConcurrency `json:"maxPending"`
		MaxSessionsPerUser TypeConcurrency `json:"maxSessionsPerUser"`
		MaxPendingPerUser  TypeConcurrency `json:"maxPendingPerUser"`
		Diag               TypeBool        `json:"diag"`
	} `json:"web"`
	Secured struct {
		Optional

		FrameTimeout TypeDuration `json:"frameTimeout"`
	} `json:"secured"`
	Stats struct {
		StatsD struct {
			Optional

			Address      TypeHostPort        `json:"address"`
			MetricPrefix TypeMetricPrefix    `json:"metricPrefix"`
			TagFormat    TypeStatsdTagFormat `json:"tagFormat"`
		} `json:"statsd"`
		Prometheus struct {
			Optional

			BindTo       TypeHostPort     `json:"bindTo"`
			HTTPPath     TypeHTTPPath     `json:"httpPath"`
			MetricPrefix TypeMetricPrefix `json:"metricPrefix"`
		} `json:"prometheus"`
	} `json:"stats"`
}

func (c *Config) GetConcurrency(defaultValue uint) uint {
	if concurrency := c.Concurrency.Get(0); concurrency != 0 {
		return concurrency
	}
	return c.Concurrency.Get(defaultValue)
}

func (c *Config) GetDNS() *url.URL {
	var dohURL *url.URL

	if dohIP := c.Network.DOHIP.Get(nil); dohIP != nil {
		dohURL, _ = url.Parse("https://" + dohIP.String())
	}

	return c.Network.DNS.Get(dohURL)
}

func (c *Config) GetDomainFrontingPort(defaultValue uint) uint {
	if port := c.DomainFronting.Port.Get(0); port != 0 {
		return port
	}
	return c.DomainFrontingPort.Get(defaultValue)
}

func (c *Config) GetDomainFrontingHost() string {
	return c.DomainFronting.Host.Get("")
}

func (c *Config) GetDomainFrontingProxyProtocol(defaultValue bool) bool {
	return c.DomainFronting.ProxyProtocol.Get(false) || c.DomainFrontingProxyProtocol.Get(defaultValue)
}

func (c *Config) Validate() error {
	if len(c.Secrets) == 0 {
		if !c.Secret.Valid() {
			return fmt.Errorf("invalid secret %s", c.Secret.String())
		}
	} else {
		for name, s := range c.Secrets {
			if !s.Valid() {
				return fmt.Errorf("invalid secret %q: %s", name, s.String())
			}
		}
	}

	if len(c.BindTo) == 0 {
		return fmt.Errorf("incorrect bind-to parameter: no addresses specified")
	}

	seen := make(map[string]struct{}, len(c.BindTo))

	for _, addr := range c.BindTo {
		v := addr.Get("")
		if v == "" {
			return fmt.Errorf("incorrect bind-to parameter: empty address")
		}

		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate bind-to address: %s", v)
		}

		seen[v] = struct{}{}
	}

	return c.validateWeb()
}

// validateWeb checks the [web] section. An empty bind-to disables the WEB
// mode, and then nothing else in the section matters.
func (c *Config) validateWeb() error {
	bind := strings.TrimSpace(c.Web.BindTo)
	if bind == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return fmt.Errorf("incorrect web.bind-to %q: %w", bind, err)
	}

	// The WEB listener speaks plain HTTP: TLS is terminated by a reverse proxy
	// on the same machine. Exposed directly, it would be a proxy without any
	// encryption or masking.
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("incorrect web.bind-to %q: must be a loopback address", bind)
	}

	if strings.TrimSpace(c.Web.Host) == "" {
		return fmt.Errorf("web.host is required when web.bind-to is set")
	}

	switch strings.ToLower(strings.TrimSpace(c.Web.SecretMode)) {
	case "", "dd", "plain":
	default:
		return fmt.Errorf("incorrect web.secret-mode %q: must be dd or plain", c.Web.SecretMode)
	}

	return nil
}

// GetSecrets returns all secrets as a map. If the new [secrets] section is used,
// returns that map. Otherwise, wraps the single Secret as {"default": Secret}.
func (c *Config) GetSecrets() map[string]mtglib.Secret {
	if len(c.Secrets) > 0 {
		return c.Secrets
	}

	return map[string]mtglib.Secret{"default": c.Secret}
}

// GetBindAddrs returns all bind addresses as strings.
func (c *Config) GetBindAddrs() []string {
	addrs := make([]string, len(c.BindTo))

	for i, hp := range c.BindTo {
		addrs[i] = hp.Get("")
	}

	return addrs
}

// GetFirstBindPort returns the port of the first bind address.
func (c *Config) GetFirstBindPort() uint {
	if len(c.BindTo) == 0 {
		return 0
	}

	return c.BindTo[0].Port
}

func (c *Config) String() string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}
