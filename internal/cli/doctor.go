package cli

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/beevik/ntp"
	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/internal/utils"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/mtglib/dcprobe"
	"github.com/dolonet/mtg-multi/network/v2"
)

var (
	tplError = template.Must(
		template.New("").Parse("  ‼️ {{ .description }}: {{ .error }}\n"),
	)

	tplWDeprecatedConfig = template.Must(
		template.New("").
			Parse(`  ⚠️ Option {{ .old | printf "%q" }}{{ if .old_section }} from section [{{ .old_section }}]{{ end }} is deprecated and will be removed in v{{ .when }}. Please use {{ .new | printf "%q" }}{{ if .new_section }} in [{{ .new_section }}] section{{ end }} instead.` + "\n"),
	)

	tplOTimeSkewness = template.Must(
		template.New("").
			Parse("  ✅ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}\n"),
	)
	tplWTimeSkewness = template.Must(
		template.New("").
			Parse("  ⚠️ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}. Please check ntp.\n"),
	)
	tplETimeSkewness = template.Must(
		template.New("").
			Parse("  ❌ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}. You will get many rejected connections!\n"),
	)

	tplODCConnect = template.Must(
		template.New("").Parse("  ✅ DC {{ .dc }} (rpc {{ .rtt }})\n"),
	)
	tplEDCConnect = template.Must(
		template.New("").Parse("  ❌ DC {{ .dc }}: {{ .error }}\n"),
	)

	tplODNSSNIMatch = template.Must(
		template.New("").Parse("  ✅ IP address {{ .ip }} matches secret hostname {{ .hostname }}\n"),
	)
	tplEDNSSNIMatch = template.Must(
		template.New("").Parse("  ❌ Hostname {{ .hostname }} {{ if .resolved }}resolves to {{ .resolved }}, but the proxy's public IP is {{ if .ip4 }}{{ .ip4 }}{{ else }}<not detected>{{ end }} (IPv4) / {{ if .ip6 }}{{ .ip6 }}{{ else }}<not detected>{{ end }} (IPv6) — none of the resolved addresses match{{ else }}cannot be resolved to any host{{ end }}\n"),
	)

	tplOFrontingDomain = template.Must(
		template.New("").Parse("  ✅ {{ .address }} is reachable\n"),
	)
	tplEFrontingDomain = template.Must(
		template.New("").Parse("  ❌ {{ .address }}: {{ .error }}\n"),
	)
)

type Doctor struct {
	conf *config.Config

	ConfigPath      string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"`                                                                       //nolint: lll
	SkipNativeCheck bool   `kong:"help='Skip the native network connectivity check (useful when proxy chaining is configured and direct egress is not expected to work).',name='skip-native-check'"` //nolint: lll
}

func (d *Doctor) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(d.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	d.conf = conf

	fmt.Println("Deprecated options")
	everythingOK := d.checkDeprecatedConfig()

	fmt.Println("Time skewness")
	everythingOK = d.checkTimeSkewness() && everythingOK

	resolver, err := network.GetDNS(conf.GetDNS())
	if err != nil {
		return fmt.Errorf("cannot create DNS resolver: %w", err)
	}

	base := network.New(
		resolver,
		"",
		conf.Network.Timeout.TCP.Get(10*time.Second),
		conf.Network.Timeout.HTTP.Get(0),
		conf.Network.Timeout.Idle.Get(0),
		net.KeepAliveConfig{
			Enable:   !conf.Network.KeepAlive.Disabled.Get(false),
			Idle:     conf.Network.KeepAlive.Idle.Get(0),
			Interval: conf.Network.KeepAlive.Interval.Get(0),
			Count:    int(conf.Network.KeepAlive.Count.Get(0)),
		},
		int(conf.Network.TCPNotSentLowat.Get(network.DefaultTCPNotSentLowat)),
	)

	fmt.Println("Validate native network connectivity")
	if d.SkipNativeCheck {
		fmt.Println("  ⏭ Skipped (--skip-native-check)")
	} else {
		everythingOK = d.checkNetwork(base) && everythingOK
	}

	for _, url := range conf.Network.Proxies {
		value, err := network.NewProxyNetwork(base, url.Get(nil))
		if err != nil {
			return err
		}

		fmt.Printf("Validate network connectivity with proxy %s\n", url.Get(nil))
		everythingOK = d.checkNetwork(value) && everythingOK
	}

	fmt.Println("Validate fronting domain connectivity")
	everythingOK = d.checkFrontingDomain(base) && everythingOK

	fmt.Println("Validate SNI-DNS match")
	everythingOK = d.checkSecretHost(resolver, base) && everythingOK

	if !everythingOK {
		os.Exit(1)
	}

	return nil
}

func (d *Doctor) checkDeprecatedConfig() bool {
	ok := true

	if d.conf.DomainFrontingIP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(os.Stdout, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-ip",
			"old_section": "",
			"new":         "host",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFronting.IP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(os.Stdout, map[string]string{ //nolint: errcheck
			"when":        "2.4.0",
			"old":         "ip",
			"old_section": "domain-fronting",
			"new":         "host",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFrontingPort.Value != 0 {
		ok = false
		tplWDeprecatedConfig.Execute(os.Stdout, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-port",
			"old_section": "",
			"new":         "port",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFrontingProxyProtocol.Value {
		ok = false
		tplWDeprecatedConfig.Execute(os.Stdout, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-proxy-protocol",
			"old_section": "",
			"new":         "proxy-protocol",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.Network.DOHIP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(os.Stdout, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "doh-ip",
			"old_section": "network",
			"new":         "dns",
			"new_section": "network",
		})
	}

	if ok {
		fmt.Println("  ✅ All good")
	}

	return ok
}

func (d *Doctor) checkTimeSkewness() bool {
	response, err := ntp.Query("0.pool.ntp.org")
	if err != nil {
		tplError.Execute(os.Stdout, map[string]any{ //nolint: errcheck
			"description": "cannot access ntp pool",
			"error":       err,
		})
		return false
	}

	skewness := response.ClockOffset.Abs()
	confValue := d.conf.TolerateTimeSkewness.Get(mtglib.DefaultTolerateTimeSkewness)
	diff := float64(skewness) / float64(confValue)
	tplData := map[string]any{
		"drift": response.ClockOffset,
		"value": confValue,
	}

	switch {
	case diff < 0.3:
		tplOTimeSkewness.Execute(os.Stdout, tplData) //nolint: errcheck
		return true
	case diff < 0.7:
		tplWTimeSkewness.Execute(os.Stdout, tplData) //nolint: errcheck
	default:
		tplETimeSkewness.Execute(os.Stdout, tplData) //nolint: errcheck
	}

	return false
}

func (d *Doctor) checkNetwork(ntw mtglib.Network) bool {
	dcs := slices.Collect(maps.Keys(essentials.TelegramCoreAddresses))
	slices.Sort(dcs)

	type dcResult struct {
		rtt time.Duration
		err error
	}
	results := make([]dcResult, len(dcs))

	var wg sync.WaitGroup
	for i, dc := range dcs {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					results[i].err = fmt.Errorf("panic: %v", r)
				}
			}()
			results[i].rtt, results[i].err = d.checkNetworkAddresses(ntw, dc, essentials.TelegramCoreAddresses[dc])
		})
	}
	wg.Wait()

	ok := true

	for i, dc := range dcs {
		if results[i].err == nil {
			tplODCConnect.Execute(os.Stdout, map[string]any{ //nolint: errcheck
				"dc":  dc,
				"rtt": results[i].rtt.Round(time.Microsecond),
			})
		} else {
			tplEDCConnect.Execute(os.Stdout, map[string]any{ //nolint: errcheck
				"dc":    dc,
				"error": results[i].err,
			})
			ok = false
		}
	}

	return ok
}

func (d *Doctor) checkNetworkAddresses(ntw mtglib.Network, dc int, addresses []string) (time.Duration, error) {
	checkAddresses := []string{}

	switch d.conf.PreferIP.Get("prefer-ip4") {
	case "only-ipv4":
		for _, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				panic(err)
			}

			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				checkAddresses = append(checkAddresses, addr)
			}
		}
	case "only-ipv6":
		for _, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				panic(err)
			}

			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				checkAddresses = append(checkAddresses, addr)
			}
		}
	default:
		checkAddresses = addresses
	}

	if len(checkAddresses) == 0 {
		return 0, fmt.Errorf("no suitable addresses after IP version filtering")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lastErr error

	for _, addr := range checkAddresses {
		conn, err := ntw.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("tcp connect to %s: %w", addr, err)
			continue
		}

		rtt, err := dcprobe.Probe(ctx, conn, dc)
		conn.Close() //nolint: errcheck

		if err != nil {
			lastErr = fmt.Errorf("rpc handshake to %s: %w", addr, err)
			continue
		}

		return rtt, nil
	}

	return 0, lastErr
}

func (d *Doctor) getFirstSecretHost() string {
	for _, s := range d.conf.GetSecrets() {
		return s.Host
	}

	return ""
}

func (d *Doctor) checkFrontingDomain(ntw mtglib.Network) bool {
	host := d.getFirstSecretHost()
	if override := d.conf.GetDomainFrontingHost(); override != "" {
		host = override
	}

	port := d.conf.GetDomainFrontingPort(mtglib.DefaultDomainFrontingPort)
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := ntw.NativeDialer()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		tplEFrontingDomain.Execute(os.Stdout, map[string]any{ //nolint: errcheck
			"address": address,
			"error":   err,
		})
		return false
	}

	conn.Close() //nolint: errcheck

	tplOFrontingDomain.Execute(os.Stdout, map[string]any{ //nolint: errcheck
		"address": address,
	})

	return true
}

func (d *Doctor) checkSecretHost(resolver *net.Resolver, ntw mtglib.Network) bool {
	host := d.getFirstSecretHost()

	res := runSNICheck(context.Background(), resolver, d.conf, ntw, host)

	if res.ResolveErr != nil {
		tplError.Execute(os.Stdout, map[string]any{ //nolint: errcheck
			"description": fmt.Sprintf("cannot resolve DNS name of %s", host),
			"error":       res.ResolveErr,
		})
		return false
	}

	if !res.PublicIPKnown() {
		tplError.Execute(os.Stdout, map[string]any{ //nolint: errcheck
			"description": "cannot detect public IP address",
			"error":       errors.New("cannot detect automatically and public-ipv4/public-ipv6 are not set in config"),
		})
		return false
	}

	if res.IPv4Match || res.IPv6Match {
		var matched net.IP

		for _, ip := range res.Resolved {
			if (res.OurIPv4 != nil && ip.String() == res.OurIPv4.String()) ||
				(res.OurIPv6 != nil && ip.String() == res.OurIPv6.String()) {
				matched = ip
				break
			}
		}

		tplODNSSNIMatch.Execute(os.Stdout, map[string]any{ //nolint: errcheck
			"ip":       matched,
			"hostname": host,
		})
		return true
	}

	strAddresses := make([]string, 0, len(res.Resolved))
	for _, ip := range res.Resolved {
		strAddresses = append(strAddresses, `"`+ip.String()+`"`)
	}

	tplEDNSSNIMatch.Execute(os.Stdout, map[string]any{ //nolint: errcheck
		"hostname": host,
		"resolved": strings.Join(strAddresses, ", "),
		"ip4":      res.OurIPv4,
		"ip6":      res.OurIPv6,
	})

	return false
}
