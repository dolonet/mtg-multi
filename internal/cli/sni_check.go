package cli

import (
	"context"
	"net"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
)

// sniCheckResult holds the data gathered while comparing the secret
// hostname's DNS records against this server's public IP addresses.
//
// IPv4Match / IPv6Match report whether a resolved record actually equals the
// corresponding public IP. They are false when that family's public IP could
// not be determined — there is nothing to compare against. Callers decide
// what counts as a clean result from these fields: `mtg doctor` and the
// startup warning apply different rules.
type sniCheckResult struct {
	Resolved   []net.IP
	OurIPv4    net.IP
	OurIPv6    net.IP
	IPv4Match  bool
	IPv6Match  bool
	ResolveErr error
}

// PublicIPKnown reports whether at least one public IP family was detected.
func (r sniCheckResult) PublicIPKnown() bool {
	return r.OurIPv4 != nil || r.OurIPv6 != nil
}

// runSNICheck resolves host and compares the records with this server's
// public IPv4 and IPv6. Public IPs come from config first and fall back to
// on-the-fly detection via ntw. host is passed explicitly rather than read
// from conf.Secret.Host so multi-secret configs can check the first secret's
// host (see Doctor.getFirstSecretHost). It gathers data only — it does not
// decide success; see sniCheckResult.
func runSNICheck(
	ctx context.Context,
	resolver *net.Resolver,
	conf *config.Config,
	ntw mtglib.Network,
	host string,
) sniCheckResult {
	res := sniCheckResult{}

	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		res.ResolveErr = err

		return res
	}

	res.Resolved = make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		res.Resolved = append(res.Resolved, a.IP)
	}

	res.OurIPv4 = conf.PublicIPv4.Get(nil)
	if res.OurIPv4 == nil {
		res.OurIPv4 = getIP(ntw, "tcp4")
	}

	res.OurIPv6 = conf.PublicIPv6.Get(nil)
	if res.OurIPv6 == nil {
		res.OurIPv6 = getIP(ntw, "tcp6")
	}

	for _, ip := range res.Resolved {
		if res.OurIPv4 != nil && ip.String() == res.OurIPv4.String() {
			res.IPv4Match = true
		}

		if res.OurIPv6 != nil && ip.String() == res.OurIPv6.String() {
			res.IPv6Match = true
		}
	}

	return res
}
