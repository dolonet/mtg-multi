package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) ReadConfig(filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	suite.NoError(err)

	return data
}

func (suite *ConfigTestSuite) TestParseEmpty() {
	_, err := config.Parse([]byte{})
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseBrokenToml() {
	_, err := config.Parse(suite.ReadConfig("broken.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseOnlySecret() {
	_, err := config.Parse(suite.ReadConfig("only_secret.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseMinimalConfig() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Equal("7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t", conf.Secret.Base64())
	suite.Require().Len(conf.BindTo, 1)
	suite.Equal("0.0.0.0:3128", conf.BindTo[0].Get(""))
}

func (suite *ConfigTestSuite) TestParseMultiBind() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)
	suite.Require().Len(conf.BindTo, 2)
	suite.Equal("127.0.0.1:443", conf.BindTo[0].Get(""))
	suite.Equal("[::1]:443", conf.BindTo[1].Get(""))
}

func (suite *ConfigTestSuite) TestMultiBindGetAddrs() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)

	addrs := conf.GetBindAddrs()
	suite.Equal([]string{"127.0.0.1:443", "[::1]:443"}, addrs)
}

func (suite *ConfigTestSuite) TestMultiBindGetFirstPort() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)
	suite.Equal(uint(443), conf.GetFirstBindPort())
}

func (suite *ConfigTestSuite) TestGetFirstBindPortEmpty() {
	conf := &config.Config{}
	suite.Equal(uint(0), conf.GetFirstBindPort())
}

func (suite *ConfigTestSuite) TestParseEmptyBindArray() {
	_, err := config.Parse(suite.ReadConfig("empty_bind.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseInvalidBindAddr() {
	_, err := config.Parse(suite.ReadConfig("invalid_bind_addr.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseNonStringBind() {
	_, err := config.Parse(suite.ReadConfig("non_string_bind.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestValidateDuplicateBindAddrs() {
	conf, err := config.Parse(suite.ReadConfig("duplicate_bind.toml"))
	suite.NoError(err)
	suite.Error(conf.Validate())
}

func (suite *ConfigTestSuite) TestParsePublicIP() {
	conf, err := config.Parse(suite.ReadConfig("public_ip.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Equal("2001:db8::1", conf.PublicIPv6.Get(nil).String())
}

func (suite *ConfigTestSuite) TestParsePublicIPv4Only() {
	conf, err := config.Parse(suite.ReadConfig("public_ip_v4_only.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestParsePublicIPInvalid() {
	_, err := config.Parse(suite.ReadConfig("public_ip_invalid.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParsePublicIPNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Nil(conf.PublicIPv4.Get(nil))
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestString() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NotEmpty(conf.String())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredWhenHostSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)

	suite.NoError(conf.DomainFronting.Host.Set("fronting-backend"))
	suite.NoError(conf.DomainFronting.IP.Set("10.0.0.10"))
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostAcceptsLiteralIP() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("10.0.0.1", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	// Deprecated [domain-fronting].ip is parsed but never used to derive
	// the dial target — the user must migrate to [domain-fronting].host.
	suite.NotNil(conf.DomainFronting.IP.Get(nil))
	suite.Equal("", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestPendingHandshakesDisabledByDefault() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.EqualValues(0, conf.Defense.PendingHandshakes.MaxPerIP.Get(0))
	suite.False(conf.Defense.PendingHandshakes.DryRun.Get(false))
}

func (suite *ConfigTestSuite) TestPendingHandshakes() {
	conf, err := config.Parse(suite.ReadConfig("pending_handshakes.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.EqualValues(32, conf.Defense.PendingHandshakes.MaxPerIP.Get(0))
	suite.True(conf.Defense.PendingHandshakes.DryRun.Get(false))
}

func (suite *ConfigTestSuite) TestSecuredDisabledByDefault() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.False(conf.Secured.Enabled.Get(false))
	suite.EqualValues(0, conf.Secured.FrameTimeout.Get(0))
}

func (suite *ConfigTestSuite) TestSecured() {
	conf, err := config.Parse(suite.ReadConfig("secured.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.True(conf.Secured.Enabled.Get(false))
	suite.Equal(1500*time.Millisecond, conf.Secured.FrameTimeout.Get(0))
}

func (suite *ConfigTestSuite) TestDCPoolDisabledByDefault() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.False(conf.DCPool.Enabled.Get(false))
	suite.EqualValues(0, conf.DCPool.Size.Get(0))
}

func (suite *ConfigTestSuite) TestDCPool() {
	conf, err := config.Parse(suite.ReadConfig("dc_pool.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.True(conf.DCPool.Enabled.Get(false))
	suite.EqualValues(4, conf.DCPool.Size.Get(0))
	suite.Equal([]int{1, 2, 3, 4, 5, -2, -4, 203}, conf.DCPool.DCs)
}

func (suite *ConfigTestSuite) TestDCPoolDefaultDCs() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Empty(conf.DCPool.DCs)
}

func (suite *ConfigTestSuite) TestDCPoolInvalid() {
	for _, name := range []string{
		"dc_pool_size_too_big.toml",
		"dc_pool_bad_dcs.toml",
		"dc_pool_dup_dcs.toml",
	} {
		conf, err := config.Parse(suite.ReadConfig(name))
		suite.NoError(err, name)
		suite.ErrorIs(conf.Validate(), mtglib.ErrDCPoolInvalid, name)
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ConfigTestSuite{})
}
