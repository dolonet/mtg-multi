package cli

import (
	"fmt"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/internal/utils"
)

type Run struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"` //nolint: lll
}

func (r *Run) Run(cli *CLI, version string) error {
	// Catch SIGHUP first: by default Go terminates on it, and systemd treats
	// that exit as clean and does not restart. Startup takes seconds (DNS
	// checks, public IP detection), and a reload signal in that window would
	// kill mtg. A signal that arrives early is applied right after startup.
	reloadSignals := utils.ReloadSignals()

	conf, err := utils.ReadConfig(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	return runProxy(conf, version, reloadSignals, func() (*config.Config, error) {
		return utils.ReadConfig(r.ConfigPath)
	})
}
