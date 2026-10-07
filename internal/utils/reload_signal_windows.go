package utils

import "os"

// ReloadSignals returns a channel that never fires: there is no SIGHUP on
// Windows.
func ReloadSignals() <-chan os.Signal {
	return nil
}
