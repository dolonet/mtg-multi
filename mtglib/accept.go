package mtglib

import (
	"context"
	"net"
	"time"

	"github.com/dolonet/mtg-multi/internal/acceptretry"
)

// acceptWithRetry accepts the next connection, retrying temporary errors with
// a growing pause. It returns an error only when the listener is unusable or
// ctx is done.
func acceptWithRetry(ctx context.Context, listener net.Listener, logger Logger) (net.Conn, error) {
	var delay time.Duration

	for {
		conn, err := listener.Accept()
		if err == nil {
			return conn, nil
		}

		if ctx.Err() != nil {
			return nil, err
		}

		if acceptretry.IsAcceptedConn(err) {
			logger.DebugError("accepted connection failed before use", err)

			continue
		}

		if !acceptretry.IsTemporary(err) {
			return nil, err
		}

		delay = acceptretry.NextDelay(delay)
		logger.BindStr("retry_in", delay.String()).WarningError("temporary accept error", err)

		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()

			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
