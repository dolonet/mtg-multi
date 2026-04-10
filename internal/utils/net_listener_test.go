package utils_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dolonet/mtg-multi/internal/utils"
	"github.com/stretchr/testify/suite"
)

type MultiListenerTestSuite struct {
	suite.Suite
}

func (suite *MultiListenerTestSuite) TestAcceptFromMultipleListeners() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l1.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l2.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	for range 2 {
		conn, err := ml.Accept()
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}

	wg.Wait()
}

func (suite *MultiListenerTestSuite) TestSingleListener() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l)
	defer ml.Close() //nolint: errcheck

	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}

		conn.Close() //nolint: errcheck
	}()

	conn, err := ml.Accept()
	suite.NoError(err)

	conn.Close() //nolint: errcheck
}

func (suite *MultiListenerTestSuite) TestCloseStopsAccept() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)

	errCh := make(chan error, 1)

	go func() {
		_, err := ml.Accept()
		errCh <- err
	}()

	suite.NoError(ml.Close())
	suite.Error(<-errCh)
}

func (suite *MultiListenerTestSuite) TestConcurrentAccept() {
	const numListeners = 3
	const connsPerListener = 10

	listeners := make([]net.Listener, numListeners)

	for i := range numListeners {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		suite.Require().NoError(err)

		listeners[i] = l
	}

	ml := utils.NewMultiListener(listeners...)
	defer ml.Close() //nolint: errcheck

	var accepted atomic.Int32

	go func() {
		for range numListeners * connsPerListener {
			conn, err := ml.Accept()
			if err != nil {
				return
			}

			accepted.Add(1)

			conn.Close() //nolint: errcheck
		}
	}()

	var wg sync.WaitGroup

	for _, l := range listeners {
		for range connsPerListener {
			wg.Add(1)

			go func() {
				defer wg.Done()

				conn, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					return
				}

				conn.Close() //nolint: errcheck
			}()
		}
	}

	wg.Wait()

	suite.Eventually(func() bool {
		return accepted.Load() == numListeners*connsPerListener
	}, 2_000_000_000, 10_000_000) // 2s timeout, 10ms poll
}

func (suite *MultiListenerTestSuite) TestAddr() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)
	defer ml.Close() //nolint: errcheck

	suite.Equal(l1.Addr(), ml.Addr())
}

func TestMultiListener(t *testing.T) {
	t.Parallel()
	suite.Run(t, &MultiListenerTestSuite{})
}
