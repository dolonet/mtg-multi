package utils_test

import (
	"net"
	"sync"
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
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}()

	go func() {
		defer wg.Done()

		conn, err := net.Dial("tcp", l2.Addr().String())
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}()

	for range 2 {
		conn, err := ml.Accept()
		suite.NoError(err)

		conn.Close() //nolint: errcheck
	}

	wg.Wait()
}

func (suite *MultiListenerTestSuite) TestCloseStopsAccept() {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	ml := utils.NewMultiListener(l1, l2)

	done := make(chan struct{})

	go func() {
		_, err := ml.Accept()
		suite.Error(err)

		close(done)
	}()

	suite.NoError(ml.Close())
	<-done
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
