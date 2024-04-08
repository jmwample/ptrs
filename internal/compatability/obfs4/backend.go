package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
)

type Backend func(f base.ServerFactory, conn net.Conn)

func makeBackend(t, a string) (Backend, error) {

	switch t {
	case "echo":
		return serverEchoHandler, nil
	case "fwd":
		addrport, err := netip.ParseAddrPort(a)
		if err != nil {
			log.Fatalf("specified fwd handler with invalid Addr:Port dst (%s): %s", a, err)
		}
		addr := net.TCPAddrFromAddrPort(addrport)
		return makeServerFwdBackend(addr), nil

	case "socks":
		return nil, fmt.Errorf("not yet implemented")
	default:
		return nil, fmt.Errorf("unknown backend name: %s", t)
	}

}

func serverEchoHandler(f base.ServerFactory, conn net.Conn) {
	defer conn.Close()
	termMon.onHandlerStart()
	defer termMon.onHandlerFinish()

	name := f.Transport().Name()
	addrStr := elideAddr(conn.RemoteAddr().String())

	if up, dn, err := copyLoop(conn, conn); err != nil {
		Warnf("%s(%s) closed connection (%d⬆️  - %d⬇️ ): %s", name, addrStr, up, dn, elideError(err))
	} else {
		Infof("%s(%s) closed connection (%d⬆️  - %d⬇️ )", name, addrStr, up, dn)
	}
}

func makeServerFwdBackend(dst *net.TCPAddr) Backend {

	return func(f base.ServerFactory, conn net.Conn) {
		defer conn.Close()
		termMon.onHandlerStart()
		defer termMon.onHandlerFinish()

		name := f.Transport().Name()
		addrStr := elideAddr(conn.RemoteAddr().String())

		fwd, err := net.DialTCP("tcp", nil, dst)
		if err != nil {
			Warnf("%s(%s) failed to connect to backend dst: %s", name, addrStr, elideError(err))
			return
		}

		if up, dn, err := copyLoop(fwd, conn); err != nil {
			Warnf("%s(%s) closed connection (%d⬆️  - %d⬇️ ): %s", name, addrStr, up, dn, elideError(err))
		} else {
			Infof("%s(%s) closed connection (%d⬆️  - %d⬇️ )", name, addrStr, up, dn)
		}
	}
}

func copyLoop(a net.Conn, b net.Conn) (int64, int64, error) {
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	var bytesUp int64 = 0
	var bytesDown int64 = 0

	go func() {
		defer wg.Done()
		defer b.Close()
		defer a.Close()
		n, err := io.Copy(b, a)
		if e, ok := err.(net.Error); !(ok && e == net.ErrClosed) || !ok {
			// if the close error is anything other than "use of closed conn" report it
			errChan <- err
		}
		bytesUp += n
	}()
	go func() {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		n, err := io.Copy(a, b)
		if e, ok := err.(net.Error); !(ok && e == net.ErrClosed) || !ok {
			// if the close error is anything other than "use of closed conn" report it
			errChan <- err
		}
		bytesDown += n
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return bytesUp, bytesDown, <-errChan
	}

	return bytesUp, bytesDown, nil
}
