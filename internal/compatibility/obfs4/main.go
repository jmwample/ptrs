/*
 * Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Go language Tor Pluggable Transport suite.  Works only as a managed
// client/server.
package main

import (
	"errors"
	"log"
	"net"
	"os"
	"path"
	"syscall"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
)

const (
	obfs4proxyVersion = "0.0.16-dev"
	obfs4proxyLogFile = "obfs4fwd.log"
	// fwdProxyAddr      = ":9001"
	// fwdProxyPort      = 9001
	// clientConnectAddr = "127.0.0.1:9001"
	// clientListenAddr  = "127.0.0.1:9000"
)

const (
	nodeIDArg     = "node-id"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"

	publicKeyArg = "public-key"
	iatArg       = "iat-mode"
)

var pubkeyTest = "d3485bec18ac4d14f05c19d38205282912d2489c6f7309865ecc13d506e0566a"
var privkeyTest = "3031323334353637383961626364656666656463626139383736353433323130"
var nodeID = "0000000000000000000000000000000000000000"
var iatMode = "0"

var termMon *termMonitor

func clientSetup(listenAddr, dstAddr string) (launched bool, listeners []net.Listener) {
	name := "obfs4"

	obfsTransport := obfs4.Transport{}

	cf, err := obfsTransport.ClientFactory("")
	if err != nil {
		log.Fatalf("failed to create client factory")
	}

	args := pt.Args{}
	args.Add(nodeIDArg, nodeID)
	args.Add(publicKeyArg, pubkeyTest)
	args.Add(iatArg, iatMode)

	parsedArgs, err := cf.ParseArgs(&args)
	if err != nil {
		log.Fatalf("failed to parse obfs4 args")
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen for tcp on %s: %s", listenAddr, err)
		return
	}

	go clientAcceptLoop(cf, ln, parsedArgs, dstAddr)

	Infof("%s registered listener: %s", name, elideAddr(ln.Addr().String()))
	listeners = append(listeners, ln)
	launched = true

	return
}

func clientAcceptLoop(cf base.ClientFactory, ln net.Listener, args any, dst string) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); (ok && !e.Timeout()) || !ok {
				if !errors.Is(e, net.ErrClosed) {
					Errorf("listener error: %s", e)
				}
				Infof("shutting down client listener")
				return
			}
			continue
		}
		Debugf("accepted new connection: %s", elideAddr(conn.RemoteAddr().String()))
		go clientHandler(cf, conn, args, dst)
	}
}

func clientHandler(cf base.ClientFactory, conn net.Conn, args any, dst string) {
	defer conn.Close()

	name := cf.Transport().Name()
	addrStr := elideAddr(conn.RemoteAddr().String())
	remote, err := cf.Dial("tcp", dst, net.Dial, args)
	if err != nil {
		Errorf("%s(%s) handshake failed: %s", name, addrStr, err)
		return
	}

	Infof("%s(%s) successful connection", name, addrStr)

	if up, dn, err := copyLoop(conn, remote); err != nil {
		Warnf("%s(%s) closed connection (%d⬆️  - %d⬇️ ): %s", name, addrStr, up, dn, elideError(err))
	} else {
		Infof("%s(%s) closed connection (%d⬆️  - %d⬇️ )", name, addrStr, up, dn)
	}
}

func serverSetup(listenAddr string, handler Backend) (launched bool, listeners []net.Listener) {
	name := "obfs4"

	args := pt.Args{}
	args.Add(nodeIDArg, nodeID)
	args.Add(privateKeyArg, privkeyTest)
	args.Add(iatArg, iatMode)

	seed, err := drbg.NewSeed()
	if err != nil {
		log.Fatalf("failed to create DRBG seed: %s", err)
		return false, nil
	}
	args.Add(seedArg, seed.Hex())

	t := &obfs4.Transport{}

	f, err := t.ServerFactory("", &args)
	if err != nil {
		log.Fatalf("failed to create server factory: %s", err)
		return false, nil
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen for tcp on %s: %s", listenAddr, err)
		return
	}

	go func() {
		_ = serverAcceptLoop(f, ln, handler)
	}()

	Infof("%s registered listener: %s", name, elideAddr(ln.Addr().String()))
	listeners = append(listeners, ln)
	launched = true

	return
}

func serverAcceptLoop(f base.ServerFactory, ln net.Listener, handler Backend) error {
	defer ln.Close()

	name := f.Transport().Name()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); (ok && !e.Timeout()) || !ok {
				if !errors.Is(e, net.ErrClosed) {
					Errorf("listener error: %s", e)
				}
				Infof("shutting down server listener")
				return err
			}
			continue
		}

		go func() {
			addrStr := elideAddr(conn.RemoteAddr().String())
			Infof("%s(%s) new connection", name, addrStr)

			// Instantiate the server transport method and handshake.
			remote, err := f.WrapConn(conn)
			if err != nil {
				Warnf("%s(%s) handshake failed: %s", name, addrStr, elideError(err))
				return
			}
			Infof("%s(%s) successful connection", name, addrStr)

			// hand the connection off to  the backend
			handler(f, remote)
		}()
	}
}

func main() {
	var err error
	// Initialize the termination state monitor as soon as possible.
	termMon = newTermMonitor()

	_, execName := path.Split(os.Args[0])
	// Handle the command line arguments.
	// Determine if this is a client or server, initialize the common state.
	args := parseArgs()

	// set global for unsage logging -_-
	unsafeLogging = args.unsafeLogging

	var ptListeners []net.Listener
	var launched bool
	if err = transports.Init(); err != nil {
		Errorf("%s failed to initialize transports: %s", execName, err)
		os.Exit(-1)
	}

	// Do the managed pluggable transport protocol configuration.
	if args.isClient {
		Infof("%s launching as Client", getVersion())

		Infof("%s initializing client transport listeners", execName)
		launched, ptListeners = clientSetup(args.listenAddr.String(), args.clientConfig.dst.String())
	} else {
		Infof("%s launching as Server", getVersion())

		handler, err := makeBackend(args.serverConfig.backendType, args.serverConfig.backendArg)
		if err != nil {
			log.Fatalf("unable to initialize backed: %s", err)
		}

		Infof("%s initializing server transport listeners", execName)
		launched, ptListeners = serverSetup(args.listenAddr.String(), handler)
	}
	if !launched {
		// Initialization failed, the client or server setup routines should
		// have logged, so just exit here.
		os.Exit(-1)
	}

	Infof("%s accepting connections", execName)
	defer func() {
		Infof("%s terminated", execName)
	}()

	// At this point, the pt config protocol is finished, and incoming
	// connections will be processed.  Wait till the parent dies
	// (immediate exit), a SIGTERM is received (immediate exit),
	// or a SIGINT is received.
	if sig := termMon.wait(false); sig == syscall.SIGTERM {
		return
	}

	// Ok, it was the first SIGINT, close all listeners, and wait till,
	// the parent dies, all the current connections are closed, or either
	// a SIGINT/SIGTERM is received, and exit.
	for _, ln := range ptListeners {
		ln.Close()
	}
	termMon.wait(true)
}
