package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"path"
	"slices"
	"strconv"
)

const usage = `Generalized forward proxy client and server for transparently proxying traffic over PTs.

Usage: fwd [OPTIONS] [LADDR] <COMMAND>

Commands:
  client  Run as client forward proxy, initiating pluggable transport connection
  server  Run as server, terminating the pluggable transport protocol
  help    Print this message or the help of the given subcommand(s)

Arguments:
  [LADDR]  Listen address, defaults to "[::]:9000" for client, "[::]:9001" for server

Options:
  -a, --args <ARGS>            Transport argument string
  -l, --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: INFO]
  -x, --unsafe-logging         Disable the address scrubber on logging
  -h, --help                   Print help
  -V, --version                Print version


Examples:
	$ fwd -s ./state/ server fwd "127.0.0.1:5201"
	$ fwd -s -l DEBUG -x server echo
	$ fwd -a "cert=AAAAAAAAAAAAAAAAAAAAAAAAAADTSFvsGKxNFPBcGdOCBSgpEtJInG9zCYZezBPVBuBWag;iat-mode=0" -l DEBUG 127.0.0.1:9000 client 127.0.0.1:9001`

// -s, --state-dir <DIR>        Path to a directory where launch state is located.

const clientUsage = `Run as client forward proxy, initiating pluggable transport connection

Usage: fwd client <DST>

Arguments:
  <DST>  Target address, proxy server address when running as client

Options:
  -h, --help  Print help`

const serverUsage = `Run as server, terminating the pluggable transport protocol

Usage: fwd server <COMMAND>

Commands:
  echo   For each (successful) connection echo client traffic back over the tunnel.
                $ fwd [OPTIONS] [LADDR] server echo

  fwd    For each (successful) connection transparently proxy traffic to the provided host.
                $ fwd [OPTIONS] [LADDR] server fwd "127.0.0.1:8080"

  socks  Run a socks5 server to handle all (successful) incoming connections.
                $ fwd [OPTIONS] [LADDR] server socks "user:example"

  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help`

var validCmds = []string{"client", "server"}

func parseArgs() CliArgs {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	var (
		err                    error
		logLevelStr, argStr    string
		unsafeLogging, showVer bool
	)

	// Handle the command line arguments.
	_, execName := path.Split(os.Args[0])
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.BoolVar(&showVer, "V", false, "Print version and exit")
	flag.StringVar(&logLevelStr, "logLevel", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")
	flag.StringVar(&logLevelStr, "l", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")
	// flag.StringVar(&stateDir, "state-dir", "", "Path to a directory where launch state is located.")
	// flag.StringVar(&stateDir, "s", "", "Path to a directory where launch state is located.")
	flag.BoolVar(&unsafeLogging, "unsafe-logging", false, "Disable the address scrubber on logging")
	flag.BoolVar(&unsafeLogging, "x", false, "Disable the address scrubber on logging")
	flag.StringVar(&argStr, "args", "", "Transport argument string")
	flag.StringVar(&argStr, "a", "", "Transport argument string")

	// We declare a subcommand using the `NewFlagSet`
	// function, and proceed to define new flags specific
	// for this subcommand.
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverCmd.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", serverUsage) }

	// For a different subcommand we can define different
	// supported flags.
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	clientCmd.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", clientUsage) }

	flag.Parse()

	if showVer {
		fmt.Printf("%s-%s\n", execName, getVersion())
		os.Exit(0)
	}

	cliArgs := CliArgs{}

	var modePosition = 0
	switch flag.NArg() {
	case 0:
		flag.Usage()
		os.Exit(1)
	case 1:
		if cliArgs.isClient {
			cliArgs.listenAddr = &net.TCPAddr{net.IPv4zero, 9000, ""}
		} else {
			cliArgs.listenAddr = &net.TCPAddr{net.IPv4zero, 9001, ""}
		}
		if !slices.Contains(validCmds, flag.Args()[0]) {
			fmt.Println("expected 'server' or 'client' subcommand\n")
			os.Exit(1)
		}
	default:
		if !slices.Contains(flag.Args()[0:2], "client") && !slices.Contains(flag.Args()[0:2], "server") {
			fmt.Println("expected 'server' or 'client' subcommand\n")
			os.Exit(1)
		}

		// if server / client cmd is not arg 0 it could be the listenAddress
		if !slices.Contains(validCmds, flag.Args()[0]) {
			cliArgs.listenAddr, err = tryParseAddr(flag.Args()[0])
			if err != nil {
				// wasnt a valid address
				fmt.Printf("provided LADDR was invalid: %s\n", err)
				fmt.Println("LADDR must be IP:port format (e.g. \"127.0.0.1:4433\", \"[1234::4321]:9000\")\n")
				os.Exit(1)
			}

			modePosition = 1
		}
	}

	// Check which subcommand is invoked.
	switch flag.Args()[modePosition] {
	// For every subcommand, we parse its own flags and
	// have access to trailing positional arguments.
	case "server":
		cliArgs.isClient = false

		serverConfig := &ServerConfig{}

		serverCmd.Parse(flag.Args()[modePosition+1:])
		cliArgs.serverConfig = &ServerConfig{}
		if serverCmd.NArg() == 0 {
			fmt.Printf("running in server mode requires backend\n\n")
			serverCmd.Usage()
			os.Exit(1)
		}

		backend := serverCmd.Args()[0]
		serverConfig.backendType = backend

		switch backend {
		case "echo":
		case "socks":
			if serverCmd.NArg() >= 2 {
				serverConfig.backendArg = serverCmd.Args()[1]
			}
		case "fwd":
			if serverCmd.NArg() < 2 {
				fmt.Printf("server backend \"%s\" requires argument\n\n", backend)
				serverCmd.Usage()
				os.Exit(1)
			}
			serverConfig.backendArg = serverCmd.Args()[1]
		default:
			fmt.Printf("invalid backend (%s): %s\n\n", backend, err)
			serverCmd.Usage()
			os.Exit(1)
		}
		cliArgs.serverConfig = serverConfig

	case "client":
		cliArgs.isClient = true

		clientCmd.Parse(flag.Args()[modePosition+1:])
		if clientCmd.NArg() == 0 {
			clientCmd.Usage()
			os.Exit(1)
		}

		dst, err := tryParseAddr(clientCmd.Args()[0])
		if err != nil {
			fmt.Printf("provided DST address was invalid: %s\n\n", err)
			clientCmd.Usage()
			os.Exit(1)
		}

		cliArgs.clientConfig = &ClientConfig{dst}
	default:
		fmt.Println("expected 'server' or 'client' subcommands - (shouldn't be possible)\n")
		os.Exit(1)
	}

	l := slog.Level(0)
	if err := l.UnmarshalText([]byte(logLevelStr)); err != nil {
		log.Fatalf("[ERROR]: %s - failed to set log level: %s", execName, err)
	}
	log.Printf("%s - log level set %s", execName, logLevelStr)

	return cliArgs
}

func tryParseAddr(s string) (*net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	addr := net.ParseIP(host)
	if addr == nil {
		return nil, fmt.Errorf("non-IP host provided: %s", host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{addr, port, ""}, nil
}

// CliArgs is a struct that holds the parsed command line arguments for either
// the client or server.
type CliArgs struct {
	legLevel      string
	unsafeLogging bool

	args string

	isClient     bool
	listenAddr   *net.TCPAddr
	clientConfig *ClientConfig
	serverConfig *ServerConfig
}

// ClientConfig is a struct that holds the parsed command line arguments for
// the client.
type ClientConfig struct {
	dst *net.TCPAddr
}

// ServerConfig is a struct that holds the parsed command line arguments for
// the server.
type ServerConfig struct {
	backendType string
	backendArg  string

	printClientArgs bool
}

func getVersion() string {
	return fmt.Sprintf("obfs4proxy-%s", obfs4proxyVersion)
}

// func (sc *ServerConfig) FromFile() error {
// 	if sc.fromFile == "" {
// 		return nil
// 	}
// 	f, err := os.Open(sc.fromFile)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()
//
// 	dec := json.NewDecoder(f)
// 	if err := dec.Decode(sc); err != nil {
// 		return err
// 	}
// 	return nil
// }
//
// func (sc *ServerConfig) PrintClientArgs() error {
// 	if !sc.printClientArgs {
// 		return nil
// 	}
// 	fmt.Printf("-node-id=%s -public-key=%s\n", sc.nodeID, sc.publicKey)
// 	return nil
// }
