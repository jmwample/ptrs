## Forward Proxy

This is an executable program designed to manage the calling interface used by
the Tor libraries when launching pluggable transports (see `pt-spec.txt`).

` [client] <---> [fwd\_client] <====> [fwd\_server] <---> [target] `

Help info

```txt
Generalized forward proxy client and server for transparently proxying traffic over PTs.

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
```

## Installation

To build:
    `cargo build --release`


To install:
    `cargo install pt-proxy --bin fwd`
This will install in the binary your local rust bin target (usually `$HOME/.cargo/bin/`),
which can either be added to your `$PATH` or copied to a different permanent location
such as `/usr/local/bin`.

## Usage


Client configuration options

```txt
$ fwd client -h
Run as client forward proxy, initiating pluggable transport connection

Usage: fwd client <DST>

Arguments:
  <DST>  Target address, server address when running as client, forward address when running as

Options:
  -h, --help  Print help
```

Server configuration options

```txt
$ fwd server -h
Run as server, terminating the pluggable transport protocol

Usage: fwd server <COMMAND>

Commands:
  echo   For each (successful) connection echo client traffic back over the tunnel.
                $ fwd [OPTIONS] server echo

  fwd    For each (successful) connection transparently proxy traffic to the provided host.
                $ fwd [OPTIONS] server fwd "127.0.0.1:8080"

  socks  Run a socks5 server to handle all (successful) incoming connections.
                $ fwd [OPTIONS] server socks --auth "user:example"

  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```


### Example

1. Start the server:

```sh
fwd server echo --unsafe-logging
2024-03-27T03:44:57.977275Z  WARN fwd: log level set to INFO
2024-03-27T03:44:57.977322Z  INFO fwd: ⚠️ ⚠️  unsafe logging enabled ⚠️ ⚠️
2024-03-27T03:44:57.979757Z  INFO fwd: client params: "cert=8xGdU1YV4rNN1EEwRZQw9JlykG4Dqan7lDSRAtNxNYfK11qFhmLDraZ6rQDj4Eq10RKxEQ,iat-mode=0"
2024-03-27T03:44:57.979871Z  INFO fwd: accepting connections
2024-03-27T03:44:57.979995Z  INFO fwd: obfs4 server accept loop launched listening on: [::]:9001
2024-03-27T03:45:23.722630Z  INFO obfs4::obfs4::sessions: s-d996c2078c710e34 handshake complete
2024-03-27T03:45:38.363711Z  INFO fwd: tunnel closed 115 115 address="[::ffff:127.0.0.1]:47092"
```


2. launch the client proxy using the arguments from the launched server:

```sh
fwd client 127.0.0.1:9001 --unsafe-logging -a "cert=8xGdU1YV4rNN1EEwRZQw9JlykG4Dqan7lDSRAtNxNYfK11qFhmLDraZ6rQDj4Eq10RKxEQ,iat-mode=0"
2024-03-27T03:45:18.902073Z  WARN fwd: log level set to INFO
2024-03-27T03:45:18.902107Z  INFO fwd: ⚠️ ⚠️  unsafe logging enabled ⚠️ ⚠️
2024-03-27T03:45:18.902378Z  INFO fwd: accepting connections
2024-03-27T03:45:18.902542Z  INFO fwd: obfs4 client accept loop launched listening on: [::]:9000
2024-03-27T03:45:23.726626Z  INFO obfs4::obfs4::sessions: c-d996c2078c710e34 handshake complete
2024-03-27T03:45:38.364201Z  INFO fwd: tunnel closed 115 115 address="[::ffff:127.0.0.1]:53610"
```


3. Connect through the local proxy

```sh
nc -vv 127.0.0.1:9000
```

