# Pluggable Transport Proxy Applications

This crates contains multiple binary exceutables designed specifically to work
with and pluggable transport library implementing the ['ptrs'] interface.


## Forward proxy

` [client] <---> [fwd\_client] <====> [fwd\_server] <---> [target] `

Usage info:

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

## Pluggable Transport Bridge

['lyrebird'] provides an executable program designed to manage the calling
interface used by the Tor libraries when launching pluggable transports (see `pt-spec.txt`).

`... [tor_client] <---> [pt_client] <====> [pt_bridge] <---> [tor_orport] ...`

Usage info:

```txt
Tunnel Tor SOCKS5 traffic through pluggable transport connections

Usage: lyrebird [OPTIONS]

Options:
      --enable-logging         Log to {TOR_PT_STATE_LOCATION}/obfs4proxy.log
      --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: ERROR]
      --unsafe-logging         Disable the address scrubber on logging
  -h, --help                   Print help
  -V, --version                Print version
```
