## Forward Proxy


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

Help info

```txt
Tunnel SOCKS5 traffic through obfs4 connections

Usage: fwd [OPTIONS] <MODE> <DST> [LADDR]

Arguments:
  <MODE>   Run in server mode or client mode [possible values: client, server]
  <DST>    Target address, server address when running as client, forward address when running as server
  [LADDR]  Listen address, defaults to "[::]:9000" for client, "[::]:9001" for server

Options:
  -l, --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: INFO]
      --unsafe-logging         Disable the address scrubber on logging
  -a, --args <ARGS>
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```
