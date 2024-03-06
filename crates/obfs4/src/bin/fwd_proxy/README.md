
# Pluggable Transports in Rust (PTRS)

[![License](https://img.shields.io/github/license/jmwample/ptrs)](https://github.com/jmwample/ptrs/blob/main/LICENSE) [![Build Status](https://github.com/jmwample/ptrs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/jmwample/ptrs/actions/workflows/rust.yml)

PTRS is a library for writing pluggable transports in Rust.

## Example CLI

An example client / server using the ptrs pluggable transport library implementing a transparent
proxy can be found in the `src/bin/proxy` directory.

```console
$ proxy server -h
Run the binary as the remote server

Usage: proxy server [OPTIONS] <LISTEN_ADDR> [PT_ARGS]...

Arguments:
  <LISTEN_ADDR>  Address to listen for incoming client connections
  [PT_ARGS]...   pluggable transport argument(s)

Options:
  -t, --transport <TRANSPORT>  pluggable transport by name [default: plain]
  -b, --backend <BACKEND>      The backend handler to use ["echo", "socks5"] [default: echo]
      --debug                  Optional argument enabling debug logging
      --trace                  Optional argument enabling debug logging
  -h, --help                   Print help
  -V, --version                Print version
```

```console
$ proxy server 127.0.0.1:8080 -t hex --debug -- "upper"
2023-11-02T16:48:00.938532Z  INFO proxy::config: started server listening on 127.0.0.1:9001
```

In a (separate) terminal you can run the client portion of the transparent proxy

```console
$ proxy server -h
Run the binary as the client-side proxy

Usage: proxy client [OPTIONS] <REMOTE> [PT_ARGS]...

Arguments:
  <REMOTE>      Optional argument specifying the client_type, default to be Runner
  [PT_ARGS]...  pluggable transport argument(s)

Options:
  -l, --listen-addr <LISTEN_ADDR>  Address to listen for incoming client connections [default: 127.0.0.1:9000]
  -t, --transport <TRANSPORT>      pluggable transport by name [default: plain]
      --debug                      Optional argument enabling debug logging
      --trace                      Optional argument enabling debug logging
  -h, --help                       Print help
  -V, --version                    Print version
```

```console
$ proxy client 127.0.0.1:8080 -t hex --debug -- "upper"
2023-11-02T16:47:01.105147Z  INFO proxy::config: started proxy client on 127.0.0.1:9000
```

The client can then be connected to on "127.0.0.1:9000" transparently proxying traffic through to
the server side and beyond.
