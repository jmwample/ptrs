
# Pluggable Transports in Rust (PTRS)

<p>
  <!--a href="https://deps.rs/repo/github/jmwample/ptrs">
    <img src="https://deps.rs/repo/github/jmwample/ptrs/status.svg">
  </a-->
  <a href="https://crates.io/crates/ptrs">
    <img src="https://img.shields.io/crates/v/ptrs.svg">
  </a>
  <a href="https://docs.rs/ptrs">
    <img src="https://docs.rs/ptrs/badge.svg">
  </a>
  <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

PTRS is a library for writing pluggable transports in Rust.

## Library Usage

This library (currently) revolves around the abstraction of connections as anything that implement
the traits [`tokio::io:AsyncRead`] + [`tokio::io::AsyncRead`] + `Unpin + Send + Sync`. This allows
us to define the expected shared behavior of pluggable transports as a transform of these
[`Stream`]s.

```rust ignore
use ptrs::Result;
use tokio::io::{AsyncRead,AsyncWrite};

pub trait StreamTransport<'a, A>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'a,
{
    fn wrap(&self, a: A) -> Result<Box<dyn Stream + 'a>>;
}
```

### Integrating ptrs Transports

Given this abstraction integrating transports into async rust applications becomes relatively
straightforward, for example, integrating the identity transport (which performs a direct copy with
no actual transform) could be done similar to:

```rust ignore
use ptrs::{stream::Stream, StreamTransport, transports::identity};
use tokio::net::TcpListener;

async fn process_socket<'s,S: Stream+'s>(stream: S) {
    // ...
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let transport = identity::Identity::new();

    loop {
        let (tcp_socket, _) = listener.accept().await?;
        let socket = transport.wrap(socket)?;
        process_socket(socket).await;
    }
    Ok(())
}
```

Integration on the client side is similarly straightforward.

```rust ignore
use ptrs::{StreamTransport, transports::identity};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let transport = identity::new();
    let mut tcp_stream = TcpStream::connect("127.0.0.1:8080").await?;
    let mut stream = transport.wrap(tcp_stream)?;

    stream.write_all(b"hello world!").await?;
    stream.read(&mut [0; 128]).await?;
    Ok(())
} // the stream is closed here
```

#### Configuration & State

The trait [`Configurable`] provides a way that transports can be provided a configuration as an
`&str` which they can parse and apply to the individual tunnels that are launched.

#### Composition

Because the ptrs interface wraps objects implementing connection oriented traits and and returns
trait objects implementing the same abstraction is is possible to wrap multiple transports on top of
one another. One reason to do this might be to have separate reliability, obfuscation and padding
strategies that can be composed interchangeably.

```rust no_run
todo!()
```

### Implementing a Transport

There are several constructions that can be used to build up a pluggable transport, in part this is
because no individual construction has proven demonstrably better than the others. However, this
demonstrates the flexibility of the high level `ptrs` trait.

#### Buffer Transform

```rust no_run
todo!()
```

#### Read / Wrap Oriented

```rust no_run
todo!()
```

#### Copy Based

```rust no_run
todo!()
```

## Example CLI

An example client / server using the ptrs pluggable transport library implementing a transparent
proxy can be found in the `src/bin/proxy` directory. More information about the proof-of-concept
proxy binary can be found in the `src/bin/proxy/README.md`. To build the proxy specifically use:

```console
cargo build --bin proxy [--release]
```

## Notes / Resources

While this is related to and motivated by the Tor pluggable transport system, the primary concern of
this repository is creating a consistent and useful abstraction for building pluggable transports.
For more information about Tor related pluggable transports see the following resources.

* [Contemporary Pluggable transport Specification (up to 3.0)](https://github.com/Pluggable-Transports/Pluggable-Transports-spec)

* [Pluggable Transport Specification (Version 1)](https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt)

* [Extended ORPort and TransportControlPort](https://gitweb.torproject.org/torspec.git/tree/proposals/196-transport-control-ports.txt)

* [Tor Extended ORPort Authentication](https://gitweb.torproject.org/torspec.git/tree/proposals/217-ext-orport-auth.txt)

## Open Source License

Dual licensing under both MIT and Apache-2.0 is the currently accepted standard by the Rust language
community and has been used for both the compiler and many public libraries since (see
[Why dual MIT/ASL2license?](https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license)).
In order to match the community standards, ptrs is using the dual MIT+Apache-2.0 license.

## Contributing

Contributors, Issues, and Pull Requests are Welcome
