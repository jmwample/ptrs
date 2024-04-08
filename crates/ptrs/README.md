
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

⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
- interface subject to change at any time 
- Not production ready
  - do not rely on this for any security critical applications

## Library Usage

This library (currently) revolves around the abstraction of connections as anything that implement
the traits [`tokio::io:AsyncRead`] + [`tokio::io::AsyncWrite`] + `Unpin + Send + Sync`. This allows
us to define the expected shared behavior of pluggable transports as a transform of these
[`Stream`]s.

```rust ignore
/// Future containing a generic result. We use this for functions that take
/// and/or return futures that will produce Read/Write tunnels once awaited.
pub type FutureResult<T, E> = Box<dyn Future<Output = Result<T, E>> + Send>;

/// Future containing a generic result, shorthand for ['FutureResult']. We use
/// this for functions that take and/or return futures that will produce
/// Read/Write tunnels once awaited.
pub(crate) type F<T, E> = FutureResult<T, E>;


/// Client Transport
pub trait ClientTransport<InRW, InErr>
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW: AsyncRead + AsyncWrite + Send + Unpin;
    type OutErr: std::error::Error + Send + Sync;
    type Builder: ClientBuilder<InRW>;

    /// Create a pluggable transport connection given a future that will return
    /// a Read/Write object that can be used as the underlying socket for the
    /// connection.
    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Create a connection for the pluggable transport client using the provided
    /// (pre-existing/pre-connected) Read/Write object as the underlying socket.
    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Returns a string identifier for this transport
    fn method_name() -> String;
}

/// Server Transport
pub trait ServerTransport<InRW>
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW: AsyncRead + AsyncWrite + Send + Unpin;
    type OutErr: std::error::Error + Send + Sync;
    type Builder: ServerBuilder<InRW>;

    /// Create/accept a connection for the pluggable transport client using the
    /// provided (pre-existing/pre-connected) Read/Write object as the
    /// underlying socket.
    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>>;

    /// Returns a string identifier for this transport
    fn method_name() -> String;
}
```

### Integrating ptrs Transports

Given this abstraction integrating transports into async rust applications becomes relatively
straightforward, for example, integrating the identity transport (which performs a direct copy with
no actual transform) could be done similar to:

```rust ignore
/// TODO
```

Integration on the client side is similarly straightforward.

```rust ignore
/// TODO
```

For more in depth integration exapmples see the binary examples in the
[`lyrebird`](https://github.com/jmwample/ptrs/tree/main/crates/lyrebird) crate.

#### Configuration & State

Transports can be configured using their respective builder interface implementations
which require `options(...)` and `statedir(...)` functions. See the
[`obfs4 transport`](../obfs4/src/pt.rs) for and example implementation of the
`ptrs` interfaces.



#### Composition

Because the ptrs interface wraps objects implementing connection oriented traits and and returns
trait objects implementing the same abstraction is is possible to wrap multiple transports on top of
one another. One reason to do this might be to have separate reliability, obfuscation and padding
strategies that can be composed interchangeably.

```rust ignore
let listener = tokio::net::TcpListener::bind("127.0.0.1:8009")
    .await
    .unwrap();

let (tcp_sock, _) = listener.accept().await.unwrap();

let pb: &BuilderS = &<Passthrough as PluggableTransport<TcpStream>>::server_builder();

let client1 = <BuilderS as ServerBuilder<TcpStream>>::build(pb);
let conn1 = client1.reveal(tcp_sock).await.unwrap();

let client2 = <BuilderS as ServerBuilder<TcpStream>>::build(pb);
let conn2 = client2.reveal(conn1).await.unwrap();

let client3 = <BuilderS as ServerBuilder<TcpStream>>::build(pb);
let mut sock = client3.reveal(conn2).await.unwrap();

let (mut r, mut w) = tokio::io::split(&mut sock);
_ = tokio::io::copy(&mut r, &mut w).await;
```

In the client:

```rust ignore
let pb: &BuilderC = &<Passthrough as PluggableTransport<TcpStream>>::client_builder();
let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
let conn_fut1 = client.establish(Box::pin(tcp_dial_fut));
let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
let conn_fut2 = client.establish(Box::pin(conn_fut1));
let client = <BuilderC as ClientBuilder<TcpStream>>::build(pb);
let conn_fut3 = client.establish(Box::pin(conn_fut2));
let mut conn = conn_fut3.await?;

let msg = b"a man a plan a canal panama";
_ = conn.write(&msg[..]).await?;
```

### Implementing a Transport

There are several constructions that can be used to build up a pluggable transport, in part this is
because no individual construction has proven demonstrably better than the others.

The [obfs4 transport](../obfs4) is implemented using the
[tokio\_util::codec](https://docs.rs/tokio-util/latest/tokio_util/codec/index.html) model.



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
