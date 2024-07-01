# Obfs4 - The obfourscator - Pluggable Transport


An implementation of obfs4 in pure rust. 

⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
- interface subject to change at any time 
- Not production ready
  - do not rely on this for any security critical applications

## Installation

To install, add the following to your project's Cargo.toml:

```toml ignore
[dependencies]
obfs4 = "0.1.0"
```

## Integration Examples


Client example using [ptrs](../ptrs)

```rs
use ptrs::{Args, ClientBuilder as _, ClientTransport as _};
use obfs4;
use tokio::net::TcpStream;

let args = Args::from_str("")?;
let client = ClientBuilder::default()
    .options(args)?
    .build();

// future that opens a tcp connection when awaited
let conn_future = TcpStream::connect("127.0.0.1:9000");

// await (create) the tcp conn, attempt to handshake, and return a wrapped Read/Write object on success.
let obfs4_conn = client.wrap(box::pin(conn_future)).await?;

// ...
```


Server example

```rs
let message = b"Hello universe";
let (mut c, mut s) = tokio::io::duplex(65_536);
let mut rng = rand::thread_rng();

let o4_server = Server::new_from_random(&mut rng);

tokio::spawn(async move {
    let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();

    let mut buf = [0_u8; 50];
    let n = o4s_stream.read(&mut buf).await.unwrap();

    // echo the message back over the tunnel
    o4s_stream.write_all(&buf[..n]).await.unwrap();
});
```

Server example using [ptrs](../ptrs)

```rs
use ptrs::{ServerBuilder as _, ServerTransport as _};
use obfs4::Obfs4PT;

let mut builder = Obfs4PT::server_builder();
let server = if params.is_some() {
    builder.options(&params.unwrap())?.build()
} else {
    builder.build()
};

let listener = tokio::net::TcpListener::bind(listen_addrs).await?;
loop {
    let (conn, _) = listener.accept()?;
    let pt_conn = server.reveal(conn).await?;

    // pt_conn wraps conn and is usable as an `AsyncRead + AsyncWrite` object.
    tokio::spawn( async move{
        // use the connection (e.g. to echo)
        let (mut r, mut w) = tokio::io::split(pt_conn);
        if let Err(e) = tokio::io::copy(&mut r, &mut w).await {
            warn!("echo closed with error: {e}")
        }
    });
}

```

### Loose Ends:

- [X] server / client compatibility test go-to-rust and rust-to-go.
- [x] double check the bit randomization and clearing for high two bits in the `dalek` representative
- [ ] length distribution things
- [ ] iat mode handling

## Performance

- comparison to golang
- NaCl encryption library(s)

